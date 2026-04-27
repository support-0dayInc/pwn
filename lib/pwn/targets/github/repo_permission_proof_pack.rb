# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module Targets
    module GitHub
      # Verifies repo-level read revocation proof before treating secondary
      # route access as reportable authz drift.
      module RepoPermissionProofPack
        DENY_STATUSES = [401, 403, 404].freeze

        # Supported Method Parameters::
        # report = PWN::Targets::GitHub::RepoPermissionProofPack.evaluate(
        #   repo: { owner: 'acme', name: 'widgets' },
        #   repo_rest_probe: { http_status: 403, body: '{"message":"Not Found"}' },
        #   repo_graphql_probe: { http_status: 200, body: '{"data":{"repository":null},"errors":[{"message":"Could not resolve to a Repository"}]}' },
        #   object_probes: [{ id: 'pull_123', surface: 'pull_html', accessible: true }]
        # )
        public_class_method def self.evaluate(opts = {})
          repo = symbolize_obj(opts[:repo] || {})
          repo_rest_probe = symbolize_obj(opts[:repo_rest_probe] || opts[:repo_metadata_rest_probe] || {})
          repo_graphql_probe = symbolize_obj(opts[:repo_graphql_probe] || opts[:repo_metadata_graphql_probe] || {})
          object_probes = normalize_object_probes(object_probes: opts[:object_probes] || opts[:secondary_probes])

          rest_gate = evaluate_rest_probe(probe: repo_rest_probe)
          graphql_gate = evaluate_graphql_probe(probe: repo_graphql_probe)

          gate_result = determine_gate_result(rest_gate: rest_gate, graphql_gate: graphql_gate)
          secondary_visible = object_probes.select { |probe| probe[:accessible] == true }

          finding_decision = case gate_result[:result]
                             when 'passed'
                               secondary_visible.empty? ? 'no_secondary_access' : 'reportable_candidate'
                             when 'failed'
                               secondary_visible.empty? ? 'control_only' : 'control_only'
                             else
                               secondary_visible.empty? ? 'insufficient_signal' : 'needs_repo_deny_proof'
                             end

          contradiction = nil
          if gate_result[:result] == 'failed' && !secondary_visible.empty?
            contradiction = 'secondary visible, repo still readable -> control-only'
          end

          summary_line = build_summary_line(
            gate_result: gate_result,
            finding_decision: finding_decision,
            contradiction: contradiction
          )

          report = {
            generated_at: Time.now.utc.iso8601,
            repo: repo,
            gate: gate_result,
            secondary_probe_count: object_probes.length,
            secondary_visible_count: secondary_visible.length,
            secondary_visible: secondary_visible,
            finding_decision: finding_decision,
            contradiction: contradiction,
            summary_line: summary_line,
            next_actions: next_actions(
              gate_result: gate_result,
              finding_decision: finding_decision,
              secondary_visible: secondary_visible
            )
          }

          output_dir = opts[:output_dir].to_s.scrub.strip
          unless output_dir.empty?
            run_id = opts[:run_id].to_s.scrub.strip
            run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-repo-permission-proof-pack" if run_id.empty?
            run_root = File.expand_path(File.join(output_dir, run_id))
            FileUtils.mkdir_p(run_root)

            write_json(path: File.join(run_root, 'repo_permission_proof_pack.json'), obj: report)
            write_markdown(path: File.join(run_root, 'repo_permission_proof_pack.md'), report: report)

            report[:run_root] = run_root
            report[:run_id] = run_id
          end

          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # gated_findings = PWN::Targets::GitHub::RepoPermissionProofPack.apply_gate_to_findings(
        #   findings: findings,
        #   proof_pack: proof_pack
        # )
        public_class_method def self.apply_gate_to_findings(opts = {})
          findings = Array(opts[:findings]).map { |finding| symbolize_obj(finding || {}) }
          proof_pack = symbolize_obj(opts[:proof_pack] || opts[:evaluation] || {})
          gate_result = normalize_token(proof_pack.dig(:gate, :result))
          finding_decision = normalize_token(proof_pack[:finding_decision])

          findings.map do |finding|
            finding_copy = symbolize_obj(finding)
            finding_copy[:repo_permission_gate] = {
              result: gate_result,
              decision: finding_decision,
              summary_line: proof_pack[:summary_line]
            }

            if gate_result == 'failed'
              finding_copy[:classification] = 'control_only'
              finding_copy[:severity] = 'info'
            elsif gate_result == 'unknown'
              finding_copy[:classification] = 'needs_repo_deny_proof'
            end

            finding_copy
          end
        rescue StandardError => e
          raise e
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>
        public_class_method def self.authors
          "AUTHOR(S):
            0day Inc. <support@0dayinc.com>
          "
        end

        # Display Usage Information
        public_class_method def self.help
          <<~HELP
            Usage:
              report = PWN::Targets::GitHub::RepoPermissionProofPack.evaluate(
                repo: { owner: 'acme', name: 'widgets' },
                repo_rest_probe: { http_status: 403, body: '{"message":"Not Found"}' },
                repo_graphql_probe: { http_status: 200, body: '{"data":{"repository":null},"errors":[{"message":"Could not resolve to a Repository"}]}' },
                object_probes: [
                  { id: 'pull_html', surface: 'pull_html', accessible: true }
                ],
                output_dir: '/tmp/repo-permission-proof-pack'
              )

              gated = PWN::Targets::GitHub::RepoPermissionProofPack.apply_gate_to_findings(
                findings: [{ id: 'f1', severity: 'high' }],
                proof_pack: report
              )
          HELP
        end

        private_class_method def self.normalize_object_probes(opts = {})
          object_probes = Array(opts[:object_probes]).map { |probe| symbolize_obj(probe || {}) }

          object_probes.map do |probe|
            status = normalize_token(probe[:status])
            accessible = probe[:accessible]
            if accessible.nil?
              accessible = true if status == 'accessible'
              accessible = false if status == 'denied'
            end

            {
              id: probe[:id].to_s,
              surface: probe[:surface].to_s,
              status: status,
              accessible: accessible == true,
              notes: probe[:notes].to_s,
              evidence_path: probe[:evidence_path].to_s,
              http_status: probe[:http_status]
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evaluate_rest_probe(opts = {})
          probe = symbolize_obj(opts[:probe] || {})
          status_code = normalize_status_code(status_code: probe[:http_status] || probe[:status_code])
          body = probe[:body].to_s
          body = probe[:response_body].to_s if body.empty?
          parsed = parse_json(body: body)

          explicit_accessible = probe[:accessible] == true
          explicit_denied = probe[:denied] == true

          readable_markers = [
            parsed[:full_name],
            parsed[:name],
            parsed[:visibility],
            parsed[:private]
          ]

          denied_message = parsed[:message].to_s.downcase
          denied_by_message = denied_message.include?('not found') ||
                              denied_message.include?('resource not accessible') ||
                              denied_message.include?('requires authentication')

          result = if explicit_accessible || (!status_code.nil? && status_code == 200 && readable_markers.compact.any? && !denied_by_message)
                     'accessible'
                   elsif explicit_denied || (!status_code.nil? && DENY_STATUSES.include?(status_code)) || denied_by_message
                     'denied'
                   else
                     'unknown'
                   end

          {
            result: result,
            http_status: status_code,
            reason: rest_reason(result: result, status_code: status_code, denied_by_message: denied_by_message)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evaluate_graphql_probe(opts = {})
          probe = symbolize_obj(opts[:probe] || {})
          status_code = normalize_status_code(status_code: probe[:http_status] || probe[:status_code])

          graphql = symbolize_obj(probe[:graphql] || {})
          body = probe[:body].to_s
          body = probe[:response_body].to_s if body.empty?

          if graphql.empty? && !body.empty?
            parsed = parse_json(body: body)
            if parsed.key?(:data) || parsed.key?(:errors)
              graphql = parsed
            end
          end

          explicit_accessible = probe[:accessible] == true
          explicit_denied = probe[:denied] == true

          repository_node = graphql.dig(:data, :repository)
          errors = Array(graphql[:errors]).map { |entry| symbolize_obj(entry || {}) }
          error_text = errors.map { |entry| entry[:message].to_s.downcase }.join(' ')
          denied_by_error = error_text.include?('could not resolve to a repository') ||
                            error_text.include?('forbidden') ||
                            error_text.include?('resource not accessible') ||
                            error_text.include?('not found')

          result = if explicit_accessible || (!status_code.nil? && status_code == 200 && !repository_node.nil?)
                     'accessible'
                   elsif explicit_denied || (!status_code.nil? && DENY_STATUSES.include?(status_code)) || denied_by_error || (!errors.empty? && repository_node.nil?)
                     'denied'
                   else
                     'unknown'
                   end

          {
            result: result,
            http_status: status_code,
            reason: graphql_reason(result: result, denied_by_error: denied_by_error)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.determine_gate_result(opts = {})
          rest_gate = symbolize_obj(opts[:rest_gate] || {})
          graphql_gate = symbolize_obj(opts[:graphql_gate] || {})

          rest_result = normalize_token(rest_gate[:result])
          graphql_result = normalize_token(graphql_gate[:result])

          result = if rest_result == 'accessible' || graphql_result == 'accessible'
                     'failed'
                   elsif rest_result == 'denied' && graphql_result == 'denied'
                     'passed'
                   else
                     'unknown'
                   end

          reason = case result
                   when 'failed'
                     'repo metadata still readable by revoked actor'
                   when 'passed'
                     'repo metadata denied in both REST and GraphQL controls'
                   else
                     'repo metadata deny proof incomplete'
                   end

          {
            result: result,
            reason: reason,
            rest_probe: rest_gate,
            graphql_probe: graphql_gate
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.next_actions(opts = {})
          gate_result = symbolize_obj(opts[:gate_result] || {})
          finding_decision = normalize_token(opts[:finding_decision])
          secondary_visible = Array(opts[:secondary_visible]).map { |probe| symbolize_obj(probe) }

          case normalize_token(gate_result[:result])
          when 'passed'
            if secondary_visible.empty?
              [
                'Collect one secondary surface probe before report packaging to confirm drift.'
              ]
            else
              [
                'Preserve repo deny controls and secondary-access artifacts in the same timeline bundle.',
                'Draft report with direct-denied vs secondary-visible contradiction section.'
              ]
            end
          when 'failed'
            [
              'Do not treat this as reportable authz drift yet; classify as control-only.',
              'Re-run revoke/permission removal until repo REST + GraphQL metadata are both denied.'
            ]
          else
            actions = [
              'Capture missing repo deny control: actor-side GET /repos/{owner}/{repo}.',
              'Capture missing repo GraphQL control: repository { visibility isPrivate viewerPermission }.'
            ]
            if finding_decision == 'needs_repo_deny_proof' && !secondary_visible.empty?
              actions << 'Hold secondary-surface evidence; severity decision waits on repo deny proof.'
            end
            actions
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_summary_line(opts = {})
          gate_result = symbolize_obj(opts[:gate_result] || {})
          finding_decision = normalize_token(opts[:finding_decision])
          contradiction = opts[:contradiction].to_s

          line = "gate=#{gate_result[:result]} decision=#{finding_decision}"
          line += " reason=#{gate_result[:reason]}"
          line += " contradiction=#{contradiction}" unless contradiction.empty?
          line
        rescue StandardError => e
          raise e
        end

        private_class_method def self.rest_reason(opts = {})
          result = normalize_token(opts[:result])
          status_code = opts[:status_code]
          denied_by_message = opts[:denied_by_message] == true

          case result
          when 'accessible'
            "HTTP #{status_code} with repo metadata fields"
          when 'denied'
            denied_by_message ? 'response message indicates denied repo access' : "HTTP #{status_code} deny status"
          else
            "HTTP #{status_code || 'n/a'} inconclusive"
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.graphql_reason(opts = {})
          result = normalize_token(opts[:result])
          denied_by_error = opts[:denied_by_error] == true

          case result
          when 'accessible'
            'GraphQL repository node returned for actor'
          when 'denied'
            denied_by_error ? 'GraphQL errors indicate repository denial' : 'GraphQL denied/inaccessible state'
          else
            'GraphQL probe inconclusive'
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_status_code(opts = {})
          status_code = opts[:status_code]
          return status_code if status_code.is_a?(Integer)
          return status_code.to_i if status_code.to_s.match?(/^\d+$/)

          nil
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_json(opts = {})
          body = opts[:body].to_s.scrub.strip
          return {} if body.empty?

          symbolize_obj(JSON.parse(body))
        rescue JSON::ParserError
          {}
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_json(opts = {})
          path = opts[:path].to_s
          obj = symbolize_obj(opts[:obj] || {})

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, JSON.pretty_generate(obj))
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_markdown(opts = {})
          path = opts[:path].to_s
          report = symbolize_obj(opts[:report] || {})

          lines = []
          lines << '# GitHub Repo Permission Proof Pack'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Gate Result: `#{report.dig(:gate, :result)}`"
          lines << "- Finding Decision: `#{report[:finding_decision]}`"
          lines << "- Summary: `#{report[:summary_line]}`"
          lines << ''

          lines << '## Gate Details'
          lines << "- Reason: #{report.dig(:gate, :reason)}"
          lines << "- REST Probe: `#{symbolize_obj(report.dig(:gate, :rest_probe) || {}).to_json}`"
          lines << "- GraphQL Probe: `#{symbolize_obj(report.dig(:gate, :graphql_probe) || {}).to_json}`"

          lines << ''
          lines << '## Secondary Visible Probes'
          if Array(report[:secondary_visible]).empty?
            lines << '- None'
          else
            Array(report[:secondary_visible]).each do |probe|
              probe_hash = symbolize_obj(probe)
              lines << "- #{probe_hash[:id]} (#{probe_hash[:surface]}) status=#{probe_hash[:status]} evidence=#{probe_hash[:evidence_path]}"
            end
          end

          lines << ''
          lines << '## Next Actions'
          Array(report[:next_actions]).each do |entry|
            lines << "- #{entry}"
          end

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, lines.join("\n"))
        rescue StandardError => e
          raise e
        end

        private_class_method def self.symbolize_obj(obj)
          case obj
          when Array
            obj.map { |entry| symbolize_obj(entry) }
          when Hash
            obj.each_with_object({}) do |(key, value), accum|
              sym_key = key.respond_to?(:to_sym) ? key.to_sym : key
              accum[sym_key] = symbolize_obj(value)
            end
          else
            obj
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_token(token)
          token.to_s.scrub.strip.downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_+|_+$/, '')
        rescue StandardError => e
          raise e
        end
      end
    end
  end
end
