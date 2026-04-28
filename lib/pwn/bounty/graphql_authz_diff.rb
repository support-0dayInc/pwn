# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module Bounty
    # GraphQL actor/tenant authz diff engine that reuses LifecycleAuthzReplay
    # capture adapters and emits report-ready diff artifacts.
    module GraphQLAuthzDiff
      autoload :CrossSurfaceObjectLineage, 'pwn/bounty/graphql_authz_diff/cross_surface_object_lineage'
      autoload :OpaqueHandleAtlas, 'pwn/bounty/graphql_authz_diff/opaque_handle_atlas'

      DEFAULT_CHECKPOINTS = ['pre_change'].freeze

      # Supported Method Parameters::
      # diff_report = PWN::Bounty::GraphQLAuthzDiff.run_diff(
      #   endpoint: 'https://target.example/graphql',
      #   actors: [
      #     { id: 'owner', session: { headers: { Authorization: 'Bearer ...' } } },
      #     { id: 'revoked_user', session: { headers: { Authorization: 'Bearer ...' } } }
      #   ],
      #   operations: [
      #     {
      #       id: 'admin_secret',
      #       operation_name: 'AdminSecret',
      #       query: 'query AdminSecret { adminSecret { id token } }',
      #       variables: {},
      #       expected_access: { owner: true, revoked_user: false }
      #     }
      #   ],
      #   output_dir: '/tmp/graphql-authz-diff',
      #   run_id: 'graphql-authz-diff-smoke'
      # )
      public_class_method def self.run_diff(opts = {})
        endpoint = opts[:endpoint].to_s.scrub.strip
        raise 'ERROR: endpoint is required' if endpoint.empty?

        actors = normalize_actors(
          actors: opts[:actors],
          actor_sessions: opts[:actor_sessions],
          actor_expectations: opts[:actor_expectations]
        )
        operations = normalize_operations(operations: opts[:operations])
        checkpoints = normalize_checkpoints(checkpoints: opts[:checkpoints])

        plan = build_plan(
          endpoint: endpoint,
          actors: actors,
          operations: operations,
          checkpoints: checkpoints,
          campaign_id: opts[:campaign_id],
          campaign_label: opts[:campaign_label],
          notes: opts[:notes]
        )

        run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
          plan: plan,
          output_dir: opts[:output_dir],
          run_id: opts[:run_id]
        )

        execution = PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
          run_obj: run_obj,
          fail_fast: opts[:fail_fast] == true
        )

        lifecycle_summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(
          run_obj: run_obj
        )

        analysis = analyze_diffs(
          run_obj: run_obj,
          actors: actors,
          operations: operations,
          checkpoints: checkpoints
        )

        diff_report = {
          generated_at: Time.now.utc.iso8601,
          run_id: run_obj[:run_id],
          run_root: run_obj[:run_root],
          endpoint: endpoint,
          checkpoints: checkpoints,
          execution: execution,
          lifecycle_summary: lifecycle_summary,
          matrix: analysis[:matrix],
          finding_count: analysis[:findings].length,
          findings: analysis[:findings]
        }

        opaque_handle_atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.run(
          diff_report: diff_report,
          surface_evidence: opts[:surface_evidence],
          object_seeds: opts[:object_seeds],
          output_dir: run_obj[:run_root]
        )
        diff_report[:opaque_handle_atlas] = opaque_handle_atlas
        diff_report[:opaque_handle_family_count] = opaque_handle_atlas[:family_count]
        diff_report[:opaque_handle_reportable_count] = opaque_handle_atlas[:reportable_candidate_count]

        cross_surface_lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.run(
          diff_report: diff_report,
          surface_evidence: opts[:surface_evidence],
          object_seeds: merged_object_seeds(
            object_seeds: opts[:object_seeds],
            opaque_handle_atlas: opaque_handle_atlas
          ),
          output_dir: run_obj[:run_root]
        )
        diff_report[:cross_surface_object_lineage] = cross_surface_lineage
        diff_report[:cross_surface_family_count] = cross_surface_lineage[:family_count]
        diff_report[:cross_surface_reportable_count] = cross_surface_lineage[:reportable_candidate_count]

        lifecycle_summary[:submission_bundle] = PWN::Bounty::LifecycleAuthzReplay::SubmissionBundle.evaluate(
          run_obj: run_obj,
          summary: lifecycle_summary,
          object_family_candidates: [opaque_handle_atlas[:best_candidate]].compact
        )

        write_json(
          path: File.join(run_obj[:run_root], 'graphql_authz_diff.json'),
          obj: diff_report
        )
        write_markdown(
          path: File.join(run_obj[:run_root], 'graphql_authz_diff.md'),
          report: diff_report
        )

        diff_report
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # plan = PWN::Bounty::GraphQLAuthzDiff.build_plan(
      #   endpoint: 'https://target.example/graphql',
      #   actors: normalized_actors,
      #   operations: normalized_operations,
      #   checkpoints: ['pre_change']
      # )
      public_class_method def self.build_plan(opts = {})
        endpoint = opts[:endpoint].to_s.scrub.strip
        actors = Array(opts[:actors]).map { |actor| symbolize_obj(actor) }
        operations = Array(opts[:operations]).map { |operation| symbolize_obj(operation) }
        checkpoints = Array(opts[:checkpoints]).map { |checkpoint| normalize_token(checkpoint) }

        raise 'ERROR: endpoint is required' if endpoint.empty?
        raise 'ERROR: actors is required' if actors.empty?
        raise 'ERROR: operations is required' if operations.empty?
        checkpoints = DEFAULT_CHECKPOINTS if checkpoints.empty?

        campaign_id = normalize_token(opts[:campaign_id])
        campaign_id = 'graphql_authz_diff' if campaign_id.empty?

        campaign_label = opts[:campaign_label].to_s.scrub.strip
        campaign_label = 'GraphQL AuthZ Diff' if campaign_label.empty?

        surfaces = operations.map do |operation|
          {
            id: operation[:id],
            label: operation[:label],
            metadata: {
              route_category: 'secondary',
              graphql_authz_diff: {
                operation_id: operation[:id],
                operation_name: operation[:operation_name],
                expected_access: operation[:expected_access]
              },
              adapter: {
                type: 'graphql',
                url: endpoint,
                operation_name: operation[:operation_name],
                query: operation[:query],
                variables: operation[:variables]
              }
            }
          }
        end

        expected_denied_after = checkpoints.select { |checkpoint| checkpoint.start_with?('post_change') }

        plan = {
          campaign: {
            id: campaign_id,
            label: campaign_label,
            target: endpoint,
            change_event: 'graphql_authz_diff',
            notes: opts[:notes].to_s
          },
          actors: actors,
          surfaces: surfaces,
          checkpoints: checkpoints,
          expected_denied_after: expected_denied_after,
          metadata: {
            graphql_authz_diff: {
              endpoint: endpoint,
              operations: operations.map do |operation|
                {
                  id: operation[:id],
                  operation_name: operation[:operation_name],
                  expected_access: operation[:expected_access]
                }
              end
            }
          }
        }

        PWN::Bounty::LifecycleAuthzReplay.normalize_plan(plan: plan)
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
            diff_report = PWN::Bounty::GraphQLAuthzDiff.run_diff(
              endpoint: 'https://target.example/graphql',
              actors: [...],
              operations: [...],
              output_dir: '/tmp/graphql-authz-diff'
            )

            plan = PWN::Bounty::GraphQLAuthzDiff.build_plan(
              endpoint: 'https://target.example/graphql',
              actors: [...],
              operations: [...],
              checkpoints: ['pre_change']
            )

            atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.run(
              diff_report: diff_report,
              surface_evidence: '/tmp/surface_evidence.json',
              object_seeds: '/tmp/object_seeds.json',
              output_dir: '/tmp/graphql-authz-diff'
            )

            lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.run(
              diff_report: diff_report,
              surface_evidence: '/tmp/surface_evidence.json',
              object_seeds: '/tmp/object_seeds.json',
              output_dir: '/tmp/graphql-authz-diff'
            )
        HELP
      end

      private_class_method def self.analyze_diffs(opts = {})
        run_obj = symbolize_obj(opts[:run_obj] || {})
        actors = Array(opts[:actors]).map { |actor| symbolize_obj(actor) }
        operations = Array(opts[:operations]).map { |operation| symbolize_obj(operation) }
        checkpoints = Array(opts[:checkpoints]).map { |checkpoint| normalize_token(checkpoint) }

        observation_lookup = build_observation_lookup(run_obj: run_obj)
        matrix = []
        findings = []

        checkpoints.each do |checkpoint|
          operations.each do |operation|
            operation_id = operation[:id]
            row = {
              checkpoint: checkpoint,
              operation_id: operation_id,
              operation_name: operation[:operation_name],
              actor_results: []
            }

            actor_results = actors.map do |actor|
              actor_id = actor[:id]
              observation = symbolize_obj(observation_lookup.dig(checkpoint, operation_id, actor_id) || {})
              status = normalize_token(observation[:status])
              graphql_payload = symbolize_obj(observation.dig(:response, :graphql) || {})
              data = symbolize_obj(graphql_payload[:data] || {})
              errors = Array(graphql_payload[:errors])
              http_status = observation.dig(:response, :http_status)

              expected_access = expected_access_for(
                actor: actor,
                operation: operation
              )

              result = {
                actor: actor_id,
                expected_access: expected_access,
                status: status,
                http_status: http_status,
                error_count: errors.length,
                data_path_count: data_paths(obj: data).length,
                evidence_path: observation[:evidence_path]
              }

              row[:actor_results] << result
              result
            end

            matrix << row

            actor_results.each do |result|
              expected_access = result[:expected_access]
              next if expected_access.nil?

              status = result[:status]
              actor_id = result[:actor]
              evidence_path = result[:evidence_path]

              if expected_access == false && status == 'accessible'
                findings << {
                  id: "#{checkpoint}:#{operation_id}:#{actor_id}:unexpected_access",
                  severity: 'high',
                  confidence: 'high',
                  finding_type: 'graphql_authz_bypass',
                  checkpoint: checkpoint,
                  operation_id: operation_id,
                  operation_name: operation[:operation_name],
                  actor: actor_id,
                  expected_access: expected_access,
                  observed_status: status,
                  summary: "Actor #{actor_id} retained GraphQL access for #{operation[:operation_name]} despite expected denial.",
                  evidence_path: evidence_path
                }
              elsif expected_access == true && status == 'denied'
                findings << {
                  id: "#{checkpoint}:#{operation_id}:#{actor_id}:unexpected_deny",
                  severity: 'medium',
                  confidence: 'medium',
                  finding_type: 'graphql_denial_regression',
                  checkpoint: checkpoint,
                  operation_id: operation_id,
                  operation_name: operation[:operation_name],
                  actor: actor_id,
                  expected_access: expected_access,
                  observed_status: status,
                  summary: "Actor #{actor_id} was denied for #{operation[:operation_name]} where access was expected.",
                  evidence_path: evidence_path
                }
              end
            end

            privileged = actor_results.find { |result| result[:expected_access] == true }
            next if privileged.nil?

            actor_results.each do |result|
              next if result[:actor] == privileged[:actor]
              next unless privileged[:status] == 'denied' && result[:status] == 'accessible'

              findings << {
                id: "#{checkpoint}:#{operation_id}:#{result[:actor]}:baseline_denied_alternate_access",
                severity: 'high',
                confidence: 'medium',
                finding_type: 'graphql_alternate_channel_access',
                checkpoint: checkpoint,
                operation_id: operation_id,
                operation_name: operation[:operation_name],
                actor: result[:actor],
                expected_access: result[:expected_access],
                observed_status: result[:status],
                summary: "Actor #{result[:actor]} was accessible for #{operation[:operation_name]} while privileged baseline actor was denied.",
                evidence_path: result[:evidence_path]
              }
            end
          end
        end

        findings.sort_by! { |finding| [-severity_rank(finding[:severity]), finding[:id]] }

        {
          matrix: matrix,
          findings: findings.uniq { |finding| finding[:id] }
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.build_observation_lookup(opts = {})
        run_obj = symbolize_obj(opts[:run_obj] || {})
        observations = Array(run_obj[:observations]).map { |observation| symbolize_obj(observation) }

        observations.each_with_object({}) do |observation, lookup|
          checkpoint = normalize_token(observation[:checkpoint])
          surface = normalize_token(observation[:surface])
          actor = normalize_token(observation[:actor])

          lookup[checkpoint] ||= {}
          lookup[checkpoint][surface] ||= {}
          lookup[checkpoint][surface][actor] = observation
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_actors(opts = {})
        raw_actors = Array(opts[:actors])
        actor_sessions = symbolize_obj(opts[:actor_sessions] || {})
        actor_expectations = symbolize_obj(opts[:actor_expectations] || {})

        raise 'ERROR: actors is required' if raw_actors.empty?

        raw_actors.each_with_index.map do |actor, index|
          actor_hash = actor.is_a?(Hash) ? symbolize_obj(actor) : { id: actor.to_s, label: actor.to_s }
          actor_id = normalize_token(actor_hash[:id] || actor_hash[:name])
          raise 'ERROR: actor id is required' if actor_id.empty?

          actor_label = actor_hash[:label].to_s.scrub.strip
          actor_label = actor_id if actor_label.empty?

          session = symbolize_obj(actor_hash[:session] || actor_sessions[actor_id] || actor_sessions[actor_id.to_sym] || {})
          expected_default = actor_hash.key?(:expected_access_default) ?
            actor_hash[:expected_access_default] :
            actor_expectations.fetch(actor_id.to_sym, actor_expectations.fetch(actor_id, index.zero?))

          {
            id: actor_id,
            label: actor_label,
            metadata: {
              session: session,
              graphql_authz_diff: {
                expected_access_default: expected_default == true
              }
            }
          }
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_operations(opts = {})
        raw_operations = Array(opts[:operations])
        raise 'ERROR: operations is required' if raw_operations.empty?

        raw_operations.each_with_index.map do |operation, index|
          operation_hash = operation.is_a?(Hash) ? symbolize_obj(operation) : { query: operation.to_s }

          operation_id = normalize_token(operation_hash[:id] || operation_hash[:operation_name] || "operation_#{index + 1}")
          operation_name = operation_hash[:operation_name].to_s.scrub.strip
          operation_name = operation_hash[:name].to_s.scrub.strip if operation_name.empty?
          operation_name = operation_id if operation_name.empty?

          query = operation_hash[:query].to_s
          raise "ERROR: operation query is required for #{operation_id}" if query.strip.empty?

          variables = symbolize_obj(operation_hash[:variables] || {})
          expected_access = normalize_expected_access(expected_access: operation_hash[:expected_access])

          {
            id: operation_id,
            label: operation_hash[:label].to_s.scrub.strip.empty? ? operation_name : operation_hash[:label].to_s.scrub.strip,
            operation_name: operation_name,
            query: query,
            variables: variables,
            expected_access: expected_access
          }
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_expected_access(opts = {})
        raw = opts[:expected_access]
        return {} if raw.nil?

        expected_access = symbolize_obj(raw)
        if expected_access.is_a?(Hash)
          expected_access.each_with_object({}) do |(key, value), acc|
            actor_id = normalize_token(key)
            next if actor_id.empty?

            acc[actor_id] = value == true
          end
        else
          {}
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_checkpoints(opts = {})
        checkpoints = Array(opts[:checkpoints]).map { |checkpoint| normalize_token(checkpoint) }.reject(&:empty?)
        checkpoints = DEFAULT_CHECKPOINTS if checkpoints.empty?
        checkpoints.uniq
      rescue StandardError => e
        raise e
      end

      private_class_method def self.merged_object_seeds(opts = {})
        object_seeds = Array(opts[:object_seeds]).map { |seed| symbolize_obj(seed) }
        opaque_handle_atlas = symbolize_obj(opts[:opaque_handle_atlas] || {})
        seed_suggestions = Array(opaque_handle_atlas[:seed_suggestions]).map { |seed| symbolize_obj(seed) }

        merged = object_seeds + seed_suggestions
        merged.uniq do |seed|
          normalize_token(seed[:family_key] || seed[:id] || seed[:node_id] || seed[:slug] || seed[:url])
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.expected_access_for(opts = {})
        actor = symbolize_obj(opts[:actor] || {})
        operation = symbolize_obj(opts[:operation] || {})
        actor_id = normalize_token(actor[:id])

        operation_expectation = symbolize_obj(operation[:expected_access] || {})
        return operation_expectation[actor_id] unless operation_expectation[actor_id].nil?

        actor_default = symbolize_obj(actor[:metadata] || {}).dig(:graphql_authz_diff, :expected_access_default)
        return actor_default unless actor_default.nil?

        nil
      rescue StandardError => e
        raise e
      end

      private_class_method def self.data_paths(opts = {})
        obj = opts[:obj]
        base_path = opts[:base_path].to_s

        case obj
        when Hash
          obj.flat_map do |key, value|
            path = base_path.empty? ? key.to_s : "#{base_path}.#{key}"
            child_paths = data_paths(obj: value, base_path: path)
            child_paths.empty? ? [path] : child_paths
          end
        when Array
          obj.each_with_index.flat_map do |value, index|
            path = "#{base_path}[#{index}]"
            child_paths = data_paths(obj: value, base_path: path)
            child_paths.empty? ? [path] : child_paths
          end
        else
          base_path.empty? ? [] : [base_path]
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.severity_rank(severity)
        case normalize_token(severity)
        when 'critical'
          4
        when 'high'
          3
        when 'medium'
          2
        when 'low'
          1
        else
          0
        end
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
        lines << '# GraphQL AuthZ Diff Report'
        lines << ''
        lines << "- Generated At (UTC): `#{report[:generated_at]}`"
        lines << "- Run ID: `#{report[:run_id]}`"
        lines << "- Endpoint: `#{report[:endpoint]}`"
        lines << "- Findings: `#{report[:finding_count]}`"
        lines << ''

        lines << '## Findings'
        if Array(report[:findings]).empty?
          lines << '- No authz deltas found in this run.'
        else
          Array(report[:findings]).each do |finding|
            finding_hash = symbolize_obj(finding)
            lines << "- [#{finding_hash[:severity].to_s.upcase}] #{finding_hash[:summary]}"
            lines << "  - operation: `#{finding_hash[:operation_name]}` checkpoint: `#{finding_hash[:checkpoint]}` actor: `#{finding_hash[:actor]}`"
            lines << "  - evidence: `#{finding_hash[:evidence_path]}`"
          end
        end

        lines << ''
        lines << '## Opaque Handle Atlas'
        atlas = symbolize_obj(report[:opaque_handle_atlas] || {})
        lines << "- Families: `#{atlas[:family_count] || 0}`"
        lines << "- Reportable Candidates: `#{atlas[:reportable_candidate_count] || 0}`"
        best_candidate = symbolize_obj(atlas[:best_candidate] || {})
        unless best_candidate.empty?
          lines << "- Best Candidate: `#{best_candidate[:family_key]}` angle=`#{best_candidate[:report_angle]}`"
        end

        lines << ''
        lines << '## Cross-Surface Lineage'
        lineage = symbolize_obj(report[:cross_surface_object_lineage] || {})
        lines << "- Families: `#{lineage[:family_count] || 0}`"
        lines << "- Reportable Candidates: `#{lineage[:reportable_candidate_count] || 0}`"

        lines << ''
        lines << '## Matrix'
        Array(report[:matrix]).each do |row|
          row_hash = symbolize_obj(row)
          lines << ''
          lines << "### #{row_hash[:checkpoint]} :: #{row_hash[:operation_name]}"
          lines << '| Actor | Expected Access | Status | HTTP | Errors | Data Paths |'
          lines << '| --- | --- | --- | --- | --- | --- |'
          Array(row_hash[:actor_results]).each do |result|
            result_hash = symbolize_obj(result)
            lines << "| #{result_hash[:actor]} | #{result_hash[:expected_access].inspect} | #{result_hash[:status]} | #{result_hash[:http_status]} | #{result_hash[:error_count]} | #{result_hash[:data_path_count]} |"
          end
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
