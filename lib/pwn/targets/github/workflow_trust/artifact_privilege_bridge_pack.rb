# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module Targets
    module GitHub
      module WorkflowTrust
        # Converts stale-acceptance + live-proof signals into a deterministic
        # replay matrix and provider-ready proof-kit artifacts.
        module ArtifactPrivilegeBridgePack
          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.analyze(
          #   transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
          #   live_proof_pack: '/tmp/workflow_trust_live_proof_pack.json',
          #   trust_policies: '/tmp/trust_policies.json'
          # )
          public_class_method def self.analyze(opts = {})
            transition_bundle = normalize_transition_bundle(
              transition_bundle: opts[:transition_bundle],
              claim_snapshots: opts[:claim_snapshots],
              trust_policies: opts[:trust_policies],
              transition_fields: opts[:transition_fields]
            )

            live_proof_pack = normalize_live_proof_pack(
              live_proof_pack: opts[:live_proof_pack],
              transition_bundle: transition_bundle,
              later_snapshot: opts[:later_snapshot] || opts[:token_snapshot],
              trust_policies: opts[:trust_policies],
              provider: opts[:provider],
              allowed_audiences: opts[:allowed_audiences],
              candidate_id: opts[:candidate_id]
            )

            trust_policies = resolve_structured_input(input: opts[:trust_policies])
            candidate = select_candidate(
              transition_bundle: transition_bundle,
              candidate_id: opts[:candidate_id]
            )

            provider = normalize_token(
              opts[:provider] ||
              live_proof_pack[:provider] ||
              candidate[:provider] ||
              infer_provider_from_policies(policies: trust_policies)
            )
            provider = 'generic' if provider.empty?

            selected_policy = select_policy(
              candidate: candidate,
              trust_policies: trust_policies,
              provider: provider
            )

            matrix = build_experiment_matrix(
              provider: provider,
              candidate: candidate,
              live_proof_pack: live_proof_pack,
              selected_policy: selected_policy
            )

            aws_policy_pack = aws_policy_pack(
              provider: provider,
              selected_policy: selected_policy,
              live_proof_pack: live_proof_pack,
              candidate: candidate
            )

            replay_ready = live_proof_pack.dig(:replay_readiness, :ready) == true
            critical_candidate = replay_ready && %w[aws gcp azure].include?(provider) && !candidate.empty?

            {
              generated_at: Time.now.utc.iso8601,
              provider: provider,
              replay_ready: replay_ready,
              critical_candidate: critical_candidate,
              impact_label: critical_candidate ? 'critical_candidate' : (replay_ready ? 'high_candidate' : 'needs_more_evidence'),
              primary_candidate: candidate,
              selected_policy: compact_policy_summary(policy: selected_policy),
              transition_bundle_summary: {
                claim_snapshot_count: transition_bundle[:claim_snapshot_count],
                trust_policy_count: transition_bundle[:trust_policy_count],
                stale_acceptance_candidate_count: transition_bundle[:stale_acceptance_candidate_count]
              },
              live_proof_summary: {
                provider: live_proof_pack[:provider],
                replay_status: live_proof_pack.dig(:replay_readiness, :status),
                blocking_reasons: Array(live_proof_pack.dig(:replay_readiness, :blocking_reasons)),
                recommendation: live_proof_pack.dig(:replay_readiness, :recommendation)
              },
              experiment_matrix: matrix,
              aws_policy_pack: aws_policy_pack,
              report_instructions: report_instructions(
                replay_ready: replay_ready,
                critical_candidate: critical_candidate,
                provider: provider,
                matrix: matrix
              )
            }
          rescue StandardError => e
            raise e
          end

          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.run(
          #   transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
          #   live_proof_pack: '/tmp/workflow_trust_live_proof_pack.json',
          #   output_dir: '/tmp/workflow-trust-bridge-pack'
          # )
          public_class_method def self.run(opts = {})
            report = analyze(opts)

            output_dir = opts[:output_dir].to_s.scrub.strip
            return report if output_dir.empty?

            write_report(output_dir: output_dir, report: report)
            report
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
                report = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.analyze(
                  transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
                  live_proof_pack: '/tmp/workflow_trust_live_proof_pack.json',
                  trust_policies: '/tmp/trust_policies.json'
                )

                report = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.run(
                  transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
                  live_proof_pack: '/tmp/workflow_trust_live_proof_pack.json',
                  trust_policies: '/tmp/trust_policies.json',
                  output_dir: '/tmp/workflow-trust-bridge-pack'
                )
            HELP
          end

          private_class_method def self.normalize_transition_bundle(opts = {})
            transition_bundle_input = opts[:transition_bundle]
            parsed = resolve_structured_input(input: transition_bundle_input)
            transition_bundle = symbolize_obj(parsed.first || {})

            if transition_bundle.empty? && !opts[:claim_snapshots].nil? && !opts[:trust_policies].nil?
              transition_bundle = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.analyze(
                claim_snapshots: opts[:claim_snapshots],
                trust_policies: opts[:trust_policies],
                transition_fields: opts[:transition_fields]
              )
            end

            transition_bundle
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_live_proof_pack(opts = {})
            parsed = resolve_structured_input(input: opts[:live_proof_pack])
            live_proof_pack = symbolize_obj(parsed.first || {})

            if live_proof_pack.empty?
              live_proof_pack = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.analyze(
                transition_bundle: opts[:transition_bundle],
                later_snapshot: opts[:later_snapshot],
                trust_policies: opts[:trust_policies],
                provider: opts[:provider],
                allowed_audiences: opts[:allowed_audiences],
                candidate_id: opts[:candidate_id]
              )
            end

            live_proof_pack
          rescue StandardError => e
            raise e
          end

          private_class_method def self.select_candidate(opts = {})
            transition_bundle = symbolize_obj(opts[:transition_bundle] || {})
            candidates = Array(transition_bundle[:stale_acceptance_candidates]).map { |entry| symbolize_obj(entry) }
            candidate_id = normalize_token(opts[:candidate_id])
            return candidates.first if candidate_id.empty?

            candidates.find { |candidate| normalize_token(candidate[:id]) == candidate_id } || candidates.first || {}
          rescue StandardError => e
            raise e
          end

          private_class_method def self.select_policy(opts = {})
            candidate = symbolize_obj(opts[:candidate] || {})
            policies = Array(opts[:trust_policies]).map { |entry| symbolize_obj(entry) }
            provider = normalize_token(opts[:provider])

            policy_name = candidate[:policy_name].to_s.scrub.strip
            selected = nil

            unless policy_name.empty?
              selected = policies.find do |policy|
                policy[:name].to_s.scrub.strip == policy_name
              end
            end

            if selected.nil? && !provider.empty?
              selected = policies.find do |policy|
                normalize_token(policy[:provider] || policy[:cloud]) == provider
              end
            end

            selected ||= policies.first
            symbolize_obj(selected || {})
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_experiment_matrix(opts = {})
            provider = normalize_token(opts[:provider])
            candidate = symbolize_obj(opts[:candidate] || {})
            live_proof_pack = symbolize_obj(opts[:live_proof_pack] || {})
            replay_status = live_proof_pack.dig(:replay_readiness, :status).to_s
            command_template = live_proof_pack.dig(:next_exchange, :command).to_s
            command_template = default_exchange_command(provider: provider) if command_template.empty?

            baseline_transition = [candidate[:from_snapshot], candidate[:to_snapshot]].reject(&:empty?).join(' -> ')

            [
              {
                id: 'control_replay',
                label: 'Control replay (known-good latest token)',
                phase: 'baseline',
                token_label: 'latest_token',
                command_template: command_template.gsub('<OIDC_TOKEN>', '<LATEST_OIDC_TOKEN>'),
                expected_positive_outcome: 'Provider returns temporary credentials/access token.',
                expected_negative_outcome: 'If denied, fix environment or audience before stale replay.',
                interpretation: 'Confirms replay path is functional for trusted token flow.',
                status_hint: replay_status
              },
              {
                id: 'stale_acceptance_replay',
                label: 'Stale acceptance replay (pre-narrowing token)',
                phase: 'vuln_probe',
                token_label: candidate[:from_snapshot].to_s.empty? ? 'stale_token' : candidate[:from_snapshot].to_s,
                command_template: command_template.gsub('<OIDC_TOKEN>', '<STALE_OIDC_TOKEN>'),
                expected_positive_outcome: 'Unexpected credential issuance despite post-narrowing expectations.',
                expected_negative_outcome: 'Access denied (expected secure behavior).',
                interpretation: "If stale token succeeds while trust should be narrowed, this is high-confidence evidence. Transition: #{baseline_transition}",
                status_hint: candidate.empty? ? 'no_candidate' : 'candidate_present'
              },
              {
                id: 'trust_tightening_validation',
                label: 'Provider trust tightening validation',
                phase: 'post_fix_control',
                token_label: 'stale_token + latest_token',
                command_template: tightening_validation_command(provider: provider),
                expected_positive_outcome: 'Stale token denied, latest token accepted after policy tightening.',
                expected_negative_outcome: 'Both accepted (policy still too broad) or both denied (policy over-tightened).',
                interpretation: 'Produces fix-verification evidence that triagers can test quickly.',
                status_hint: 'requires_policy_update_test'
              }
            ]
          rescue StandardError => e
            raise e
          end

          private_class_method def self.aws_policy_pack(opts = {})
            provider = normalize_token(opts[:provider])
            selected_policy = symbolize_obj(opts[:selected_policy] || {})
            live_proof_pack = symbolize_obj(opts[:live_proof_pack] || {})
            candidate = symbolize_obj(opts[:candidate] || {})

            return {} unless provider == 'aws'

            token_claims = symbolize_obj(
              live_proof_pack.dig(:token_snapshot, :claims_preview) ||
              live_proof_pack.dig(:token_snapshot, :claims) ||
              {}
            )

            baseline = if selected_policy.empty?
                         aws_policy_template_from_candidate(candidate: candidate, token_claims: token_claims)
                       else
                         selected_policy
                       end

            tightened = tighten_aws_policy(policy: baseline, token_claims: token_claims)

            {
              provider: 'aws',
              baseline_policy: baseline,
              tightened_policy_candidate: tightened[:policy],
              tightening_summary: tightened[:summary],
              assume_role_template: {
                command: live_proof_pack.dig(:next_exchange, :command).to_s.empty? ? default_exchange_command(provider: 'aws') : live_proof_pack.dig(:next_exchange, :command),
                expected_positive: 'Credentials issued for latest trusted claims.',
                expected_negative: 'AccessDenied/InvalidIdentityToken for stale or mismatched claims.'
              }
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.aws_policy_template_from_candidate(opts = {})
            candidate = symbolize_obj(opts[:candidate] || {})
            token_claims = symbolize_obj(opts[:token_claims] || {})

            sub_pattern = token_claims[:sub].to_s
            sub_pattern = 'repo:<ORG>/<REPO>:ref:refs/heads/*' if sub_pattern.empty?
            aud_pattern = token_claims[:aud].to_s
            aud_pattern = 'sts.amazonaws.com' if aud_pattern.empty?

            {
              provider: 'aws',
              name: candidate[:policy_name].to_s.empty? ? 'generated_aws_trust_policy' : candidate[:policy_name].to_s,
              statements: [
                {
                  condition: {
                    StringLike: {
                      'token.actions.githubusercontent.com:sub' => sub_pattern,
                      'token.actions.githubusercontent.com:aud' => aud_pattern
                    }
                  }
                }
              ]
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.tighten_aws_policy(opts = {})
            policy = symbolize_obj(opts[:policy] || {})
            token_claims = symbolize_obj(opts[:token_claims] || {})

            target_sub = token_claims[:sub].to_s
            target_aud = token_claims[:aud].to_s
            target_sub = '<PINNED_SUBJECT>' if target_sub.empty?
            target_aud = 'sts.amazonaws.com' if target_aud.empty?

            mutated_fields = []

            tightened_policy = symbolize_obj(policy)
            statements = Array(tightened_policy[:statements] || tightened_policy[:Statement])
            statements = statements.map { |entry| symbolize_obj(entry) }

            statements.each do |statement|
              condition = symbolize_obj(statement[:condition] || statement[:Condition] || {})
              condition.each_value do |condition_values|
                cond_hash = symbolize_obj(condition_values || {})
                cond_hash.keys.each do |field|
                  value = cond_hash[field]
                  normalized_field = field.to_s.downcase

                  if normalized_field.end_with?(':sub')
                    next unless wildcard_or_multi?(value)

                    cond_hash[field] = target_sub
                    mutated_fields << 'sub'
                  end

                  if normalized_field.end_with?(':aud')
                    next unless wildcard_or_multi?(value)

                    cond_hash[field] = target_aud
                    mutated_fields << 'aud'
                  end
                end
              end
            end

            tightened_policy[:statements] = statements
            tightened_policy.delete(:Statement)

            {
              policy: tightened_policy,
              summary: {
                mutated_fields: mutated_fields.uniq,
                pinned_sub: target_sub,
                pinned_aud: target_aud,
                rationale: 'Reduce wildcard/multi acceptance to exact live-proof claims for post-fix validation.'
              }
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.wildcard_or_multi?(value)
            return true if value.is_a?(Array) && value.length > 1

            value.to_s.include?('*') || value.to_s.include?('?')
          rescue StandardError => e
            raise e
          end

          private_class_method def self.report_instructions(opts = {})
            replay_ready = opts[:replay_ready] == true
            critical_candidate = opts[:critical_candidate] == true
            provider = opts[:provider].to_s
            matrix = Array(opts[:matrix]).map { |entry| symbolize_obj(entry) }

            instructions = []
            instructions << "Run matrix steps in order: #{matrix.map { |entry| entry[:id] }.join(' -> ')}."
            instructions << 'Preserve full request/response, status code, and provider error body for each matrix step.'
            instructions << 'Attach baseline success + stale-token success/failure + trust-tightening control outcomes.'

            if critical_candidate
              instructions << "Current signals support #{provider.upcase} critical-candidate framing once stale replay succeeds and tightening control denies stale token."
            elsif replay_ready
              instructions << 'Replay path is ready; convert matrix output into report narrative and include negative controls.'
            else
              instructions << 'Address replay blocking reasons first, then rerun bridge pack for submission-grade matrix evidence.'
            end

            instructions.uniq
          rescue StandardError => e
            raise e
          end

          private_class_method def self.tightening_validation_command(opts = {})
            provider = normalize_token(opts[:provider])

            case provider
            when 'aws'
              'Apply tightened trust policy, rerun stale token exchange (expect deny), then rerun latest token exchange (expect allow).'
            when 'gcp', 'azure', 'vault'
              'Apply narrowed provider trust mapping for live claims, rerun stale vs latest exchange, and compare outcomes.'
            else
              'Apply tightened trust policy and replay stale + latest tokens against provider exchange endpoint.'
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.default_exchange_command(opts = {})
            provider = normalize_token(opts[:provider])

            case provider
            when 'aws'
              "aws sts assume-role-with-web-identity --role-arn '<ROLE_ARN>' --role-session-name 'pwn-bridge-pack' --web-identity-token '<OIDC_TOKEN>'"
            when 'gcp'
              "curl -sS https://sts.googleapis.com/v1/token -H 'Content-Type: application/json' -d '{\"subjectToken\":\"<OIDC_TOKEN>\"}'"
            when 'azure'
              "curl -sS -X POST 'https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token' --data-urlencode 'client_assertion=<OIDC_TOKEN>'"
            when 'vault'
              "vault write auth/jwt/login role='<ROLE_NAME>' jwt='<OIDC_TOKEN>'"
            else
              "exchange_provider_token --token '<OIDC_TOKEN>'"
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.compact_policy_summary(opts = {})
            policy = symbolize_obj(opts[:policy] || {})
            return {} if policy.empty?

            {
              provider: normalize_token(policy[:provider] || policy[:cloud]),
              policy_name: policy[:name].to_s,
              statement_count: Array(policy[:statements] || policy[:Statement]).length
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.infer_provider_from_policies(opts = {})
            policies = Array(opts[:policies]).map { |entry| symbolize_obj(entry) }
            return 'generic' if policies.empty?

            serialized = policies.to_json.downcase
            return 'aws' if serialized.include?('token.actions.githubusercontent.com') || serialized.include?('sts.amazonaws.com')
            return 'gcp' if serialized.include?('iam.googleapis.com') || serialized.include?('workloadidentity')
            return 'azure' if serialized.include?('federatedidentitycredential') || serialized.include?('management.azure.com')
            return 'vault' if serialized.include?('vault')

            'generic'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_report(opts = {})
            output_dir = opts[:output_dir].to_s.scrub.strip
            report = symbolize_obj(opts[:report] || {})
            FileUtils.mkdir_p(output_dir)

            json_path = File.join(output_dir, 'workflow_trust_artifact_privilege_bridge_pack.json')
            markdown_path = File.join(output_dir, 'workflow_trust_artifact_privilege_bridge_pack.md')
            matrix_path = File.join(output_dir, 'workflow_trust_artifact_privilege_bridge_matrix.json')

            File.write(json_path, JSON.pretty_generate(report))
            File.write(markdown_path, build_markdown_report(report: report))
            File.write(matrix_path, JSON.pretty_generate(symbolize_obj(report[:experiment_matrix] || [])))

            aws_pack = symbolize_obj(report[:aws_policy_pack] || {})
            unless aws_pack.empty?
              baseline_policy_path = File.join(output_dir, 'workflow_trust_aws_trust_policy_baseline.json')
              tightened_policy_path = File.join(output_dir, 'workflow_trust_aws_trust_policy_tightened_candidate.json')
              assume_role_template_path = File.join(output_dir, 'workflow_trust_aws_assume_role_template.txt')

              File.write(baseline_policy_path, JSON.pretty_generate(symbolize_obj(aws_pack[:baseline_policy] || {})))
              File.write(tightened_policy_path, JSON.pretty_generate(symbolize_obj(aws_pack[:tightened_policy_candidate] || {})))
              File.write(
                assume_role_template_path,
                [
                  aws_pack.dig(:assume_role_template, :command).to_s,
                  '',
                  "# expected_positive: #{aws_pack.dig(:assume_role_template, :expected_positive)}",
                  "# expected_negative: #{aws_pack.dig(:assume_role_template, :expected_negative)}"
                ].join("\n")
              )
            end

            {
              json_path: json_path,
              markdown_path: markdown_path,
              matrix_path: matrix_path
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_markdown_report(opts = {})
            report = symbolize_obj(opts[:report] || {})
            candidate = symbolize_obj(report[:primary_candidate] || {})
            live_summary = symbolize_obj(report[:live_proof_summary] || {})

            lines = []
            lines << '# GitHub Workflow Trust Artifact Privilege Bridge Pack'
            lines << ''
            lines << "- Generated At (UTC): `#{report[:generated_at]}`"
            lines << "- Provider: `#{report[:provider]}`"
            lines << "- Replay Ready: `#{report[:replay_ready]}`"
            lines << "- Critical Candidate: `#{report[:critical_candidate]}`"
            lines << "- Impact Label: `#{report[:impact_label]}`"
            lines << ''

            lines << '## Primary Stale-Acceptance Candidate'
            if candidate.empty?
              lines << '- No stale-acceptance candidate selected.'
            else
              lines << "- Candidate ID: `#{candidate[:id]}`"
              lines << "- Policy: `#{candidate[:policy_name]}`"
              lines << "- Transition: `#{candidate[:from_snapshot]} -> #{candidate[:to_snapshot]}`"
              lines << "- Narrowing Fields: `#{Array(candidate[:narrowing_fields]).join(', ')}`"
            end

            lines << ''
            lines << '## Live Proof Summary'
            lines << "- Replay Status: `#{live_summary[:replay_status]}`"
            lines << "- Blocking Reasons: `#{Array(live_summary[:blocking_reasons]).join(', ')}`"
            lines << "- Recommendation: #{live_summary[:recommendation]}"

            lines << ''
            lines << '## Experiment Matrix'
            lines << '| Step | Phase | Token Label | Expected Positive | Expected Negative |'
            lines << '| --- | --- | --- | --- | --- |'
            Array(report[:experiment_matrix]).each do |entry|
              step = symbolize_obj(entry)
              lines << "| `#{step[:id]}` | #{step[:phase]} | `#{step[:token_label]}` | #{step[:expected_positive_outcome]} | #{step[:expected_negative_outcome]} |"
              lines << ''
              lines << "```bash\n#{step[:command_template]}\n```"
              lines << "- interpretation: #{step[:interpretation]}"
            end

            aws_pack = symbolize_obj(report[:aws_policy_pack] || {})
            unless aws_pack.empty?
              lines << ''
              lines << '## AWS Proof-Kit Export'
              lines << "- baseline_policy_name: `#{symbolize_obj(aws_pack[:baseline_policy] || {})[:name]}`"
              lines << "- tightened_mutated_fields: `#{Array(aws_pack.dig(:tightening_summary, :mutated_fields)).join(', ')}`"
              lines << "- pinned_sub: `#{aws_pack.dig(:tightening_summary, :pinned_sub)}`"
              lines << "- pinned_aud: `#{aws_pack.dig(:tightening_summary, :pinned_aud)}`"
            end

            lines << ''
            lines << '## Report Instructions'
            Array(report[:report_instructions]).each do |instruction|
              lines << "- #{instruction}"
            end

            lines.join("\n")
          rescue StandardError => e
            raise e
          end

          private_class_method def self.resolve_structured_input(opts = {})
            input = opts[:input]

            case input
            when nil
              []
            when Array
              symbolize_obj(input)
            when Hash
              hash_input = symbolize_obj(input)
              if hash_input.key?(:items)
                Array(hash_input[:items]).map { |entry| symbolize_obj(entry) }
              elsif hash_input.key?(:policies)
                Array(hash_input[:policies]).map { |entry| symbolize_obj(entry) }
              else
                [hash_input]
              end
            when String
              value = input.to_s.scrub.strip
              return [] if value.empty?

              if File.exist?(value)
                parsed = JSON.parse(File.read(value))
                return resolve_structured_input(input: parsed)
              end

              parsed = JSON.parse(value)
              resolve_structured_input(input: parsed)
            else
              [symbolize_obj(input)]
            end
          rescue JSON::ParserError => e
            raise "ERROR: unable to parse structured input: #{e.message}"
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
end
