# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Targets
    module GitHub
      module WorkflowTrust
        # Converts ranked lineage paths into safe, owned-fixture validation steps.
        module FixtureUpgradeStepPack
          DEFAULT_MAX_PATHS = 6

          # Supported Method Parameters::
          # pack = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.analyze(
          #   lineage_report: '/tmp/workflow_trust_reusable_workflow_lineage.json',
          #   permission_gate: '/tmp/repo_permission_proof_pack.json',
          #   oidc_claim_context: '/tmp/oidc_claims.json'
          # )
          public_class_method def self.analyze(opts = {})
            lineage_report = resolve_structured_input(input: opts[:lineage_report]).first || {}
            lineage_report = symbolize_obj(lineage_report)

            permission_gate = resolve_structured_input(input: opts[:permission_gate]).first || {}
            permission_gate = symbolize_obj(permission_gate)

            oidc_claim_context = normalize_claim_context(
              claim_context: resolve_structured_input(input: opts[:oidc_claim_context])
            )

            max_paths = opts[:max_paths].to_i
            max_paths = DEFAULT_MAX_PATHS if max_paths <= 0

            steps = Array(lineage_report[:paths]).first(max_paths).map do |path|
              build_step_for_path(
                path: path,
                permission_gate: permission_gate,
                oidc_claim_context: oidc_claim_context
              )
            end

            safe_to_execute_count = steps.count do |step|
              normalize_token(step[:gate_status]) == 'passed' || normalize_token(step[:gate_status]) == 'unknown'
            end

            {
              generated_at: Time.now.utc.iso8601,
              source_path_count: Array(lineage_report[:paths]).length,
              planned_step_count: steps.length,
              safe_to_execute_count: safe_to_execute_count,
              blocked_count: steps.count { |step| normalize_token(step[:gate_status]) == 'failed' },
              steps: steps,
              summary: {
                critical_paths: steps.count { |step| normalize_token(step[:severity]) == 'critical' },
                high_paths: steps.count { |step| normalize_token(step[:severity]) == 'high' },
                p1_upgrades: steps.count { |step| normalize_token(step[:upgrade_priority]) == 'p1' }
              }
            }
          rescue StandardError => e
            raise e
          end

          # Supported Method Parameters::
          # pack = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.scan_repo(
          #   repo_path: '/path/to/repo',
          #   output_dir: '/tmp/workflow-trust-fixture-step-pack'
          # )
          public_class_method def self.scan_repo(opts = {})
            repo_path = opts[:repo_path].to_s.scrub.strip
            raise 'ERROR: repo_path is required' if repo_path.empty?
            raise "ERROR: repo_path does not exist: #{repo_path}" unless Dir.exist?(repo_path)

            workflows = PWN::Targets::GitHub::WorkflowTrust.load_workflows(repo_path: repo_path)
            lineage_report = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.analyze(
              workflows: workflows
            )

            pack = analyze(
              lineage_report: lineage_report,
              permission_gate: opts[:permission_gate],
              oidc_claim_context: opts[:oidc_claim_context],
              max_paths: opts[:max_paths]
            )
            pack[:repo_path] = File.expand_path(repo_path)

            output_dir = opts[:output_dir].to_s.scrub.strip
            write_report(output_dir: output_dir, report: pack) unless output_dir.empty?

            pack
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
                pack = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.analyze(
                  lineage_report: '/tmp/workflow_trust_reusable_workflow_lineage.json',
                  permission_gate: '/tmp/repo_permission_proof_pack.json',
                  oidc_claim_context: '/tmp/oidc_claims.json'
                )

                pack = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.scan_repo(
                  repo_path: '/path/to/repo',
                  output_dir: '/tmp/workflow-trust-fixture-step-pack'
                )
            HELP
          end

          private_class_method def self.build_step_for_path(opts = {})
            path = symbolize_obj(opts[:path] || {})
            permission_gate = symbolize_obj(opts[:permission_gate] || {})
            oidc_claim_context = normalize_claim_context(claim_context: opts[:oidc_claim_context])

            preferred_sink_kind = normalize_token(path[:preferred_sink_kind])
            chain_type = normalize_token(path[:chain_type])
            gate_status = gate_status_for(path: path, permission_gate: permission_gate)

            {
              id: "fixture_step_pack:#{normalize_token(path[:id])}",
              path_id: path[:id],
              title: path[:title].to_s,
              severity: normalize_token(path[:severity]),
              chain_type: chain_type,
              preferred_sink_kind: preferred_sink_kind,
              upgrade_priority: normalize_token(path[:upgrade_priority]),
              gate_status: gate_status,
              required_permissions: required_permissions(preferred_sink_kind: preferred_sink_kind),
              expected_claims: expected_claims(
                preferred_sink_kind: preferred_sink_kind,
                oidc_claim_context: oidc_claim_context
              ),
              upgrade_steps: upgrade_steps(
                chain_type: chain_type,
                preferred_sink_kind: preferred_sink_kind,
                path: path
              ),
              safe_fixture_notes: safe_fixture_notes(
                chain_type: chain_type,
                preferred_sink_kind: preferred_sink_kind
              ),
              stop_conditions: stop_conditions(
                gate_status: gate_status,
                preferred_sink_kind: preferred_sink_kind
              ),
              validation_checks: validation_checks(
                chain_type: chain_type,
                preferred_sink_kind: preferred_sink_kind,
                gate_status: gate_status
              )
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.gate_status_for(opts = {})
            permission_gate = symbolize_obj(opts[:permission_gate] || {})
            gate = symbolize_obj(permission_gate[:gate] || {})
            gate_result = normalize_token(gate[:result])
            return 'unknown' if gate_result.empty?

            gate_result
          rescue StandardError => e
            raise e
          end

          private_class_method def self.required_permissions(opts = {})
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])

            case preferred_sink_kind
            when 'oidc_role_assumption'
              {
                id_token: 'write',
                contents: 'read',
                workflow_identity_scope: 'job_workflow_ref + sub + aud'
              }
            when 'write_token'
              {
                contents: 'write',
                actions: 'read',
                pull_requests: 'write_or_read'
              }
            when 'deployment_environment'
              {
                environment_approval: 'required',
                contents: 'read',
                deployments: 'write_or_read'
              }
            when 'secret_inheritance'
              {
                secrets_mode: 'inherit_or_explicit',
                contents: 'read',
                id_token: 'optional'
              }
            else
              {
                contents: 'read',
                note: 'confirm minimal token scope before fixture validation'
              }
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.expected_claims(opts = {})
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])
            oidc_claim_context = symbolize_obj(opts[:oidc_claim_context] || {})

            return {} unless preferred_sink_kind == 'oidc_role_assumption'

            sample_claim = Array(oidc_claim_context).find { |entry| symbolize_obj(entry)[:sub] }
            sample_claim = symbolize_obj(sample_claim || {})

            {
              sub: sample_claim[:sub] || 'repo:<owner>/<repo>:ref:refs/heads/<fixture-branch>',
              aud: sample_claim[:aud] || 'sts.amazonaws.com',
              job_workflow_ref: sample_claim[:job_workflow_ref] || '<owner>/<repo>/.github/workflows/<workflow>.yml@refs/heads/<branch>',
              repository_visibility: sample_claim[:repository_visibility] || 'private_or_internal',
              custom_property_claims: sample_claim.select { |key, _value| key.to_s.start_with?('repository_owner_id', 'repository_id', 'repository_visibility', 'repository_') }
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.upgrade_steps(opts = {})
            chain_type = normalize_token(opts[:chain_type])
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])
            path = symbolize_obj(opts[:path] || {})

            steps = []
            steps << 'Create a dedicated benign fixture branch and isolate all validation commits.'

            if chain_type == 'reusable_workflow_call'
              steps << "Instrument caller workflow `#{path[:from_workflow]}` with a harmless canary input marker."
              steps << 'Trigger workflow_call path from controlled untrusted entry (fork PR/comment) and capture downstream job trace.'
            elsif chain_type == 'workflow_run_artifact_fan_in'
              steps << 'Publish a benign marker artifact in upstream untrusted workflow run.'
              steps << 'Trigger downstream workflow_run consumer and confirm marker ingestion path.'
            else
              steps << 'Execute controlled untrusted trigger path and capture full workflow/job logs.'
            end

            case preferred_sink_kind
            when 'oidc_role_assumption'
              steps << 'Capture OIDC token issuance event and decode claims (sub/aud/job_workflow_ref) without exfiltrating secrets.'
              steps << 'Verify token exchange endpoint reachability with deny-safe controls before any privileged action attempt.'
            when 'write_token'
              steps << 'Attempt benign repository write primitive (e.g., label/update draft comment) and capture audit logs.'
            when 'secret_inheritance'
              steps << 'Prove secret propagation using non-sensitive canary secret value and verify downstream exposure boundary.'
            when 'deployment_environment'
              steps << 'Validate environment gate behavior with dry-run deployment and approval trace capture.'
            end

            steps
          rescue StandardError => e
            raise e
          end

          private_class_method def self.safe_fixture_notes(opts = {})
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])

            notes = [
              'Use only owned fixtures and non-production repos/roles for active validation.',
              'Never execute destructive write actions; keep tests reversible and auditable.',
              'Store raw logs/artifacts with timestamps for duplicate-resistant reporting.'
            ]

            if preferred_sink_kind == 'oidc_role_assumption'
              notes << 'Limit cloud role testing to read-only identity/introspection APIs unless explicit scope permits otherwise.'
            end

            notes
          rescue StandardError => e
            raise e
          end

          private_class_method def self.stop_conditions(opts = {})
            gate_status = normalize_token(opts[:gate_status])
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])

            conditions = []
            conditions << 'Stop immediately if permission gate is failed/control-only.' if gate_status == 'failed'
            conditions << 'Stop if fixture change leaks real credentials or sensitive production data.'
            conditions << 'Stop if workflow execution path diverges from expected untrusted trigger chain.'
            conditions << 'Stop if custom-property/OIDC claim constraints are already fully enforced and deny-safe.' if preferred_sink_kind == 'oidc_role_assumption'
            conditions
          rescue StandardError => e
            raise e
          end

          private_class_method def self.validation_checks(opts = {})
            chain_type = normalize_token(opts[:chain_type])
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])
            gate_status = normalize_token(opts[:gate_status])

            checks = [
              'Confirm untrusted trigger reaches intended workflow/job path.',
              'Confirm expected permission scope on executing job token.',
              'Capture before/after artifacts proving only fixture canary data moved.'
            ]

            checks << 'Confirm permission gate passed or remains unknown before severity upgrade.' unless gate_status == 'failed'

            if chain_type == 'workflow_run_artifact_fan_in'
              checks << 'Verify downstream consumer ingested upstream artifact canary unchanged.'
            end

            if preferred_sink_kind == 'oidc_role_assumption'
              checks << 'Decode OIDC claims and compare against trust policy expectations (sub/aud/job_workflow_ref).'
            elsif preferred_sink_kind == 'write_token'
              checks << 'Verify benign write primitive succeeds only through vulnerable path.'
            end

            checks
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_report(opts = {})
            output_dir = opts[:output_dir].to_s.scrub.strip
            report = symbolize_obj(opts[:report] || {})
            FileUtils.mkdir_p(output_dir)

            json_path = File.join(output_dir, 'workflow_trust_fixture_upgrade_step_pack.json')
            markdown_path = File.join(output_dir, 'workflow_trust_fixture_upgrade_step_pack.md')

            File.write(json_path, JSON.pretty_generate(report))
            File.write(markdown_path, build_markdown_report(report: report))

            {
              json_path: json_path,
              markdown_path: markdown_path
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_markdown_report(opts = {})
            report = symbolize_obj(opts[:report] || {})

            lines = []
            lines << '# GitHub Workflow Trust Fixture Upgrade Step Pack'
            lines << ''
            lines << "- Generated At (UTC): `#{report[:generated_at]}`"
            lines << "- Source Paths: `#{report[:source_path_count]}`"
            lines << "- Planned Steps: `#{report[:planned_step_count]}`"
            lines << "- Safe to Execute: `#{report[:safe_to_execute_count]}`"
            lines << ''

            lines << '## Step Packs'
            if Array(report[:steps]).empty?
              lines << '- No lineage paths were available for fixture upgrade planning.'
            else
              Array(report[:steps]).each do |step|
                step_hash = symbolize_obj(step)
                lines << "- [#{step_hash[:severity].to_s.upcase}] #{step_hash[:title]}"
                lines << "  - chain: `#{step_hash[:chain_type]}` sink: `#{step_hash[:preferred_sink_kind]}` gate: `#{step_hash[:gate_status]}`"
                lines << "  - upgrade_priority: `#{step_hash[:upgrade_priority]}`"
                lines << "  - expected_claims: `#{symbolize_obj(step_hash[:expected_claims] || {}).to_json}`"
                lines << '  - upgrade_steps:'
                Array(step_hash[:upgrade_steps]).each do |entry|
                  lines << "    - #{entry}"
                end
                lines << '  - validation_checks:'
                Array(step_hash[:validation_checks]).each do |entry|
                  lines << "    - #{entry}"
                end
              end
            end

            lines.join("\n")
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_claim_context(opts = {})
            claim_context = symbolize_obj(opts[:claim_context])

            case claim_context
            when Array
              claim_context.flat_map do |entry|
                entry_hash = symbolize_obj(entry)
                nested_claims = entry_hash[:claims]
                if nested_claims.is_a?(Array)
                  nested_claims.map { |claim| symbolize_obj(claim) }
                elsif entry_hash.is_a?(Hash) && !entry_hash.empty?
                  [entry_hash]
                else
                  []
                end
              end
            when Hash
              claims = claim_context[:claims]
              if claims.is_a?(Array)
                claims.map { |entry| symbolize_obj(entry) }
              else
                [claim_context]
              end
            else
              []
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.resolve_structured_input(opts = {})
            input = opts[:input]

            case input
            when nil
              []
            when Array
              input.map { |entry| symbolize_obj(entry) }
            when Hash
              [symbolize_obj(input)]
            when String
              path = input.to_s.scrub.strip
              return [] if path.empty?

              if File.exist?(path)
                content = File.read(path)
                parsed = begin
                  JSON.parse(content)
                rescue JSON::ParserError
                  YAML.safe_load(content, aliases: true)
                end
                return resolve_structured_input(input: parsed)
              end

              parsed = begin
                JSON.parse(path)
              rescue JSON::ParserError
                YAML.safe_load(path, aliases: true)
              end
              resolve_structured_input(input: parsed)
            else
              [symbolize_obj(input)]
            end
          rescue Psych::SyntaxError, JSON::ParserError
            []
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
