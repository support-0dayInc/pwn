# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Targets
    module GitHub
      # Parse GitHub Actions workflows into a privilege/trust graph and
      # rank high-signal CI/CD exploit hypotheses.
      module WorkflowTrust
        autoload :ArtifactPrivilegeBridgePack, 'pwn/targets/github/workflow_trust/artifact_privilege_bridge_pack'
        autoload :FixtureUpgradeStepPack, 'pwn/targets/github/workflow_trust/fixture_upgrade_step_pack'
        autoload :LiveProofPack, 'pwn/targets/github/workflow_trust/live_proof_pack'
        autoload :ReusableWorkflowLineage, 'pwn/targets/github/workflow_trust/reusable_workflow_lineage'
        autoload :TransitionBundle, 'pwn/targets/github/workflow_trust/transition_bundle'

        UNTRUSTED_EVENT_NAMES = %w[pull_request pull_request_target issue_comment workflow_run].freeze
        WRITE_PERMISSION_LEVELS = %w[write admin].freeze

        # Supported Method Parameters::
        # report = PWN::Targets::GitHub::WorkflowTrust.scan_repo(
        #   repo_path: '/path/to/repo',
        #   oidc_claims: '/path/to/oidc_claims.json',
        #   trust_policies: '/path/to/trust_policies.json',
        #   output_dir: '/tmp/workflow-trust'
        # )
        public_class_method def self.scan_repo(opts = {})
          repo_path = opts[:repo_path].to_s.scrub.strip
          raise 'ERROR: repo_path is required' if repo_path.empty?
          raise "ERROR: repo_path does not exist: #{repo_path}" unless Dir.exist?(repo_path)

          workflows = opts[:workflows]
          workflows = load_workflows(repo_path: repo_path) if workflows.nil?

          graph = build_privilege_graph(workflows: workflows)

          oidc_eval = evaluate_oidc_acceptance(
            oidc_claims: opts[:oidc_claims],
            trust_policies: opts[:trust_policies]
          )

          findings = rank_findings(
            repo_path: repo_path,
            job_records: graph[:job_records],
            oidc_eval: oidc_eval
          )

          reusable_workflow_lineage = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.analyze(
            workflows: workflows
          )

          fixture_upgrade_step_pack = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.analyze(
            lineage_report: reusable_workflow_lineage,
            permission_gate: opts[:permission_gate],
            oidc_claim_context: opts[:oidc_claim_context],
            max_paths: opts[:fixture_max_paths]
          )

          report = {
            scanned_at: Time.now.utc.iso8601,
            repo_path: File.expand_path(repo_path),
            workflow_count: workflows.length,
            job_count: graph[:job_records].length,
            graph: {
              nodes: graph[:nodes],
              edges: graph[:edges]
            },
            oidc_acceptance: oidc_eval,
            reusable_workflow_lineage: reusable_workflow_lineage,
            fixture_upgrade_step_pack: fixture_upgrade_step_pack,
            finding_count: findings.length,
            findings: findings.sort_by { |finding| [-severity_rank(finding[:severity]), finding[:id]] }
          }

          output_dir = opts[:output_dir].to_s.scrub.strip
          write_report(output_dir: output_dir, report: report) unless output_dir.empty?

          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # workflows = PWN::Targets::GitHub::WorkflowTrust.load_workflows(
        #   repo_path: '/path/to/repo'
        # )
        public_class_method def self.load_workflows(opts = {})
          repo_path = opts[:repo_path].to_s.scrub.strip
          raise 'ERROR: repo_path is required' if repo_path.empty?

          workflow_globs = [
            File.join(repo_path, '.github', 'workflows', '*.yml'),
            File.join(repo_path, '.github', 'workflows', '*.yaml')
          ]

          workflow_paths = workflow_globs.flat_map { |pattern| Dir.glob(pattern) }.uniq.sort
          workflows = []

          workflow_paths.each do |workflow_path|
            parsed = YAML.safe_load_file(workflow_path, aliases: true)
            parsed = symbolize_obj(parsed)
            next unless parsed.is_a?(Hash)

            workflow_name = parsed[:name].to_s.scrub.strip
            workflow_name = File.basename(workflow_path) if workflow_name.empty?

            workflow_on = workflow_on_field(workflow_hash: parsed)

            workflows << {
              file_path: workflow_path,
              file_name: File.basename(workflow_path),
              workflow_name: workflow_name,
              on: workflow_on,
              permissions: symbolize_obj(parsed[:permissions]),
              jobs: symbolize_obj(parsed[:jobs] || {}),
              raw: parsed
            }
          rescue Psych::SyntaxError => e
            workflows << {
              file_path: workflow_path,
              file_name: File.basename(workflow_path),
              workflow_name: File.basename(workflow_path),
              parse_error: e.message,
              raw: {}
            }
          end

          workflows
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # oidc_eval = PWN::Targets::GitHub::WorkflowTrust.evaluate_oidc_acceptance(
        #   oidc_claims: '/path/to/oidc_claims.json',
        #   trust_policies: '/path/to/trust_policies.json'
        # )
        public_class_method def self.evaluate_oidc_acceptance(opts = {})
          oidc_claims = resolve_structured_input(input: opts[:oidc_claims])
          trust_policies = resolve_structured_input(input: opts[:trust_policies])
          claim_snapshots = resolve_structured_input(input: opts[:claim_snapshots])
          claim_snapshots = oidc_claims if claim_snapshots.empty?

          policy_results = trust_policies.map do |policy|
            policy_hash = symbolize_obj(policy)
            provider = infer_policy_provider(policy: policy_hash)
            sub_patterns = extract_policy_patterns(policy: policy_hash, field: :sub)
            aud_patterns = extract_policy_patterns(policy: policy_hash, field: :aud)

            accepted_claims = oidc_claims.select do |claim|
              claim_hash = symbolize_obj(claim)
              sub = claim_hash[:sub].to_s
              aud = claim_hash[:aud].to_s

              sub_match = sub_patterns.empty? || sub_patterns.any? { |pattern| glob_match?(value: sub, pattern: pattern) }
              aud_match = aud_patterns.empty? || aud_patterns.any? { |pattern| glob_match?(value: aud, pattern: pattern) }
              sub_match && aud_match
            end

            broad_sub_acceptance = sub_patterns.any? { |pattern| broad_sub_pattern?(pattern: pattern) }
            untrusted_matches = accepted_claims.select do |claim|
              event_name = normalize_token(claim[:event_name] || claim[:event])
              UNTRUSTED_EVENT_NAMES.include?(event_name)
            end

            {
              provider: provider,
              policy_name: policy_hash[:name].to_s,
              sub_patterns: sub_patterns,
              aud_patterns: aud_patterns,
              broad_sub_acceptance: broad_sub_acceptance,
              accepted_claim_count: accepted_claims.length,
              accepted_untrusted_claim_count: untrusted_matches.length,
              accepted_untrusted_claims: untrusted_matches.map { |claim| symbolize_obj(claim) }
            }
          end

          result = {
            oidc_claim_count: oidc_claims.length,
            trust_policy_count: trust_policies.length,
            policy_results: policy_results,
            broad_acceptance_policy_count: policy_results.count { |result| result[:broad_sub_acceptance] },
            untrusted_claim_acceptance_count: policy_results.sum { |result| result[:accepted_untrusted_claim_count] }
          }

          if claim_snapshots.length >= 2
            transition_bundle = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.analyze(
              claim_snapshots: claim_snapshots,
              trust_policies: trust_policies,
              transition_fields: opts[:transition_fields]
            )

            result[:transition_bundle] = transition_bundle
            result[:stale_acceptance_candidate_count] = transition_bundle[:stale_acceptance_candidate_count]

            unless opts[:later_snapshot].nil? && opts[:token_snapshot].nil?
              live_proof_pack = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.analyze(
                transition_bundle: transition_bundle,
                later_snapshot: opts[:later_snapshot] || opts[:token_snapshot],
                trust_policies: trust_policies,
                provider: opts[:provider],
                allowed_audiences: opts[:allowed_audiences],
                candidate_id: opts[:candidate_id]
              )

              artifact_privilege_bridge_pack = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.analyze(
                transition_bundle: transition_bundle,
                live_proof_pack: live_proof_pack,
                trust_policies: trust_policies,
                provider: opts[:provider],
                candidate_id: opts[:candidate_id],
                allowed_audiences: opts[:allowed_audiences]
              )

              result[:live_proof_pack] = live_proof_pack
              result[:artifact_privilege_bridge_pack] = artifact_privilege_bridge_pack
              result[:replay_ready] = live_proof_pack.dig(:replay_readiness, :ready) == true
              result[:critical_candidate] = artifact_privilege_bridge_pack[:critical_candidate] == true
            end
          end

          result
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
              report = PWN::Targets::GitHub::WorkflowTrust.scan_repo(
                repo_path: '/path/to/repo',
                oidc_claims: '/tmp/oidc_claims.json',
                trust_policies: '/tmp/trust_policies.json',
                output_dir: '/tmp/workflow-trust'
              )

              workflows = PWN::Targets::GitHub::WorkflowTrust.load_workflows(
                repo_path: '/path/to/repo'
              )

              oidc_eval = PWN::Targets::GitHub::WorkflowTrust.evaluate_oidc_acceptance(
                oidc_claims: '/tmp/oidc_claims.json',
                trust_policies: '/tmp/trust_policies.json'
              )

              transition_report = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.run(
                claim_snapshots: '/tmp/ordered_claim_snapshots.json',
                trust_policies: '/tmp/trust_policies.json',
                output_dir: '/tmp/workflow-trust-transition-bundle'
              )

              live_proof = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.run(
                transition_bundle: transition_report,
                later_snapshot: '/tmp/later_token_snapshot.json',
                output_dir: '/tmp/workflow-trust-live-proof-pack'
              )

              bridge_pack = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.run(
                transition_bundle: transition_report,
                live_proof_pack: live_proof,
                trust_policies: '/tmp/trust_policies.json',
                output_dir: '/tmp/workflow-trust-bridge-pack'
              )

              lineage = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.scan_repo(
                repo_path: '/path/to/repo',
                output_dir: '/tmp/workflow-trust-lineage'
              )

              fixture_steps = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.scan_repo(
                repo_path: '/path/to/repo',
                permission_gate: '/tmp/repo_permission_proof_pack.json',
                oidc_claim_context: '/tmp/oidc_claims.json',
                output_dir: '/tmp/workflow-trust-fixture-step-pack'
              )
          HELP
        end

        private_class_method def self.build_privilege_graph(opts = {})
          workflows = Array(opts[:workflows]).map { |workflow| symbolize_obj(workflow) }

          nodes = []
          edges = []
          job_records = []

          workflows.each do |workflow|
            workflow_file = workflow[:file_name].to_s
            workflow_name = workflow[:workflow_name].to_s
            workflow_permissions = normalize_permissions(workflow[:permissions])
            triggers = extract_triggers(workflow[:on])

            jobs_hash = symbolize_obj(workflow[:jobs] || {})
            jobs_hash.each do |job_name, job_def|
              job_hash = symbolize_obj(job_def || {})
              job_id = "#{workflow_file}:#{job_name}"

              job_permissions = normalize_permissions(job_hash[:permissions])
              effective_permissions = merge_permissions(
                workflow_permissions: workflow_permissions,
                job_permissions: job_permissions
              )

              write_scopes = effective_permissions.select do |_scope, level|
                WRITE_PERMISSION_LEVELS.include?(normalize_token(level))
              end.keys

              steps = Array(job_hash[:steps]).map { |step| symbolize_obj(step) }
              produces_artifact = steps.any? { |step| step[:uses].to_s.downcase.include?('actions/upload-artifact') }
              consumes_artifact = steps.any? { |step| step[:uses].to_s.downcase.include?('actions/download-artifact') }

              pull_request_target_untrusted_checkout = pull_request_target_untrusted_checkout?(
                triggers: triggers,
                steps: steps
              )

              comment_body_shell_injection = comment_body_shell_injection?(steps: steps)

              workflow_run_artifact_fanin = triggers.include?('workflow_run') && consumes_artifact && !write_scopes.empty?

              uses_oidc = normalize_token(
                effective_permissions['id-token'] ||
                effective_permissions[:'id-token'] ||
                effective_permissions[:id_token]
              ) == 'write'

              nodes << {
                id: "workflow:#{workflow_file}",
                type: 'workflow',
                label: workflow_name,
                file: workflow_file
              }
              nodes << {
                id: "job:#{job_id}",
                type: 'job',
                label: job_name.to_s,
                file: workflow_file
              }

              triggers.each do |trigger|
                trigger_node_id = "trigger:#{workflow_file}:#{trigger}"
                nodes << {
                  id: trigger_node_id,
                  type: 'trigger',
                  label: trigger,
                  file: workflow_file
                }
                edges << {
                  from: trigger_node_id,
                  to: "job:#{job_id}",
                  relation: 'invokes'
                }
              end

              edges << {
                from: "workflow:#{workflow_file}",
                to: "job:#{job_id}",
                relation: 'contains'
              }

              if produces_artifact
                edges << {
                  from: "job:#{job_id}",
                  to: "artifact:#{workflow_file}:#{job_name}",
                  relation: 'produces'
                }
              end

              if consumes_artifact
                edges << {
                  from: "artifact:#{workflow_file}:#{job_name}",
                  to: "job:#{job_id}",
                  relation: 'consumes'
                }
              end

              job_records << {
                job_id: job_id,
                file: workflow_file,
                workflow_name: workflow_name,
                job_name: job_name.to_s,
                triggers: triggers,
                write_scopes: write_scopes,
                uses_oidc: uses_oidc,
                pull_request_target_untrusted_checkout: pull_request_target_untrusted_checkout,
                comment_body_shell_injection: comment_body_shell_injection,
                workflow_run_artifact_fanin: workflow_run_artifact_fanin,
                produces_artifact: produces_artifact,
                consumes_artifact: consumes_artifact
              }
            end
          end

          {
            nodes: dedup_nodes(nodes: nodes),
            edges: edges.uniq,
            job_records: job_records
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.rank_findings(opts = {})
          repo_path = opts[:repo_path]
          job_records = Array(opts[:job_records]).map { |job_record| symbolize_obj(job_record) }
          oidc_eval = symbolize_obj(opts[:oidc_eval] || {})

          findings = []

          job_records.each do |job|
            untrusted_trigger = (job[:triggers] & UNTRUSTED_EVENT_NAMES).any?

            if job[:pull_request_target_untrusted_checkout]
              findings << make_finding(
                id: "#{job[:job_id]}:pr_target_untrusted_checkout",
                severity: 'critical',
                confidence: 'high',
                category: 'workflow-trust',
                title: 'pull_request_target checks out attacker-controlled ref',
                file: job[:file],
                job_name: job[:job_name],
                preconditions: 'Attacker can open PR from fork/branch with controlled code.',
                likely_impact: 'Privileged job executes attacker code with secrets/write token exposure.',
                evidence: {
                  triggers: job[:triggers],
                  write_scopes: job[:write_scopes]
                }
              )
            end

            if untrusted_trigger && !job[:write_scopes].empty?
              findings << make_finding(
                id: "#{job[:job_id]}:untrusted_trigger_write_token",
                severity: 'high',
                confidence: 'medium',
                category: 'token-permissions',
                title: 'Untrusted trigger runs with write-capable GITHUB_TOKEN scopes',
                file: job[:file],
                job_name: job[:job_name],
                preconditions: 'Attacker controls workflow input on untrusted trigger path.',
                likely_impact: 'Repository write, workflow tampering, package publish, or security signal suppression.',
                evidence: {
                  triggers: job[:triggers],
                  write_scopes: job[:write_scopes]
                }
              )
            end

            if job[:comment_body_shell_injection]
              findings << make_finding(
                id: "#{job[:job_id]}:comment_body_shell_injection",
                severity: 'high',
                confidence: 'medium',
                category: 'injection',
                title: 'Comment/body data flows into shell execution',
                file: job[:file],
                job_name: job[:job_name],
                preconditions: 'Attacker can submit comment/body text consumed by run step.',
                likely_impact: 'Command injection during workflow execution.',
                evidence: {
                  triggers: job[:triggers]
                }
              )
            end

            if job[:workflow_run_artifact_fanin]
              findings << make_finding(
                id: "#{job[:job_id]}:workflow_run_artifact_fanin",
                severity: 'high',
                confidence: 'medium',
                category: 'artifact-trust',
                title: 'workflow_run consumes artifacts and has write capability',
                file: job[:file],
                job_name: job[:job_name],
                preconditions: 'Attacker influences upstream workflow artifact content.',
                likely_impact: 'Artifact poisoning into privileged workflow path.',
                evidence: {
                  triggers: job[:triggers],
                  consumes_artifact: job[:consumes_artifact],
                  write_scopes: job[:write_scopes]
                }
              )
            end

            if job[:uses_oidc] && untrusted_trigger
              broad_policies = Array(oidc_eval[:policy_results]).select { |policy| policy[:broad_sub_acceptance] }
              untrusted_acceptance = broad_policies.any? { |policy| policy[:accepted_untrusted_claim_count].to_i.positive? }

              if untrusted_acceptance
                findings << make_finding(
                  id: "#{job[:job_id]}:broad_oidc_acceptance",
                  severity: 'critical',
                  confidence: 'medium',
                  category: 'oidc-trust',
                  title: 'OIDC trust policy broadly accepts untrusted workflow subjects',
                  file: job[:file],
                  job_name: job[:job_name],
                  preconditions: 'OIDC-enabled job can be reached from untrusted workflow input.',
                  likely_impact: 'Cloud role assumption from attacker-influenced workflow execution.',
                  evidence: {
                    triggers: job[:triggers],
                    broad_oidc_policy_count: broad_policies.length,
                    untrusted_claim_acceptance_count: oidc_eval[:untrusted_claim_acceptance_count]
                  }
                )
              end
            end
          end

          findings.uniq { |finding| finding[:id] }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.pull_request_target_untrusted_checkout?(opts = {})
          triggers = Array(opts[:triggers]).map { |trigger| normalize_token(trigger) }
          return false unless triggers.include?('pull_request_target')

          steps = Array(opts[:steps]).map { |step| symbolize_obj(step) }
          steps.any? do |step|
            uses_checkout = step[:uses].to_s.downcase.include?('actions/checkout')
            ref = symbolize_obj(step[:with] || {})[:ref].to_s
            script = step[:run].to_s

            uses_checkout && (
              ref.include?('github.event.pull_request.head') ||
              ref.include?('github.head_ref') ||
              script.include?('github.event.pull_request.head')
            )
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.comment_body_shell_injection?(opts = {})
          steps = Array(opts[:steps]).map { |step| symbolize_obj(step) }
          steps.any? do |step|
            run_script = step[:run].to_s
            run_script.include?('github.event.comment.body') ||
              run_script.include?('github.event.issue.title') ||
              run_script.include?('github.event.pull_request.title')
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_triggers(on_field)
          on_val = symbolize_obj(on_field)

          triggers = case on_val
                     when String, Symbol
                       [normalize_token(on_val)]
                     when Array
                       on_val.map { |entry| normalize_token(entry) }
                     when Hash
                       on_val.keys.map { |key| normalize_token(key) }
                     else
                       []
                     end

          triggers.reject(&:empty?).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.workflow_on_field(opts = {})
          workflow_hash = symbolize_obj(opts[:workflow_hash] || {})
          workflow_hash[:on] || workflow_hash['on'] || workflow_hash[true] || workflow_hash[:true]
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_permissions(permissions)
          perms = symbolize_obj(permissions)

          case perms
          when String, Symbol
            level = normalize_token(perms)
            return { '*' => 'write' } if level == 'write_all'
            return { '*' => 'read' } if level == 'read_all'

            { '*' => level }
          when Hash
            perms.each_with_object({}) do |(scope, level), accum|
              scope_key = scope.to_s.tr('_', '-')
              accum[scope_key] = normalize_token(level)
            end
          else
            {}
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.merge_permissions(opts = {})
          workflow_permissions = symbolize_obj(opts[:workflow_permissions] || {})
          job_permissions = symbolize_obj(opts[:job_permissions] || {})
          return workflow_permissions if job_permissions.empty?

          workflow_permissions.merge(job_permissions)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolve_structured_input(opts = {})
          input = opts[:input]

          case input
          when nil
            []
          when String
            path = input.to_s.scrub.strip
            return [] if path.empty?
            return [] unless File.exist?(path)

            content = File.read(path)
            parsed = begin
              JSON.parse(content)
            rescue JSON::ParserError
              YAML.safe_load(content, aliases: true)
            end
            parsed = symbolize_obj(parsed)
            parsed.is_a?(Array) ? parsed : [parsed]
          when Array
            input.map { |entry| symbolize_obj(entry) }
          when Hash
            [symbolize_obj(input)]
          else
            []
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_policy_provider(opts = {})
          policy = symbolize_obj(opts[:policy] || {})
          provider = normalize_token(policy[:provider] || policy[:cloud])
          return provider unless provider.empty?

          policy_text = policy.to_json.downcase
          return 'aws' if policy_text.include?('token.actions.githubusercontent.com')
          return 'gcp' if policy_text.include?('google')
          return 'azure' if policy_text.include?('azure')

          'unknown'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_policy_patterns(opts = {})
          policy = symbolize_obj(opts[:policy] || {})
          field = normalize_token(opts[:field])

          raw_patterns = []

          raw_patterns.concat(Array(policy[:sub_patterns])) if field == 'sub'
          raw_patterns.concat(Array(policy[:aud_patterns])) if field == 'aud'

          statements = Array(policy[:statements] || policy[:Statement])
          statements.each do |statement|
            statement_hash = symbolize_obj(statement || {})
            condition = symbolize_obj(statement_hash[:condition] || statement_hash[:Condition] || {})

            condition.each_value do |cond_values|
              cond_hash = symbolize_obj(cond_values || {})
              cond_hash.each do |cond_key, cond_value|
                key = cond_key.to_s
                next unless key.end_with?(":#{field}") || key == field

                raw_patterns.concat(Array(cond_value))
              end
            end
          end

          raw_patterns.map(&:to_s).map(&:strip).reject(&:empty?).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.glob_match?(opts = {})
          value = opts[:value].to_s
          pattern = opts[:pattern].to_s
          return false if pattern.empty?

          regex = Regexp.new("\\A#{Regexp.escape(pattern).gsub('\\*', '.*')}\\z")
          regex.match?(value)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.broad_sub_pattern?(opts = {})
          pattern = opts[:pattern].to_s.strip
          return false if pattern.empty?
          return false unless pattern.include?('*')

          normalized = pattern.downcase
          return true if normalized.match?(%r{^repo:[^:]+/[^:]+:\*$})
          return true if normalized.match?(%r{^repo:[^:]+/[^:]+:ref:\*$})
          return true if normalized.end_with?(':*') && !normalized.include?(':ref:refs/heads/')

          false
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_report(opts = {})
          output_dir = opts[:output_dir].to_s.scrub.strip
          report = symbolize_obj(opts[:report] || {})
          FileUtils.mkdir_p(output_dir)

          json_path = File.join(output_dir, 'workflow_trust_report.json')
          markdown_path = File.join(output_dir, 'workflow_trust_report.md')

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
          lines << '# GitHub Workflow Trust Report'
          lines << ''
          lines << "- Scanned At (UTC): `#{report[:scanned_at]}`"
          lines << "- Repo Path: `#{report[:repo_path]}`"
          lines << "- Workflows: `#{report[:workflow_count]}`"
          lines << "- Jobs: `#{report[:job_count]}`"
          lines << "- Findings: `#{report[:finding_count]}`"
          lines << ''

          lines << '## Ranked Findings'
          if Array(report[:findings]).empty?
            lines << '- No high-signal workflow trust paths detected in this pass.'
          else
            Array(report[:findings]).each do |finding|
              finding_hash = symbolize_obj(finding)
              lines << "- [#{finding_hash[:severity].to_s.upcase}] #{finding_hash[:title]}"
              lines << "  - file: `#{finding_hash[:file]}` job: `#{finding_hash[:job_name]}`"
              lines << "  - preconditions: #{finding_hash[:preconditions]}"
              lines << "  - impact: #{finding_hash[:likely_impact]}"
            end
          end

          lines << ''
          lines << '## OIDC Acceptance Summary'
          oidc_summary = symbolize_obj(report[:oidc_acceptance] || {})
          lines << "- Trust Policies: `#{oidc_summary[:trust_policy_count]}`"
          lines << "- OIDC Claims: `#{oidc_summary[:oidc_claim_count]}`"
          lines << "- Broad Acceptance Policies: `#{oidc_summary[:broad_acceptance_policy_count]}`"
          lines << "- Untrusted Claim Acceptances: `#{oidc_summary[:untrusted_claim_acceptance_count]}`"

          bridge_pack = symbolize_obj(oidc_summary[:artifact_privilege_bridge_pack] || {})
          unless bridge_pack.empty?
            lines << ''
            lines << '## Artifact Privilege Bridge Pack'
            lines << "- Provider: `#{bridge_pack[:provider]}`"
            lines << "- Replay Ready: `#{bridge_pack[:replay_ready]}`"
            lines << "- Critical Candidate: `#{bridge_pack[:critical_candidate]}`"
            lines << "- Matrix Steps: `#{Array(bridge_pack[:experiment_matrix]).length}`"
          end

          lines << ''
          lines << '## Reusable Workflow Lineage'
          lineage = symbolize_obj(report[:reusable_workflow_lineage] || {})
          lines << "- Paths: `#{lineage[:path_count] || 0}`"
          lines << "- Critical Paths: `#{lineage[:critical_path_count] || 0}`"
          lines << "- High Paths: `#{lineage[:high_path_count] || 0}`"

          top_paths = Array(lineage[:paths]).first(5)
          if top_paths.empty?
            lines << '- No cross-workflow escalation paths ranked in this pass.'
          else
            top_paths.each do |path|
              path_hash = symbolize_obj(path)
              lines << "- [#{path_hash[:severity].to_s.upcase}] #{path_hash[:title]}"
              lines << "  - chain: `#{path_hash[:chain_type]}` sink: `#{path_hash[:preferred_sink_kind]}` upgrade: `#{path_hash[:upgrade_priority]}`"
              lines << "  - next test: #{path_hash[:best_next_owned_test]}"
            end
          end

          lines << ''
          lines << '## Fixture Upgrade Step Pack'
          fixture_pack = symbolize_obj(report[:fixture_upgrade_step_pack] || {})
          lines << "- Planned Steps: `#{fixture_pack[:planned_step_count] || 0}`"
          lines << "- Safe to Execute: `#{fixture_pack[:safe_to_execute_count] || 0}`"
          lines << "- Blocked: `#{fixture_pack[:blocked_count] || 0}`"

          top_steps = Array(fixture_pack[:steps]).first(5)
          if top_steps.empty?
            lines << '- No fixture upgrade steps generated in this pass.'
          else
            top_steps.each do |step|
              step_hash = symbolize_obj(step)
              lines << "- [#{step_hash[:severity].to_s.upcase}] #{step_hash[:title]}"
              lines << "  - chain: `#{step_hash[:chain_type]}` sink: `#{step_hash[:preferred_sink_kind]}` gate: `#{step_hash[:gate_status]}`"
              lines << "  - first validation check: #{Array(step_hash[:validation_checks]).first}"
            end
          end

          lines.join("\n")
        rescue StandardError => e
          raise e
        end

        private_class_method def self.make_finding(opts = {})
          {
            id: opts[:id].to_s,
            category: opts[:category].to_s,
            severity: normalize_token(opts[:severity]),
            confidence: normalize_token(opts[:confidence]),
            title: opts[:title].to_s,
            file: opts[:file].to_s,
            job_name: opts[:job_name].to_s,
            preconditions: opts[:preconditions].to_s,
            likely_impact: opts[:likely_impact].to_s,
            evidence: symbolize_obj(opts[:evidence] || {})
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.dedup_nodes(opts = {})
          nodes = Array(opts[:nodes]).map { |node| symbolize_obj(node) }
          deduped = {}
          nodes.each do |node|
            deduped[node[:id]] ||= node
          end
          deduped.values
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
