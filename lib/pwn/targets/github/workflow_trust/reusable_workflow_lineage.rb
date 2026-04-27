# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module Targets
    module GitHub
      module WorkflowTrust
        # Cross-workflow trust-boundary path analysis for reusable workflows,
        # workflow_run fan-in, artifact handoff, and inherited secret/oidc sinks.
        module ReusableWorkflowLineage
          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.analyze(
          #   workflows: workflows
          # )
          public_class_method def self.analyze(opts = {})
            workflows = Array(opts[:workflows]).map { |workflow| symbolize_obj(workflow) }

            workflow_records = workflows.map { |workflow| normalize_workflow_record(workflow: workflow) }
            reusable_edges = build_reusable_edges(workflow_records: workflow_records)
            workflow_run_edges = build_workflow_run_edges(workflow_records: workflow_records)

            paths = []
            paths.concat(build_reusable_workflow_paths(workflow_records: workflow_records, reusable_edges: reusable_edges))
            paths.concat(build_workflow_run_paths(workflow_records: workflow_records, workflow_run_edges: workflow_run_edges))

            paths = paths.uniq { |path| path[:id] }
            paths = paths.sort_by { |path| [-severity_rank(path[:severity]), path[:id]] }

            {
              generated_at: Time.now.utc.iso8601,
              workflow_count: workflow_records.length,
              reusable_edge_count: reusable_edges.length,
              workflow_run_edge_count: workflow_run_edges.length,
              path_count: paths.length,
              critical_path_count: paths.count { |path| normalize_token(path[:severity]) == 'critical' },
              high_path_count: paths.count { |path| normalize_token(path[:severity]) == 'high' },
              paths: paths
            }
          rescue StandardError => e
            raise e
          end

          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.scan_repo(
          #   repo_path: '/path/to/repo',
          #   output_dir: '/tmp/workflow-trust-lineage'
          # )
          public_class_method def self.scan_repo(opts = {})
            repo_path = opts[:repo_path].to_s.scrub.strip
            raise 'ERROR: repo_path is required' if repo_path.empty?
            raise "ERROR: repo_path does not exist: #{repo_path}" unless Dir.exist?(repo_path)

            workflows = PWN::Targets::GitHub::WorkflowTrust.load_workflows(repo_path: repo_path)
            report = analyze(workflows: workflows)
            report[:repo_path] = File.expand_path(repo_path)

            output_dir = opts[:output_dir].to_s.scrub.strip
            unless output_dir.empty?
              write_report(output_dir: output_dir, report: report)
            end

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
                report = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.analyze(
                  workflows: workflows
                )

                report = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.scan_repo(
                  repo_path: '/path/to/repo',
                  output_dir: '/tmp/workflow-trust-lineage'
                )
            HELP
          end

          private_class_method def self.normalize_workflow_record(opts = {})
            workflow = symbolize_obj(opts[:workflow] || {})

            file_name = workflow[:file_name].to_s
            workflow_name = workflow[:workflow_name].to_s
            triggers = extract_triggers(on_field: workflow[:on])
            workflow_permissions = normalize_permissions(permissions: workflow[:permissions])

            jobs = symbolize_obj(workflow[:jobs] || {}).map do |job_name, job_def|
              normalize_job_record(
                workflow_file: file_name,
                workflow_permissions: workflow_permissions,
                job_name: job_name,
                job_def: job_def
              )
            end

            {
              workflow_id: file_name,
              file_name: file_name,
              workflow_name: workflow_name,
              triggers: triggers,
              workflow_run_sources: extract_workflow_run_sources(on_field: workflow[:on]),
              jobs: jobs
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_job_record(opts = {})
            workflow_file = opts[:workflow_file].to_s
            workflow_permissions = symbolize_obj(opts[:workflow_permissions] || {})
            job_name = opts[:job_name].to_s
            job = symbolize_obj(opts[:job_def] || {})
            steps = Array(job[:steps]).map { |step| symbolize_obj(step || {}) }

            job_permissions = normalize_permissions(permissions: job[:permissions])
            effective_permissions = workflow_permissions.merge(job_permissions)
            write_scopes = effective_permissions.select do |_scope, level|
              %w[write admin].include?(normalize_token(level))
            end.keys

            uses_oidc = normalize_token(
              effective_permissions['id-token'] ||
              effective_permissions[:'id-token'] ||
              effective_permissions[:id_token]
            ) == 'write'

            environment = normalize_environment(environment: job[:environment])
            secrets_mode = normalize_secrets_mode(secrets: job[:secrets])
            explicit_secret_passthrough = secrets_mode == 'explicit'
            uses_reusable = job[:uses].to_s.scrub.strip

            {
              job_id: "#{workflow_file}:#{job_name}",
              job_name: job_name,
              uses_reusable: uses_reusable,
              reusable_target: normalize_reusable_target(uses_reusable: uses_reusable),
              needs: Array(job[:needs]).map { |entry| entry.to_s },
              uploads_artifact: steps.any? { |step| step[:uses].to_s.downcase.include?('actions/upload-artifact') },
              downloads_artifact: steps.any? { |step| step[:uses].to_s.downcase.include?('actions/download-artifact') },
              uses_oidc: uses_oidc,
              write_scopes: write_scopes,
              environment: environment,
              secrets_mode: secrets_mode,
              explicit_secret_passthrough: explicit_secret_passthrough,
              privileged: uses_oidc || !write_scopes.empty? || !environment.empty? || explicit_secret_passthrough,
              sink_kinds: sink_kinds(
                uses_oidc: uses_oidc,
                write_scopes: write_scopes,
                environment: environment,
                secrets_mode: secrets_mode,
                explicit_secret_passthrough: explicit_secret_passthrough
              )
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_reusable_edges(opts = {})
            workflow_records = Array(opts[:workflow_records]).map { |workflow| symbolize_obj(workflow) }
            workflow_lookup = workflow_records.each_with_object({}) do |workflow, accum|
              accum[workflow[:file_name].to_s] = workflow
              accum[workflow[:workflow_name].to_s] = workflow unless workflow[:workflow_name].to_s.empty?
            end

            workflow_records.flat_map do |workflow|
              Array(workflow[:jobs]).map do |job|
                job_hash = symbolize_obj(job)
                target = job_hash[:reusable_target]
                next if target.to_s.empty?

                callee = resolve_callee_workflow(workflow_lookup: workflow_lookup, target: target)

                {
                  caller_workflow: workflow[:file_name],
                  caller_workflow_name: workflow[:workflow_name],
                  caller_job: job_hash[:job_name],
                  reusable_target: target,
                  callee_workflow: callee&.dig(:file_name),
                  callee_workflow_name: callee&.dig(:workflow_name),
                  caller_job_record: job_hash,
                  callee_record: callee.nil? ? nil : symbolize_obj(callee)
                }
              end
            end.compact
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_workflow_run_edges(opts = {})
            workflow_records = Array(opts[:workflow_records]).map { |workflow| symbolize_obj(workflow) }

            workflow_records.flat_map do |downstream_workflow|
              source_names = Array(downstream_workflow[:workflow_run_sources]).map(&:to_s)
              next [] if source_names.empty?

              source_names.flat_map do |source_name|
                normalized_source = normalize_token(source_name)
                upstream_candidates = workflow_records.select do |workflow|
                  normalize_token(workflow[:workflow_name]) == normalized_source ||
                    normalize_token(File.basename(workflow[:file_name], File.extname(workflow[:file_name]))) == normalized_source
                end

                upstream_candidates.map do |upstream|
                  {
                    upstream_workflow: upstream[:file_name],
                    upstream_workflow_name: upstream[:workflow_name],
                    downstream_workflow: downstream_workflow[:file_name],
                    downstream_workflow_name: downstream_workflow[:workflow_name],
                    source_name: source_name,
                    upstream_record: upstream,
                    downstream_record: downstream_workflow
                  }
                end
              end
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_reusable_workflow_paths(opts = {})
            workflow_records = Array(opts[:workflow_records]).map { |workflow| symbolize_obj(workflow) }
            reusable_edges = Array(opts[:reusable_edges]).map { |edge| symbolize_obj(edge) }

            untrusted_workflow_ids = workflow_records.select do |workflow|
              (Array(workflow[:triggers]) & PWN::Targets::GitHub::WorkflowTrust::UNTRUSTED_EVENT_NAMES).any?
            end.map { |workflow| workflow[:file_name] }

            reusable_edges.filter_map do |edge|
              next unless untrusted_workflow_ids.include?(edge[:caller_workflow])

              caller_job = symbolize_obj(edge[:caller_job_record] || {})
              callee = symbolize_obj(edge[:callee_record] || {})
              callee_jobs = Array(callee[:jobs]).map { |job| symbolize_obj(job) }
              sink_job = callee_jobs.find { |job| job[:privileged] == true }

              sink_kinds = Array(sink_job&.dig(:sink_kinds))
              sink_kinds = Array(caller_job[:sink_kinds]) if sink_kinds.empty?
              preferred_sink_kind = sink_kinds.first || 'workflow_call_chain'

              severity = if %w[oidc_role_assumption write_token].include?(preferred_sink_kind)
                           'critical'
                         else
                           'high'
                         end

              missing_signals = []
              missing_signals << 'callee_workflow_not_resolved' if callee.empty?
              missing_signals << 'privileged_sink_not_confirmed' if sink_job.nil?
              unless %w[inherit explicit].include?(normalize_token(caller_job[:secrets_mode]))
                missing_signals << 'secret_flow_not_confirmed'
              end

              {
                id: "reusable:#{edge[:caller_workflow]}:#{edge[:caller_job]}:#{edge[:reusable_target]}",
                chain_type: 'reusable_workflow_call',
                severity: severity,
                confidence: missing_signals.empty? ? 'high' : 'medium',
                title: 'Untrusted workflow_call chain reaches privileged reusable workflow sink',
                from_workflow: edge[:caller_workflow],
                to_workflow: edge[:callee_workflow],
                entry_triggers: workflow_records.find { |workflow| workflow[:file_name] == edge[:caller_workflow] }&.dig(:triggers) || [],
                preferred_sink_kind: preferred_sink_kind,
                upgrade_priority: upgrade_priority(preferred_sink_kind: preferred_sink_kind, missing_signals: missing_signals),
                missing_signals: missing_signals,
                best_next_owned_test: best_next_owned_test(chain_type: 'reusable_workflow_call', preferred_sink_kind: preferred_sink_kind),
                evidence: {
                  caller_job: edge[:caller_job],
                  reusable_target: edge[:reusable_target],
                  secrets_mode: caller_job[:secrets_mode],
                  sink_job: sink_job&.dig(:job_name),
                  sink_kinds: sink_kinds
                }
              }
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_workflow_run_paths(opts = {})
            workflow_records = Array(opts[:workflow_records]).map { |workflow| symbolize_obj(workflow) }
            workflow_run_edges = Array(opts[:workflow_run_edges]).map { |edge| symbolize_obj(edge) }

            untrusted_workflow_ids = workflow_records.select do |workflow|
              (Array(workflow[:triggers]) & PWN::Targets::GitHub::WorkflowTrust::UNTRUSTED_EVENT_NAMES).any?
            end.map { |workflow| workflow[:file_name] }

            workflow_run_edges.filter_map do |edge|
              next unless untrusted_workflow_ids.include?(edge[:upstream_workflow])

              upstream_jobs = Array(edge.dig(:upstream_record, :jobs)).map { |job| symbolize_obj(job) }
              downstream_jobs = Array(edge.dig(:downstream_record, :jobs)).map { |job| symbolize_obj(job) }

              artifact_producers = upstream_jobs.select { |job| job[:uploads_artifact] == true }
              privileged_consumers = downstream_jobs.select do |job|
                job[:downloads_artifact] == true && job[:privileged] == true
              end

              next if artifact_producers.empty? && privileged_consumers.empty?

              sink_kinds = privileged_consumers.flat_map { |job| Array(job[:sink_kinds]) }
              preferred_sink_kind = sink_kinds.first || 'artifact_to_privileged_job'

              missing_signals = []
              missing_signals << 'artifact_producer_not_confirmed' if artifact_producers.empty?
              missing_signals << 'privileged_artifact_consumer_not_confirmed' if privileged_consumers.empty?

              severity = if %w[oidc_role_assumption write_token].include?(preferred_sink_kind)
                           'critical'
                         else
                           'high'
                         end

              {
                id: "workflow_run:#{edge[:upstream_workflow]}:#{edge[:downstream_workflow]}:#{edge[:source_name]}",
                chain_type: 'workflow_run_artifact_fan_in',
                severity: severity,
                confidence: missing_signals.empty? ? 'high' : 'medium',
                title: 'Untrusted workflow_run artifact handoff reaches privileged downstream job',
                from_workflow: edge[:upstream_workflow],
                to_workflow: edge[:downstream_workflow],
                entry_triggers: workflow_records.find { |workflow| workflow[:file_name] == edge[:upstream_workflow] }&.dig(:triggers) || [],
                preferred_sink_kind: preferred_sink_kind,
                upgrade_priority: upgrade_priority(preferred_sink_kind: preferred_sink_kind, missing_signals: missing_signals),
                missing_signals: missing_signals,
                best_next_owned_test: best_next_owned_test(chain_type: 'workflow_run_artifact_fan_in', preferred_sink_kind: preferred_sink_kind),
                evidence: {
                  source_name: edge[:source_name],
                  artifact_producers: artifact_producers.map { |job| job[:job_name] },
                  privileged_consumers: privileged_consumers.map { |job| job[:job_name] },
                  downstream_trigger_sources: Array(edge.dig(:downstream_record, :workflow_run_sources))
                }
              }
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.upgrade_priority(opts = {})
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])
            missing_signals = Array(opts[:missing_signals]).map { |entry| normalize_token(entry) }

            return 'p1' if missing_signals.empty? && %w[oidc_role_assumption write_token].include?(preferred_sink_kind)
            return 'p2' if missing_signals.empty?
            return 'p2' if missing_signals.length <= 1

            'p3'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.best_next_owned_test(opts = {})
            chain_type = normalize_token(opts[:chain_type])
            preferred_sink_kind = normalize_token(opts[:preferred_sink_kind])

            case [chain_type, preferred_sink_kind]
            when ['reusable_workflow_call', 'oidc_role_assumption']
              'Trigger caller workflow from controlled PR branch and capture downstream reusable workflow OIDC token issuance.'
            when ['reusable_workflow_call', 'write_token']
              'Trigger caller workflow from controlled input and verify reusable workflow job can mutate repository state.'
            when ['workflow_run_artifact_fan_in', 'oidc_role_assumption']
              'Poison upstream artifact with marker and verify privileged downstream workflow_run job reaches OIDC exchange step.'
            when ['workflow_run_artifact_fan_in', 'write_token']
              'Poison upstream artifact and verify downstream privileged consumer can write to repo/packages.'
            else
              'Run controlled input from untrusted trigger and capture privileged downstream step execution with full artifacts.'
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_reusable_target(opts = {})
            uses_reusable = opts[:uses_reusable].to_s.scrub.strip
            return '' unless uses_reusable.include?('.github/workflows/')

            uses_reusable
          rescue StandardError => e
            raise e
          end

          private_class_method def self.resolve_callee_workflow(opts = {})
            workflow_lookup = symbolize_obj(opts[:workflow_lookup] || {})
            target = opts[:target].to_s
            return nil if target.empty?

            path_part = target.split('@').first.to_s
            basename = File.basename(path_part)
            normalized_basename = normalize_token(File.basename(basename, File.extname(basename)))

            workflow_lookup.values.find do |workflow|
              workflow_hash = symbolize_obj(workflow)
              file_match = workflow_hash[:file_name].to_s == basename || workflow_hash[:file_name].to_s == path_part
              name_match = normalize_token(workflow_hash[:workflow_name]) == normalized_basename ||
                           normalize_token(File.basename(workflow_hash[:file_name], File.extname(workflow_hash[:file_name]))) == normalized_basename
              file_match || name_match
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.extract_workflow_run_sources(opts = {})
            on_field = symbolize_obj(opts[:on_field])
            return [] unless on_field.is_a?(Hash)

            workflow_run = symbolize_obj(on_field[:workflow_run] || on_field['workflow_run'] || {})
            workflows = workflow_run[:workflows] || workflow_run['workflows']
            Array(workflows).map(&:to_s).map(&:strip).reject(&:empty?).uniq
          rescue StandardError => e
            raise e
          end

          private_class_method def self.extract_triggers(opts = {})
            on_field = symbolize_obj(opts[:on_field])

            triggers = case on_field
                       when String, Symbol
                         [normalize_token(on_field)]
                       when Array
                         on_field.map { |entry| normalize_token(entry) }
                       when Hash
                         on_field.keys.map { |key| normalize_token(key) }
                       else
                         []
                       end

            triggers.reject(&:empty?).uniq
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_permissions(opts = {})
            permissions = symbolize_obj(opts[:permissions])

            case permissions
            when String, Symbol
              level = normalize_token(permissions)
              return { '*' => 'write' } if level == 'write_all'
              return { '*' => 'read' } if level == 'read_all'

              { '*' => level }
            when Hash
              permissions.each_with_object({}) do |(scope, level), accum|
                scope_key = scope.to_s.tr('_', '-')
                accum[scope_key] = normalize_token(level)
              end
            else
              {}
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_environment(opts = {})
            environment = symbolize_obj(opts[:environment])

            case environment
            when String, Symbol
              value = environment.to_s.scrub.strip
              value.empty? ? '' : value
            when Hash
              name = environment[:name].to_s.scrub.strip
              name.empty? ? '' : name
            else
              ''
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_secrets_mode(opts = {})
            secrets = symbolize_obj(opts[:secrets])

            case secrets
            when String, Symbol
              token = normalize_token(secrets)
              return 'inherit' if token == 'inherit'

              token.empty? ? 'none' : 'explicit'
            when Hash
              return 'none' if secrets.empty?

              'explicit'
            else
              'none'
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.sink_kinds(opts = {})
            kinds = []
            kinds << 'oidc_role_assumption' if opts[:uses_oidc] == true
            kinds << 'write_token' unless Array(opts[:write_scopes]).empty?
            kinds << 'deployment_environment' unless opts[:environment].to_s.empty?

            secrets_mode = normalize_token(opts[:secrets_mode])
            explicit_secret_passthrough = opts[:explicit_secret_passthrough] == true
            if secrets_mode == 'inherit' || explicit_secret_passthrough
              kinds << 'secret_inheritance'
            end

            kinds.uniq
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_report(opts = {})
            output_dir = opts[:output_dir].to_s.scrub.strip
            report = symbolize_obj(opts[:report] || {})
            FileUtils.mkdir_p(output_dir)

            json_path = File.join(output_dir, 'workflow_trust_reusable_workflow_lineage.json')
            markdown_path = File.join(output_dir, 'workflow_trust_reusable_workflow_lineage.md')

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
            lines << '# GitHub Workflow Trust Reusable Workflow Lineage'
            lines << ''
            lines << "- Generated At (UTC): `#{report[:generated_at]}`"
            lines << "- Workflow Count: `#{report[:workflow_count]}`"
            lines << "- Reusable Edges: `#{report[:reusable_edge_count]}`"
            lines << "- workflow_run Edges: `#{report[:workflow_run_edge_count]}`"
            lines << "- Paths: `#{report[:path_count]}`"
            lines << ''

            lines << '## Ranked Paths'
            if Array(report[:paths]).empty?
              lines << '- No cross-workflow escalation paths detected in this pass.'
            else
              Array(report[:paths]).each do |path|
                path_hash = symbolize_obj(path)
                lines << "- [#{path_hash[:severity].to_s.upcase}] #{path_hash[:title]}"
                lines << "  - chain: `#{path_hash[:chain_type]}` from: `#{path_hash[:from_workflow]}` to: `#{path_hash[:to_workflow]}`"
                lines << "  - sink: `#{path_hash[:preferred_sink_kind]}` upgrade: `#{path_hash[:upgrade_priority]}`"
                lines << "  - missing_signals: `#{Array(path_hash[:missing_signals]).join(', ')}`"
                lines << "  - best_next_owned_test: #{path_hash[:best_next_owned_test]}"
              end
            end

            lines.join("\n")
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
end
