# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module Targets
    module GitHub
      module WorkflowTrust
        # Ordered OIDC claim transition analysis that highlights stale acceptance
        # candidates after claim drift/narrowing across adjacent snapshots.
        module TransitionBundle
          DEFAULT_TRANSITION_FIELDS = %w[
            sub
            aud
            workflow_ref
            job_workflow_ref
            event_name
            ref
            repository
            environment
            actor
          ].freeze

          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.analyze(
          #   claim_snapshots: '/tmp/ordered_claim_snapshots.json',
          #   trust_policies: '/tmp/trust_policies.json'
          # )
          public_class_method def self.analyze(opts = {})
            claim_snapshots = resolve_structured_input(input: opts[:claim_snapshots])
            trust_policies = resolve_structured_input(input: opts[:trust_policies])

            transition_fields = normalize_transition_fields(
              transition_fields: opts[:transition_fields]
            )

            normalized_snapshots = claim_snapshots.each_with_index.map do |snapshot, index|
              normalize_snapshot(snapshot: snapshot, index: index)
            end

            bundles = trust_policies.each_with_index.map do |policy, index|
              build_policy_bundle(
                policy: policy,
                policy_index: index,
                normalized_snapshots: normalized_snapshots,
                transition_fields: transition_fields
              )
            end

            stale_candidates = bundles.flat_map do |bundle|
              Array(bundle[:stale_acceptance_candidates]).map { |candidate| symbolize_obj(candidate) }
            end

            {
              generated_at: Time.now.utc.iso8601,
              claim_snapshot_count: normalized_snapshots.length,
              trust_policy_count: trust_policies.length,
              transition_fields: transition_fields,
              bundle_count: bundles.length,
              stale_acceptance_candidate_count: stale_candidates.length,
              stale_acceptance_candidates: stale_candidates,
              bundles: bundles
            }
          rescue StandardError => e
            raise e
          end

          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.run(
          #   claim_snapshots: '/tmp/ordered_claim_snapshots.json',
          #   trust_policies: '/tmp/trust_policies.json',
          #   output_dir: '/tmp/workflow-trust-transition-bundle'
          # )
          public_class_method def self.run(opts = {})
            report = analyze(
              claim_snapshots: opts[:claim_snapshots],
              trust_policies: opts[:trust_policies],
              transition_fields: opts[:transition_fields]
            )

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
                report = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.analyze(
                  claim_snapshots: '/tmp/ordered_claim_snapshots.json',
                  trust_policies: '/tmp/trust_policies.json'
                )

                report = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.run(
                  claim_snapshots: '/tmp/ordered_claim_snapshots.json',
                  trust_policies: '/tmp/trust_policies.json',
                  output_dir: '/tmp/workflow-trust-transition-bundle'
                )
            HELP
          end

          private_class_method def self.build_policy_bundle(opts = {})
            policy = symbolize_obj(opts[:policy] || {})
            policy_index = opts[:policy_index].to_i
            normalized_snapshots = Array(opts[:normalized_snapshots]).map { |snapshot| symbolize_obj(snapshot) }
            transition_fields = Array(opts[:transition_fields]).map { |field| normalize_token(field) }

            provider = infer_policy_provider(policy: policy)
            policy_name = policy[:name].to_s.scrub.strip
            policy_name = "policy_#{policy_index + 1}" if policy_name.empty?

            sub_patterns = extract_policy_patterns(policy: policy, field: :sub)
            aud_patterns = extract_policy_patterns(policy: policy, field: :aud)
            wildcard_fields = []
            wildcard_fields << 'sub' if sub_patterns.any? { |pattern| wildcard_pattern?(pattern: pattern) }
            wildcard_fields << 'aud' if aud_patterns.any? { |pattern| wildcard_pattern?(pattern: pattern) }

            timeline = normalized_snapshots.map do |snapshot|
              claim = symbolize_obj(snapshot[:claim] || {})
              eval_result = evaluate_claim_against_policy(
                claim: claim,
                sub_patterns: sub_patterns,
                aud_patterns: aud_patterns
              )

              {
                index: snapshot[:index],
                snapshot_id: snapshot[:snapshot_id],
                captured_at: snapshot[:captured_at],
                note: snapshot[:note],
                accepted: eval_result[:accepted],
                matched_sub_patterns: eval_result[:matched_sub_patterns],
                matched_aud_patterns: eval_result[:matched_aud_patterns],
                claim: compact_claim_fields(claim: claim, transition_fields: transition_fields)
              }
            end

            transition_diffs = []
            timeline.each_cons(2).with_index do |(previous_snapshot, current_snapshot), transition_index|
              changed_fields = changed_transition_fields(
                previous_claim: previous_snapshot[:claim],
                current_claim: current_snapshot[:claim],
                transition_fields: transition_fields
              )
              next if changed_fields.empty?

              accepted_after_drift = previous_snapshot[:accepted] && current_snapshot[:accepted]
              narrowing_fields = changed_fields.select { |field| wildcard_fields.include?(field) }
              stale_acceptance_after_narrowing = accepted_after_drift && !narrowing_fields.empty?

              transition_diffs << {
                id: "#{normalize_token(policy_name)}:t#{transition_index + 1}",
                from_snapshot: previous_snapshot[:snapshot_id],
                to_snapshot: current_snapshot[:snapshot_id],
                changed_fields: changed_fields,
                narrowing_fields: narrowing_fields,
                accepted_before: previous_snapshot[:accepted],
                accepted_after: current_snapshot[:accepted],
                accepted_after_drift: accepted_after_drift,
                stale_acceptance_after_narrowing: stale_acceptance_after_narrowing,
                transition_kind: transition_kind(
                  accepted_before: previous_snapshot[:accepted],
                  accepted_after: current_snapshot[:accepted]
                )
              }
            end

            stale_candidates = transition_diffs.select do |diff|
              diff[:stale_acceptance_after_narrowing] == true
            end.map do |diff|
              {
                id: "#{diff[:id]}:stale_acceptance",
                provider: provider,
                policy_name: policy_name,
                severity: 'high',
                confidence: 'medium',
                from_snapshot: diff[:from_snapshot],
                to_snapshot: diff[:to_snapshot],
                changed_fields: diff[:changed_fields],
                narrowing_fields: diff[:narrowing_fields],
                summary: "Policy #{policy_name} remained accepted after claim drift in #{diff[:narrowing_fields].join(', ')}.",
                evidence: {
                  accepted_before: diff[:accepted_before],
                  accepted_after: diff[:accepted_after],
                  transition_kind: diff[:transition_kind]
                }
              }
            end

            {
              provider: provider,
              policy_name: policy_name,
              sub_patterns: sub_patterns,
              aud_patterns: aud_patterns,
              wildcard_fields: wildcard_fields,
              timeline: timeline,
              transition_diff_count: transition_diffs.length,
              transition_diffs: transition_diffs,
              accepted_after_drift_count: transition_diffs.count { |diff| diff[:accepted_after_drift] },
              stale_acceptance_after_narrowing_count: transition_diffs.count { |diff| diff[:stale_acceptance_after_narrowing] },
              stale_acceptance_candidates: stale_candidates
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.transition_kind(opts = {})
            accepted_before = opts[:accepted_before] == true
            accepted_after = opts[:accepted_after] == true

            return 'accepted_to_accepted' if accepted_before && accepted_after
            return 'accepted_to_denied' if accepted_before && !accepted_after
            return 'denied_to_accepted' if !accepted_before && accepted_after

            'denied_to_denied'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.changed_transition_fields(opts = {})
            previous_claim = symbolize_obj(opts[:previous_claim] || {})
            current_claim = symbolize_obj(opts[:current_claim] || {})
            transition_fields = Array(opts[:transition_fields]).map { |field| normalize_token(field) }

            transition_fields.select do |field|
              prev_value = claim_field_value(claim: previous_claim, field: field)
              current_value = claim_field_value(claim: current_claim, field: field)
              value_changed?(previous_value: prev_value, current_value: current_value)
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.claim_field_value(opts = {})
            claim = symbolize_obj(opts[:claim] || {})
            field = opts[:field].to_s
            field_sym = field.to_sym

            value = claim[field_sym]
            value = claim[field] if value.nil?
            value = claim[:repository_owner] if value.nil? && field == 'repository_owner'
            value
          rescue StandardError => e
            raise e
          end

          private_class_method def self.value_changed?(opts = {})
            previous_value = opts[:previous_value]
            current_value = opts[:current_value]

            previous_json = previous_value.is_a?(String) ? previous_value : previous_value.to_json
            current_json = current_value.is_a?(String) ? current_value : current_value.to_json

            previous_json != current_json
          rescue StandardError => e
            raise e
          end

          private_class_method def self.compact_claim_fields(opts = {})
            claim = symbolize_obj(opts[:claim] || {})
            transition_fields = Array(opts[:transition_fields]).map { |field| normalize_token(field) }

            transition_fields.each_with_object({}) do |field, accum|
              value = claim_field_value(claim: claim, field: field)
              next if value.nil?
              next if value.respond_to?(:empty?) && value.empty?

              accum[field.to_sym] = value
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_snapshot(opts = {})
            snapshot = symbolize_obj(opts[:snapshot] || {})
            index = opts[:index].to_i

            claim = snapshot[:claim]
            claim = snapshot if claim.nil?
            claim = symbolize_obj(claim || {})

            snapshot_id = snapshot[:snapshot_id].to_s.scrub.strip
            snapshot_id = snapshot[:id].to_s.scrub.strip if snapshot_id.empty?
            snapshot_id = snapshot[:label].to_s.scrub.strip if snapshot_id.empty?
            snapshot_id = "snapshot_#{index + 1}" if snapshot_id.empty?

            {
              index: index,
              snapshot_id: snapshot_id,
              captured_at: snapshot[:captured_at].to_s,
              note: snapshot[:note].to_s,
              claim: claim
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.evaluate_claim_against_policy(opts = {})
            claim = symbolize_obj(opts[:claim] || {})
            sub_patterns = Array(opts[:sub_patterns]).map(&:to_s)
            aud_patterns = Array(opts[:aud_patterns]).map(&:to_s)

            sub = claim[:sub].to_s
            aud = claim[:aud].to_s

            matched_sub_patterns = sub_patterns.select { |pattern| glob_match?(value: sub, pattern: pattern) }
            matched_aud_patterns = aud_patterns.select { |pattern| glob_match?(value: aud, pattern: pattern) }

            sub_match = sub_patterns.empty? || !matched_sub_patterns.empty?
            aud_match = aud_patterns.empty? || !matched_aud_patterns.empty?

            {
              accepted: sub_match && aud_match,
              matched_sub_patterns: matched_sub_patterns,
              matched_aud_patterns: matched_aud_patterns
            }
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
              elsif hash_input.key?(:claims)
                Array(hash_input[:claims]).map { |entry| symbolize_obj(entry) }
              elsif hash_input.key?(:claim_snapshots)
                Array(hash_input[:claim_snapshots]).map { |entry| symbolize_obj(entry) }
              elsif hash_input.key?(:policies)
                Array(hash_input[:policies]).map { |entry| symbolize_obj(entry) }
              else
                [hash_input]
              end
            when String
              str = input.to_s.scrub.strip
              return [] if str.empty?

              if File.exist?(str)
                parsed = JSON.parse(File.read(str))
                return resolve_structured_input(input: parsed)
              end

              parsed = JSON.parse(str)
              resolve_structured_input(input: parsed)
            else
              [symbolize_obj(input)]
            end
          rescue JSON::ParserError => e
            raise "ERROR: unable to parse structured input: #{e.message}"
          rescue StandardError => e
            raise e
          end

          private_class_method def self.infer_policy_provider(opts = {})
            policy = symbolize_obj(opts[:policy] || {})

            provider = normalize_token(policy[:provider])
            return provider unless provider.empty?

            serialized = policy.to_json.downcase
            return 'aws' if serialized.include?('token.actions.githubusercontent.com') || serialized.include?('sts.amazonaws.com')
            return 'gcp' if serialized.include?('iam.googleapis.com') || serialized.include?('workloadidentity')
            return 'azure' if serialized.include?('federatedidentitycredential') || serialized.include?('management.azure.com')

            'generic'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.extract_policy_patterns(opts = {})
            policy = symbolize_obj(opts[:policy] || {})
            field = normalize_token(opts[:field])

            normalized_suffix = case field
                                when 'sub'
                                  ':sub'
                                when 'aud'
                                  ':aud'
                                else
                                  ":#{field}"
                                end

            statements = Array(policy[:statements]).map { |statement| symbolize_obj(statement) }
            patterns = []

            statements.each do |statement|
              condition = symbolize_obj(statement[:condition] || {})
              condition.each_value do |condition_value|
                condition_hash = symbolize_obj(condition_value || {})
                condition_hash.each do |condition_field, condition_pattern|
                  field_name = condition_field.to_s.downcase
                  next unless field_name.end_with?(normalized_suffix)

                  patterns.concat(Array(condition_pattern).map(&:to_s))
                end
              end
            end

            patterns.uniq
          rescue StandardError => e
            raise e
          end

          private_class_method def self.glob_match?(opts = {})
            value = opts[:value].to_s
            pattern = opts[:pattern].to_s
            return false if pattern.empty?

            regex = Regexp.escape(pattern).gsub('\\*', '.*').gsub('\\?', '.')
            !!(value =~ /^#{regex}$/)
          rescue StandardError => e
            raise e
          end

          private_class_method def self.wildcard_pattern?(opts = {})
            pattern = opts[:pattern].to_s
            pattern.include?('*') || pattern.include?('?')
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_transition_fields(opts = {})
            transition_fields = Array(opts[:transition_fields]).map { |field| normalize_token(field) }
            transition_fields = DEFAULT_TRANSITION_FIELDS if transition_fields.empty?
            transition_fields.reject(&:empty?).uniq
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_report(opts = {})
            output_dir = opts[:output_dir].to_s.scrub.strip
            report = symbolize_obj(opts[:report] || {})
            FileUtils.mkdir_p(output_dir)

            json_path = File.join(output_dir, 'workflow_trust_transition_bundle.json')
            markdown_path = File.join(output_dir, 'workflow_trust_transition_bundle.md')

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
            lines << '# GitHub Workflow Trust Transition Bundle'
            lines << ''
            lines << "- Generated At (UTC): `#{report[:generated_at]}`"
            lines << "- Claim Snapshots: `#{report[:claim_snapshot_count]}`"
            lines << "- Trust Policies: `#{report[:trust_policy_count]}`"
            lines << "- Stale Acceptance Candidates: `#{report[:stale_acceptance_candidate_count]}`"
            lines << ''

            lines << '## Stale Acceptance Candidates'
            stale_candidates = Array(report[:stale_acceptance_candidates]).map { |candidate| symbolize_obj(candidate) }
            if stale_candidates.empty?
              lines << '- No stale acceptance candidates detected in this transition set.'
            else
              stale_candidates.each do |candidate|
                lines << "- [#{candidate[:severity].to_s.upcase}] #{candidate[:summary]}"
                lines << "  - policy: `#{candidate[:policy_name]}` provider: `#{candidate[:provider]}`"
                lines << "  - transition: `#{candidate[:from_snapshot]} -> #{candidate[:to_snapshot]}`"
                lines << "  - narrowing_fields: `#{Array(candidate[:narrowing_fields]).join(', ')}`"
              end
            end

            lines << ''
            lines << '## Policy Transition Diffs'
            Array(report[:bundles]).each do |bundle|
              bundle_hash = symbolize_obj(bundle)
              lines << ''
              lines << "### #{bundle_hash[:policy_name]} (#{bundle_hash[:provider]})"
              lines << "- transition diffs: `#{bundle_hash[:transition_diff_count]}`"
              lines << "- accepted_after_drift: `#{bundle_hash[:accepted_after_drift_count]}`"
              lines << "- stale_after_narrowing: `#{bundle_hash[:stale_acceptance_after_narrowing_count]}`"

              if Array(bundle_hash[:transition_diffs]).empty?
                lines << '- No adjacent claim-field transitions detected.'
              else
                Array(bundle_hash[:transition_diffs]).each do |diff|
                  diff_hash = symbolize_obj(diff)
                  lines << "- `#{diff_hash[:from_snapshot]} -> #{diff_hash[:to_snapshot]}`"
                  lines << "  - changed_fields: `#{Array(diff_hash[:changed_fields]).join(', ')}`"
                  lines << "  - narrowing_fields: `#{Array(diff_hash[:narrowing_fields]).join(', ')}`"
                  lines << "  - accepted_after_drift: `#{diff_hash[:accepted_after_drift]}`"
                  lines << "  - stale_acceptance_after_narrowing: `#{diff_hash[:stale_acceptance_after_narrowing]}`"
                end
              end
            end

            lines.join("\n")
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
