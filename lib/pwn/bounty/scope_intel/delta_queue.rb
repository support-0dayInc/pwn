# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'uri'
require 'yaml'

module PWN
  module Bounty
    module ScopeIntel
      # Persists scope snapshots and emits a ranked delta queue to accelerate
      # first-mover recon on newly in-scope high-value assets.
      module DeltaQueue
        DEFAULT_MAX_QUEUE_ENTRIES = 40

        # Supported Method Parameters::
        # report = PWN::Bounty::ScopeIntel::DeltaQueue.run(
        #   program_name: 'target-program',
        #   scope_details: scope_details_hash,
        #   output_dir: '/tmp/scope-intel-delta-queue'
        # )
        public_class_method def self.run(opts = {})
          input_hash = symbolize_obj(opts || {})

          new_scope_intel = resolve_scope_intel(
            scope_intel: input_hash[:new_scope_intel],
            scope_details: input_hash[:scope_details],
            program_name: input_hash[:program_name],
            include_ai_analysis: input_hash[:include_ai_analysis],
            proxy: input_hash[:proxy]
          )

          program_name = input_hash[:program_name].to_s.scrub.strip
          program_name = new_scope_intel[:program_name].to_s.scrub.strip if program_name.empty?
          program_name = 'unknown_program' if program_name.empty?

          output_dir = input_hash[:output_dir].to_s.scrub.strip
          snapshot_dir = resolved_snapshot_dir(
            snapshot_dir: input_hash[:snapshot_dir],
            output_dir: output_dir
          )

          previous_snapshot = if input_hash[:old_scope_intel].is_a?(Hash)
                                {
                                  path: '',
                                  data: symbolize_obj(input_hash[:old_scope_intel])
                                }
                              else
                                load_latest_snapshot(
                                  snapshot_dir: snapshot_dir,
                                  program_name: program_name
                                )
                              end

          old_scope_intel = symbolize_obj(previous_snapshot[:data] || {})

          diff = if old_scope_intel.empty?
                   diff_without_previous(new_scope_intel: new_scope_intel)
                 else
                   PWN::Bounty::ScopeIntel.diff_rows(
                     old_scope_intel: old_scope_intel,
                     new_scope_intel: new_scope_intel
                   )
                 end

          queue = build_delta_queue(
            diff: diff,
            max_queue_entries: input_hash[:max_queue_entries]
          )

          saved_snapshot = save_snapshot(
            snapshot_dir: snapshot_dir,
            program_name: program_name,
            scope_intel: new_scope_intel
          )

          report = {
            generated_at: Time.now.utc.iso8601,
            program_name: program_name,
            snapshot: {
              previous_snapshot_path: previous_snapshot[:path].to_s,
              current_snapshot_path: saved_snapshot[:path].to_s
            },
            diff_summary: {
              old_count: diff[:old_count].to_i,
              new_count: diff[:new_count].to_i,
              added_count: diff[:added_count].to_i,
              removed_count: diff[:removed_count].to_i,
              changed_count: diff[:changed_count].to_i
            },
            queue_count: queue.length,
            delta_queue: queue,
            burp_target_seeds: queue.map { |entry| entry[:burp_seed] }.reject(&:empty?).uniq,
            next_steps: next_steps(queue: queue)
          }

          unless output_dir.empty?
            FileUtils.mkdir_p(output_dir)
            write_json(path: File.join(output_dir, 'scope_intel_delta_queue.json'), obj: report)
            write_markdown(path: File.join(output_dir, 'scope_intel_delta_queue.md'), report: report)
            write_burp_targets(path: File.join(output_dir, 'scope_intel_delta_queue_burp_targets.txt'), report: report)
          end

          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::ScopeIntel::DeltaQueue.build(
        #   old_scope_intel: old_scope_intel,
        #   new_scope_intel: new_scope_intel
        # )
        public_class_method def self.build(opts = {})
          run(opts)
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # profile = PWN::Bounty::ScopeIntel::DeltaQueue.load_profile(
        #   yaml_path: '/path/to/scope_intel.delta_queue.example.yaml'
        # )
        public_class_method def self.load_profile(opts = {})
          yaml_path = opts[:yaml_path].to_s.scrub.strip
          raise 'ERROR: yaml_path is required' if yaml_path.empty?
          raise "ERROR: profile YAML does not exist: #{yaml_path}" unless File.exist?(yaml_path)

          raw_profile = YAML.safe_load_file(yaml_path, aliases: true) || {}
          symbolize_obj(raw_profile)
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
              report = PWN::Bounty::ScopeIntel::DeltaQueue.run(
                program_name: 'example-program',
                scope_details: scope_details_hash,
                output_dir: '/tmp/scope-intel-delta-queue'
              )

              report = PWN::Bounty::ScopeIntel::DeltaQueue.run(
                old_scope_intel: old_scope_intel,
                new_scope_intel: new_scope_intel,
                output_dir: '/tmp/scope-intel-delta-queue'
              )
          HELP
        end

        private_class_method def self.resolve_scope_intel(opts = {})
          scope_intel = symbolize_obj(opts[:scope_intel] || {})
          return scope_intel unless scope_intel.empty?

          scope_details = opts[:scope_details]
          program_name = opts[:program_name].to_s.scrub.strip
          include_ai_analysis = opts[:include_ai_analysis] == true

          if scope_details.nil? && program_name.empty?
            raise 'ERROR: provide new_scope_intel or scope_details/program_name'
          end

          PWN::Bounty::ScopeIntel.compile(
            scope_details: scope_details,
            program_name: program_name,
            include_ai_analysis: include_ai_analysis,
            proxy: opts[:proxy]
          )
        rescue StandardError => e
          raise e
        end

        private_class_method def self.diff_without_previous(opts = {})
          new_scope_intel = symbolize_obj(opts[:new_scope_intel] || {})
          rows = Array(new_scope_intel[:rows]).map { |entry| symbolize_obj(entry) }

          {
            compared_at: Time.now.utc.iso8601,
            old_count: 0,
            new_count: rows.length,
            added_count: rows.length,
            removed_count: 0,
            changed_count: 0,
            added: rows,
            removed: [],
            changed: []
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_delta_queue(opts = {})
          diff = symbolize_obj(opts[:diff] || {})
          max_queue_entries = opts[:max_queue_entries].to_i
          max_queue_entries = DEFAULT_MAX_QUEUE_ENTRIES if max_queue_entries <= 0
          max_queue_entries = 200 if max_queue_entries > 200

          entries = []

          Array(diff[:added]).map { |row| symbolize_obj(row) }.each do |row|
            queue_entry = queue_entry_for_row(row: row, delta_type: 'added')
            entries << queue_entry unless queue_entry.nil?
          end

          Array(diff[:changed]).map { |row| symbolize_obj(row) }.each do |changed|
            before = symbolize_obj(changed[:before] || {})
            after = symbolize_obj(changed[:after] || {})

            queue_entry = queue_entry_for_changed_row(before: before, after: after)
            entries << queue_entry unless queue_entry.nil?
          end

          ranked = entries.sort_by do |entry|
            [
              -entry[:priority_score].to_i,
              entry[:identifier].to_s,
              entry[:delta_type].to_s
            ]
          end

          ranked.first(max_queue_entries)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.queue_entry_for_changed_row(opts = {})
          before = symbolize_obj(opts[:before] || {})
          after = symbolize_obj(opts[:after] || {})

          changed_reasons = []
          changed_reasons << 'eligible_for_bounty_flipped_true' if before[:eligible_for_bounty] != true && after[:eligible_for_bounty] == true
          changed_reasons << 'staging_marker_new' if before[:requires_staging] != true && after[:requires_staging] == true
          changed_reasons << 'owned_account_marker_new' if before[:requires_owned_account] != true && after[:requires_owned_account] == true
          changed_reasons << 'asset_type_changed' if normalize_token(before[:asset_type]) != normalize_token(after[:asset_type])
          changed_reasons << 'third_party_excluded_now_true' if before[:third_party_excluded] != true && after[:third_party_excluded] == true

          return nil if changed_reasons.empty?

          entry = queue_entry_for_row(row: after, delta_type: 'changed')
          return nil if entry.nil?

          reason_bonus = 0
          reason_bonus += 18 if changed_reasons.include?('eligible_for_bounty_flipped_true')
          reason_bonus += 10 if changed_reasons.include?('staging_marker_new')
          reason_bonus += 6 if changed_reasons.include?('owned_account_marker_new')
          reason_bonus -= 18 if changed_reasons.include?('third_party_excluded_now_true')

          entry[:priority_score] = [[entry[:priority_score] + reason_bonus, 0].max, 100].min
          entry[:priority_tier] = priority_tier(score: entry[:priority_score])
          entry[:reasons] = (Array(entry[:reasons]) + changed_reasons).uniq
          entry[:recommended_playbooks] = (Array(entry[:recommended_playbooks]) + changed_reason_playbooks(changed_reasons: changed_reasons)).uniq

          entry
        rescue StandardError => e
          raise e
        end

        private_class_method def self.queue_entry_for_row(opts = {})
          row = symbolize_obj(opts[:row] || {})
          delta_type = opts[:delta_type].to_s

          identifier = row[:identifier].to_s.scrub.strip
          return nil if identifier.empty?

          score = score_row(row: row, delta_type: delta_type)
          return nil if score <= 0

          burp_seed = burp_seed_from_identifier(identifier: identifier)

          reasons = reasons_for_row(row: row, delta_type: delta_type)
          playbooks = playbooks_for_row(row: row)

          {
            queue_id: Digest::SHA256.hexdigest("#{delta_type}|#{identifier}")[0, 12],
            delta_type: delta_type,
            identifier: identifier,
            display_name: row[:display_name].to_s,
            asset_type: normalize_token(row[:asset_type]),
            priority_score: score,
            priority_tier: priority_tier(score: score),
            eligible_for_bounty: row[:eligible_for_bounty] == true,
            requires_staging: row[:requires_staging] == true,
            requires_owned_account: row[:requires_owned_account] == true,
            third_party_excluded: row[:third_party_excluded] == true,
            signup_mode: row[:signup_mode].to_s,
            acquired_brand: row[:acquired_brand].to_s,
            burp_seed: burp_seed,
            reasons: reasons,
            recommended_playbooks: playbooks,
            notes: row[:notes].to_s
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.score_row(opts = {})
          row = symbolize_obj(opts[:row] || {})
          delta_type = opts[:delta_type].to_s

          score = 20
          score += 16 if delta_type == 'added'
          score += 10 if row[:eligible_for_bounty] == true
          score += 7 if row[:eligible_for_submission] == true
          score += 12 if row[:requires_staging] == true
          score += 8 if row[:requires_owned_account] == true
          score += 6 unless row[:acquired_brand].to_s.scrub.strip.empty?
          score -= 22 if row[:third_party_excluded] == true

          text = [
            row[:identifier],
            row[:display_name],
            row[:instruction],
            row[:notes],
            row[:asset_type]
          ].join(' ').downcase

          score += 12 if text.match?(/admin|administrator|internal/)
          score += 10 if text.match?(/staging|beta|sandbox|test|preprod/)
          score += 8 if text.match?(/api|graphql|rest|endpoint/)
          score += 6 if text.match?(/auth|permission|access|role|account/)

          asset_type = normalize_token(row[:asset_type])
          score += 8 if %w[web api].include?(asset_type)
          score += 4 if asset_type.include?('mobile')

          [[score, 0].max, 100].min
        rescue StandardError => e
          raise e
        end

        private_class_method def self.reasons_for_row(opts = {})
          row = symbolize_obj(opts[:row] || {})
          delta_type = opts[:delta_type].to_s

          reasons = []
          reasons << 'new_scope_entry' if delta_type == 'added'
          reasons << 'bounty_eligible' if row[:eligible_for_bounty] == true
          reasons << 'staging_beta_test_surface' if row[:requires_staging] == true
          reasons << 'owned_account_authz_surface' if row[:requires_owned_account] == true
          reasons << 'acquired_brand_or_rare_surface' unless row[:acquired_brand].to_s.scrub.strip.empty?
          reasons << 'third_party_excluded' if row[:third_party_excluded] == true

          text = [row[:identifier], row[:display_name], row[:instruction], row[:notes]].join(' ').downcase
          reasons << 'admin_surface_hint' if text.match?(/admin|internal/)
          reasons << 'api_surface_hint' if text.match?(/api|graphql|rest/)
          reasons << 'authz_surface_hint' if text.match?(/auth|permission|role|access/)

          reasons.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.playbooks_for_row(opts = {})
          row = symbolize_obj(opts[:row] || {})
          text = [row[:identifier], row[:display_name], row[:instruction], row[:notes]].join(' ').downcase

          playbooks = []
          playbooks << 'sensitive_file_exposure_pack' if text.match?(/staging|beta|admin|backup|config|test/)
          playbooks << 'lifecycle_authz_replay' if text.match?(/auth|permission|role|account|access/)
          playbooks << 'graphql_authz_diff' if text.match?(/graphql|api/)
          playbooks << 'ssrf_chain' if text.match?(/webhook|fetch|url|import|pdf|avatar/)

          playbooks = ['manual_recon'] if playbooks.empty?
          playbooks.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.changed_reason_playbooks(opts = {})
          changed_reasons = Array(opts[:changed_reasons]).map { |entry| normalize_token(entry) }
          playbooks = []
          playbooks << 'lifecycle_authz_replay' if changed_reasons.include?('owned_account_marker_new') || changed_reasons.include?('eligible_for_bounty_flipped_true')
          playbooks << 'sensitive_file_exposure_pack' if changed_reasons.include?('staging_marker_new')
          playbooks << 'manual_scope_validation' if changed_reasons.include?('third_party_excluded_now_true')
          playbooks.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.priority_tier(opts = {})
          score = opts[:score].to_i
          return 'critical' if score >= 86
          return 'high' if score >= 72
          return 'medium' if score >= 56

          'low'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.burp_seed_from_identifier(opts = {})
          identifier = opts[:identifier].to_s.scrub.strip
          return '' if identifier.empty?

          if identifier.start_with?('*.')
            return "https://#{identifier[2..]}"
          end

          if identifier.match?(%r{\Ahttps?://}i)
            begin
              uri = URI.parse(identifier)
              return "#{uri.scheme}://#{uri.host}" unless uri.host.to_s.empty?
            rescue URI::InvalidURIError
              return ''
            end
          end

          if identifier.match?(/\A[a-z0-9.-]+\.[a-z]{2,}\z/i)
            return "https://#{identifier}"
          end

          ''
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolved_snapshot_dir(opts = {})
          snapshot_dir = opts[:snapshot_dir].to_s.scrub.strip
          return snapshot_dir unless snapshot_dir.empty?

          output_dir = opts[:output_dir].to_s.scrub.strip
          return '' if output_dir.empty?

          File.join(output_dir, 'scope_intel_snapshots')
        rescue StandardError => e
          raise e
        end

        private_class_method def self.load_latest_snapshot(opts = {})
          snapshot_dir = opts[:snapshot_dir].to_s.scrub.strip
          program_name = normalize_token(opts[:program_name])

          return { path: '', data: {} } if snapshot_dir.empty?
          return { path: '', data: {} } unless Dir.exist?(snapshot_dir)

          pattern = File.join(snapshot_dir, "#{program_name}-*.json")
          latest_path = Dir.glob(pattern).sort.last
          return { path: '', data: {} } if latest_path.to_s.empty?

          parsed = symbolize_obj(JSON.parse(File.read(latest_path)))
          scope_intel = symbolize_obj(parsed[:scope_intel] || {})

          {
            path: latest_path,
            data: scope_intel
          }
        rescue JSON::ParserError
          { path: '', data: {} }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.save_snapshot(opts = {})
          snapshot_dir = opts[:snapshot_dir].to_s.scrub.strip
          return { path: '' } if snapshot_dir.empty?

          program_name = normalize_token(opts[:program_name])
          scope_intel = symbolize_obj(opts[:scope_intel] || {})
          return { path: '' } if scope_intel.empty?

          FileUtils.mkdir_p(snapshot_dir)

          timestamp = Time.now.utc.strftime('%Y%m%dT%H%M%SZ')
          path = File.join(snapshot_dir, "#{program_name}-#{timestamp}.json")

          payload = {
            saved_at: Time.now.utc.iso8601,
            program_name: opts[:program_name].to_s,
            scope_intel: scope_intel
          }

          File.write(path, JSON.pretty_generate(payload))

          { path: path }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.next_steps(opts = {})
          queue = Array(opts[:queue]).map { |entry| symbolize_obj(entry) }
          return ['No high-value deltas detected. Re-run after next scope refresh or broaden target program set.'] if queue.empty?

          top = queue.first

          [
            "Start with `#{top[:identifier]}` (#{top[:priority_tier]} priority) and capture baseline route map in Burp.",
            'Run recommended playbooks for top-5 entries and preserve per-route evidence hashes for report reuse.',
            'Re-run DeltaQueue after every scope import to keep first-mover queue fresh.'
          ]
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
          lines << '# ScopeIntel Delta Queue'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Program: `#{report[:program_name]}`"
          lines << "- Previous Snapshot: `#{report.dig(:snapshot, :previous_snapshot_path)}`"
          lines << "- Current Snapshot: `#{report.dig(:snapshot, :current_snapshot_path)}`"
          lines << "- Queue Entries: `#{report[:queue_count]}`"
          lines << ''

          lines << '## Diff Summary'
          diff_summary = symbolize_obj(report[:diff_summary] || {})
          lines << "- old_count: `#{diff_summary[:old_count]}`"
          lines << "- new_count: `#{diff_summary[:new_count]}`"
          lines << "- added_count: `#{diff_summary[:added_count]}`"
          lines << "- removed_count: `#{diff_summary[:removed_count]}`"
          lines << "- changed_count: `#{diff_summary[:changed_count]}`"
          lines << ''

          lines << '## Ranked Delta Queue'
          queue = Array(report[:delta_queue]).map { |entry| symbolize_obj(entry) }
          if queue.empty?
            lines << '- No queue entries.'
          else
            queue.each do |entry|
              lines << "- [#{entry[:priority_tier]}|#{entry[:priority_score]}] `#{entry[:identifier]}` (#{entry[:delta_type]})"
              lines << "  - playbooks: `#{Array(entry[:recommended_playbooks]).join(', ')}`"
              lines << "  - reasons: `#{Array(entry[:reasons]).join(', ')}`"
              lines << "  - burp_seed: `#{entry[:burp_seed]}`" unless entry[:burp_seed].to_s.empty?
            end
          end

          lines << ''
          lines << '## Next Steps'
          Array(report[:next_steps]).each do |step|
            lines << "- #{step}"
          end

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, lines.join("\n"))
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_burp_targets(opts = {})
          path = opts[:path].to_s
          report = symbolize_obj(opts[:report] || {})

          seeds = Array(report[:burp_target_seeds]).map(&:to_s).reject(&:empty?).uniq

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, seeds.join("\n"))
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
