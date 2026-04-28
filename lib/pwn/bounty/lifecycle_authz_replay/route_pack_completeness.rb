# frozen_string_literal: true

module PWN
  module Bounty
    module LifecycleAuthzReplay
      # Route-family completeness scoring for warm lifecycle authz windows.
      module RoutePackCompleteness
        DEFAULT_FAMILY_IMPACT = {
          proof: 'report_blocker',
          direct: 'report_blocker',
          secondary: 'confidence_drop',
          artifact: 'nice_to_have',
          export: 'nice_to_have',
          notification: 'nice_to_have'
        }.freeze

        # Supported Method Parameters::
        # completeness = PWN::Bounty::LifecycleAuthzReplay::RoutePackCompleteness.evaluate(
        #   run_obj: run_obj
        # )
        public_class_method def self.evaluate(opts = {})
          run_obj = opts[:run_obj]
          raise 'run_obj is required' unless run_obj.is_a?(Hash)

          plan = symbolize_obj(run_obj[:plan] || {})
          coverage_cells = Array(run_obj.dig(:coverage_matrix, :cells)).map { |cell| symbolize_obj(cell) }

          surface_lookup = build_surface_lookup(surfaces: plan[:surfaces])
          expected_denied_after = Array(plan[:expected_denied_after]).map { |checkpoint| normalize_token(checkpoint) }
          post_checkpoints = expected_denied_after
          actors = Array(plan[:actors]).map { |actor| symbolize_obj(actor) }.map { |actor| actor[:id].to_s }

          family_impacts = resolve_family_impacts(plan: plan)
          family_gaps = evaluate_family_gaps(
            coverage_cells: coverage_cells,
            surface_lookup: surface_lookup,
            post_checkpoints: post_checkpoints,
            actors: actors,
            family_impacts: family_impacts
          )

          contradiction_gaps = detect_contradiction_gaps(
            coverage_cells: coverage_cells,
            surface_lookup: surface_lookup,
            post_checkpoints: post_checkpoints,
            actors: actors
          )

          gap_findings = family_gaps + contradiction_gaps

          completeness_cells = completeness_scope_cells(
            coverage_cells: coverage_cells,
            surface_lookup: surface_lookup,
            post_checkpoints: post_checkpoints,
            family_impacts: family_impacts
          )

          completion_score = calculate_completion_score(cells: completeness_cells)
          checklists = build_checklists(
            coverage_cells: coverage_cells,
            surface_lookup: surface_lookup,
            family_impacts: family_impacts,
            post_checkpoints: post_checkpoints
          )

          {
            generated_at: Time.now.utc.iso8601,
            completion_score: completion_score,
            report_blocker_count: gap_findings.count { |gap| normalize_token(gap[:impact_level]) == 'report_blocker' },
            confidence_drop_count: gap_findings.count { |gap| normalize_token(gap[:impact_level]) == 'confidence_drop' },
            nice_to_have_count: gap_findings.count { |gap| normalize_token(gap[:impact_level]) == 'nice_to_have' },
            gap_findings: gap_findings.sort_by { |gap| [impact_rank(gap[:impact_level]), gap[:route_family].to_s, gap[:reason].to_s] },
            checklists: checklists
          }
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
              completeness = PWN::Bounty::LifecycleAuthzReplay::RoutePackCompleteness.evaluate(
                run_obj: run_obj
              )
          HELP
        end

        private_class_method def self.build_surface_lookup(opts = {})
          surfaces = Array(opts[:surfaces]).map { |surface| symbolize_obj(surface) }

          surfaces.each_with_object({}) do |surface, accum|
            metadata = symbolize_obj(surface[:metadata] || {})
            route_family = normalize_route_family(
              route_family: metadata[:route_family] || metadata[:route_category],
              surface_id: surface[:id],
              surface_label: surface[:label]
            )

            accum[surface[:id].to_s] = {
              id: surface[:id].to_s,
              label: surface[:label].to_s,
              route_family: route_family,
              metadata: metadata
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolve_family_impacts(opts = {})
          plan = symbolize_obj(opts[:plan] || {})
          override = symbolize_obj(plan.dig(:metadata, :route_pack_completeness, :family_impacts) || {})

          default = symbolize_obj(DEFAULT_FAMILY_IMPACT)
          default.merge(override.transform_keys { |key| normalize_token(key).to_sym })
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evaluate_family_gaps(opts = {})
          coverage_cells = Array(opts[:coverage_cells]).map { |cell| symbolize_obj(cell) }
          surface_lookup = symbolize_obj(opts[:surface_lookup] || {})
          post_checkpoints = Array(opts[:post_checkpoints]).map { |checkpoint| normalize_token(checkpoint) }
          actors = Array(opts[:actors]).map { |actor| actor.to_s }
          family_impacts = symbolize_obj(opts[:family_impacts] || {})

          families_present = surface_lookup.values.map { |surface| normalize_route_family(route_family: surface[:route_family]) }.uniq
          return [] if families_present.empty?

          families_present.flat_map do |family|
            impact_level = normalize_token(family_impacts[family.to_sym])
            next [] if impact_level.empty?

            family_cells = coverage_cells.select do |cell|
              checkpoint = normalize_token(cell[:checkpoint])
              surface_meta = surface_lookup_entry(surface_lookup: surface_lookup, surface_id: cell[:surface])
              normalize_route_family(route_family: surface_meta[:route_family]) == family &&
                post_checkpoints.include?(checkpoint)
            end

            next [] if family_cells.empty?

            captured = family_cells.select { |cell| normalize_token(cell[:status]) != 'missing' }
            denied = family_cells.select { |cell| normalize_token(cell[:status]) == 'denied' }

            gaps = []
            if captured.empty?
              gaps << {
                route_family: family,
                impact_level: impact_level,
                reason: 'no_post_change_capture',
                details: 'No post-change cells were captured for this route family.'
              }
            end

            if %w[direct proof].include?(family) && denied.empty?
              gaps << {
                route_family: family,
                impact_level: impact_level,
                reason: 'missing_post_change_deny_proof',
                details: 'No denied proof captured for direct/proof family in expected-denied checkpoints.'
              }
            end

            if family == 'secondary'
              actor_without_secondary = actors.select do |actor|
                actor_cells = family_cells.select { |cell| cell[:actor].to_s == actor }
                actor_cells.none? { |cell| normalize_token(cell[:status]) != 'missing' }
              end

              unless actor_without_secondary.empty?
                gaps << {
                  route_family: family,
                  impact_level: impact_level,
                  reason: 'missing_secondary_retest',
                  details: "Secondary family not re-tested for actors: #{actor_without_secondary.join(', ')}"
                }
              end
            end

            gaps
          end.compact
        rescue StandardError => e
          raise e
        end

        private_class_method def self.detect_contradiction_gaps(opts = {})
          coverage_cells = Array(opts[:coverage_cells]).map { |cell| symbolize_obj(cell) }
          surface_lookup = symbolize_obj(opts[:surface_lookup] || {})
          post_checkpoints = Array(opts[:post_checkpoints]).map { |checkpoint| normalize_token(checkpoint) }
          actors = Array(opts[:actors]).map { |actor| actor.to_s }

          gaps = []
          post_checkpoints.each do |checkpoint|
            actors.each do |actor|
              actor_cells = coverage_cells.select do |cell|
                normalize_token(cell[:checkpoint]) == checkpoint && cell[:actor].to_s == actor
              end

              direct_denied = actor_cells.any? do |cell|
                surface = surface_lookup_entry(surface_lookup: surface_lookup, surface_id: cell[:surface])
                normalize_route_family(route_family: surface[:route_family]) == 'direct' &&
                  normalize_token(cell[:status]) == 'denied'
              end

              secondary_accessible = actor_cells.any? do |cell|
                surface = surface_lookup_entry(surface_lookup: surface_lookup, surface_id: cell[:surface])
                normalize_route_family(route_family: surface[:route_family]) == 'secondary' &&
                  normalize_token(cell[:status]) == 'accessible'
              end

              if secondary_accessible && !direct_denied
                gaps << {
                  route_family: 'contradiction',
                  impact_level: 'report_blocker',
                  reason: 'secondary_visible_without_direct_retest',
                  details: "checkpoint=#{checkpoint} actor=#{actor} has secondary access without direct denied proof"
                }
              end
            end
          end

          gaps
        rescue StandardError => e
          raise e
        end

        private_class_method def self.completeness_scope_cells(opts = {})
          coverage_cells = Array(opts[:coverage_cells]).map { |cell| symbolize_obj(cell) }
          surface_lookup = symbolize_obj(opts[:surface_lookup] || {})
          post_checkpoints = Array(opts[:post_checkpoints]).map { |checkpoint| normalize_token(checkpoint) }
          family_impacts = symbolize_obj(opts[:family_impacts] || {})

          coverage_cells.select do |cell|
            checkpoint = normalize_token(cell[:checkpoint])
            next false unless post_checkpoints.include?(checkpoint)

            surface = surface_lookup_entry(surface_lookup: surface_lookup, surface_id: cell[:surface])
            family = normalize_route_family(route_family: surface[:route_family])
            impact = normalize_token(family_impacts[family.to_sym])
            %w[report_blocker confidence_drop].include?(impact)
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.calculate_completion_score(opts = {})
          cells = Array(opts[:cells]).map { |cell| symbolize_obj(cell) }
          return 100 if cells.empty?

          captured = cells.count { |cell| normalize_token(cell[:status]) != 'missing' }
          ((captured.to_f / cells.length.to_f) * 100.0).round(2)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_checklists(opts = {})
          coverage_cells = Array(opts[:coverage_cells]).map { |cell| symbolize_obj(cell) }
          surface_lookup = symbolize_obj(opts[:surface_lookup] || {})
          family_impacts = symbolize_obj(opts[:family_impacts] || {})
          post_checkpoints = Array(opts[:post_checkpoints]).map { |checkpoint| normalize_token(checkpoint) }

          checklist_items = coverage_cells.filter_map do |cell|
            next unless normalize_token(cell[:status]) == 'missing'

            checkpoint = normalize_token(cell[:checkpoint])
            stage = post_checkpoints.include?(checkpoint) ? 'post_change' : 'pre_change'
            surface = surface_lookup_entry(surface_lookup: surface_lookup, surface_id: cell[:surface])
            family = normalize_route_family(route_family: surface[:route_family])
            impact_level = normalize_token(family_impacts[family.to_sym])
            impact_level = 'nice_to_have' if impact_level.empty?

            {
              checkpoint: cell[:checkpoint],
              actor: cell[:actor],
              surface: cell[:surface],
              route_family: family,
              stage: stage,
              impact_level: impact_level
            }
          end

          {
            pre_change: {
              item_count: checklist_items.count { |item| item[:stage] == 'pre_change' },
              items: checklist_items
                .select { |item| item[:stage] == 'pre_change' }
                .sort_by { |item| [impact_rank(item[:impact_level]), item[:checkpoint], item[:actor], item[:surface]] }
            },
            post_change: {
              item_count: checklist_items.count { |item| item[:stage] == 'post_change' },
              items: checklist_items
                .select { |item| item[:stage] == 'post_change' }
                .sort_by { |item| [impact_rank(item[:impact_level]), item[:checkpoint], item[:actor], item[:surface]] }
            }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.surface_lookup_entry(opts = {})
          surface_lookup = symbolize_obj(opts[:surface_lookup] || {})
          surface_id = opts[:surface_id].to_s

          surface = surface_lookup[surface_id]
          surface = surface_lookup[surface_id.to_sym] if surface.nil?
          symbolize_obj(surface || {})
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_route_family(opts = {})
          route_family = normalize_token(opts[:route_family])
          return route_family unless route_family.empty?

          token_space = [opts[:surface_id], opts[:surface_label]].map { |entry| normalize_token(entry) }.join('_')

          return 'direct' if token_space.include?('settings') || token_space.include?('member') || token_space.include?('collaborator')
          return 'artifact' if token_space.include?('artifact')
          return 'export' if token_space.include?('export') || token_space.include?('download')
          return 'notification' if token_space.include?('notification') || token_space.include?('activity') || token_space.include?('timeline')
          return 'proof' if token_space.include?('proof') || token_space.include?('gate')

          'secondary'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.impact_rank(impact_level)
          case normalize_token(impact_level)
          when 'report_blocker'
            0
          when 'confidence_drop'
            1
          when 'nice_to_have'
            2
          else
            3
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
