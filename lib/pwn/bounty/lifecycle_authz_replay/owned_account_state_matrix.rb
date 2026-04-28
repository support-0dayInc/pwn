# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'uri'
require 'yaml'

module PWN
  module Bounty
    module LifecycleAuthzReplay
      # Builds reusable owned-account lifecycle state matrices so operators can
      # quickly capture before/after authz contradictions with controls.
      module OwnedAccountStateMatrix
        DEFAULT_CHECKPOINT_OFFSETS_MINUTES = [0, 10, 30].freeze

        # Supported Method Parameters::
        # report = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.run(
        #   yaml_path: '/path/to/lifecycle_authz_replay.owned_account_state_matrix.example.yaml'
        # )
        public_class_method def self.run(opts = {})
          profile = resolve_profile(opts: opts)
          report = analyze_profile(profile: profile)

          output_dir = profile[:output_dir]
          return report if output_dir.empty?

          run_root = File.expand_path(File.join(output_dir, report[:run_id]))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'owned_account_state_matrix.json'), obj: report)
          write_json(path: File.join(run_root, 'owned_account_state_matrix_transition_plan.json'), obj: report[:transition_plan])
          write_markdown(path: File.join(run_root, 'owned_account_state_matrix.md'), report: report)

          report[:run_root] = run_root
          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.analyze(
        #   actors: [...],
        #   route_seeds: [...]
        # )
        public_class_method def self.analyze(opts = {})
          profile = resolve_profile(opts: opts)
          analyze_profile(profile: profile)
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # profile = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.load_profile(
        #   yaml_path: '/path/to/profile.yaml'
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
              report = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.run(
                yaml_path: '/path/to/lifecycle_authz_replay.owned_account_state_matrix.example.yaml',
                output_dir: '/tmp/owned-account-state-matrix'
              )

              report = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.analyze(
                base_url: 'https://target.example',
                actors: [
                  { id: 'revoked_member', role: 'subject' },
                  { id: 'control_user', role: 'control' }
                ],
                route_seeds: [
                  { route: '/api/v1/reports/generate', route_family: 'direct' },
                  { route: '/exports/reports/download', route_family: 'artifact' }
                ]
              )
          HELP
        end

        private_class_method def self.resolve_profile(opts = {})
          input_hash = symbolize_obj(opts[:opts] || {})

          profile = if input_hash[:yaml_path].to_s.scrub.strip.empty?
                      input_hash
                    else
                      loaded = load_profile(yaml_path: input_hash[:yaml_path])
                      loaded.merge(input_hash.reject { |key, _value| key == :yaml_path })
                    end

          {
            run_id: normalized_run_id(profile: profile),
            target: profile[:target].to_s.scrub.strip,
            base_url: profile[:base_url].to_s.scrub.strip,
            output_dir: profile[:output_dir].to_s.scrub.strip,
            transition: normalize_transition(profile: profile),
            checkpoint_offsets_minutes: normalize_checkpoint_offsets(offsets: profile[:checkpoint_offsets_minutes]),
            actors: normalize_actors(actors: profile[:actors]),
            boundary_event: normalize_boundary_event(boundary_event: profile[:boundary_event]),
            route_seeds: normalize_route_seeds(profile: profile)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_run_id(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          run_id = profile[:run_id].to_s.scrub.strip
          run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-owned-account-state-matrix" if run_id.empty?
          run_id
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_transition(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          transition = normalize_token(profile[:transition])
          transition = normalize_token(profile.dig(:boundary_event, :type)) if transition.empty?
          transition = 'revoke' if transition.empty?
          transition
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_checkpoint_offsets(opts = {})
          offsets = Array(opts[:offsets]).map(&:to_i)
          offsets = DEFAULT_CHECKPOINT_OFFSETS_MINUTES if offsets.empty?
          offsets = offsets.uniq.sort
          offsets = [0] if offsets.empty?
          offsets
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_actors(opts = {})
          actors = Array(opts[:actors]).map { |entry| symbolize_obj(entry || {}) }

          actors = [
            { id: 'subject_user', label: 'Subject User', role: 'subject' },
            { id: 'control_user', label: 'Control User', role: 'control' }
          ] if actors.empty?

          actors.each_with_index.map do |actor, index|
            actor_id = normalize_token(actor[:id])
            actor_id = normalize_token(actor[:name]) if actor_id.empty?
            actor_id = "actor_#{index + 1}" if actor_id.empty?

            role = normalize_token(actor[:role])
            role = 'subject' if role.empty? && index.zero?
            role = 'control' if role.empty?
            role = 'control' unless %w[subject control primary].include?(role)

            {
              id: actor_id,
              label: actor[:label].to_s.scrub.strip.empty? ? actor_id : actor[:label].to_s.scrub.strip,
              role: role,
              account_ref: actor[:account_ref].to_s.scrub.strip
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_boundary_event(opts = {})
          event = symbolize_obj(opts[:boundary_event] || {})

          {
            type: normalize_token(event[:type]).empty? ? 'membership_revoke' : normalize_token(event[:type]),
            object_ref: event[:object_ref].to_s.scrub.strip,
            actor_ref: event[:actor_ref].to_s.scrub.strip,
            notes: event[:notes].to_s.scrub.strip
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_route_seeds(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          seeds = Array(profile[:route_seeds]).map { |entry| symbolize_obj(entry || {}) }

          derived_atlas = symbolize_obj(profile[:derived_artifact_surface_atlas] || {})
          seeds.concat(seeds_from_derived_atlas(derived_atlas: derived_atlas))

          if seeds.empty?
            seeds = [
              { route: '/api/v1/members/revoke', route_family: 'direct', object_family: 'member' },
              { route: '/exports/members/download', route_family: 'artifact', object_family: 'member' }
            ]
          end

          seeds.map do |seed|
            route = normalize_route(route: seed[:route] || seed[:identifier])
            next nil if route.empty?

            route_family = normalize_token(seed[:route_family])
            route_family = infer_route_family(route: route) if route_family.empty?
            route_family = 'secondary' unless %w[direct secondary artifact export notification].include?(route_family)

            object_family = normalize_token(seed[:object_family])
            object_family = infer_object_family(route: route) if object_family.empty?

            {
              route: route,
              route_family: route_family,
              object_family: object_family,
              label: seed[:label].to_s.scrub.strip,
              method: seed[:method].to_s.scrub.strip.upcase,
              absolute_url: seed[:absolute_url].to_s.scrub.strip,
              checkpoint_hint: normalize_token(seed[:checkpoint_hint])
            }
          end.compact.uniq { |seed| [seed[:route], seed[:route_family]] }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.seeds_from_derived_atlas(opts = {})
          derived_atlas = symbolize_obj(opts[:derived_atlas] || {})
          chains = Array(derived_atlas[:chains]).map { |entry| symbolize_obj(entry) }

          chains.flat_map do |chain|
            object_family = normalize_token(chain[:object_family])
            seeds = []

            Array(chain[:generate_routes]).each do |route|
              seeds << {
                route: route,
                route_family: 'direct',
                object_family: object_family,
                checkpoint_hint: chain[:checkpoint_hint]
              }
            end

            Array(chain[:status_routes]).each do |route|
              seeds << {
                route: route,
                route_family: 'secondary',
                object_family: object_family,
                checkpoint_hint: chain[:checkpoint_hint]
              }
            end

            Array(chain[:download_routes]).each do |route|
              seeds << {
                route: route,
                route_family: 'artifact',
                object_family: object_family,
                checkpoint_hint: chain[:checkpoint_hint]
              }
            end

            seeds
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.analyze_profile(opts = {})
          profile = symbolize_obj(opts[:profile] || {})

          checkpoints = build_checkpoints(offsets: profile[:checkpoint_offsets_minutes])
          surfaces = build_surfaces(route_seeds: profile[:route_seeds], base_url: profile[:base_url])
          cells = build_state_cells(
            checkpoints: checkpoints,
            actors: profile[:actors],
            surfaces: surfaces
          )

          transition_plan = build_transition_plan(
            profile: profile,
            checkpoints: checkpoints,
            surfaces: surfaces
          )

          {
            generated_at: Time.now.utc.iso8601,
            run_id: profile[:run_id],
            target: profile[:target],
            transition: profile[:transition],
            boundary_event: profile[:boundary_event],
            actor_count: profile[:actors].length,
            surface_count: surfaces.length,
            checkpoint_count: checkpoints.length,
            matrix_cell_count: cells.length,
            matrix: {
              checkpoints: checkpoints,
              actors: profile[:actors],
              surfaces: surfaces,
              cells: cells
            },
            transition_plan: transition_plan,
            artifact_access_drift_matrix_starter: artifact_access_drift_matrix_starter(
              surfaces: surfaces,
              checkpoints: checkpoints,
              profile: profile
            ),
            cross_surface_object_lineage_starter: cross_surface_object_lineage_starter(surfaces: surfaces, profile: profile),
            submission_bundle_starter: submission_bundle_starter(cells: cells, profile: profile)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_checkpoints(opts = {})
          offsets = Array(opts[:offsets]).map(&:to_i)
          timeline = PWN::Bounty::LifecycleAuthzReplay.transition_timeline(
            transition: 'revoke',
            checkpoint_offsets_minutes: offsets
          )

          Array(timeline[:timeline]).map do |entry|
            {
              checkpoint: entry[:checkpoint],
              phase: entry[:phase],
              offset_minutes: entry[:offset_minutes],
              expected_status: entry[:expected_status]
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_surfaces(opts = {})
          route_seeds = Array(opts[:route_seeds]).map { |entry| symbolize_obj(entry) }
          base_url = opts[:base_url].to_s.scrub.strip

          route_seeds.each_with_index.map do |seed, index|
            route = seed[:route].to_s
            route_family = seed[:route_family].to_s
            object_family = seed[:object_family].to_s
            method = seed[:method].to_s
            method = 'GET' if method.empty?

            surface_id = normalize_token("#{object_family}_#{route_family}_#{index + 1}")
            surface_id = "surface_#{index + 1}" if surface_id.empty?

            absolute_url = seed[:absolute_url].to_s
            absolute_url = absolutize_route(route: route, base_url: base_url) if absolute_url.empty?

            {
              id: surface_id,
              label: seed[:label].to_s.scrub.strip.empty? ? route : seed[:label].to_s.scrub.strip,
              route: route,
              route_family: route_family,
              object_family: object_family,
              metadata: {
                route_category: route_family == 'direct' ? 'direct' : 'secondary',
                route_family: route_family,
                object_family: object_family,
                owned_account_state_matrix: {
                  checkpoint_hint: seed[:checkpoint_hint],
                  object_family: object_family
                },
                adapter: {
                  type: 'http',
                  request: {
                    method: method,
                    url: absolute_url
                  }
                }
              }
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_state_cells(opts = {})
          checkpoints = Array(opts[:checkpoints]).map { |entry| symbolize_obj(entry) }
          actors = Array(opts[:actors]).map { |entry| symbolize_obj(entry) }
          surfaces = Array(opts[:surfaces]).map { |entry| symbolize_obj(entry) }

          checkpoints.flat_map do |checkpoint|
            actors.flat_map do |actor|
              surfaces.map do |surface|
                expected_status = expected_status_for_cell(
                  checkpoint: checkpoint,
                  actor: actor,
                  surface: surface
                )

                {
                  checkpoint: checkpoint[:checkpoint],
                  actor: actor[:id],
                  actor_role: actor[:role],
                  surface: surface[:id],
                  route: surface[:route],
                  route_family: surface[:route_family],
                  object_family: surface[:object_family],
                  expected_status: expected_status,
                  control_type: actor[:role] == 'control' ? 'negative_control' : 'primary_flow'
                }
              end
            end
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.expected_status_for_cell(opts = {})
          checkpoint = symbolize_obj(opts[:checkpoint] || {})
          actor = symbolize_obj(opts[:actor] || {})
          surface = symbolize_obj(opts[:surface] || {})

          phase = checkpoint[:phase].to_s
          actor_role = actor[:role].to_s
          route_family = surface[:route_family].to_s

          return 'denied' if actor_role == 'control'
          return 'accessible' if actor_role == 'primary'
          return 'accessible' if phase == 'pre'

          return 'denied' if route_family == 'direct'
          'monitor_for_survival'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_transition_plan(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          checkpoints = Array(opts[:checkpoints]).map { |entry| symbolize_obj(entry) }
          surfaces = Array(opts[:surfaces]).map { |entry| symbolize_obj(entry) }

          actors_for_plan = Array(profile[:actors]).map { |entry| symbolize_obj(entry) }

          plan = {
            campaign: {
              id: normalize_token("owned_account_#{profile[:transition]}"),
              label: 'Owned Account State Matrix Replay',
              target: profile[:target],
              change_event: profile[:transition],
              notes: profile.dig(:boundary_event, :notes).to_s
            },
            actors: actors_for_plan.map { |actor| { id: actor[:id], label: actor[:label], metadata: { role: actor[:role], account_ref: actor[:account_ref] } } },
            surfaces: surfaces.map { |surface| { id: surface[:id], label: surface[:label], metadata: surface[:metadata] } },
            checkpoints: checkpoints.map { |entry| entry[:checkpoint] },
            expected_denied_after: checkpoints.map { |entry| entry[:checkpoint] }.reject { |checkpoint| checkpoint == 'pre_change' },
            metadata: {
              owned_account_state_matrix: {
                boundary_event: profile[:boundary_event],
                transition: profile[:transition],
                route_seed_count: surfaces.length,
                generated_at: Time.now.utc.iso8601
              }
            }
          }

          PWN::Bounty::LifecycleAuthzReplay.normalize_plan(plan: plan)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.artifact_access_drift_matrix_starter(opts = {})
          surfaces = Array(opts[:surfaces]).map { |entry| symbolize_obj(entry) }
          checkpoints = Array(opts[:checkpoints]).map { |entry| symbolize_obj(entry) }
          profile = symbolize_obj(opts[:profile] || {})

          {
            expected_denied_after: checkpoints.map { |entry| entry[:checkpoint] }.reject { |checkpoint| checkpoint == 'pre_change' },
            object_families: surfaces.map { |surface| surface[:object_family] }.reject(&:empty?).uniq,
            direct_surface_ids: surfaces.select { |surface| surface[:route_family] == 'direct' }.map { |surface| surface[:id] },
            derived_surface_ids: surfaces.select { |surface| %w[artifact export notification].include?(surface[:route_family]) }.map { |surface| surface[:id] },
            boundary_event: profile[:boundary_event],
            recommended_module: 'PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix'
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.cross_surface_object_lineage_starter(opts = {})
          surfaces = Array(opts[:surfaces]).map { |entry| symbolize_obj(entry) }
          profile = symbolize_obj(opts[:profile] || {})

          {
            object_seeds: surfaces.map do |surface|
              {
                family_key: surface[:object_family],
                refs: [surface[:route]],
                aliases: [surface[:id]]
              }
            end,
            route_pairs: surfaces.group_by { |surface| surface[:object_family] }.map do |family, family_surfaces|
              {
                object_family: family,
                direct_routes: family_surfaces.select { |surface| surface[:route_family] == 'direct' }.map { |surface| surface[:route] },
                alternate_routes: family_surfaces.reject { |surface| surface[:route_family] == 'direct' }.map { |surface| surface[:route] }
              }
            end,
            boundary_event: profile[:boundary_event],
            recommended_module: 'PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage'
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.submission_bundle_starter(opts = {})
          cells = Array(opts[:cells]).map { |entry| symbolize_obj(entry) }
          profile = symbolize_obj(opts[:profile] || {})

          {
            contradiction_cells: cells.select do |cell|
              cell[:expected_status] == 'monitor_for_survival' || cell[:expected_status] == 'denied'
            end.map do |cell|
              {
                checkpoint: cell[:checkpoint],
                actor: cell[:actor],
                route: cell[:route],
                route_family: cell[:route_family],
                expected_status: cell[:expected_status]
              }
            end,
            boundary_event: profile[:boundary_event],
            recommended_module: 'PWN::Bounty::LifecycleAuthzReplay::SubmissionBundle'
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_route(opts = {})
          route = opts[:route].to_s.scrub.strip
          return '' if route.empty?

          if route.match?(%r{\Ahttps?://}i)
            begin
              uri = URI.parse(route)
              route = uri.path.to_s
            rescue URI::InvalidURIError
              route = ''
            end
          end

          route = "/#{route}" unless route.start_with?('/')
          route = route.gsub(%r{//+}, '/')
          route = route.sub(/\?.*\z/, '')
          route = route.sub(/#.*\z/, '')
          route = route.chomp('/') unless route == '/'
          route
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_route_family(opts = {})
          route = opts[:route].to_s.downcase

          return 'artifact' if route.match?(/download|artifact|attachment|export|archive|report|pdf|csv|zip/)
          return 'secondary' if route.match?(/status|poll|timeline|activity|notification/)

          'direct'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_object_family(opts = {})
          route = normalize_route(route: opts[:route])
          segments = route.split('/').reject(&:empty?)
          token = segments.reverse.find do |segment|
            normalized = normalize_token(segment)
            !normalized.empty? && normalized.length > 2 &&
              !%w[api v1 v2 v3 admin internal members member download export report reports status poll generate create revoke invite accept role roles].include?(normalized)
          end

          normalize_token(token)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.absolutize_route(opts = {})
          route = normalize_route(route: opts[:route])
          base_url = opts[:base_url].to_s.scrub.strip

          return route if base_url.empty?
          return route unless base_url.match?(%r{\Ahttps?://}i)

          "#{base_url.chomp('/')}#{route}"
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
            value = input.to_s.scrub.strip
            return [] if value.empty?

            if File.exist?(value)
              content = File.read(value)
              parsed = parse_json_if_possible(data: content)
              return resolve_structured_input(input: parsed) unless parsed.nil?

              return [content]
            end

            parsed_inline = parse_json_if_possible(data: value)
            return resolve_structured_input(input: parsed_inline) unless parsed_inline.nil?

            [value]
          else
            [symbolize_obj(input)]
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_json_if_possible(opts = {})
          data = opts[:data].to_s.scrub.strip
          return nil if data.empty?

          JSON.parse(data)
        rescue JSON::ParserError
          nil
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
          lines << '# Lifecycle Authz Replay — Owned Account State Matrix'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Run ID: `#{report[:run_id]}`"
          lines << "- Transition: `#{report[:transition]}`"
          lines << "- Matrix Cells: `#{report[:matrix_cell_count]}`"
          lines << ''

          lines << '## Surfaces'
          Array(report.dig(:matrix, :surfaces)).each do |surface|
            surface_hash = symbolize_obj(surface)
            lines << "- `#{surface_hash[:id]}` route=`#{surface_hash[:route]}` route_family=`#{surface_hash[:route_family]}` object_family=`#{surface_hash[:object_family]}`"
          end

          lines << ''
          lines << '## State Matrix (expected)'
          lines << '| Checkpoint | Actor | Actor Role | Surface | Route Family | Expected Status |'
          lines << '| --- | --- | --- | --- | --- | --- |'
          Array(report.dig(:matrix, :cells)).each do |cell|
            cell_hash = symbolize_obj(cell)
            lines << "| #{cell_hash[:checkpoint]} | #{cell_hash[:actor]} | #{cell_hash[:actor_role]} | #{cell_hash[:surface]} | #{cell_hash[:route_family]} | #{cell_hash[:expected_status]} |"
          end

          lines << ''
          lines << '## Starters'
          lines << "- ArtifactAccessDriftMatrix direct surfaces: `#{Array(report.dig(:artifact_access_drift_matrix_starter, :direct_surface_ids)).join(', ')}`"
          lines << "- ArtifactAccessDriftMatrix derived surfaces: `#{Array(report.dig(:artifact_access_drift_matrix_starter, :derived_surface_ids)).join(', ')}`"
          lines << "- Cross-surface object seeds: `#{Array(report.dig(:cross_surface_object_lineage_starter, :object_seeds)).length}`"
          lines << "- Submission contradiction cells: `#{Array(report.dig(:submission_bundle_starter, :contradiction_cells)).length}`"

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
