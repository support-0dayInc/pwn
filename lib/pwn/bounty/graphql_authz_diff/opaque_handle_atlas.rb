# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Bounty
    module GraphQLAuthzDiff
      # Builds object-handle families across GraphQL + REST/UI evidence to
      # accelerate cross-surface authz contradiction replay.
      module OpaqueHandleAtlas
        DIRECT_ROUTE_HINTS = %w[direct canonical baseline primary gate].freeze
        HANDLE_KEY_HINTS = %w[
          id
          node_id
          nodeid
          databaseid
          database_id
          global_id
          object_id
          objectid
          migration_id
          upload_id
          attachment_id
          export_id
          slug
          full_name
          url
          html_url
          path
          key
          handle
        ].freeze

        URL_OBJECT_PATTERNS = [
          %r{/(?:issues?|pulls?|merge_requests?|migrations?|uploads?|attachments?|artifacts?|exports?|comments?|repos?|projects?)/([^/?#]+)}i,
          %r{/([a-z0-9_.-]+/[a-z0-9_.-]+)(?:/|\?|#|$)}i
        ].freeze

        # Supported Method Parameters::
        # atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.analyze(
        #   diff_report: '/tmp/graphql_authz_diff.json',
        #   surface_evidence: '/tmp/surface_evidence.json',
        #   object_seeds: '/tmp/object_seeds.json'
        # )
        public_class_method def self.analyze(opts = {})
          diff_report = resolve_structured_input(input: opts[:diff_report]).first || {}
          diff_report = symbolize_obj(diff_report)

          matrix = Array(diff_report[:matrix]).map { |row| symbolize_obj(row) }
          surface_evidence = resolve_structured_input(input: opts[:surface_evidence])
          object_seeds = resolve_structured_input(input: opts[:object_seeds])

          evidence_route_map = surface_evidence.each_with_object({}) do |entry, accum|
            entry_hash = symbolize_obj(entry)
            key = normalize_token(entry_hash[:surface] || entry_hash[:operation_id] || entry_hash[:operation_name])
            next if key.empty?

            accum[key] = normalize_route_family(route_family: entry_hash[:route_family])
          end

          observations = []
          observations.concat(extract_graphql_observations(matrix: matrix, evidence_route_map: evidence_route_map))
          observations.concat(extract_surface_observations(surface_evidence: surface_evidence))

          seed_lookup = build_seed_lookup(object_seeds: object_seeds)
          families = cluster_families(observations: observations, seed_lookup: seed_lookup)

          ranked_families = families.map do |family_key, family_observations|
            build_family_result(family_key: family_key, observations: family_observations)
          end
          ranked_families.sort_by! { |family| [-family_rank(report_angle: family[:report_angle]), family[:family_key]] }

          best_candidate = ranked_families.find do |family|
            normalize_token(family[:report_angle]) == 'direct_denied_alternate_accessible'
          end
          best_candidate ||= ranked_families.first

          seed_suggestions = ranked_families.map do |family|
            {
              family_key: family[:family_key],
              aliases: Array(family[:surviving_routes]).uniq,
              refs: Array(family[:refs]).first(20)
            }
          end

          {
            generated_at: Time.now.utc.iso8601,
            run_id: diff_report[:run_id],
            observation_count: observations.length,
            family_count: ranked_families.length,
            reportable_candidate_count: ranked_families.count { |family| normalize_token(family[:report_angle]) == 'direct_denied_alternate_accessible' },
            best_candidate: best_candidate,
            seed_suggestions: seed_suggestions,
            families: ranked_families,
            summary: summarize_families(families: ranked_families)
          }
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.run(
        #   diff_report: '/tmp/graphql_authz_diff.json',
        #   output_dir: '/tmp/graphql-authz-diff'
        # )
        public_class_method def self.run(opts = {})
          atlas = analyze(
            diff_report: opts[:diff_report],
            surface_evidence: opts[:surface_evidence],
            object_seeds: opts[:object_seeds]
          )

          output_dir = opts[:output_dir].to_s.scrub.strip
          return atlas if output_dir.empty?

          write_bundle(output_dir: output_dir, atlas: atlas)
          atlas
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
              atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.analyze(
                diff_report: '/tmp/graphql_authz_diff.json',
                surface_evidence: '/tmp/surface_evidence.json',
                object_seeds: '/tmp/object_seeds.json'
              )

              atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.run(
                diff_report: '/tmp/graphql_authz_diff.json',
                output_dir: '/tmp/graphql-authz-diff'
              )
          HELP
        end

        private_class_method def self.extract_graphql_observations(opts = {})
          matrix = Array(opts[:matrix]).map { |row| symbolize_obj(row) }
          evidence_route_map = opts[:evidence_route_map].is_a?(Hash) ? opts[:evidence_route_map] : {}

          matrix.flat_map do |row|
            row_hash = symbolize_obj(row)
            checkpoint = normalize_token(row_hash[:checkpoint])
            surface = normalize_token(row_hash[:operation_id])
            surface_label = row_hash[:operation_name].to_s
            route_family = evidence_route_map[surface] || evidence_route_map[surface.to_sym]
            route_family = infer_route_family(surface_id: surface, surface_label: surface_label) if route_family.to_s.empty?

            Array(row_hash[:actor_results]).filter_map do |actor_result|
              actor_hash = symbolize_obj(actor_result)
              actor = normalize_token(actor_hash[:actor])
              status = normalize_token(actor_hash[:status])
              evidence_path = actor_hash[:evidence_path].to_s
              expected_access = actor_hash[:expected_access]

              next if actor.empty?
              next if expected_access.nil?

              evidence = parse_evidence_file(evidence_path: evidence_path)
              refs = extract_refs_from_entry(
                entry: {
                  operation_id: surface,
                  operation_name: surface_label,
                  evidence: evidence
                }
              )
              refs << normalize_ref(ref: surface) if refs.empty?

              {
                source: 'graphql_authz_diff',
                checkpoint: checkpoint,
                actor: actor,
                surface: surface,
                surface_label: surface_label,
                route_family: route_family,
                status: status,
                accessible: status == 'accessible',
                refs: refs.uniq,
                evidence_path: evidence_path
              }
            end
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_surface_observations(opts = {})
          surface_evidence = Array(opts[:surface_evidence]).map { |entry| symbolize_obj(entry) }

          surface_evidence.filter_map do |entry|
            status = normalize_token(entry[:status])
            status = 'accessible' if entry[:accessible] == true
            status = 'denied' if entry[:denied] == true
            status = 'unknown' if status.empty?

            surface = normalize_token(entry[:surface] || entry[:operation_id] || entry[:route])
            surface_label = entry[:surface_label].to_s
            route_family = normalize_route_family(route_family: entry[:route_family])
            route_family = infer_route_family(surface_id: surface, surface_label: surface_label) if route_family.empty?

            refs = extract_refs_from_entry(entry: entry)
            next if refs.empty? && status == 'unknown'

            {
              source: 'surface_evidence',
              checkpoint: normalize_token(entry[:checkpoint]),
              actor: normalize_token(entry[:actor]),
              surface: surface,
              surface_label: surface_label,
              route_family: route_family,
              status: status,
              accessible: status == 'accessible',
              refs: refs,
              evidence_path: entry[:evidence_path].to_s
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_refs_from_entry(opts = {})
          entry = symbolize_obj(opts[:entry] || {})
          refs = []

          refs.concat(Array(entry[:object_refs]))
          refs.concat(Array(entry[:refs]))

          HANDLE_KEY_HINTS.each do |key|
            refs << entry[key.to_sym] if entry.key?(key.to_sym)
            refs << entry[key] if entry.key?(key)
          end

          refs << entry[:operation_id]
          refs << entry[:operation_name]
          refs << entry[:surface]
          refs << entry[:route]

          evidence = symbolize_obj(entry[:evidence] || parse_evidence_file(evidence_path: entry[:evidence_path]))
          refs.concat(collect_refs_from_obj(obj: evidence))

          refs.concat(extract_refs_from_text(text: entry.to_json))
          refs.concat(extract_refs_from_text(text: evidence.to_json)) unless evidence.empty?

          refs.map { |ref| normalize_ref(ref: ref) }.reject(&:empty?).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.collect_refs_from_obj(opts = {})
          obj = opts[:obj]

          case obj
          when Hash
            refs = []
            obj.each do |key, value|
              normalized_key = normalize_token(key)
              refs << value if HANDLE_KEY_HINTS.include?(normalized_key)
              refs.concat(collect_refs_from_obj(obj: value))
            end
            refs
          when Array
            obj.flat_map { |entry| collect_refs_from_obj(obj: entry) }
          else
            []
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_refs_from_text(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          refs = []

          # GraphQL global ids (gid:// style)
          refs.concat(text.scan(%r{gid://[A-Za-z0-9_./-]+}).flatten)

          # base64-like node ids (keep conservative length)
          refs.concat(text.scan(/\b[A-Za-z0-9+\/=]{16,}\b/).flatten.select do |token|
            token.match?(/[A-Z]/) && token.match?(/[a-z]/) && token.match?(/[0-9]/)
          end)

          URL_OBJECT_PATTERNS.each do |pattern|
            refs.concat(text.scan(pattern).flatten)
          end

          refs
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_seed_lookup(opts = {})
          object_seeds = Array(opts[:object_seeds]).map { |seed| symbolize_obj(seed) }

          object_seeds.each_with_object({}) do |seed, accum|
            family_key = normalize_ref(ref: seed[:family_key] || seed[:id] || seed[:node_id] || seed[:slug] || seed[:url])
            next if family_key.empty?

            refs = []
            refs << seed[:id]
            refs << seed[:node_id]
            refs << seed[:database_id]
            refs << seed[:slug]
            refs << seed[:url]
            refs.concat(Array(seed[:aliases]))
            refs.concat(Array(seed[:refs]))

            refs.each do |ref|
              normalized = normalize_ref(ref: ref)
              next if normalized.empty?

              accum[normalized] = family_key
            end
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.cluster_families(opts = {})
          observations = Array(opts[:observations]).map { |entry| symbolize_obj(entry) }
          seed_lookup = opts[:seed_lookup].is_a?(Hash) ? opts[:seed_lookup] : {}

          observations.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |observation, accum|
            refs = Array(observation[:refs]).map { |ref| normalize_ref(ref: ref) }.reject(&:empty?)
            family_keys = refs.map do |ref|
              seed_lookup[ref] || seed_lookup[ref.to_sym]
            end.compact.uniq
            family_keys = [family_key_from_refs(refs: refs)] if family_keys.empty?

            family_keys.each do |family_key|
              accum[family_key] << observation
            end
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.family_key_from_refs(opts = {})
          refs = Array(opts[:refs]).map { |ref| normalize_ref(ref: ref) }.reject(&:empty?)
          return 'family_unknown' if refs.empty?

          refs.sort_by do |ref|
            [ref_priority(ref: ref), ref.length, ref]
          end.first
        rescue StandardError => e
          raise e
        end

        private_class_method def self.ref_priority(opts = {})
          ref = opts[:ref].to_s
          return 0 if ref.start_with?('gid://')
          return 1 if ref.match?(%r{^[a-z0-9_.-]+/[a-z0-9_.-]+$})
          return 2 if ref.match?(/^object_[a-z0-9_.-]+$/)
          return 3 if ref.match?(/^[0-9]{2,}$/)

          4
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_family_result(opts = {})
          family_key = opts[:family_key].to_s
          observations = Array(opts[:observations]).map { |entry| symbolize_obj(entry) }

          direct_denied = observations.any? do |entry|
            normalize_route_family(route_family: entry[:route_family]) == 'direct' && normalize_token(entry[:status]) == 'denied'
          end

          alternate_accessible_routes = observations.select do |entry|
            normalize_route_family(route_family: entry[:route_family]) != 'direct' && normalize_token(entry[:status]) == 'accessible'
          end.map { |entry| entry[:surface] }.uniq

          report_angle = if direct_denied && !alternate_accessible_routes.empty?
                           'direct_denied_alternate_accessible'
                         elsif !alternate_accessible_routes.empty?
                           'alternate_access_without_direct_denial'
                         elsif direct_denied
                           'direct_denied_only'
                         else
                           'inconclusive'
                         end

          {
            family_key: family_key,
            observation_count: observations.length,
            direct_denied: direct_denied,
            alternate_accessible: !alternate_accessible_routes.empty?,
            surviving_routes: alternate_accessible_routes,
            refs: observations.flat_map { |entry| Array(entry[:refs]) }.uniq,
            report_angle: report_angle,
            best_next_capture: best_next_capture(report_angle: report_angle),
            observations: observations.map do |entry|
              {
                source: entry[:source],
                checkpoint: entry[:checkpoint],
                actor: entry[:actor],
                surface: entry[:surface],
                route_family: normalize_route_family(route_family: entry[:route_family]),
                status: entry[:status],
                evidence_path: entry[:evidence_path]
              }
            end
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.best_next_capture(opts = {})
          case normalize_token(opts[:report_angle])
          when 'direct_denied_alternate_accessible'
            'Replay one adjacent direct-denied checkpoint and preserve matching alternate-route evidence hash for the same family.'
          when 'alternate_access_without_direct_denial'
            'Capture direct/canonical route denial for the same family and actor to complete contradiction proof.'
          when 'direct_denied_only'
            'Probe at least one non-canonical route (REST/UI/export/attachment/upload) for this family.'
          else
            'Collect additional family-linked observations across at least two route families.'
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_families(opts = {})
          families = Array(opts[:families]).map { |entry| symbolize_obj(entry) }

          {
            direct_denied_alternate_accessible: families.count { |family| normalize_token(family[:report_angle]) == 'direct_denied_alternate_accessible' },
            alternate_access_without_direct_denial: families.count { |family| normalize_token(family[:report_angle]) == 'alternate_access_without_direct_denial' },
            direct_denied_only: families.count { |family| normalize_token(family[:report_angle]) == 'direct_denied_only' },
            inconclusive: families.count { |family| normalize_token(family[:report_angle]) == 'inconclusive' }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.family_rank(opts = {})
          case normalize_token(opts[:report_angle])
          when 'direct_denied_alternate_accessible'
            4
          when 'alternate_access_without_direct_denial'
            3
          when 'direct_denied_only'
            2
          else
            1
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_route_family(opts = {})
          surface_id = opts[:surface_id].to_s
          surface_label = opts[:surface_label].to_s
          token_space = [surface_id, surface_label].map { |entry| normalize_token(entry) }.join('_')

          DIRECT_ROUTE_HINTS.each do |hint|
            return 'direct' if token_space.include?(normalize_token(hint))
          end

          'alternate'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_route_family(opts = {})
          route_family = normalize_token(opts[:route_family])
          return 'direct' if route_family == 'direct'
          return 'alternate' if route_family.empty?

          route_family
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_bundle(opts = {})
          output_dir = opts[:output_dir].to_s.scrub.strip
          atlas = symbolize_obj(opts[:atlas] || {})
          FileUtils.mkdir_p(output_dir)

          json_path = File.join(output_dir, 'opaque_handle_atlas.json')
          markdown_path = File.join(output_dir, 'opaque_handle_atlas.md')

          File.write(json_path, JSON.pretty_generate(atlas))
          File.write(markdown_path, build_markdown(atlas: atlas))

          {
            json_path: json_path,
            markdown_path: markdown_path
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_markdown(opts = {})
          atlas = symbolize_obj(opts[:atlas] || {})

          lines = []
          lines << '# GraphQL Opaque Handle Atlas'
          lines << ''
          lines << "- Generated At (UTC): `#{atlas[:generated_at]}`"
          lines << "- Run ID: `#{atlas[:run_id]}`"
          lines << "- Families: `#{atlas[:family_count]}`"
          lines << "- Reportable Candidates: `#{atlas[:reportable_candidate_count]}`"
          lines << ''

          best = symbolize_obj(atlas[:best_candidate] || {})
          unless best.empty?
            lines << '## Best Candidate'
            lines << "- family_key: `#{best[:family_key]}`"
            lines << "- report_angle: `#{best[:report_angle]}`"
            lines << "- direct_denied: `#{best[:direct_denied]}`"
            lines << "- alternate_accessible: `#{best[:alternate_accessible]}`"
            lines << "- surviving_routes: `#{Array(best[:surviving_routes]).join(', ')}`"
            lines << ''
          end

          lines << '## Families'
          if Array(atlas[:families]).empty?
            lines << '- No handle families identified in this pass.'
          else
            Array(atlas[:families]).each do |family|
              family_hash = symbolize_obj(family)
              lines << "- `#{family_hash[:family_key]}` angle=`#{family_hash[:report_angle]}`"
              lines << "  - direct_denied=`#{family_hash[:direct_denied]}` alternate_accessible=`#{family_hash[:alternate_accessible]}`"
              lines << "  - refs=`#{Array(family_hash[:refs]).first(10).join(', ')}`"
            end
          end

          lines.join("\n")
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_evidence_file(opts = {})
          evidence_path = opts[:evidence_path].to_s
          return {} if evidence_path.empty?
          return {} unless File.exist?(evidence_path)

          symbolize_obj(JSON.parse(File.read(evidence_path)))
        rescue JSON::ParserError
          {}
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

        private_class_method def self.normalize_ref(opts = {})
          ref = opts[:ref]
          return '' if ref.nil?

          normalized = ref.to_s.scrub.strip.downcase
          normalized = normalized.gsub(/[\"'`]/, '')
          normalized = normalized.gsub(/\s+/, '_')
          normalized = normalized.gsub(/[^a-z0-9:_\/.\-]+/, '')
          normalized = normalized.gsub(/_{2,}/, '_').gsub(/^_+|_+$/, '')

          return '' if normalized.empty?
          return '' if normalized.length < 2

          normalized
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
