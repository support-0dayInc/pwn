# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Bounty
    module GraphQLAuthzDiff
      # Correlates GraphQL authz deltas with optional REST/UI evidence and
      # clusters object families to produce report-shaped cross-surface drift.
      module CrossSurfaceObjectLineage
        DIRECT_ROUTE_HINTS = %w[direct primary canonical repo_meta metadata baseline].freeze

        # Supported Method Parameters::
        # lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.analyze(
        #   diff_report: '/tmp/graphql_authz_diff.json',
        #   surface_evidence: '/tmp/surface_evidence.json',
        #   object_seeds: '/tmp/object_seeds.json'
        # )
        public_class_method def self.analyze(opts = {})
          diff_report = resolve_structured_input(input: opts[:diff_report]).first || {}
          diff_report = symbolize_obj(diff_report)

          matrix = Array(diff_report[:matrix]).map { |row| symbolize_obj(row) }
          findings = Array(diff_report[:findings]).map { |finding| symbolize_obj(finding) }
          surface_evidence = resolve_structured_input(input: opts[:surface_evidence])
          object_seeds = resolve_structured_input(input: opts[:object_seeds])

          evidence_route_map = surface_evidence.each_with_object({}) do |entry, accum|
            entry_hash = symbolize_obj(entry)
            key = normalize_token(entry_hash[:surface] || entry_hash[:operation_id] || entry_hash[:operation_name])
            next if key.empty?

            accum[key] = normalize_route_family(route_family: entry_hash[:route_family])
          end

          observations = []
          observations.concat(extract_graphql_observations(
            matrix: matrix,
            findings: findings,
            evidence_route_map: evidence_route_map
          ))
          observations.concat(extract_surface_observations(surface_evidence: surface_evidence))

          seed_lookup = build_seed_lookup(object_seeds: object_seeds)
          families = cluster_families(observations: observations, seed_lookup: seed_lookup)

          ranked_families = families.map do |family_key, family_observations|
            build_family_result(
              family_key: family_key,
              observations: family_observations
            )
          end

          ranked_families.sort_by! do |family|
            [-family_rank(report_angle: family[:report_angle]), family[:family_key]]
          end

          {
            generated_at: Time.now.utc.iso8601,
            run_id: diff_report[:run_id],
            family_count: ranked_families.length,
            reportable_candidate_count: ranked_families.count { |family| family[:report_angle] == 'cross_surface_authz_drift' },
            families: ranked_families,
            summary: summarize_families(families: ranked_families)
          }
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.run(
        #   diff_report: '/tmp/graphql_authz_diff.json',
        #   output_dir: '/tmp/graphql-authz-diff'
        # )
        public_class_method def self.run(opts = {})
          lineage = analyze(
            diff_report: opts[:diff_report],
            surface_evidence: opts[:surface_evidence],
            object_seeds: opts[:object_seeds]
          )

          output_dir = opts[:output_dir].to_s.scrub.strip
          return lineage if output_dir.empty?

          write_lineage_bundle(output_dir: output_dir, lineage: lineage)
          lineage
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
              lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.analyze(
                diff_report: '/tmp/graphql_authz_diff.json',
                surface_evidence: '/tmp/surface_evidence.json',
                object_seeds: '/tmp/object_seeds.json'
              )

              lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.run(
                diff_report: '/tmp/graphql_authz_diff.json',
                output_dir: '/tmp/graphql-authz-diff'
              )
          HELP
        end

        private_class_method def self.extract_graphql_observations(opts = {})
          matrix = Array(opts[:matrix]).map { |row| symbolize_obj(row) }
          findings = Array(opts[:findings]).map { |finding| symbolize_obj(finding) }
          evidence_route_map = opts[:evidence_route_map].is_a?(Hash) ? opts[:evidence_route_map] : {}

          finding_lookup = findings.each_with_object({}) do |finding, accum|
            key = [
              normalize_token(finding[:checkpoint]),
              normalize_token(finding[:operation_id]),
              normalize_token(finding[:actor])
            ].join(':')
            accum[key] ||= []
            accum[key] << finding
          end

          matrix.flat_map do |row|
            row_hash = symbolize_obj(row)
            checkpoint = normalize_token(row_hash[:checkpoint])
            operation_id = normalize_token(row_hash[:operation_id])
            operation_name = row_hash[:operation_name].to_s
            route_family = evidence_route_map[operation_id]
            route_family = evidence_route_map[operation_id.to_sym] if route_family.nil?
            route_family ||= infer_route_family(surface_id: operation_id, surface_label: operation_name)

            Array(row_hash[:actor_results]).map do |actor_result|
              actor_hash = symbolize_obj(actor_result)
              actor = normalize_token(actor_hash[:actor])
              status = normalize_token(actor_hash[:status])
              expected_access = actor_hash[:expected_access]
              evidence_path = actor_hash[:evidence_path].to_s

              next if actor.empty?
              next unless expected_access == false

              observation_key = [checkpoint, operation_id, actor].join(':')
              matched_findings = Array(finding_lookup[observation_key])

              evidence = parse_evidence_file(evidence_path: evidence_path)
              refs = extract_object_refs(
                evidence: evidence,
                operation_id: operation_id,
                operation_name: operation_name,
                matched_findings: matched_findings
              )

              {
                source: 'graphql_authz_diff',
                checkpoint: checkpoint,
                actor: actor,
                surface: operation_id,
                surface_label: operation_name,
                route_family: route_family,
                status: status,
                accessible: status == 'accessible',
                evidence_path: evidence_path,
                refs: refs,
                finding_ids: matched_findings.map { |finding| finding[:id] }
              }
            end
          end.compact
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_surface_observations(opts = {})
          surface_evidence = Array(opts[:surface_evidence]).map { |entry| symbolize_obj(entry) }

          surface_evidence.filter_map do |entry|
            status = normalize_token(entry[:status])
            status = entry[:accessible] == true ? 'accessible' : status
            status = entry[:denied] == true ? 'denied' : status
            status = 'unknown' if status.empty?

            refs = surface_refs_from_entry(entry: entry)

            next if status == 'unknown' && refs.empty?

            {
              source: 'surface_evidence',
              checkpoint: normalize_token(entry[:checkpoint]),
              actor: normalize_token(entry[:actor]),
              surface: normalize_token(entry[:surface] || entry[:operation_id] || entry[:route]),
              surface_label: entry[:surface_label].to_s,
              route_family: normalize_route_family(route_family: entry[:route_family]),
              status: status,
              accessible: status == 'accessible',
              evidence_path: entry[:evidence_path].to_s,
              refs: refs,
              finding_ids: []
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_seed_lookup(opts = {})
          object_seeds = Array(opts[:object_seeds]).map { |seed| symbolize_obj(seed) }

          object_seeds.each_with_object({}) do |seed, accum|
            seed_key = normalize_seed_key(seed: seed)
            next if seed_key.empty?

            refs = []
            refs << seed[:id]
            refs << seed[:node_id]
            refs << seed[:url]
            refs << seed[:slug]
            refs.concat(Array(seed[:aliases]))
            refs.compact.each do |ref|
              normalized = normalize_ref(ref: ref)
              accum[normalized] = seed_key unless normalized.empty?
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
              seed_lookup[ref] || seed_lookup[ref.to_sym] || ref
            end.uniq
            family_keys = [fallback_family_key(observation: observation)] if family_keys.empty?

            family_keys.each do |family_key|
              accum[family_key] << observation
            end
          end
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

          alternate_accessible = !alternate_accessible_routes.empty?

          report_angle = if direct_denied && alternate_accessible
                           'cross_surface_authz_drift'
                         elsif alternate_accessible
                           'alternate_surface_access_without_direct_gate'
                         elsif direct_denied
                           'direct_denied_only'
                         else
                           'inconclusive'
                         end

          best_next_capture = case report_angle
                              when 'cross_surface_authz_drift'
                                'Capture one additional direct-denied checkpoint adjacent to the surviving alternate route for report confidence.'
                              when 'alternate_surface_access_without_direct_gate'
                                'Capture direct/canonical route denial for same actor/object to complete contradiction proof.'
                              when 'direct_denied_only'
                                'Probe at least one alternate route (REST/UI/export/attachment) for same object family.'
                              else
                                'Collect more object-linked observations across at least two surfaces.'
                              end

          {
            family_key: family_key,
            observation_count: observations.length,
            direct_denied: direct_denied,
            alternate_accessible: alternate_accessible,
            surviving_routes: alternate_accessible_routes,
            report_angle: report_angle,
            best_next_capture: best_next_capture,
            observations: observations.map do |entry|
              {
                source: entry[:source],
                checkpoint: entry[:checkpoint],
                actor: entry[:actor],
                surface: entry[:surface],
                route_family: normalize_route_family(route_family: entry[:route_family]),
                status: entry[:status],
                evidence_path: entry[:evidence_path],
                finding_ids: entry[:finding_ids]
              }
            end
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_families(opts = {})
          families = Array(opts[:families]).map { |entry| symbolize_obj(entry) }

          {
            cross_surface_authz_drift: families.count { |family| family[:report_angle] == 'cross_surface_authz_drift' },
            alternate_surface_access_without_direct_gate: families.count { |family| family[:report_angle] == 'alternate_surface_access_without_direct_gate' },
            direct_denied_only: families.count { |family| family[:report_angle] == 'direct_denied_only' },
            inconclusive: families.count { |family| family[:report_angle] == 'inconclusive' }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.family_rank(opts = {})
          case normalize_token(opts[:report_angle])
          when 'cross_surface_authz_drift'
            4
          when 'alternate_surface_access_without_direct_gate'
            3
          when 'direct_denied_only'
            2
          else
            1
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.fallback_family_key(opts = {})
          observation = symbolize_obj(opts[:observation] || {})
          actor = normalize_token(observation[:actor])
          surface = normalize_token(observation[:surface])
          checkpoint = normalize_token(observation[:checkpoint])

          "#{actor}:#{surface}:#{checkpoint}".gsub(/^:+|:+$/, '')
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_object_refs(opts = {})
          evidence = symbolize_obj(opts[:evidence] || {})
          operation_id = opts[:operation_id].to_s
          operation_name = opts[:operation_name].to_s
          matched_findings = Array(opts[:matched_findings]).map { |entry| symbolize_obj(entry) }

          refs = []

          graphql_data = symbolize_obj(evidence.dig(:response, :graphql, :data) || {})
          refs.concat(collect_refs_from_obj(obj: graphql_data))

          if refs.empty?
            refs << normalize_ref(ref: operation_id)
            refs << normalize_ref(ref: operation_name)

            matched_findings.each do |finding|
              refs << normalize_ref(ref: finding[:operation_id])
              refs << normalize_ref(ref: finding[:operation_name])
            end
          end

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
              if %w[id node_id nodeid databaseid number slug url html_url full_name key].include?(normalized_key)
                refs << normalize_ref(ref: value)
              end
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

        private_class_method def self.surface_refs_from_entry(opts = {})
          entry = symbolize_obj(opts[:entry] || {})

          refs = []
          refs.concat(Array(entry[:object_refs] || entry[:refs]))
          refs << entry[:object_id]
          refs << entry[:node_id]
          refs << entry[:database_id]
          refs << entry[:slug]
          refs << entry[:handle]
          refs << entry[:attachment_id]
          refs << entry[:upload_id]
          refs << entry[:migration_id]
          refs << entry[:url]
          refs << entry[:route]
          refs << entry[:path]

          evidence = parse_evidence_file(evidence_path: entry[:evidence_path])
          refs.concat(collect_refs_from_obj(obj: evidence))

          url_hint = evidence.dig(:request, :url) || evidence.dig(:request, :path) || evidence.dig(:response, :url)
          refs << url_hint unless url_hint.to_s.empty?

          refs.concat(extract_refs_from_url(url: entry[:url]))
          refs.concat(extract_refs_from_url(url: url_hint))

          refs.map { |ref| normalize_ref(ref: ref) }.reject(&:empty?).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_refs_from_url(opts = {})
          url = opts[:url].to_s
          return [] if url.empty?

          refs = []
          object_match = url.match(%r{/(?:objects?|issues?|pulls?|merge_requests?|migrations?|uploads?|attachments?|artifacts?|exports?|comments?|repos?|projects?)/([^/?#]+)}i)
          refs << object_match[1] unless object_match.nil?

          slug_match = url.match(%r{/([a-z0-9_.-]+/[a-z0-9_.-]+)(?:/|\?|#|$)}i)
          refs << slug_match[1] unless slug_match.nil?

          refs
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_seed_key(opts = {})
          seed = symbolize_obj(opts[:seed] || {})
          candidate = seed[:family_key] || seed[:id] || seed[:node_id] || seed[:url] || seed[:slug]
          normalize_ref(ref: candidate)
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
          return 'alternate' if route_family == 'alternate' || route_family.empty?

          route_family
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_lineage_bundle(opts = {})
          output_dir = opts[:output_dir].to_s.scrub.strip
          lineage = symbolize_obj(opts[:lineage] || {})
          FileUtils.mkdir_p(output_dir)

          json_path = File.join(output_dir, 'cross_surface_object_lineage.json')
          markdown_path = File.join(output_dir, 'cross_surface_object_lineage.md')

          File.write(json_path, JSON.pretty_generate(lineage))
          File.write(markdown_path, build_markdown_report(lineage: lineage))

          {
            json_path: json_path,
            markdown_path: markdown_path
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_markdown_report(opts = {})
          lineage = symbolize_obj(opts[:lineage] || {})

          lines = []
          lines << '# GraphQL Cross-Surface Object Lineage'
          lines << ''
          lines << "- Generated At (UTC): `#{lineage[:generated_at]}`"
          lines << "- Run ID: `#{lineage[:run_id]}`"
          lines << "- Object Families: `#{lineage[:family_count]}`"
          lines << "- Reportable Candidates: `#{lineage[:reportable_candidate_count]}`"
          lines << ''

          lines << '## Family Summary'
          summary = symbolize_obj(lineage[:summary] || {})
          summary.each do |key, value|
            lines << "- #{key}: `#{value}`"
          end

          lines << ''
          lines << '## Families'
          if Array(lineage[:families]).empty?
            lines << '- No cross-surface object families were identified.'
          else
            Array(lineage[:families]).each do |family|
              family_hash = symbolize_obj(family)
              lines << "- `#{family_hash[:family_key]}` angle=`#{family_hash[:report_angle]}`"
              lines << "  - direct_denied=`#{family_hash[:direct_denied]}` alternate_accessible=`#{family_hash[:alternate_accessible]}`"
              lines << "  - surviving_routes=`#{Array(family_hash[:surviving_routes]).join(', ')}`"
              lines << "  - best_next_capture=#{family_hash[:best_next_capture]}"
            end
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

          ref.to_s.scrub.strip.downcase.gsub(/\s+/, '_')
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
