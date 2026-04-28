# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'uri'
require 'yaml'

module PWN
  module Bounty
    module BundleIntel
      # Clusters direct->derived artifact route chains (generate/status/download)
      # from static artifacts so operators can quickly feed drift and exposure packs.
      module DerivedArtifactSurfaceAtlas
        DEFAULT_MAX_CHAINS = 40
        ROUTE_REGEX = %r{/(?:[a-z0-9._~-]+/?){1,12}}i

        GENERATE_HINTS = %w[generate create render start queue begin request export build].freeze
        STATUS_HINTS = %w[status state progress poll job task processing queued].freeze
        DOWNLOAD_HINTS = %w[download artifact file export attachment archive pdf csv xlsx zip].freeze
        ADMIN_HINTS = %w[admin internal staff owner privileged].freeze
        STAGING_HINTS = %w[staging beta sandbox test preprod].freeze

        ARTIFACT_KIND_HINTS = {
          'pdf' => %w[pdf],
          'csv' => %w[csv],
          'spreadsheet' => %w[xlsx xls sheet],
          'archive' => %w[zip tar gz archive backup],
          'report' => %w[report reports],
          'invoice' => %w[invoice invoices billing],
          'export' => %w[export exports]
        }.freeze

        # Supported Method Parameters::
        # report = PWN::Bounty::BundleIntel::DerivedArtifactSurfaceAtlas.run(
        #   yaml_path: '/path/to/bundle_intel.derived_artifact_surface_atlas.example.yaml'
        # )
        public_class_method def self.run(opts = {})
          profile = resolve_profile(opts: opts)
          report = analyze_profile(profile: profile)

          output_dir = profile[:output_dir]
          return report if output_dir.empty?

          run_root = File.expand_path(File.join(output_dir, report[:run_id]))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'derived_artifact_surface_atlas.json'), obj: report)
          write_markdown(path: File.join(run_root, 'derived_artifact_surface_atlas.md'), report: report)
          write_lines(path: File.join(run_root, 'derived_artifact_surface_atlas_burp_seeds.txt'), lines: report[:burp_seeds])

          report[:run_root] = run_root
          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::BundleIntel::DerivedArtifactSurfaceAtlas.analyze(
        #   route_permission_atlas: '/tmp/route_permission_atlas.json',
        #   base_url: 'https://target.example'
        # )
        public_class_method def self.analyze(opts = {})
          profile = resolve_profile(opts: opts)
          analyze_profile(profile: profile)
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # profile = PWN::Bounty::BundleIntel::DerivedArtifactSurfaceAtlas.load_profile(
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
              report = PWN::Bounty::BundleIntel::DerivedArtifactSurfaceAtlas.run(
                yaml_path: '/path/to/bundle_intel.derived_artifact_surface_atlas.example.yaml',
                output_dir: '/tmp/bundle-intel-derived-artifacts'
              )

              report = PWN::Bounty::BundleIntel::DerivedArtifactSurfaceAtlas.analyze(
                route_permission_atlas: '/tmp/route_permission_atlas.json',
                base_url: 'https://target.example'
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
            max_chains: normalized_max_chains(max_chains: profile[:max_chains]),
            route_permission_atlas: resolve_route_permission_atlas(profile: profile),
            artifacts: normalize_artifacts(profile: profile)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_run_id(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          run_id = profile[:run_id].to_s.scrub.strip
          run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-derived-artifact-surface-atlas" if run_id.empty?
          run_id
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_max_chains(opts = {})
          max_chains = opts[:max_chains].to_i
          max_chains = DEFAULT_MAX_CHAINS if max_chains <= 0
          max_chains = 200 if max_chains > 200
          max_chains
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_artifacts(opts = {})
          profile = symbolize_obj(opts[:profile] || {})

          collected = []
          collected.concat(Array(profile[:artifacts]))
          collected.concat(Array(profile[:html]))
          collected.concat(Array(profile[:js_bundles]))
          collected.concat(Array(profile[:source_maps]))
          collected.concat(Array(profile[:burp_responses]))
          collected.concat(Array(profile[:openapi_docs]))
          collected.concat(Array(profile[:graphql_docs]))

          collected.map(&:to_s).map(&:scrub).reject { |entry| entry.strip.empty? }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolve_route_permission_atlas(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          atlas_input = profile[:route_permission_atlas]

          parsed = resolve_structured_input(input: atlas_input)
          candidate = symbolize_obj(parsed.first || {})
          return candidate unless candidate.empty?

          return {} if normalize_artifacts(profile: profile).empty?

          PWN::Bounty::BundleIntel::RoutePermissionAtlas.analyze(
            run_id: "#{normalized_run_id(profile: profile)}_seed",
            base_url: profile[:base_url],
            target: profile[:target],
            artifacts: normalize_artifacts(profile: profile)
          )
        rescue StandardError => e
          raise e
        end

        private_class_method def self.analyze_profile(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          route_permission_atlas = symbolize_obj(profile[:route_permission_atlas] || {})
          entries = Array(route_permission_atlas[:entries]).map { |entry| symbolize_obj(entry) }

          route_candidates = entries.select { |entry| entry[:entry_type].to_s == 'route' }
          route_candidates += route_candidates_from_artifacts(artifacts: profile[:artifacts])
          route_candidates = route_candidates.uniq { |entry| entry[:identifier].to_s }

          chains = build_chains(route_candidates: route_candidates, base_url: profile[:base_url])
          chains = chains.sort_by { |chain| [-chain[:priority_score].to_i, chain[:object_family].to_s] }
          chains = chains.first(profile[:max_chains])

          {
            generated_at: Time.now.utc.iso8601,
            run_id: profile[:run_id],
            target: profile[:target],
            base_url: profile[:base_url],
            route_permission_entry_count: entries.length,
            route_candidate_count: route_candidates.length,
            chain_count: chains.length,
            chains: chains,
            burp_seeds: build_burp_seeds(chains: chains, base_url: profile[:base_url]),
            artifact_access_drift_matrix_starters: build_artifact_access_starters(chains: chains),
            sensitive_file_exposure_starters: build_sensitive_file_starters(chains: chains, base_url: profile[:base_url]),
            summary: summarize_chains(chains: chains)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.route_candidates_from_artifacts(opts = {})
          artifacts = Array(opts[:artifacts]).map(&:to_s)

          artifacts.flat_map do |text|
            extract_routes_from_text(text: text).map do |route|
              {
                entry_type: 'route',
                identifier: route,
                role_hint: role_hint_for(route: route),
                object_family: infer_object_family(route: route),
                evidence_sources: []
              }
            end
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_routes_from_text(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          text.scan(ROUTE_REGEX).flatten.map { |entry| normalize_route(route: entry) }.reject do |route|
            segments = route.split('/').reject(&:empty?)
            first = segments.first.to_s

            route.empty? ||
              route == '/' ||
              route.length < 5 ||
              (first.include?('.') && segments.length > 1) ||
              route.match?(/\.(?:js|css|png|jpg|jpeg|svg|woff2?|ttf)(?:\?|$)/i)
          end.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_chains(opts = {})
          route_candidates = Array(opts[:route_candidates]).map { |entry| symbolize_obj(entry) }
          base_url = opts[:base_url].to_s

          grouped = route_candidates.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |entry, accum|
            route = normalize_route(route: entry[:identifier])
            next if route.empty?

            family = entry[:object_family].to_s
            family = infer_object_family(route: route) if family.empty?
            family = 'generic_object' if family.empty?

            accum[family] << normalize_route_entry(entry: entry, route: route, base_url: base_url)
          end

          grouped.map do |object_family, candidates|
            build_chain_for_family(object_family: object_family, candidates: candidates)
          end.compact
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_route_entry(opts = {})
          entry = symbolize_obj(opts[:entry] || {})
          route = opts[:route].to_s
          base_url = opts[:base_url].to_s

          phase = classify_phase(route: route)
          artifact_kind = classify_artifact_kind(route: route)
          route_family = classify_route_family(route: route, phase: phase)

          {
            route: route,
            absolute_route: absolutize_route(route: route, base_url: base_url),
            phase: phase,
            route_family: route_family,
            artifact_kind: artifact_kind,
            role_hint: entry[:role_hint].to_s,
            evidence_source_count: Array(entry[:evidence_sources]).length,
            recommended_lane: entry[:recommended_replay_lane].to_s
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_chain_for_family(opts = {})
          object_family = opts[:object_family].to_s
          candidates = Array(opts[:candidates]).map { |entry| symbolize_obj(entry) }
          return nil if candidates.empty?

          generate_routes = candidates.select { |entry| entry[:phase] == 'generate' }.map { |entry| entry[:route] }.uniq
          status_routes = candidates.select { |entry| entry[:phase] == 'status' }.map { |entry| entry[:route] }.uniq
          download_routes = candidates.select { |entry| entry[:phase] == 'download' }.map { |entry| entry[:route] }.uniq

          route_pair_ready = !generate_routes.empty? && !download_routes.empty?
          return nil if generate_routes.empty? && download_routes.empty?

          artifact_kind = most_common(items: candidates.map { |entry| entry[:artifact_kind] })
          role_hint = most_common(items: candidates.map { |entry| entry[:role_hint] })
          staging_hint = candidates.any? { |entry| STAGING_HINTS.any? { |term| entry[:route].downcase.include?(term) } }
          admin_hint = candidates.any? { |entry| ADMIN_HINTS.any? { |term| entry[:route].downcase.include?(term) } }

          follow_on_pack = if route_pair_ready
                             'lifecycle_authz_replay_artifact_access_drift_matrix'
                           elsif download_routes.any?
                             'sensitive_file_exposure_pack'
                           else
                             'bundle_intel_route_permission_atlas'
                           end

          priority_score = score_chain(
            route_pair_ready: route_pair_ready,
            generate_count: generate_routes.length,
            status_count: status_routes.length,
            download_count: download_routes.length,
            staging_hint: staging_hint,
            admin_hint: admin_hint,
            role_hint: role_hint
          )

          {
            chain_id: Digest::SHA256.hexdigest("#{object_family}|#{artifact_kind}|#{generate_routes.first}|#{download_routes.first}")[0, 12],
            object_family: object_family,
            artifact_kind: artifact_kind,
            route_family: route_pair_ready ? 'direct_and_derived' : (download_routes.any? ? 'derived_only' : 'direct_only'),
            checkpoint_hint: route_pair_ready ? 'post_change_t0' : 'post_change_capture',
            role_hint: role_hint,
            priority_score: priority_score,
            priority_tier: priority_tier(score: priority_score),
            recommended_follow_on_pack: follow_on_pack,
            route_pair_ready: route_pair_ready,
            generate_routes: generate_routes,
            status_routes: status_routes,
            download_routes: download_routes,
            alternate_route_hint: (download_routes - generate_routes).first.to_s,
            evidence_source_count: candidates.map { |entry| entry[:evidence_source_count].to_i }.sum
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.classify_phase(opts = {})
          route = opts[:route].to_s.downcase
          return 'download' if DOWNLOAD_HINTS.any? { |term| route.include?(term) }
          return 'status' if STATUS_HINTS.any? { |term| route.include?(term) }
          return 'generate' if GENERATE_HINTS.any? { |term| route.include?(term) }

          'unknown'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.classify_artifact_kind(opts = {})
          route = opts[:route].to_s.downcase
          ARTIFACT_KIND_HINTS.each do |kind, terms|
            return kind if terms.any? { |term| route.include?(term) }
          end

          'generic_artifact'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.classify_route_family(opts = {})
          route = opts[:route].to_s.downcase
          phase = opts[:phase].to_s

          return 'direct' if phase == 'generate'
          return 'artifact' if phase == 'download'
          return 'secondary' if phase == 'status'

          return 'artifact' if route.include?('download') || route.include?('export')
          return 'direct' if route.include?('create') || route.include?('generate')

          'secondary'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.score_chain(opts = {})
          route_pair_ready = opts[:route_pair_ready] == true
          generate_count = opts[:generate_count].to_i
          status_count = opts[:status_count].to_i
          download_count = opts[:download_count].to_i
          staging_hint = opts[:staging_hint] == true
          admin_hint = opts[:admin_hint] == true
          role_hint = opts[:role_hint].to_s

          score = 28
          score += 24 if route_pair_ready
          score += [generate_count, 3].min * 6
          score += [status_count, 2].min * 4
          score += [download_count, 3].min * 8
          score += 10 if staging_hint
          score += 12 if admin_hint
          score += 6 unless role_hint.empty?

          [[score, 0].max, 100].min
        rescue StandardError => e
          raise e
        end

        private_class_method def self.priority_tier(opts = {})
          score = opts[:score].to_i
          return 'critical' if score >= 88
          return 'high' if score >= 74
          return 'medium' if score >= 58

          'low'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_burp_seeds(opts = {})
          chains = Array(opts[:chains]).map { |entry| symbolize_obj(entry) }
          base_url = opts[:base_url].to_s

          seeds = chains.flat_map do |chain|
            Array(chain[:generate_routes]) + Array(chain[:status_routes]) + Array(chain[:download_routes])
          end

          if !base_url.empty? && base_url.match?(%r{\Ahttps?://}i)
            seeds = seeds.map { |route| absolutize_route(route: route, base_url: base_url) }
          end

          seeds.map(&:to_s).reject(&:empty?).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_artifact_access_starters(opts = {})
          chains = Array(opts[:chains]).map { |entry| symbolize_obj(entry) }

          chains.select { |chain| chain[:route_pair_ready] == true }.map do |chain|
            {
              family_key: chain[:object_family],
              checkpoint_hint: chain[:checkpoint_hint],
              direct_routes: Array(chain[:generate_routes]),
              derived_routes: Array(chain[:download_routes]),
              route_family: chain[:route_family],
              recommended_module: 'PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix'
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_sensitive_file_starters(opts = {})
          chains = Array(opts[:chains]).map { |entry| symbolize_obj(entry) }
          base_url = opts[:base_url].to_s

          chains.flat_map do |chain|
            Array(chain[:download_routes]).map do |route|
              {
                object_family: chain[:object_family],
                artifact_kind: chain[:artifact_kind],
                route: route,
                url: absolutize_route(route: route, base_url: base_url),
                recommended_module: 'PWN::Bounty::SensitiveFileExposurePack'
              }
            end
          end.uniq { |entry| entry[:url] }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_chains(opts = {})
          chains = Array(opts[:chains]).map { |entry| symbolize_obj(entry) }

          {
            by_priority_tier: tally_by(chains: chains, key: :priority_tier),
            by_follow_on_pack: tally_by(chains: chains, key: :recommended_follow_on_pack),
            route_pair_ready_count: chains.count { |chain| chain[:route_pair_ready] == true }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.tally_by(opts = {})
          chains = Array(opts[:chains]).map { |entry| symbolize_obj(entry) }
          key = opts[:key].to_sym

          chains.each_with_object(Hash.new(0)) do |chain, accum|
            value = chain[key].to_s
            value = 'unknown' if value.empty?
            accum[value] += 1
          end.sort.to_h
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_object_family(opts = {})
          route = normalize_route(route: opts[:route])
          segments = route.split('/').reject(&:empty?)
          token = segments.reverse.find do |segment|
            normalized = normalize_token(segment)
            !normalized.empty? && normalized.length > 2 &&
              !%w[api v1 v2 v3 admin internal export exports download downloads status poll create generate report reports pdf csv zip file files].include?(normalized)
          end
          normalize_token(token)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.role_hint_for(opts = {})
          route = opts[:route].to_s.downcase
          ADMIN_HINTS.find { |term| route.include?(term) }.to_s
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

        private_class_method def self.most_common(opts = {})
          items = Array(opts[:items]).map(&:to_s).map(&:strip).reject(&:empty?)
          return '' if items.empty?

          counts = items.each_with_object(Hash.new(0)) { |item, accum| accum[item] += 1 }
          counts.max_by { |item, count| [count, item] }.first.to_s
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
          lines << '# BundleIntel Derived Artifact Surface Atlas'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Run ID: `#{report[:run_id]}`"
          lines << "- Chains: `#{report[:chain_count]}`"
          lines << ''

          lines << '## Ranked Chains'
          chains = Array(report[:chains]).map { |entry| symbolize_obj(entry) }
          if chains.empty?
            lines << '- No direct/derived artifact chain candidates discovered.'
          else
            chains.each do |chain|
              lines << "- [#{chain[:priority_tier]}|#{chain[:priority_score]}] object=`#{chain[:object_family]}` kind=`#{chain[:artifact_kind]}`"
              lines << "  - route_family: `#{chain[:route_family]}` checkpoint_hint=`#{chain[:checkpoint_hint]}`"
              lines << "  - generate_routes: `#{Array(chain[:generate_routes]).join(', ')}`"
              lines << "  - status_routes: `#{Array(chain[:status_routes]).join(', ')}`" unless Array(chain[:status_routes]).empty?
              lines << "  - download_routes: `#{Array(chain[:download_routes]).join(', ')}`"
              lines << "  - follow_on_pack: `#{chain[:recommended_follow_on_pack]}`"
            end
          end

          lines << ''
          lines << '## Burp Seeds'
          Array(report[:burp_seeds]).each do |seed|
            lines << "- #{seed}"
          end

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, lines.join("\n"))
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_lines(opts = {})
          path = opts[:path].to_s
          lines = Array(opts[:lines]).map(&:to_s).reject(&:empty?).uniq

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
