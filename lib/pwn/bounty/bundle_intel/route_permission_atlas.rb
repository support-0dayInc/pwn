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
      # Converts static bundle artifacts into a ranked atlas of hidden routes,
      # GraphQL operations, and permission hints for low-noise replay lanes.
      module RoutePermissionAtlas
        DEFAULT_MAX_ENTRIES = 80

        URL_REGEX = %r{https?://[a-z0-9.-]+(?::\d+)?(?:/[\w\-./%~:+?=&]*)?}i
        ROUTE_REGEX = %r{/(?:[a-z0-9._~-]+/?){1,10}}i
        PERMISSION_REGEX = /\b[a-z][a-z0-9_]{1,24}:[a-z][a-z0-9_]{1,24}\b/
        GRAPHQL_OPERATION_REGEX = /\b(?:query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]{2,})/
        PERSISTED_HASH_REGEX = /\b[a-f0-9]{64}\b/i

        ROLE_HINT_TERMS = %w[
          admin
          administrator
          owner
          maintainer
          manager
          support
          superuser
          internal
          staff
          reviewer
          approver
        ].freeze

        FEATURE_FLAG_TERMS = %w[
          feature
          flag
          toggle
          experiment
          rollout
          enable
          gate
        ].freeze

        GENERIC_SEGMENTS = %w[
          api
          graphql
          graph
          v1
          v2
          v3
          admin
          beta
          test
          staging
          internal
          app
          web
          ui
          svc
          service
        ].freeze

        OBJECT_FAMILY_HINTS = %w[
          user
          users
          account
          accounts
          org
          organization
          organizations
          team
          teams
          project
          projects
          repo
          repos
          repository
          repositories
          issue
          issues
          member
          members
          role
          roles
          permission
          permissions
          token
          tokens
          key
          keys
          secret
          secrets
          workflow
          workflows
          artifact
          artifacts
          attachment
          attachments
          export
          exports
          report
          reports
          invoice
          invoices
          payment
          payments
        ].freeze

        # Supported Method Parameters::
        # report = PWN::Bounty::BundleIntel::RoutePermissionAtlas.run(
        #   yaml_path: '/path/to/bundle_intel.route_permission_atlas.example.yaml'
        # )
        public_class_method def self.run(opts = {})
          profile = resolve_profile(opts: opts)
          report = analyze_profile(profile: profile)

          output_dir = profile[:output_dir]
          return report if output_dir.empty?

          run_root = File.expand_path(File.join(output_dir, report[:run_id]))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'route_permission_atlas.json'), obj: report)
          write_markdown(path: File.join(run_root, 'route_permission_atlas.md'), report: report)
          write_lines(path: File.join(run_root, 'route_permission_atlas_burp_seeds.txt'), lines: report[:burp_seeds])

          report[:run_root] = run_root
          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::BundleIntel::RoutePermissionAtlas.analyze(
        #   artifacts: [...]
        # )
        public_class_method def self.analyze(opts = {})
          profile = resolve_profile(opts: opts)
          analyze_profile(profile: profile)
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # profile = PWN::Bounty::BundleIntel::RoutePermissionAtlas.load_profile(
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
              report = PWN::Bounty::BundleIntel::RoutePermissionAtlas.run(
                yaml_path: '/path/to/bundle_intel.route_permission_atlas.example.yaml',
                output_dir: '/tmp/bundle-intel'
              )

              report = PWN::Bounty::BundleIntel::RoutePermissionAtlas.analyze(
                base_url: 'https://target.example',
                html: ['<a href="/admin/users">Admin</a>'],
                js_bundles: ['query AdminUsers { users { id } }'],
                source_maps: ['feature_admin_panel_enabled=true'],
                burp_responses: ['{"request":{"url":"https://target.example/api/v1/users"}}']
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
            max_entries: normalized_max_entries(max_entries: profile[:max_entries]),
            artifacts: normalize_artifacts(profile: profile)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_run_id(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          run_id = profile[:run_id].to_s.scrub.strip
          run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-route-permission-atlas" if run_id.empty?
          run_id
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_max_entries(opts = {})
          max_entries = opts[:max_entries].to_i
          max_entries = DEFAULT_MAX_ENTRIES if max_entries <= 0
          max_entries = 300 if max_entries > 300
          max_entries
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_artifacts(opts = {})
          profile = symbolize_obj(opts[:profile] || {})

          artifacts = []
          artifacts.concat(expand_artifacts(input: profile[:artifacts], source_type: 'artifact'))
          artifacts.concat(expand_artifacts(input: profile[:html], source_type: 'html'))
          artifacts.concat(expand_artifacts(input: profile[:js_bundles], source_type: 'js_bundle'))
          artifacts.concat(expand_artifacts(input: profile[:source_maps], source_type: 'source_map'))
          artifacts.concat(expand_artifacts(input: profile[:burp_responses], source_type: 'burp_response'))

          deduped = artifacts.map { |entry| symbolize_obj(entry) }.reject do |artifact|
            artifact[:text].to_s.scrub.strip.empty?
          end

          deduped.uniq { |artifact| artifact[:artifact_id] }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.expand_artifacts(opts = {})
          input = opts[:input]
          source_type = opts[:source_type].to_s
          entries = resolve_structured_input(input: input)

          entries.each_with_index.filter_map do |entry, index|
            artifact = normalize_artifact_entry(
              entry: entry,
              source_type: source_type,
              index: index
            )
            artifact
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_artifact_entry(opts = {})
          entry = opts[:entry]
          source_type = opts[:source_type].to_s
          index = opts[:index].to_i

          entry_hash = entry.is_a?(Hash) ? symbolize_obj(entry) : {}

          explicit_id = entry_hash[:artifact_id].to_s.scrub.strip
          explicit_id = entry_hash[:id].to_s.scrub.strip if explicit_id.empty?
          explicit_id = "#{source_type}_#{index + 1}" if explicit_id.empty?

          text = if entry_hash.empty?
                   entry.to_s
                 else
                   extract_text_from_entry(entry_hash: entry_hash)
                 end

          text = text.to_s.scrub
          return nil if text.strip.empty?

          artifact_id = "#{normalize_token(explicit_id)}_#{Digest::SHA256.hexdigest(text)[0, 10]}"

          {
            artifact_id: artifact_id,
            source_type: source_type.empty? ? 'artifact' : source_type,
            source_label: entry_hash[:source_label].to_s,
            text: text
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_text_from_entry(opts = {})
          entry_hash = symbolize_obj(opts[:entry_hash] || {})

          path = entry_hash[:path].to_s.scrub.strip
          if !path.empty? && File.exist?(path)
            content = File.read(path)
            parsed = parse_json_if_possible(data: content)
            return collect_strings(obj: parsed).join(' ') unless parsed.nil?

            return content
          end

          preferred = [
            entry_hash[:text],
            entry_hash[:content],
            entry_hash[:body],
            entry_hash[:raw],
            entry_hash[:html],
            entry_hash[:javascript],
            entry_hash[:response],
            entry_hash[:request],
            entry_hash[:payload]
          ].compact.map(&:to_s).join("\n")

          return preferred unless preferred.strip.empty?

          collect_strings(obj: entry_hash).join(' ')
        rescue StandardError => e
          raise e
        end

        private_class_method def self.analyze_profile(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          artifacts = Array(profile[:artifacts]).map { |artifact| symbolize_obj(artifact) }

          observations = artifacts.flat_map do |artifact|
            extract_observations(artifact: artifact)
          end

          grouped = observations.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |observation, accum|
            key = "#{observation[:entry_type]}:#{observation[:identifier]}"
            accum[key] << observation
          end

          entries = grouped.map do |_key, group|
            build_entry(group: group)
          end

          annotate_alternate_routes!(entries: entries)

          entries.sort_by! do |entry|
            [
              -entry[:priority_score].to_i,
              entry[:entry_type].to_s,
              entry[:identifier].to_s
            ]
          end

          entries = entries.first(profile[:max_entries])

          route_entries = entries.select { |entry| entry[:entry_type] == 'route' }
          graphql_entries = entries.select { |entry| entry[:entry_type] == 'graphql_operation' }

          {
            generated_at: Time.now.utc.iso8601,
            run_id: profile[:run_id],
            target: profile[:target],
            base_url: profile[:base_url],
            artifact_count: artifacts.length,
            observation_count: observations.length,
            entry_count: entries.length,
            route_count: route_entries.length,
            graphql_operation_count: graphql_entries.length,
            feature_flag_count: entries.sum { |entry| Array(entry[:feature_flags]).length },
            host_pivot_count: entries.sum { |entry| Array(entry[:host_pivots]).length },
            entries: entries,
            burp_seeds: build_burp_seeds(entries: route_entries, base_url: profile[:base_url]),
            lifecycle_replay_starters: entries.select { |entry| entry[:recommended_replay_lane] == 'lifecycle_authz_replay' }.map { |entry| entry[:identifier] },
            graphql_diff_starters: entries.select { |entry| entry[:recommended_replay_lane] == 'graphql_authz_diff' }.map { |entry| entry[:identifier] },
            ssrf_sink_hints: entries.select { |entry| entry[:recommended_replay_lane] == 'ssrf_chain' }.map { |entry| entry[:identifier] },
            summary: summarize_entries(entries: entries)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_observations(opts = {})
          artifact = symbolize_obj(opts[:artifact] || {})
          text = artifact[:text].to_s
          return [] if text.empty?

          routes = extract_routes(text: text)
          urls = extract_urls(text: text)
          hosts = urls.map do |url|
            begin
              URI.parse(url).host.to_s
            rescue URI::InvalidURIError
              ''
            end
          end.reject(&:empty?).uniq

          roles = extract_role_hints(text: text)
          feature_flags = extract_feature_flags(text: text)
          permissions = extract_permission_strings(text: text)
          graphql_ops = extract_graphql_operations(text: text)
          persisted_hashes = extract_persisted_hashes(text: text)

          observations = []

          routes.each do |route|
            observations << {
              entry_type: 'route',
              identifier: normalize_route(route: route),
              source_id: artifact[:artifact_id],
              source_type: artifact[:source_type],
              role_hints: roles,
              object_hints: extract_object_hints(text: route),
              feature_flags: feature_flags,
              permission_strings: permissions,
              host_pivots: hosts
            }
          end

          graphql_ops.each do |operation|
            observations << {
              entry_type: 'graphql_operation',
              identifier: "graphql:#{operation}",
              source_id: artifact[:artifact_id],
              source_type: artifact[:source_type],
              role_hints: roles,
              object_hints: extract_object_hints(text: operation),
              feature_flags: feature_flags,
              permission_strings: permissions,
              host_pivots: hosts
            }
          end

          persisted_hashes.each do |hash|
            observations << {
              entry_type: 'persisted_query_hash',
              identifier: "persisted_query:#{hash}",
              source_id: artifact[:artifact_id],
              source_type: artifact[:source_type],
              role_hints: roles,
              object_hints: extract_object_hints(text: text),
              feature_flags: feature_flags,
              permission_strings: permissions,
              host_pivots: hosts
            }
          end

          observations
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_routes(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          raw_routes = text.scan(ROUTE_REGEX).flatten.map { |route| normalize_route(route: route) }

          raw_routes.reject do |route|
            segments = route.split('/').reject(&:empty?)
            first_segment = segments.first.to_s

            route.empty? ||
              route == '/' ||
              route.length < 4 ||
              route.start_with?('//') ||
              route.match?(/\.(?:js|css|png|jpg|jpeg|svg|woff2?|ttf)(?:\?|$)/i) ||
              (first_segment.include?('.') && segments.length > 1)
          end.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_urls(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          text.scan(URL_REGEX).flatten.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_role_hints(opts = {})
          text = opts[:text].to_s.downcase
          return [] if text.empty?

          ROLE_HINT_TERMS.select { |term| text.include?(term) }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_feature_flags(opts = {})
          text = opts[:text].to_s.downcase
          return [] if text.empty?

          flags = text.scan(/\b[a-z0-9_.:-]{4,64}\b/).flatten.select do |token|
            FEATURE_FLAG_TERMS.any? { |term| token.include?(term) }
          end

          flags.first(25).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_permission_strings(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          text.scan(PERMISSION_REGEX).flatten.first(25).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_graphql_operations(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          text.scan(GRAPHQL_OPERATION_REGEX).flatten.map(&:to_s).uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_persisted_hashes(opts = {})
          text = opts[:text].to_s
          return [] if text.empty?

          text.scan(PERSISTED_HASH_REGEX).flatten.map(&:downcase).uniq.first(30)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_object_hints(opts = {})
          text = opts[:text].to_s.downcase
          return [] if text.empty?

          OBJECT_FAMILY_HINTS.select do |hint|
            text.include?(hint)
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_entry(opts = {})
          group = Array(opts[:group]).map { |entry| symbolize_obj(entry) }
          representative = symbolize_obj(group.first || {})

          entry_type = representative[:entry_type].to_s
          identifier = representative[:identifier].to_s

          role_hint = most_common(items: group.flat_map { |entry| Array(entry[:role_hints]) })
          object_family = infer_object_family(group: group)

          feature_flags = group.flat_map { |entry| Array(entry[:feature_flags]) }.uniq.first(20)
          permission_strings = group.flat_map { |entry| Array(entry[:permission_strings]) }.uniq.first(20)
          host_pivots = group.flat_map { |entry| Array(entry[:host_pivots]) }.uniq.first(15)
          evidence_sources = group.map do |entry|
            {
              source_id: entry[:source_id],
              source_type: entry[:source_type]
            }
          end.uniq

          recommended_lane = recommended_replay_lane(
            entry_type: entry_type,
            identifier: identifier,
            object_family: object_family,
            role_hint: role_hint,
            permission_strings: permission_strings
          )

          score = score_entry(
            entry_type: entry_type,
            identifier: identifier,
            role_hint: role_hint,
            feature_flags: feature_flags,
            permission_strings: permission_strings,
            host_pivots: host_pivots,
            recommended_lane: recommended_lane
          )

          {
            entry_id: Digest::SHA256.hexdigest("#{entry_type}|#{identifier}")[0, 12],
            entry_type: entry_type,
            identifier: identifier,
            priority_score: score,
            priority_tier: priority_tier(score: score),
            role_hint: role_hint,
            object_family: object_family,
            alternate_route_hint: '',
            recommended_replay_lane: recommended_lane,
            evidence_source_count: evidence_sources.length,
            evidence_sources: evidence_sources,
            feature_flags: feature_flags,
            permission_strings: permission_strings,
            host_pivots: host_pivots
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_object_family(opts = {})
          group = Array(opts[:group]).map { |entry| symbolize_obj(entry) }
          hinted = most_common(items: group.flat_map { |entry| Array(entry[:object_hints]) }.map { |entry| normalize_object_family(entry) })
          return hinted unless hinted.empty?

          identifier = group.first[:identifier].to_s
          if identifier.start_with?('graphql:')
            operation = identifier.sub('graphql:', '')
            tokens = operation.gsub(/([a-z])([A-Z])/, '\1_\2').downcase.split('_')
            token = tokens.reverse.find { |entry| entry.length > 2 }
            return normalize_object_family(token)
          end

          segments = identifier.split('/').map { |segment| normalize_token(segment) }
          segment = segments.reverse.find do |entry|
            !entry.empty? && !GENERIC_SEGMENTS.include?(entry)
          end
          normalize_object_family(segment)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.recommended_replay_lane(opts = {})
          entry_type = opts[:entry_type].to_s
          identifier = opts[:identifier].to_s.downcase
          object_family = opts[:object_family].to_s
          role_hint = opts[:role_hint].to_s
          permission_strings = Array(opts[:permission_strings]).map(&:to_s)

          return 'graphql_authz_diff' if entry_type == 'graphql_operation' || identifier.include?('graphql')
          return 'ssrf_chain' if identifier.match?(/webhook|callback|import|fetch|avatar|proxy|pdf/)
          return 'sensitive_file_exposure_pack' if identifier.match?(/backup|dump|export|config|\.env|secret|token|key/)

          authz_signal = identifier.match?(/admin|permission|role|member|team|org|account|access/) ||
            !role_hint.empty? ||
            permission_strings.any?

          return 'lifecycle_authz_replay' if authz_signal
          return 'graphql_authz_diff' if object_family.match?(/issue|project|repo|member|role/)

          'manual_recon'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.score_entry(opts = {})
          entry_type = opts[:entry_type].to_s
          identifier = opts[:identifier].to_s.downcase
          role_hint = opts[:role_hint].to_s
          feature_flags = Array(opts[:feature_flags])
          permission_strings = Array(opts[:permission_strings])
          host_pivots = Array(opts[:host_pivots])
          recommended_lane = opts[:recommended_lane].to_s

          score = 24
          score += 14 if entry_type == 'route'
          score += 11 if entry_type == 'graphql_operation'
          score += 8 if entry_type == 'persisted_query_hash'
          score += 18 if identifier.match?(/admin|internal|permission|role|account|member|org|team/)
          score += 11 if identifier.match?(/staging|beta|test|sandbox|preprod/)
          score += 10 if identifier.match?(/api|graphql|rest|endpoint/)
          score += 7 if identifier.match?(/webhook|fetch|import|callback|avatar|pdf/)
          score += 8 unless role_hint.empty?
          score += [feature_flags.length, 4].min * 2
          score += [permission_strings.length, 4].min * 3
          score += [host_pivots.length, 3].min * 2

          score += case recommended_lane
                   when 'lifecycle_authz_replay'
                     8
                   when 'graphql_authz_diff'
                     7
                   when 'ssrf_chain'
                     6
                   when 'sensitive_file_exposure_pack'
                     6
                   else
                     0
                   end

          [[score, 0].max, 100].min
        rescue StandardError => e
          raise e
        end

        private_class_method def self.priority_tier(opts = {})
          score = opts[:score].to_i
          return 'critical' if score >= 85
          return 'high' if score >= 72
          return 'medium' if score >= 55

          'low'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.annotate_alternate_routes!(opts = {})
          entries = Array(opts[:entries]).map { |entry| symbolize_obj(entry) }

          routes_by_family = entries.select do |entry|
            entry[:entry_type] == 'route' && !entry[:object_family].to_s.empty?
          end.group_by { |entry| entry[:object_family] }

          entries.each do |entry|
            object_family = entry[:object_family].to_s
            next if object_family.empty?

            candidates = Array(routes_by_family[object_family]).map { |candidate| candidate[:identifier] }.uniq
            next if candidates.empty?

            alternate = candidates.find { |candidate| candidate != entry[:identifier] }
            entry[:alternate_route_hint] = alternate.to_s
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_burp_seeds(opts = {})
          entries = Array(opts[:entries]).map { |entry| symbolize_obj(entry) }
          base_url = opts[:base_url].to_s.scrub.strip

          seeds = entries.map { |entry| entry[:identifier].to_s }.select { |route| route.start_with?('/') }

          if !base_url.empty? && base_url.match?(%r{\Ahttps?://}i)
            seeds = seeds.map { |route| "#{base_url.chomp('/')}#{route}" }
          end

          seeds.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_entries(opts = {})
          entries = Array(opts[:entries]).map { |entry| symbolize_obj(entry) }

          {
            by_entry_type: tally_by(entries: entries, key: :entry_type),
            by_priority_tier: tally_by(entries: entries, key: :priority_tier),
            by_replay_lane: tally_by(entries: entries, key: :recommended_replay_lane)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.tally_by(opts = {})
          entries = Array(opts[:entries]).map { |entry| symbolize_obj(entry) }
          key = opts[:key].to_sym

          entries.each_with_object(Hash.new(0)) do |entry, accum|
            value = entry[key].to_s
            value = 'unknown' if value.empty?
            accum[value] += 1
          end.sort.to_h
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

        private_class_method def self.normalize_object_family(value)
          token = normalize_token(value)
          return '' if token.empty?
          return token[0..-2] if token.end_with?('s') && token.length > 4

          token
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

        private_class_method def self.parse_json_if_possible(opts = {})
          data = opts[:data].to_s.scrub.strip
          return nil if data.empty?

          JSON.parse(data)
        rescue JSON::ParserError
          nil
        rescue StandardError => e
          raise e
        end

        private_class_method def self.collect_strings(opts = {})
          obj = opts[:obj]

          case obj
          when Hash
            obj.values.flat_map { |value| collect_strings(obj: value) }
          when Array
            obj.flat_map { |value| collect_strings(obj: value) }
          else
            obj.to_s
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
          lines << '# BundleIntel Route Permission Atlas'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Run ID: `#{report[:run_id]}`"
          lines << "- Artifact Count: `#{report[:artifact_count]}`"
          lines << "- Entries: `#{report[:entry_count]}`"
          lines << ''

          lines << '## Ranked Entries'
          entries = Array(report[:entries]).map { |entry| symbolize_obj(entry) }
          if entries.empty?
            lines << '- No route/operation candidates discovered.'
          else
            entries.each do |entry|
              lines << "- [#{entry[:priority_tier]}|#{entry[:priority_score]}] `#{entry[:identifier]}` (#{entry[:entry_type]})"
              lines << "  - lane: `#{entry[:recommended_replay_lane]}` role_hint=`#{entry[:role_hint]}` object_family=`#{entry[:object_family]}`"
              lines << "  - alternate_route_hint: `#{entry[:alternate_route_hint]}`" unless entry[:alternate_route_hint].to_s.empty?
              lines << "  - feature_flags: `#{Array(entry[:feature_flags]).first(6).join(', ')}`" unless Array(entry[:feature_flags]).empty?
              lines << "  - permission_strings: `#{Array(entry[:permission_strings]).first(6).join(', ')}`" unless Array(entry[:permission_strings]).empty?
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
