# frozen_string_literal: true

require 'json'
require 'time'

module PWN
  module Bounty
    module LifecycleAuthzReplay
      # Detect direct-denied vs derived-artifact-accessible drift across
      # post-change checkpoints and actors.
      module ArtifactAccessDriftMatrix
        DERIVED_ROUTE_FAMILIES = %w[artifact export notification].freeze

        # Supported Method Parameters::
        # matrix = PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix.evaluate(
        #   run_obj: run_obj
        # )
        public_class_method def self.evaluate(opts = {})
          run_obj = opts[:run_obj]
          raise 'run_obj is required' unless run_obj.is_a?(Hash)

          plan = symbolize_obj(run_obj[:plan] || {})
          cells = Array(run_obj.dig(:coverage_matrix, :cells)).map { |cell| symbolize_obj(cell) }

          surface_lookup = build_surface_lookup(surfaces: plan[:surfaces])
          expected_denied_after = Array(plan[:expected_denied_after]).map { |checkpoint| normalize_token(checkpoint) }
          expected_denied_after = Array(plan[:checkpoints]).map { |checkpoint| normalize_token(checkpoint) } if expected_denied_after.empty?

          observations = cells.filter_map do |cell|
            checkpoint = normalize_token(cell[:checkpoint])
            next unless expected_denied_after.include?(checkpoint)
            next if normalize_token(cell[:status]) == 'missing'

            surface_meta = symbolize_obj(surface_lookup[cell[:surface].to_s] || {})
            route_family = normalize_route_family(route_family: surface_meta[:route_family])
            next if route_family.empty?

            evidence = parse_evidence(evidence_path: cell[:evidence_path])
            response = symbolize_obj(evidence[:response] || {})
            request = symbolize_obj(evidence[:request] || {})
            headers = symbolize_obj(response[:headers] || {})

            {
              checkpoint: checkpoint,
              actor: cell[:actor].to_s,
              surface: cell[:surface].to_s,
              route_family: route_family,
              status: normalize_token(cell[:status]),
              evidence_path: cell[:evidence_path].to_s,
              http_status: response[:http_status],
              method: request[:method].to_s.upcase,
              auth_context: auth_context(request: request),
              redirect_chain: normalize_redirect_chain(response: response),
              cache_headers: extract_cache_headers(headers: headers),
              content_hash: extract_content_hash(response: response, headers: headers),
              family_key: family_key(
                surface_meta: surface_meta,
                cell: cell,
                evidence: evidence
              )
            }
          end

          families = observations.group_by { |entry| entry[:family_key] }

          family_results = families.map do |family_key, family_observations|
            build_family_result(family_key: family_key, observations: family_observations)
          end

          family_results.sort_by! do |family|
            [-family_rank(report_angle: family[:report_angle]), family[:family_key]]
          end

          {
            generated_at: Time.now.utc.iso8601,
            family_count: family_results.length,
            reportable_candidate_count: family_results.count { |family| family[:report_angle] == 'direct_denied_derived_accessible' },
            families: family_results,
            summary: summarize(family_results: family_results)
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
              matrix = PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix.evaluate(
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

        private_class_method def self.normalize_route_family(opts = {})
          route_family = normalize_token(opts[:route_family])
          return route_family unless route_family.empty?

          token_space = [opts[:surface_id], opts[:surface_label]].map { |entry| normalize_token(entry) }.join('_')
          return 'direct' if token_space.include?('settings') || token_space.include?('member') || token_space.include?('collaborator') || token_space.include?('api')
          return 'artifact' if token_space.include?('artifact') || token_space.include?('attachment') || token_space.include?('blob')
          return 'export' if token_space.include?('export') || token_space.include?('download')
          return 'notification' if token_space.include?('notification') || token_space.include?('activity') || token_space.include?('timeline')

          'secondary'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_evidence(opts = {})
          evidence_path = opts[:evidence_path].to_s
          return {} if evidence_path.empty?
          return {} unless File.exist?(evidence_path)

          symbolize_obj(JSON.parse(File.read(evidence_path)))
        rescue JSON::ParserError
          {}
        rescue StandardError => e
          raise e
        end

        private_class_method def self.family_key(opts = {})
          surface_meta = symbolize_obj(opts[:surface_meta] || {})
          cell = symbolize_obj(opts[:cell] || {})
          evidence = symbolize_obj(opts[:evidence] || {})
          actor = normalize_token(cell[:actor])
          actor = 'actor' if actor.empty?

          metadata = symbolize_obj(surface_meta[:metadata] || {})
          explicit = metadata.dig(:artifact_access_drift, :object_family) || metadata[:object_family]
          explicit = explicit.to_s.strip
          unless explicit.empty?
            return "#{normalize_token(explicit)}:#{actor}"
          end

          path_hint = evidence.dig(:request, :url).to_s
          path_hint = cell[:surface].to_s if path_hint.empty?

          object_token = infer_object_token_from_url(url: path_hint)
          return "#{object_token}:#{actor}" unless object_token.empty?

          "#{normalize_token(path_hint)}:#{actor}"
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_object_token_from_url(opts = {})
          url = opts[:url].to_s
          return '' if url.empty?

          object_match = url.match(%r{/(?:objects?|issues?|pulls?|repos?)/([^/?#]+)}i)
          return '' if object_match.nil?

          token = object_match[1].to_s
          token = token.split('.').first.to_s
          token = normalize_token(token)
          return '' if token.empty?

          "object_#{token}"
        rescue StandardError => e
          raise e
        end

        private_class_method def self.auth_context(opts = {})
          request = symbolize_obj(opts[:request] || {})
          headers = symbolize_obj(request[:headers] || {})
          header_text = headers.to_json.downcase

          return 'authenticated' if header_text.include?('authorization') || header_text.include?('cookie')

          'anonymous_or_unknown'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_redirect_chain(opts = {})
          response = symbolize_obj(opts[:response] || {})
          chain = response[:redirect_chain]
          chain = Array(chain).map(&:to_s)
          return chain unless chain.empty?

          headers = symbolize_obj(response[:headers] || {})
          location = headers['Location'] || headers[:Location] || headers['location'] || headers[:location]
          return [] if location.to_s.empty?

          [location.to_s]
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_cache_headers(opts = {})
          headers = symbolize_obj(opts[:headers] || {})

          {
            cache_control: headers['Cache-Control'] || headers[:'Cache-Control'] || headers['cache-control'] || headers[:cache_control],
            expires: headers['Expires'] || headers[:Expires] || headers['expires'] || headers[:expires],
            etag: headers['ETag'] || headers[:ETag] || headers['etag'] || headers[:etag]
          }.reject { |_key, value| value.nil? || value.to_s.empty? }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_content_hash(opts = {})
          response = symbolize_obj(opts[:response] || {})
          headers = symbolize_obj(opts[:headers] || {})

          response[:body_sha256] || response[:content_sha256] ||
            headers['X-Content-SHA256'] || headers[:'X-Content-SHA256'] || headers['x-content-sha256'] || headers[:x_content_sha256]
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_family_result(opts = {})
          family_key = opts[:family_key].to_s
          observations = Array(opts[:observations]).map { |entry| symbolize_obj(entry) }

          direct_denied = observations.any? do |entry|
            entry[:route_family] == 'direct' && entry[:status] == 'denied'
          end

          derived_accessible_observations = observations.select do |entry|
            DERIVED_ROUTE_FAMILIES.include?(entry[:route_family]) && entry[:status] == 'accessible'
          end

          derived_accessible = !derived_accessible_observations.empty?
          surviving_derived_routes = derived_accessible_observations.map { |entry| entry[:surface] }.uniq

          report_angle = if direct_denied && derived_accessible
                           'direct_denied_derived_accessible'
                         elsif derived_accessible
                           'derived_access_without_direct_deny'
                         elsif direct_denied
                           'direct_denied_only'
                         else
                           'inconclusive'
                         end

          {
            family_key: family_key,
            observation_count: observations.length,
            direct_denied: direct_denied,
            derived_accessible: derived_accessible,
            surviving_derived_routes: surviving_derived_routes,
            report_angle: report_angle,
            best_next_capture: best_next_capture(report_angle: report_angle),
            observations: observations
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.best_next_capture(opts = {})
          case normalize_token(opts[:report_angle])
          when 'direct_denied_derived_accessible'
            'Capture one adjacent post-change checkpoint and preserve response hashes/headers for the derived route.'
          when 'derived_access_without_direct_deny'
            'Capture direct route denial at the same checkpoint/actor to complete contradiction proof.'
          when 'direct_denied_only'
            'Probe at least one derived artifact/export/notification route for the same object family.'
          else
            'Expand route coverage with one direct and one derived surface at the same post-change checkpoint.'
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize(opts = {})
          family_results = Array(opts[:family_results]).map { |entry| symbolize_obj(entry) }

          {
            direct_denied_derived_accessible: family_results.count { |family| family[:report_angle] == 'direct_denied_derived_accessible' },
            derived_access_without_direct_deny: family_results.count { |family| family[:report_angle] == 'derived_access_without_direct_deny' },
            direct_denied_only: family_results.count { |family| family[:report_angle] == 'direct_denied_only' },
            inconclusive: family_results.count { |family| family[:report_angle] == 'inconclusive' }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.family_rank(opts = {})
          case normalize_token(opts[:report_angle])
          when 'direct_denied_derived_accessible'
            4
          when 'derived_access_without_direct_deny'
            3
          when 'direct_denied_only'
            2
          else
            1
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
