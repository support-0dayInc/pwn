# frozen_string_literal: true

require 'json'

module PWN
  module Bounty
    module LifecycleAuthzReplay
      module CaptureAdapters
        module GraphQL
          DENIED_ERROR_PATTERNS = [
            /forbidden/i,
            /unauthor/i,
            /access\s*denied/i,
            /permission/i,
            /not\s*allowed/i
          ].freeze

          public_class_method def self.capture(opts = {})
            checkpoint = opts[:checkpoint]
            actor_record = opts[:actor_record]
            surface_record = opts[:surface_record]
            adapter_cfg = opts[:adapter_cfg]

            checkpoint_cfg = Base.send(
              :adapter_cfg_for_checkpoint,
              adapter_cfg: adapter_cfg,
              checkpoint: checkpoint
            )

            request_cfg = Base.send(:symbolize_obj, checkpoint_cfg[:request] || {})
            request_cfg = {
              method: 'POST',
              url: checkpoint_cfg[:url] || request_cfg[:url],
              headers: Base.send(
                :deep_merge_hashes,
                request_cfg[:headers] || {},
                { 'Content-Type' => 'application/json' }
              ),
              body: {
                query: checkpoint_cfg[:query] || request_cfg[:query],
                operationName: checkpoint_cfg[:operation_name] || request_cfg[:operation_name],
                variables: checkpoint_cfg[:variables] || request_cfg[:variables] || {}
              }
            }

            if request_cfg[:body][:query].to_s.strip.empty?
              raise "surface #{surface_record[:id]} graphql adapter requires query"
            end

            http_capture = HTTP.capture(
              run_obj: opts[:run_obj],
              checkpoint: checkpoint,
              actor_record: actor_record,
              surface_record: surface_record,
              adapter_cfg: Base.send(
                :deep_merge_hashes,
                checkpoint_cfg,
                { request: request_cfg }
              )
            )

            graphql_status = classify_graphql_status(http_capture: http_capture)
            parsed = parse_graphql_response(http_capture: http_capture)

            response_payload = Base.send(:symbolize_obj, http_capture[:response] || {})
            response_payload[:graphql] = parsed

            {
              status: graphql_status,
              request: http_capture[:request],
              response: response_payload,
              notes: "graphql capture #{request_cfg[:body][:operationName] || 'operation'} -> #{response_payload[:http_status]}",
              artifact_paths: http_capture[:artifact_paths]
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.classify_graphql_status(opts = {})
            http_capture = Base.send(:symbolize_obj, opts[:http_capture] || {})
            response = Base.send(:symbolize_obj, http_capture[:response] || {})

            http_status = response[:http_status].to_i
            http_status_result = Base.send(:status_from_http, adapter_cfg: {}, http_status: http_status)
            return http_status_result if http_status_result == 'denied'

            parsed = parse_graphql_response(http_capture: http_capture)
            errors = Array(parsed[:errors])
            data_present = !parsed[:data].nil?

            denied_by_error = errors.any? do |error|
              message = Base.send(:symbolize_obj, error)[:message].to_s
              DENIED_ERROR_PATTERNS.any? { |pattern| message.match?(pattern) }
            end

            return 'denied' if denied_by_error
            return 'accessible' if data_present && errors.empty? && http_status.positive?

            http_status_result
          rescue StandardError => e
            raise e
          end

          private_class_method def self.parse_graphql_response(opts = {})
            http_capture = Base.send(:symbolize_obj, opts[:http_capture] || {})
            response = Base.send(:symbolize_obj, http_capture[:response] || {})
            body_path = response[:body_path].to_s
            return {} if body_path.empty? || !File.exist?(body_path)

            body = File.read(body_path)
            parsed = JSON.parse(body)
            Base.send(:symbolize_obj, parsed)
          rescue JSON::ParserError
            {}
          rescue StandardError => e
            raise e
          end
        end
      end
    end
  end
end
