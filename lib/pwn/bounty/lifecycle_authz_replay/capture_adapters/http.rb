# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module PWN
  module Bounty
    module LifecycleAuthzReplay
      module CaptureAdapters
        module HTTP
          public_class_method def self.capture(opts = {})
            run_obj = opts[:run_obj]
            checkpoint = opts[:checkpoint]
            actor_record = opts[:actor_record]
            surface_record = opts[:surface_record]
            adapter_cfg = opts[:adapter_cfg]

            checkpoint_cfg = Base.send(
              :adapter_cfg_for_checkpoint,
              adapter_cfg: adapter_cfg,
              checkpoint: checkpoint
            )

            actor_profile = Base.send(:actor_session_profile, actor_record: actor_record)

            request_cfg = Base.send(:symbolize_obj, checkpoint_cfg[:request] || {})
            method = request_cfg[:method].to_s.strip.upcase
            method = 'GET' if method.empty?

            url = request_cfg[:url].to_s.strip
            url = checkpoint_cfg[:url].to_s.strip if url.empty?
            raise "surface #{surface_record[:id]} adapter request.url is required" if url.empty?

            uri = URI.parse(url)
            request_class = request_class_for(method)

            headers = Base.send(
              :merge_headers,
              actor_profile: actor_profile,
              request_headers: request_cfg[:headers] || {}
            )

            cookie_header = Base.send(
              :merge_cookies,
              actor_profile: actor_profile,
              request_cookies: request_cfg[:cookies] || {}
            )
            headers['Cookie'] = cookie_header unless cookie_header.empty?

            body = request_cfg[:body]
            if body.is_a?(Hash) || body.is_a?(Array)
              body = JSON.dump(body)
              headers['Content-Type'] ||= 'application/json'
            end

            request = request_class.new(uri)
            headers.each do |header_name, header_value|
              request[header_name] = header_value.to_s
            end
            request.body = body.to_s unless body.nil?

            open_timeout = checkpoint_cfg[:open_timeout].to_i
            open_timeout = 10 if open_timeout <= 0
            read_timeout = checkpoint_cfg[:read_timeout].to_i
            read_timeout = 20 if read_timeout <= 0

            response = nil
            Net::HTTP.start(
              uri.host,
              uri.port,
              use_ssl: uri.scheme == 'https',
              open_timeout: open_timeout,
              read_timeout: read_timeout
            ) do |http|
              response = http.request(request)
            end

            response_body = response.body.to_s
            response_status = response.code.to_i
            response_headers = response.each_header.to_h

            capture_dir = Base.send(
              :capture_dir,
              run_obj: run_obj,
              checkpoint: checkpoint,
              actor: actor_record[:id],
              surface: surface_record[:id]
            )

            request_path = File.join(capture_dir, 'request.json')
            response_headers_path = File.join(capture_dir, 'response.headers.json')
            response_body_path = File.join(capture_dir, 'response.body.txt')

            Base.send(
              :write_json,
              path: request_path,
              obj: {
                method: method,
                url: url,
                headers: headers,
                body: body
              }
            )
            Base.send(:write_json, path: response_headers_path, obj: response_headers)
            Base.send(:write_text, path: response_body_path, text: response_body)

            {
              status: Base.send(:status_from_http, adapter_cfg: checkpoint_cfg, http_status: response_status),
              request: {
                method: method,
                url: url,
                headers: headers,
                body: body
              },
              response: {
                http_status: response_status,
                headers: response_headers,
                body_path: response_body_path,
                body_preview: response_body[0, 2048]
              },
              notes: "http capture #{method} #{url} -> #{response_status}",
              artifact_paths: [request_path, response_headers_path, response_body_path]
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.request_class_for(method)
            case method.to_s.upcase
            when 'GET'
              Net::HTTP::Get
            when 'POST'
              Net::HTTP::Post
            when 'PUT'
              Net::HTTP::Put
            when 'PATCH'
              Net::HTTP::Patch
            when 'DELETE'
              Net::HTTP::Delete
            when 'HEAD'
              Net::HTTP::Head
            else
              raise "unsupported HTTP method: #{method}"
            end
          rescue StandardError => e
            raise e
          end
        end
      end
    end
  end
end
