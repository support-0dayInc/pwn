# frozen_string_literal: true

require 'fileutils'
require 'json'

module PWN
  module Bounty
    module LifecycleAuthzReplay
      module CaptureAdapters
        # Shared adapter helpers.
        module Base
          private_class_method def self.normalize_token(token)
            token.to_s.strip.downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_+|_+$/, '')
          rescue StandardError => e
            raise e
          end

          private_class_method def self.symbolize_obj(obj)
            case obj
            when Array
              obj.map { |entry| symbolize_obj(entry) }
            when Hash
              obj.each_with_object({}) do |(key, value), accum|
                key_sym = key.respond_to?(:to_sym) ? key.to_sym : key
                accum[key_sym] = symbolize_obj(value)
              end
            else
              obj
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.deep_merge_hashes(base_hash, overlay_hash)
            base = symbolize_obj(base_hash || {})
            overlay = symbolize_obj(overlay_hash || {})

            base.merge(overlay) do |_key, old_val, new_val|
              if old_val.is_a?(Hash) && new_val.is_a?(Hash)
                deep_merge_hashes(old_val, new_val)
              else
                new_val
              end
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.adapter_cfg_for_checkpoint(opts = {})
            adapter_cfg = symbolize_obj(opts[:adapter_cfg] || {})
            checkpoint = normalize_token(opts[:checkpoint])

            checkpoint_overrides = symbolize_obj(adapter_cfg[:checkpoint_overrides] || {})
            checkpoint_cfg = symbolize_obj(checkpoint_overrides[checkpoint] || checkpoint_overrides[:default] || {})

            deep_merge_hashes(adapter_cfg, checkpoint_cfg)
          rescue StandardError => e
            raise e
          end

          private_class_method def self.actor_session_profile(opts = {})
            actor_record = symbolize_obj(opts[:actor_record] || {})
            actor_metadata = symbolize_obj(actor_record[:metadata] || {})
            session = symbolize_obj(actor_metadata[:session] || {})

            headers = symbolize_obj(session[:headers] || {})
            headers = deep_merge_hashes(headers, symbolize_obj(actor_metadata[:headers] || {}))

            cookies = symbolize_obj(session[:cookies] || {})
            cookies = deep_merge_hashes(cookies, symbolize_obj(actor_metadata[:cookies] || {}))

            bearer_token = session[:bearer_token].to_s
            bearer_token = actor_metadata[:bearer_token].to_s if bearer_token.empty?

            {
              headers: headers,
              cookies: cookies,
              bearer_token: bearer_token
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.capture_dir(opts = {})
            run_obj = opts[:run_obj]
            checkpoint = normalize_token(opts[:checkpoint])
            actor = normalize_token(opts[:actor])
            surface = normalize_token(opts[:surface])

            path = File.join(run_obj[:artifacts_dir], checkpoint, actor, "#{surface}.capture")
            FileUtils.mkdir_p(path)
            path
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_json(path:, obj:)
            FileUtils.mkdir_p(File.dirname(path))
            File.write(path, JSON.pretty_generate(symbolize_obj(obj || {})))
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_text(path:, text:)
            FileUtils.mkdir_p(File.dirname(path))
            File.write(path, text.to_s)
          rescue StandardError => e
            raise e
          end

          private_class_method def self.merge_headers(opts = {})
            actor_profile = symbolize_obj(opts[:actor_profile] || {})
            request_headers = symbolize_obj(opts[:request_headers] || {})

            merged = {}
            actor_profile[:headers].to_h.each do |key, value|
              merged[key.to_s] = value.to_s
            end
            request_headers.each do |key, value|
              merged[key.to_s] = value.to_s
            end

            bearer_token = actor_profile[:bearer_token].to_s
            merged['Authorization'] = "Bearer #{bearer_token}" unless bearer_token.empty? || merged.key?('Authorization')

            merged
          rescue StandardError => e
            raise e
          end

          private_class_method def self.merge_cookies(opts = {})
            actor_profile = symbolize_obj(opts[:actor_profile] || {})
            request_cookies = symbolize_obj(opts[:request_cookies] || {})

            merged = {}
            actor_profile[:cookies].to_h.each do |key, value|
              merged[key.to_s] = value.to_s
            end
            request_cookies.each do |key, value|
              merged[key.to_s] = value.to_s
            end

            return '' if merged.empty?

            merged.map { |name, value| "#{name}=#{value}" }.join('; ')
          rescue StandardError => e
            raise e
          end

          private_class_method def self.status_from_http(opts = {})
            adapter_cfg = symbolize_obj(opts[:adapter_cfg] || {})
            http_status = opts[:http_status].to_i

            denied_statuses = Array(adapter_cfg[:denied_http_statuses] || [401, 403]).map(&:to_i)
            accessible_statuses = Array(adapter_cfg[:accessible_http_statuses] || [200, 201, 202, 204, 206, 301, 302, 307, 308]).map(&:to_i)

            return 'denied' if denied_statuses.include?(http_status)
            return 'accessible' if accessible_statuses.include?(http_status)

            'unknown'
          rescue StandardError => e
            raise e
          end
        end
      end
    end
  end
end
