# frozen_string_literal: true

module PWN
  module Bounty
    module LifecycleAuthzReplay
      module CaptureAdapters
        module Browser
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

            use_transparent_browser = checkpoint_cfg[:use_transparent_browser] == true
            if use_transparent_browser
              begin
                return capture_via_transparent_browser(
                  run_obj: opts[:run_obj],
                  checkpoint: checkpoint,
                  actor_record: actor_record,
                  surface_record: surface_record,
                  checkpoint_cfg: checkpoint_cfg
                )
              rescue StandardError => e
                return fallback_http_capture(
                  opts: opts,
                  checkpoint_cfg: checkpoint_cfg,
                  fallback_reason: "transparent_browser_failed: #{e.message}"
                )
              end
            end

            fallback_http_capture(
              opts: opts,
              checkpoint_cfg: checkpoint_cfg,
              fallback_reason: 'transparent_browser_disabled'
            )
          rescue StandardError => e
            raise e
          end

          private_class_method def self.capture_via_transparent_browser(opts = {})
            run_obj = opts[:run_obj]
            checkpoint = opts[:checkpoint]
            actor_record = opts[:actor_record]
            surface_record = opts[:surface_record]
            checkpoint_cfg = Base.send(:symbolize_obj, opts[:checkpoint_cfg] || {})

            request_cfg = Base.send(:symbolize_obj, checkpoint_cfg[:request] || {})
            url = request_cfg[:url].to_s.strip
            url = checkpoint_cfg[:url].to_s.strip if url.empty?
            raise "surface #{surface_record[:id]} browser adapter requires url" if url.empty?

            browser_type = checkpoint_cfg[:browser_type].to_s.strip
            browser_type = 'headless' if browser_type.empty?

            browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: browser_type.to_sym)
            browser = browser_obj[:browser]
            browser.goto(url)

            page_html = browser.html.to_s
            page_title = browser.title.to_s

            capture_dir = Base.send(
              :capture_dir,
              run_obj: run_obj,
              checkpoint: checkpoint,
              actor: actor_record[:id],
              surface: surface_record[:id]
            )

            html_path = File.join(capture_dir, 'page.html')
            screenshot_path = File.join(capture_dir, 'screenshot.png')

            Base.send(:write_text, path: html_path, text: page_html)
            begin
              browser.screenshot.save(screenshot_path)
            rescue StandardError
              screenshot_path = nil
            end

            artifact_paths = [html_path]
            artifact_paths << screenshot_path unless screenshot_path.nil?

            {
              status: page_html.empty? ? 'unknown' : 'accessible',
              request: {
                method: 'GET',
                url: url
              },
              response: {
                page_title: page_title,
                html_path: html_path,
                screenshot_path: screenshot_path
              },
              notes: "browser capture GET #{url}",
              artifact_paths: artifact_paths.compact
            }
          ensure
            PWN::Plugins::TransparentBrowser.close(browser_obj: browser_obj) if defined?(browser_obj)
          end

          private_class_method def self.fallback_http_capture(opts = {})
            original_opts = opts[:opts] || {}
            checkpoint_cfg = Base.send(:symbolize_obj, opts[:checkpoint_cfg] || {})
            fallback_reason = opts[:fallback_reason].to_s

            request_cfg = Base.send(:symbolize_obj, checkpoint_cfg[:request] || {})
            request_cfg[:method] ||= 'GET'
            request_cfg[:headers] = Base.send(
              :deep_merge_hashes,
              request_cfg[:headers] || {},
              { Accept: 'text/html,application/xhtml+xml' }
            )

            http_capture = HTTP.capture(
              run_obj: original_opts[:run_obj],
              checkpoint: original_opts[:checkpoint],
              actor_record: original_opts[:actor_record],
              surface_record: original_opts[:surface_record],
              adapter_cfg: Base.send(
                :deep_merge_hashes,
                checkpoint_cfg,
                { request: request_cfg }
              )
            )

            http_capture[:notes] = [http_capture[:notes], "browser_fallback_reason=#{fallback_reason}"].reject(&:empty?).join(' | ')
            http_capture
          rescue StandardError => e
            raise e
          end
        end
      end
    end
  end
end
