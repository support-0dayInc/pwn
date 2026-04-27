# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'socket'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplayCaptureAdaptersSmokeTest < Minitest::Test
  class TinyCaptureServer
    attr_reader :base_url

    def initialize
      @server = TCPServer.new('127.0.0.1', 0)
      @port = @server.addr[1]
      @base_url = "http://127.0.0.1:#{@port}"
      @shutdown = false
      @thread = Thread.new { run }
    end

    def close
      @shutdown = true
      begin
        TCPSocket.new('127.0.0.1', @port).close
      rescue StandardError
        nil
      end
      @thread.join(2)
      @server.close
    rescue StandardError
      nil
    end

    private

    def run
      until @shutdown
        begin
          socket = @server.accept
          handle_client(socket)
        rescue StandardError
          next
        end
      end
    end

    def handle_client(socket)
      request_line = socket.gets
      return socket.close if request_line.nil?

      method, path, _http_version = request_line.split(' ')
      headers = {}
      while (line = socket.gets)
        break if line == "\r\n"

        key, value = line.split(':', 2)
        headers[key] = value.to_s.strip
      end

      body = ''
      content_length = headers['Content-Length'].to_i
      body = socket.read(content_length) if content_length.positive?

      response = dispatch(method: method, path: path, headers: headers, body: body)
      write_response(socket: socket, response: response)
      socket.close
    rescue StandardError
      socket.close rescue nil
    end

    def dispatch(method:, path:, headers:, body:)
      actor = headers['X-Actor'].to_s

      if method == 'GET' && path == '/settings'
        return [403, { 'Content-Type' => 'text/html' }, '<html><body>Forbidden</body></html>'] if actor == 'revoked_user'

        return [200, { 'Content-Type' => 'text/html' }, '<html><body>Settings</body></html>']
      end

      if method == 'GET' && path == '/api/meta'
        return [403, { 'Content-Type' => 'application/json' }, JSON.dump(error: 'forbidden')] if actor == 'revoked_user'

        return [200, { 'Content-Type' => 'application/json' }, JSON.dump(repo: 'private-repo', visibility: 'private')]
      end

      if method == 'POST' && path == '/graphql'
        payload = JSON.parse(body)
        if actor == 'revoked_user'
          denied = {
            errors: [
              {
                message: 'Forbidden: viewer cannot access repository'
              }
            ],
            data: nil
          }
          return [200, { 'Content-Type' => 'application/json' }, JSON.dump(denied)]
        end

        ok = {
          data: {
            repository: {
              name: 'private-repo'
            }
          },
          operationName: payload['operationName']
        }
        return [200, { 'Content-Type' => 'application/json' }, JSON.dump(ok)]
      end

      [404, { 'Content-Type' => 'application/json' }, JSON.dump(error: 'not found')]
    rescue JSON::ParserError
      [400, { 'Content-Type' => 'application/json' }, JSON.dump(error: 'bad json')]
    end

    def write_response(socket:, response:)
      status, headers, body = response
      reason = {
        200 => 'OK',
        400 => 'Bad Request',
        403 => 'Forbidden',
        404 => 'Not Found'
      }[status] || 'OK'

      headers = headers.dup
      headers['Content-Length'] = body.bytesize.to_s

      socket.write("HTTP/1.1 #{status} #{reason}\r\n")
      headers.each { |key, value| socket.write("#{key}: #{value}\r\n") }
      socket.write("\r\n")
      socket.write(body)
    end
  end

  def test_execute_capture_matrix_records_adapter_artifacts
    server = TinyCaptureServer.new

    Dir.mktmpdir('lifecycle-capture-adapters-smoke-') do |tmp_dir|
      plan = {
        campaign: {
          id: 'acme-lifecycle-capture',
          target: server.base_url,
          change_event: 'remove_collaborator'
        },
        actors: [
          {
            id: 'owner',
            session: {
              headers: {
                'X-Actor' => 'owner'
              }
            }
          },
          {
            id: 'revoked_user',
            session: {
              headers: {
                'X-Actor' => 'revoked_user'
              }
            }
          }
        ],
        surfaces: [
          {
            id: 'settings_page',
            adapter: {
              type: 'browser',
              use_transparent_browser: false,
              request: {
                method: 'GET',
                url: "#{server.base_url}/settings"
              }
            }
          },
          {
            id: 'metadata_api',
            adapter: {
              type: 'http',
              request: {
                method: 'GET',
                url: "#{server.base_url}/api/meta"
              }
            }
          },
          {
            id: 'repo_graphql',
            adapter: {
              type: 'graphql',
              url: "#{server.base_url}/graphql",
              operation_name: 'RepoQuery',
              query: 'query RepoQuery { repository { name } }',
              variables: {}
            }
          }
        ],
        checkpoints: %w[pre_change post_change_t0],
        expected_denied_after: ['post_change_t0']
      }

      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
        plan: plan,
        output_dir: tmp_dir,
        run_id: 'capture-adapters-smoke'
      )

      pre_exec = PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
        run_obj: run_obj,
        checkpoint: 'pre_change',
        actor: 'owner'
      )

      post_exec = PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user'
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)

      assert_equal(3, pre_exec[:attempted_cells])
      assert_equal(0, pre_exec[:failed_cells])
      assert_equal(3, post_exec[:attempted_cells])
      assert_equal(0, post_exec[:failed_cells])
      assert_equal(0, summary[:totals][:stale_access_findings])

      execution_path = File.join(tmp_dir, 'capture-adapters-smoke', 'capture_execution.json')
      assert(File.exist?(execution_path))

      gql_capture_path = File.join(
        tmp_dir,
        'capture-adapters-smoke',
        'artifacts',
        'post_change_t0',
        'revoked_user',
        'repo_graphql.capture',
        'response.body.txt'
      )
      assert(File.exist?(gql_capture_path))
    end
  ensure
    server.close if server
  end
end
