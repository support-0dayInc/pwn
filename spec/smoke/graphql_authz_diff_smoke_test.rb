# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'socket'
require 'tmpdir'
require 'pwn'

class GraphQLAuthzDiffSmokeTest < Minitest::Test
  class TinyGraphQLServer
    attr_reader :endpoint

    def initialize
      @server = TCPServer.new('127.0.0.1', 0)
      @port = @server.addr[1]
      @endpoint = "http://127.0.0.1:#{@port}/graphql"
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
      return [404, { 'Content-Type' => 'application/json' }, JSON.dump(error: 'not found')] unless method == 'POST' && path == '/graphql'

      actor = headers['X-Actor'].to_s
      payload = JSON.parse(body)
      operation_name = payload['operationName'].to_s

      case operation_name
      when 'AdminSecrets'
        if actor == 'revoked_user'
          # intentionally vulnerable behavior for authz-diff detection
          return [200, { 'Content-Type' => 'application/json' }, JSON.dump(data: { adminSecrets: [{ id: 't1', token: 'leaked' }] })]
        end

        return [200, { 'Content-Type' => 'application/json' }, JSON.dump(data: { adminSecrets: [{ id: 't1', token: 'owner-only' }] })]
      when 'TeamPrivate'
        if actor == 'revoked_user'
          denied = {
            errors: [{ message: 'Forbidden: viewer cannot access team data' }],
            data: {
              team: {
                id: 't1',
                name: nil
              }
            }
          }
          return [200, { 'Content-Type' => 'application/json' }, JSON.dump(denied)]
        end

        return [200, { 'Content-Type' => 'application/json' }, JSON.dump(data: { team: { id: 't1', name: 'Acme' } })]
      else
        [200, { 'Content-Type' => 'application/json' }, JSON.dump(data: {})]
      end
    rescue JSON::ParserError
      [400, { 'Content-Type' => 'application/json' }, JSON.dump(error: 'bad json')]
    end

    def write_response(socket:, response:)
      status, headers, body = response
      reason = {
        200 => 'OK',
        400 => 'Bad Request',
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

  def test_graphql_authz_diff_flags_unexpected_access
    server = TinyGraphQLServer.new

    Dir.mktmpdir('graphql-authz-diff-smoke-') do |tmp_dir|
      report = PWN::Bounty::GraphQLAuthzDiff.run_diff(
        endpoint: server.endpoint,
        actors: [
          {
            id: 'owner',
            label: 'Owner',
            session: {
              headers: {
                'X-Actor' => 'owner'
              }
            },
            expected_access_default: true
          },
          {
            id: 'revoked_user',
            label: 'Revoked User',
            session: {
              headers: {
                'X-Actor' => 'revoked_user'
              }
            },
            expected_access_default: false
          }
        ],
        operations: [
          {
            id: 'admin_secrets',
            operation_name: 'AdminSecrets',
            query: 'query AdminSecrets { adminSecrets { id token } }',
            expected_access: {
              owner: true,
              revoked_user: false
            }
          },
          {
            id: 'team_private',
            operation_name: 'TeamPrivate',
            query: 'query TeamPrivate { team { id name } }',
            expected_access: {
              owner: true,
              revoked_user: false
            }
          }
        ],
        output_dir: tmp_dir,
        run_id: 'graphql-authz-diff-smoke',
        surface_evidence: [
          {
            operation_id: 'team_private',
            route_family: 'direct'
          },
          {
            operation_id: 'admin_secrets',
            route_family: 'alternate'
          }
        ],
        object_seeds: [
          {
            id: 't1',
            aliases: ['team_private', 'admin_secrets']
          }
        ]
      )

      assert_equal('graphql-authz-diff-smoke', report[:run_id])
      assert(report[:finding_count] >= 1)
      assert(report[:findings].any? { |finding| finding[:id].include?('admin_secrets:revoked_user:unexpected_access') })
      assert(report[:cross_surface_family_count] >= 1)
      assert(report[:cross_surface_reportable_count] >= 1)
      assert_equal('cross_surface_authz_drift', report.dig(:cross_surface_object_lineage, :families, 0, :report_angle))

      json_report = File.join(tmp_dir, 'graphql-authz-diff-smoke', 'graphql_authz_diff.json')
      markdown_report = File.join(tmp_dir, 'graphql-authz-diff-smoke', 'graphql_authz_diff.md')
      lineage_json = File.join(tmp_dir, 'graphql-authz-diff-smoke', 'cross_surface_object_lineage.json')
      lineage_markdown = File.join(tmp_dir, 'graphql-authz-diff-smoke', 'cross_surface_object_lineage.md')
      assert(File.exist?(json_report))
      assert(File.exist?(markdown_report))
      assert(File.exist?(lineage_json))
      assert(File.exist?(lineage_markdown))
    end
  ensure
    server.close if server
  end
end
