# frozen_string_literal: true

require 'json'

module PWN
  module AI
    module MCP
      # Minimal stdio MCP server implementation (JSON-RPC over LSP framing).
      module Server
        module_function

        PROTOCOL_VERSION = '2024-11-05'
        SERVER_NAME = 'pwn-ai-mcp'

        def run!(io_in: $stdin, io_out: $stdout)
          loop do
            request = read_message(io_in)
            break if request.nil?

            begin
              response = handle_request(request)
              write_message(io_out, response) if response
            rescue StandardError => e
              if request.is_a?(Hash) && request['id']
                write_message(io_out, error_response(id: request['id'], code: -32603, message: e.message))
              end
            end
          end
        end

        def handle_request(request)
          method = request['method']

          case method
          when 'initialize'
            success_response(
              id: request['id'],
              result: {
                protocolVersion: PROTOCOL_VERSION,
                serverInfo: {
                  name: SERVER_NAME,
                  version: (defined?(PWN::VERSION) ? PWN::VERSION : 'unknown')
                },
                capabilities: {
                  tools: {}
                }
              }
            )
          when 'notifications/initialized'
            nil
          when 'ping'
            success_response(id: request['id'], result: {})
          when 'tools/list'
            success_response(id: request['id'], result: { tools: Registry.list_tools })
          when 'tools/call'
            params = request['params'] || {}
            tool_name = params['name']
            arguments = params['arguments'] || {}
            tool_response = Registry.call_tool(name: tool_name, arguments: arguments)

            safe_tool_response = deep_json_safe(tool_response)
            success_response(
              id: request['id'],
              result: {
                content: [
                  {
                    type: 'text',
                    text: JSON.pretty_generate(safe_tool_response)
                  }
                ],
                isError: tool_response[:ok] != true
              }
            )
          else
            return nil unless request['id']

            error_response(id: request['id'], code: -32601, message: "Unknown method: #{method}")
          end
        end

        def read_message(io)
          headers = {}

          loop do
            line = io.gets
            return nil if line.nil?

            line = line.strip
            break if line.empty?

            key, value = line.split(':', 2)
            next if key.nil? || value.nil?

            headers[key.strip.downcase] = value.strip
          end

          length = headers['content-length']&.to_i
          return nil unless length && length.positive?

          body = io.read(length)
          return nil if body.nil? || body.empty?

          JSON.parse(body)
        end

        def write_message(io, payload)
          json = JSON.dump(payload)
          io.write("Content-Length: #{json.bytesize}\r\n\r\n")
          io.write(json)
          io.flush
        end

        def success_response(id:, result:)
          {
            jsonrpc: '2.0',
            id: id,
            result: result
          }
        end

        def error_response(id:, code:, message:)
          {
            jsonrpc: '2.0',
            id: id,
            error: {
              code: code,
              message: message
            }
          }
        end

        def deep_json_safe(obj)
          case obj
          when Hash
            obj.each_with_object({}) do |(k, v), memo|
              memo[k.to_s] = deep_json_safe(v)
            end
          when Array
            obj.map { |v| deep_json_safe(v) }
          when String, Integer, Float, TrueClass, FalseClass, NilClass
            obj
          when Symbol
            obj.to_s
          else
            obj.respond_to?(:to_h) ? deep_json_safe(obj.to_h) : obj.to_s
          end
        end
      end
    end
  end
end
