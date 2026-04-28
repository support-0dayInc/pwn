# frozen_string_literal: true

module PWN
  module AI
    module MCP
      # Tool registry + invocation adapter used by MCP server.
      module Registry
        module_function

        TOOLS = [
          {
            name: 'pwn.help',
            description: 'List top-level PWN namespaces.',
            inputSchema: {
              type: 'object',
              properties: {},
              additionalProperties: false
            }
          },
          {
            name: 'pwn.inventory_recursive',
            description: 'Recursively enumerate modules/classes and methods under a namespace.',
            inputSchema: {
              type: 'object',
              properties: {
                root: { type: 'string', description: 'Namespace root (default: PWN)' },
                max_depth: { type: 'integer', description: 'Optional recursion depth limit' }
              },
              additionalProperties: false
            }
          },
          {
            name: 'pwn.methods',
            description: 'Return method inventory for one constant path.',
            inputSchema: {
              type: 'object',
              properties: {
                constant_path: { type: 'string', description: 'Constant path (e.g., PWN::Plugins::Git)' }
              },
              required: ['constant_path'],
              additionalProperties: false
            }
          },
          {
            name: 'pwn.invoke',
            description: 'Invoke a public class/module method on PWN with policy checks.',
            inputSchema: {
              type: 'object',
              properties: {
                constant_path: { type: 'string', description: 'Constant path to module/class (must start with PWN::)' },
                method: { type: 'string', description: 'Public singleton method name' },
                args: {
                  oneOf: [
                    { type: 'object', description: 'Preferred named args hash for opts-style APIs' },
                    { type: 'array', description: 'Positional args for non-hash signatures' }
                  ]
                },
                confirm_dangerous: { type: 'boolean', description: 'Required for methods classified as dangerous by policy' }
              },
              required: ['constant_path', 'method'],
              additionalProperties: false
            }
          }
        ].freeze

        def list_tools
          TOOLS
        end

        def call_tool(name:, arguments: {})
          case name
          when 'pwn.help'
            { ok: true, result: PWN.help }
          when 'pwn.inventory_recursive'
            root = (arguments['root'] || arguments[:root] || 'PWN').to_s
            max_depth = arguments['max_depth'] || arguments[:max_depth]
            max_depth = nil if max_depth.nil?
            max_depth = Integer(max_depth) unless max_depth.nil?
            { ok: true, result: Introspection.recursive_inventory(root: root, max_depth: max_depth) }
          when 'pwn.methods'
            constant_path = (arguments['constant_path'] || arguments[:constant_path]).to_s
            raise ArgumentError, 'constant_path is required' if constant_path.empty?

            { ok: true, result: Introspection.method_inventory(constant_path: constant_path) }
          when 'pwn.invoke'
            invoke(arguments)
          else
            raise ArgumentError, "Unknown tool: #{name}"
          end
        rescue StandardError, SecurityError => e
          {
            ok: false,
            error: {
              type: e.class.to_s,
              message: e.message
            }
          }
        end

        def invoke(arguments)
          constant_path = (arguments['constant_path'] || arguments[:constant_path]).to_s
          method_name = (arguments['method'] || arguments[:method]).to_s
          confirm = arguments['confirm_dangerous'] == true || arguments[:confirm_dangerous] == true
          args = arguments.key?('args') ? arguments['args'] : arguments[:args]

          raise ArgumentError, 'constant_path must start with PWN::' unless constant_path.start_with?('PWN::') || constant_path == 'PWN'
          raise ArgumentError, 'method is required' if method_name.empty?

          allowed, reason = Policy.invocation_allowed?(method_name: method_name, confirm_dangerous: confirm)
          raise SecurityError, reason unless allowed

          target = Introspection.constantize(constant_path)
          raise ArgumentError, "#{constant_path} does not respond to .#{method_name}" unless target.respond_to?(method_name)

          begin
            result = if args.nil?
                       target.public_send(method_name)
                     elsif args.is_a?(Hash)
                       target.public_send(method_name, symbolize_hash(args))
                     elsif args.is_a?(Array)
                       target.public_send(method_name, *args)
                     else
                       target.public_send(method_name, args)
                     end
          rescue ArgumentError
            # Fallback for APIs that expect string-keyed hash or positional hash.
            if args.is_a?(Hash)
              result = target.public_send(method_name, args)
            else
              raise
            end
          end

          {
            ok: true,
            result: result,
            invocation: {
              constant_path: constant_path,
              method: method_name,
              policy: reason
            }
          }
        end

        def symbolize_hash(obj)
          obj.each_with_object({}) do |(k, v), memo|
            key = k.respond_to?(:to_sym) ? k.to_sym : k
            memo[key] = v.is_a?(Hash) ? symbolize_hash(v) : v
          end
        end
      end
    end
  end
end
