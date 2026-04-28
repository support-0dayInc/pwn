# frozen_string_literal: true

module PWN
  module AI
    module MCP
      # Recursive module/method discovery for PWN namespace.
      module Introspection
        module_function

        def constantize(path)
          names = path.to_s.split('::').reject(&:empty?)
          raise ArgumentError, 'constant path is required' if names.empty?

          names.reduce(Object) do |ctx, name|
            if ctx.const_defined?(name, false)
              ctx.const_get(name, false)
            else
              raise NameError, "uninitialized constant #{path}"
            end
          end
        end

        def constant_children(const_obj)
          return [] unless const_obj.respond_to?(:constants)

          const_obj.constants(false).sort.map do |name|
            begin
              child = const_obj.const_get(name, false)
              {
                name: name.to_s,
                path: "#{const_obj.name}::#{name}",
                type: child.is_a?(Class) ? 'class' : 'module'
              }
            rescue StandardError, ScriptError => e
              {
                name: name.to_s,
                path: "#{const_obj.name}::#{name}",
                type: 'unknown',
                error: e.message
              }
            end
          end
        end

        def singleton_methods_for(const_obj)
          return [] unless const_obj.respond_to?(:singleton_methods)

          const_obj.singleton_methods(false).map(&:to_s).sort
        end

        def instance_methods_for(const_obj)
          return [] unless const_obj.respond_to?(:instance_methods)

          const_obj.instance_methods(false).map(&:to_s).sort
        end

        def method_inventory(constant_path: 'PWN')
          const_obj = constantize(constant_path)
          {
            constant_path: constant_path,
            type: const_obj.is_a?(Class) ? 'class' : 'module',
            singleton_methods: singleton_methods_for(const_obj),
            instance_methods: instance_methods_for(const_obj)
          }
        end

        def recursive_inventory(root: 'PWN', max_depth: nil)
          root_obj = constantize(root)
          queue = [[root_obj, 0]]
          seen = {}
          inventory = []
          load_errors = []

          until queue.empty?
            const_obj, depth = queue.shift
            next if seen[const_obj.object_id]

            seen[const_obj.object_id] = true
            path = const_obj.name || root

            entry = {
              path: path,
              depth: depth,
              type: const_obj.is_a?(Class) ? 'class' : 'module',
              singleton_methods: singleton_methods_for(const_obj),
              instance_methods: instance_methods_for(const_obj)
            }
            inventory << entry

            next if max_depth && depth >= max_depth

            constant_children(const_obj).each do |child_info|
              if child_info[:error]
                load_errors << child_info
                next
              end

              begin
                child = constantize(child_info[:path])
                next unless child.is_a?(Module)

                queue << [child, depth + 1]
              rescue StandardError, ScriptError => e
                load_errors << {
                  path: child_info[:path],
                  type: child_info[:type],
                  error: e.message
                }
              end
            end
          end

          {
            root: root,
            generated_at: Time.now.utc.iso8601,
            constants_count: inventory.length,
            load_error_count: load_errors.length,
            load_errors: load_errors.sort_by { |row| row[:path].to_s },
            inventory: inventory.sort_by { |row| row[:path] }
          }
        end
      end
    end
  end
end
