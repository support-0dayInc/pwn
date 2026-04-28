# frozen_string_literal: true

module PWN
  module AI
    module MCP
      # Safety policy for tool invocation.
      module Policy
        module_function

        SAFE_READ_PATTERNS = [
          /help\z/i,
          /authors\z/i,
          /status\z/i,
          /list\z/i,
          /search\z/i,
          /show\z/i,
          /describe\z/i,
          /inventory\z/i,
          /report\z/i,
          /version\z/i,
          /info\z/i,
          /check\z/i,
          /reflect_on\z/i
        ].freeze

        RISKY_PATTERNS = [
          /delete/i,
          /destroy/i,
          /drop/i,
          /remove/i,
          /wipe/i,
          /exec/i,
          /shell/i,
          /spawn/i,
          /fork/i,
          /write/i,
          /patch/i,
          /upload/i,
          /download/i,
          /connect/i,
          /send/i,
          /post/i,
          /put/i,
          /create/i,
          /update/i,
          /clone/i,
          /pull/i,
          /push/i,
          /commit/i,
          /scan/i,
          /attack/i,
          /exploit/i
        ].freeze

        INTERNAL_DENYLIST = %w[
          object_id
          singleton_class
          class
          module_eval
          class_eval
          instance_eval
          send
          public_send
          eval
          system
          method
          methods
          private_methods
          protected_methods
          constants
          const_get
          const_set
          remove_const
        ].freeze

        def method_safety(method_name)
          name = method_name.to_s
          return :denied if INTERNAL_DENYLIST.include?(name)
          return :read_only if SAFE_READ_PATTERNS.any? { |rx| rx.match?(name) }
          return :dangerous if RISKY_PATTERNS.any? { |rx| rx.match?(name) }

          :unknown
        end

        def invocation_allowed?(method_name:, confirm_dangerous: false)
          case method_safety(method_name)
          when :denied
            [false, 'Method is explicitly denied by MCP policy']
          when :dangerous
            if confirm_dangerous
              [true, 'dangerous-confirmed']
            else
              [false, 'Method appears dangerous. Re-run with confirm_dangerous=true to proceed.']
            end
          else
            [true, 'allowed']
          end
        end
      end
    end
  end
end
