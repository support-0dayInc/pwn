# frozen_string_literal: true

require 'json'
require 'time'

module PWN
  module AI
    # Model Context Protocol bridge for PWN.
    # Exposes introspection + controlled invocation so LLM clients can call PWN directly.
    module MCP
      autoload :Introspection, 'pwn/ai/mcp/introspection'
      autoload :Policy, 'pwn/ai/mcp/policy'
      autoload :Registry, 'pwn/ai/mcp/registry'
      autoload :Server, 'pwn/ai/mcp/server'

      public_class_method def self.help
        constants.sort
      end
    end
  end
end
