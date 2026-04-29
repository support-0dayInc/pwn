# frozen_string_literal: true

module PWN
  module Bounty
    # Agentic surface discovery and abuse-chain planning helpers.
    module AgenticSurface
      autoload :ToolPermissionAtlas, 'pwn/bounty/agentic_surface/tool_permission_atlas'

      # Display Usage Information
      public_class_method def self.help
        constants.sort
      end
    end
  end
end
