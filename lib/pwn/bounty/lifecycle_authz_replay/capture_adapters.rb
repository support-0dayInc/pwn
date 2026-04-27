# frozen_string_literal: true

module PWN
  module Bounty
    module LifecycleAuthzReplay
      module CaptureAdapters
        autoload :Base, 'pwn/bounty/lifecycle_authz_replay/capture_adapters/base'
        autoload :Browser, 'pwn/bounty/lifecycle_authz_replay/capture_adapters/browser'
        autoload :GraphQL, 'pwn/bounty/lifecycle_authz_replay/capture_adapters/graphql'
        autoload :HTTP, 'pwn/bounty/lifecycle_authz_replay/capture_adapters/http'

        public_class_method def self.help
          constants.sort
        end
      end
    end
  end
end
