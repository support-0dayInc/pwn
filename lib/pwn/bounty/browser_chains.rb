# frozen_string_literal: true

module PWN
  module Bounty
    # Browser-driven chain analysis helpers for bug bounty conversion.
    module BrowserChains
      autoload :OneClickStateChangePack, 'pwn/bounty/browser_chains/one_click_state_change_pack'

      # Display Usage Information
      public_class_method def self.help
        constants.sort
      end
    end
  end
end
