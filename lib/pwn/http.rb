# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads HTTP modules
  # into memory only when they're needed.
  module HTTP
    autoload :SSRFChain, 'pwn/http/ssrf_chain'

    # Display a List of Every PWN::HTTP Module
    public_class_method def self.help
      constants.sort
    end
  end
end
