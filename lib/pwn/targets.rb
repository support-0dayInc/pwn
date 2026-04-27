# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads Target modules
  # into memory only when they're needed.
  module Targets
    autoload :GitHub, 'pwn/targets/github'

    # Display a List of Every PWN::Targets Module

    public_class_method def self.help
      constants.sort
    end
  end
end
