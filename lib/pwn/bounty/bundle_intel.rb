# frozen_string_literal: true

module PWN
  module Bounty
    # BundleIntel discovers hidden routes/permissions/operations from static
    # artifacts (HTML, JS bundles, source maps, traffic captures).
    module BundleIntel
      autoload :RoutePermissionAtlas, 'pwn/bounty/bundle_intel/route_permission_atlas'

      # Display Usage Information
      public_class_method def self.help
        constants.sort
      end
    end
  end
end
