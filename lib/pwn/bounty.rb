# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads Bounty modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module Bounty
    autoload :BrowserChains, 'pwn/bounty/browser_chains'
    autoload :BundleIntel, 'pwn/bounty/bundle_intel'
    autoload :GraphQLAuthzDiff, 'pwn/bounty/graphql_authz_diff'
    autoload :LifecycleAuthzReplay, 'pwn/bounty/lifecycle_authz_replay'
    autoload :ScopeIntel, 'pwn/bounty/scope_intel'
    autoload :SensitiveFileExposurePack, 'pwn/bounty/sensitive_file_exposure_pack'

    # Display a List of Every PWN::Bounty Module

    public_class_method def self.help
      constants.sort
    end
  end
end
