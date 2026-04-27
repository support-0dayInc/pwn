# frozen_string_literal: true

module PWN
  module Targets
    module GitHub
      autoload :RepoPermissionProofPack, 'pwn/targets/github/repo_permission_proof_pack'
      autoload :WorkflowTrust, 'pwn/targets/github/workflow_trust'

      # Display a List of Every PWN::Targets::GitHub Module

      public_class_method def self.help
        constants.sort
      end
    end
  end
end
