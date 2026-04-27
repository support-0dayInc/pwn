# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class WorkflowTrustTransitionBundleSmokeTest < Minitest::Test
  def test_transition_bundle_flags_stale_acceptance_after_claim_drift
    claim_snapshots = [
      {
        snapshot_id: 'pre_narrowing',
        claim: {
          sub: 'repo:acme/repo:ref:refs/heads/feature-red',
          aud: 'sts.amazonaws.com',
          workflow_ref: 'acme/repo/.github/workflows/deploy.yml@refs/heads/feature-red',
          event_name: 'pull_request_target'
        }
      },
      {
        snapshot_id: 'post_narrowing',
        claim: {
          sub: 'repo:acme/repo:ref:refs/heads/main',
          aud: 'sts.amazonaws.com',
          workflow_ref: 'acme/repo/.github/workflows/deploy.yml@refs/heads/main',
          event_name: 'workflow_dispatch'
        }
      }
    ]

    trust_policies = [
      {
        provider: 'aws',
        name: 'broad-subject-role',
        statements: [
          {
            condition: {
              StringLike: {
                'token.actions.githubusercontent.com:sub' => 'repo:acme/repo:ref:refs/heads/*',
                'token.actions.githubusercontent.com:aud' => 'sts.amazonaws.com'
              }
            }
          }
        ]
      }
    ]

    Dir.mktmpdir('workflow-trust-transition-bundle-') do |tmp_dir|
      report = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.run(
        claim_snapshots: claim_snapshots,
        trust_policies: trust_policies,
        output_dir: tmp_dir
      )

      assert_equal(2, report[:claim_snapshot_count])
      assert_equal(1, report[:trust_policy_count])
      assert(report[:stale_acceptance_candidate_count] >= 1)
      assert(report[:bundles].first[:transition_diff_count] >= 1)
      assert(report[:bundles].first[:stale_acceptance_after_narrowing_count] >= 1)

      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_transition_bundle.json')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_transition_bundle.md')))
    end
  end

  def test_evaluate_oidc_acceptance_embeds_transition_bundle
    claim_snapshots = [
      {
        snapshot_id: 'before',
        claim: {
          sub: 'repo:acme/repo:ref:refs/heads/feature-a',
          aud: 'sts.amazonaws.com',
          event_name: 'pull_request_target'
        }
      },
      {
        snapshot_id: 'after',
        claim: {
          sub: 'repo:acme/repo:ref:refs/heads/main',
          aud: 'sts.amazonaws.com',
          event_name: 'workflow_dispatch'
        }
      }
    ]

    trust_policies = [
      {
        provider: 'aws',
        name: 'wildcard-branch-policy',
        statements: [
          {
            condition: {
              StringLike: {
                'token.actions.githubusercontent.com:sub' => 'repo:acme/repo:ref:refs/heads/*',
                'token.actions.githubusercontent.com:aud' => 'sts.amazonaws.com'
              }
            }
          }
        ]
      }
    ]

    oidc_eval = PWN::Targets::GitHub::WorkflowTrust.evaluate_oidc_acceptance(
      oidc_claims: claim_snapshots.map { |entry| entry[:claim] },
      claim_snapshots: claim_snapshots,
      trust_policies: trust_policies
    )

    assert_equal(2, oidc_eval[:oidc_claim_count])
    refute_nil(oidc_eval[:transition_bundle])
    assert(oidc_eval[:stale_acceptance_candidate_count] >= 1)
  end
end
