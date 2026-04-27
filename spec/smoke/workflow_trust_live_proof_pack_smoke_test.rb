# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class WorkflowTrustLiveProofPackSmokeTest < Minitest::Test
  def test_live_proof_pack_marks_aws_replay_ready_for_stale_acceptance_candidate
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

    transition_bundle = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.analyze(
      claim_snapshots: claim_snapshots,
      trust_policies: trust_policies
    )

    later_snapshot = {
      sub: 'repo:acme/repo:ref:refs/heads/main',
      aud: 'sts.amazonaws.com',
      iss: 'https://token.actions.githubusercontent.com',
      exp: Time.now.to_i + 900,
      event_name: 'workflow_dispatch'
    }

    Dir.mktmpdir('workflow-trust-live-proof-pack-') do |tmp_dir|
      report = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.run(
        transition_bundle: transition_bundle,
        later_snapshot: later_snapshot,
        output_dir: tmp_dir
      )

      assert(report[:replay_ready])
      assert_equal('aws', report[:provider])
      assert_equal('claims_only_json', report.dig(:token_snapshot, :snapshot_type))
      assert_equal('critical_candidate', report[:impact_label])
      assert(report.dig(:next_exchange, :command).include?('assume-role-with-web-identity'))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_live_proof_pack.json')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_live_proof_pack.md')))
    end
  end

  def test_evaluate_oidc_acceptance_embeds_live_proof_pack
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
      trust_policies: trust_policies,
      later_snapshot: {
        sub: 'repo:acme/repo:ref:refs/heads/main',
        aud: 'sts.amazonaws.com',
        exp: Time.now.to_i + 900
      }
    )

    refute_nil(oidc_eval[:transition_bundle])
    refute_nil(oidc_eval[:live_proof_pack])
    assert(oidc_eval[:replay_ready])
    assert(oidc_eval.dig(:live_proof_pack, :replay_readiness, :ready))
  end
end
