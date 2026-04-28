# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class WorkflowTrustArtifactPrivilegeBridgePackSmokeTest < Minitest::Test
  def test_artifact_privilege_bridge_pack_exports_replay_matrix_and_aws_policy_kit
    claim_snapshots = [
      {
        snapshot_id: 'before_narrowing',
        claim: {
          sub: 'repo:acme/repo:ref:refs/heads/feature-red',
          aud: 'sts.amazonaws.com',
          event_name: 'pull_request_target'
        }
      },
      {
        snapshot_id: 'after_narrowing',
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
        name: 'broad-branch-policy',
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

    live_proof_pack = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.analyze(
      transition_bundle: transition_bundle,
      later_snapshot: {
        sub: 'repo:acme/repo:ref:refs/heads/main',
        aud: 'sts.amazonaws.com',
        exp: Time.now.to_i + 900
      },
      trust_policies: trust_policies
    )

    Dir.mktmpdir('workflow-trust-bridge-pack-') do |tmp_dir|
      report = PWN::Targets::GitHub::WorkflowTrust::ArtifactPrivilegeBridgePack.run(
        transition_bundle: transition_bundle,
        live_proof_pack: live_proof_pack,
        trust_policies: trust_policies,
        output_dir: tmp_dir
      )

      assert_equal('aws', report[:provider])
      assert_equal(true, report[:replay_ready])
      assert_equal(true, report[:critical_candidate])

      matrix_ids = Array(report[:experiment_matrix]).map { |entry| entry[:id] }
      assert_includes(matrix_ids, 'control_replay')
      assert_includes(matrix_ids, 'stale_acceptance_replay')
      assert_includes(matrix_ids, 'trust_tightening_validation')

      refute_empty(report[:aws_policy_pack])
      assert_equal('aws', report.dig(:aws_policy_pack, :provider))
      assert_equal('sts.amazonaws.com', report.dig(:aws_policy_pack, :tightening_summary, :pinned_aud))

      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_artifact_privilege_bridge_pack.json')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_artifact_privilege_bridge_pack.md')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_artifact_privilege_bridge_matrix.json')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_aws_trust_policy_baseline.json')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_aws_trust_policy_tightened_candidate.json')))
      assert(File.exist?(File.join(tmp_dir, 'workflow_trust_aws_assume_role_template.txt')))
    end
  end

  def test_evaluate_oidc_acceptance_embeds_artifact_bridge_pack
    claim_snapshots = [
      {
        snapshot_id: 'before',
        claim: {
          sub: 'repo:acme/repo:ref:refs/heads/feature-x',
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
        name: 'wildcard-sub-policy',
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

    assert_equal(true, oidc_eval[:replay_ready])
    assert_equal(true, oidc_eval[:critical_candidate])
    refute_nil(oidc_eval[:artifact_privilege_bridge_pack])
    assert_equal('aws', oidc_eval.dig(:artifact_privilege_bridge_pack, :provider))
    assert_equal(true, oidc_eval.dig(:artifact_privilege_bridge_pack, :critical_candidate))
  end
end
