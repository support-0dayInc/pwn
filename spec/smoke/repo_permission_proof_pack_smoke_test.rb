# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class RepoPermissionProofPackSmokeTest < Minitest::Test
  def test_proof_pack_marks_reportable_when_repo_controls_are_denied
    Dir.mktmpdir('repo-permission-proof-pack-smoke-') do |tmp_dir|
      report = PWN::Targets::GitHub::RepoPermissionProofPack.evaluate(
        repo: {
          owner: 'acme',
          name: 'widgets',
          actor: 'revoked_user'
        },
        repo_rest_probe: {
          http_status: 403,
          body: '{"message":"Not Found"}'
        },
        repo_graphql_probe: {
          http_status: 200,
          body: '{"data":{"repository":null},"errors":[{"message":"Could not resolve to a Repository with the name \"widgets\"."}]}'
        },
        object_probes: [
          {
            id: 'pull_123',
            surface: 'pull_html',
            status: 'accessible',
            evidence_path: 'artifacts/post_change_t0/revoked_user/pull_123/response.txt'
          }
        ],
        output_dir: tmp_dir,
        run_id: 'repo-permission-proof-pack-smoke'
      )

      assert_equal('passed', report.dig(:gate, :result))
      assert_equal('reportable_candidate', report[:finding_decision])
      assert_equal(1, report[:secondary_visible_count])
      assert_equal('repo-permission-proof-pack-smoke', report[:run_id])
      assert(File.exist?(File.join(tmp_dir, 'repo-permission-proof-pack-smoke', 'repo_permission_proof_pack.json')))
      assert(File.exist?(File.join(tmp_dir, 'repo-permission-proof-pack-smoke', 'repo_permission_proof_pack.md')))
    end
  end

  def test_proof_pack_downgrades_to_control_only_when_repo_still_readable
    report = PWN::Targets::GitHub::RepoPermissionProofPack.evaluate(
      repo_rest_probe: {
        http_status: 200,
        body: '{"full_name":"acme/widgets","private":true}'
      },
      repo_graphql_probe: {
        http_status: 200,
        body: '{"data":{"repository":{"visibility":"PRIVATE","isPrivate":true,"viewerPermission":"READ"}}}'
      },
      object_probes: [
        {
          id: 'pull_123',
          surface: 'pull_graphql',
          accessible: true
        }
      ]
    )

    assert_equal('failed', report.dig(:gate, :result))
    assert_equal('control_only', report[:finding_decision])
    assert_equal('secondary visible, repo still readable -> control-only', report[:contradiction])

    gated_findings = PWN::Targets::GitHub::RepoPermissionProofPack.apply_gate_to_findings(
      findings: [{ id: 'f1', severity: 'high' }],
      proof_pack: report
    )

    assert_equal('control_only', gated_findings.first[:classification])
    assert_equal('info', gated_findings.first[:severity])
  end
end
