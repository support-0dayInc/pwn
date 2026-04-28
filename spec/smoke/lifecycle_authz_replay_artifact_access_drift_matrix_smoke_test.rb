# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplayArtifactAccessDriftMatrixSmokeTest < Minitest::Test
  def test_artifact_access_drift_detects_direct_denied_derived_accessible
    Dir.mktmpdir('lifecycle-artifact-drift-smoke-') do |tmp_dir|
      plan = {
        campaign: {
          id: 'artifact-drift-smoke',
          target: 'https://example.test',
          change_event: 'revoke'
        },
        actors: ['revoked_user'],
        surfaces: [
          {
            id: 'canonical_object_api',
            metadata: {
              route_family: 'direct'
            }
          },
          {
            id: 'object_export_download',
            metadata: {
              route_family: 'export',
              artifact_access_drift: {
                object_family: 'object_123'
              }
            }
          }
        ],
        checkpoints: %w[pre_change post_change_t0],
        expected_denied_after: ['post_change_t0']
      }

      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
        plan: plan,
        output_dir: tmp_dir,
        run_id: 'artifact-drift-smoke'
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user',
        surface: 'canonical_object_api',
        status: :denied,
        request: { method: 'GET', url: 'https://example.test/api/object/123', headers: { Authorization: 'Bearer revoked' } },
        response: { http_status: 403 }
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user',
        surface: 'object_export_download',
        status: :accessible,
        request: { method: 'GET', url: 'https://example.test/export/object/123.csv', headers: { Authorization: 'Bearer revoked' } },
        response: {
          http_status: 200,
          headers: {
            'Cache-Control' => 'private, max-age=60',
            'ETag' => 'abc123'
          },
          content_sha256: 'deadbeef'
        }
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)
      drift = summary[:artifact_access_drift]

      refute_nil(drift)
      assert_equal(1, drift[:reportable_candidate_count])
      assert_equal('direct_denied_derived_accessible', drift.dig(:families, 0, :report_angle))
      assert_equal(1, summary[:totals][:artifact_access_drift_findings])
    end
  end
end
