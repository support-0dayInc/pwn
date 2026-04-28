# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplaySubmissionBundleSmokeTest < Minitest::Test
  def test_finalize_run_embeds_submission_bundle_submit_now
    Dir.mktmpdir('lifecycle-submission-bundle-smoke-') do |tmp_dir|
      plan = {
        campaign: {
          id: 'submission-bundle-smoke',
          target: 'https://example.test/acme/private-repo',
          change_event: 'revoke'
        },
        actors: ['revoked_user'],
        surfaces: [
          {
            id: 'repo_collaborator_api',
            metadata: {
              route_category: 'direct',
              route_family: 'direct'
            }
          },
          {
            id: 'repo_notification_feed',
            metadata: {
              route_category: 'secondary',
              route_family: 'secondary'
            }
          }
        ],
        checkpoints: %w[pre_change post_change_t0],
        expected_denied_after: ['post_change_t0']
      }

      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
        plan: plan,
        output_dir: tmp_dir,
        run_id: 'submission-bundle-smoke'
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'pre_change',
        actor: 'revoked_user',
        surface: 'repo_collaborator_api',
        status: :accessible,
        response: { http_status: 200 }
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'pre_change',
        actor: 'revoked_user',
        surface: 'repo_notification_feed',
        status: :accessible,
        response: { http_status: 200 }
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user',
        surface: 'repo_collaborator_api',
        status: :denied,
        response: { http_status: 403 }
      )

      PWN::Bounty::LifecycleAuthzReplay.record_observation(
        run_obj: run_obj,
        checkpoint: 'post_change_t0',
        actor: 'revoked_user',
        surface: 'repo_notification_feed',
        status: :accessible,
        response: {
          http_status: 200,
          body_preview: 'Notification index still reachable for revoked actor'
        }
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)
      submission = summary[:submission_bundle]

      refute_nil(submission)
      assert_equal('submit_now', submission[:decision])
      assert(submission[:ready_to_submit])
      assert_equal([], submission[:missing_proof])
      assert_equal([], submission[:contradictions])
      assert(File.exist?(File.join(tmp_dir, 'submission-bundle-smoke', 'SUBMISSION_BUNDLE.json')))
      assert(File.exist?(File.join(tmp_dir, 'submission-bundle-smoke', 'SUBMISSION_BUNDLE.md')))
    end
  end

  def test_submission_bundle_marks_control_only_when_direct_route_still_accessible
    Dir.mktmpdir('lifecycle-submission-bundle-contradiction-') do |tmp_dir|
      plan = {
        campaign: {
          id: 'submission-bundle-contradiction',
          target: 'https://example.test/acme/private-repo',
          change_event: 'revoke'
        },
        actors: ['revoked_user'],
        surfaces: [
          {
            id: 'repo_collaborator_api',
            metadata: {
              route_category: 'direct',
              route_family: 'direct'
            }
          },
          {
            id: 'repo_notification_feed',
            metadata: {
              route_category: 'secondary',
              route_family: 'secondary'
            }
          }
        ],
        checkpoints: %w[pre_change post_change_t0],
        expected_denied_after: ['post_change_t0']
      }

      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
        plan: plan,
        output_dir: tmp_dir,
        run_id: 'submission-bundle-contradiction'
      )

      PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
        run_obj: run_obj,
        capture_proc: lambda do |opts|
          checkpoint = opts[:checkpoint]
          surface = opts[:surface]

          if checkpoint == 'post_change_t0' && surface == 'repo_collaborator_api'
            { status: 'accessible', response: { http_status: 200 } }
          elsif checkpoint == 'post_change_t0'
            { status: 'accessible', response: { http_status: 200 } }
          else
            { status: 'accessible', response: { http_status: 200 } }
          end
        end
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)
      submission = summary[:submission_bundle]

      assert_equal('control_only', submission[:decision])
      assert_includes(submission[:contradictions], 'repo_still_readable')
      refute(submission[:ready_to_submit])
    end
  end
end
