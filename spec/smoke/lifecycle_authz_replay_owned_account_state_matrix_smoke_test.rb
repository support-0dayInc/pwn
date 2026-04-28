# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplayOwnedAccountStateMatrixSmokeTest < Minitest::Test
  def test_owned_account_state_matrix_builds_transition_plan_and_drives_artifact_drift_capture
    Dir.mktmpdir('lifecycle-owned-account-state-matrix-') do |tmp_dir|
      report = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.run(
        run_id: 'owned-account-state-matrix-smoke',
        target: 'https://app.example.test',
        base_url: 'https://app.example.test',
        transition: 'revoke',
        actors: [
          { id: 'revoked_member', role: 'subject', label: 'Revoked Member' },
          { id: 'control_member', role: 'control', label: 'Control Member' }
        ],
        route_seeds: [
          { route: '/api/v1/team/members/revoke', route_family: 'direct', object_family: 'member' },
          { route: '/api/v1/team/members/status', route_family: 'secondary', object_family: 'member' },
          { route: '/exports/team/members/download', route_family: 'artifact', object_family: 'member' }
        ],
        output_dir: tmp_dir
      )

      assert_equal('owned-account-state-matrix-smoke', report[:run_id])
      assert_equal('revoke', report[:transition])
      assert(report[:matrix_cell_count] > 0)
      assert(report.dig(:matrix, :checkpoints).any? { |entry| entry[:checkpoint] == 'pre_change' })
      assert(report.dig(:matrix, :checkpoints).any? { |entry| entry[:checkpoint] == 'post_change_t0' })
      assert(report.dig(:artifact_access_drift_matrix_starter, :direct_surface_ids).any?)
      assert(report.dig(:artifact_access_drift_matrix_starter, :derived_surface_ids).any?)

      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
        plan: report[:transition_plan],
        output_dir: tmp_dir,
        run_id: 'owned-account-state-matrix-replay-smoke'
      )

      PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
        run_obj: run_obj,
        capture_proc: lambda do |opts|
          actor = opts[:actor]
          checkpoint = opts[:checkpoint]
          route_family = opts.dig(:surface_record, :metadata, :route_family).to_s

          status = if actor == 'control_member'
                     'denied'
                   elsif checkpoint == 'pre_change'
                     'accessible'
                   elsif route_family == 'direct'
                     'denied'
                   elsif route_family == 'artifact'
                     'accessible'
                   else
                     'accessible'
                   end

          {
            status: status,
            request: {
              method: 'GET',
              url: opts.dig(:surface_record, :metadata, :adapter, :request, :url)
            },
            response: {
              http_status: status == 'denied' ? 403 : 200,
              body_sha256: "#{opts[:surface]}-#{status}"
            },
            notes: "#{actor} #{checkpoint} #{route_family} #{status}"
          }
        end
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)
      assert(summary.dig(:artifact_access_drift, :reportable_candidate_count) > 0)
      assert(summary[:totals][:mixed_surface_findings] > 0)

      run_root = File.join(tmp_dir, 'owned-account-state-matrix-smoke')
      assert(File.exist?(File.join(run_root, 'owned_account_state_matrix.json')))
      assert(File.exist?(File.join(run_root, 'owned_account_state_matrix_transition_plan.json')))
      assert(File.exist?(File.join(run_root, 'owned_account_state_matrix.md')))
    end
  end
end
