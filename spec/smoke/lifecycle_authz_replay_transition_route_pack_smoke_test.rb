# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplayTransitionRoutePackSmokeTest < Minitest::Test
  def test_transition_route_pack_plan_and_mixed_surface_detection
    Dir.mktmpdir('lifecycle-transition-route-pack-') do |tmp_dir|
      run_obj = PWN::Bounty::LifecycleAuthzReplay.start_transition_run(
        provider: :github,
        lane: :reviewer_revocation,
        transition: :revoke,
        target: 'https://github.example/acme/private-repo',
        route_vars: {
          api_base: 'https://api.github.example',
          owner: 'acme',
          repo: 'private-repo',
          subject_actor: 'revoked_user'
        },
        output_dir: tmp_dir,
        run_id: 'transition-route-pack-smoke'
      )

      assert(run_obj[:plan][:checkpoints].include?('pre_change'))
      assert(run_obj[:plan][:checkpoints].include?('post_change_t0'))
      assert(run_obj[:plan][:checkpoints].include?('post_change_t10m'))
      assert(run_obj[:plan][:checkpoints].include?('post_change_t30m'))
      assert(run_obj[:plan][:checkpoints].include?('post_change_t60m'))

      replay_file = File.join(tmp_dir, 'transition-route-pack-smoke', 'transition_replay.json')
      assert(File.exist?(replay_file))

      capture_execution = PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
        run_obj: run_obj,
        capture_proc: lambda do |opts|
          checkpoint = opts[:checkpoint]
          route_category = opts.dig(:surface_record, :metadata, :route_category).to_s

          status = if checkpoint == 'pre_change'
                     'accessible'
                   elsif route_category == 'direct'
                     'denied'
                   else
                     'accessible'
                   end

          {
            status: status,
            request: {
              method: 'GET',
              checkpoint: checkpoint
            },
            response: {
              http_status: status == 'denied' ? 403 : 200
            },
            notes: "#{route_category} => #{status}"
          }
        end
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)

      assert_equal(run_obj[:coverage_matrix][:cells].length, capture_execution[:attempted_cells])
      assert(summary[:totals][:stale_access_findings] > 0)
      assert(summary[:totals][:mixed_surface_findings] > 0)

      first_mixed = summary[:mixed_surface_findings].first
      assert(!first_mixed[:direct_denied_surfaces].empty?)
      assert(!first_mixed[:secondary_accessible_surfaces].empty?)
    end
  end
end
