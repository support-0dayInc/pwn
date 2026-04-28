# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class LifecycleAuthzReplayRoutePackCompletenessSmokeTest < Minitest::Test
  def test_route_pack_completeness_flags_blockers_for_missing_direct_retest
    Dir.mktmpdir('lifecycle-route-pack-completeness-') do |tmp_dir|
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
        run_id: 'route-pack-completeness-smoke'
      )

      PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
        run_obj: run_obj,
        capture_proc: lambda do |opts|
          checkpoint = opts[:checkpoint]
          actor = opts[:actor]
          route_category = opts.dig(:surface_record, :metadata, :route_category).to_s

          status = if checkpoint == 'pre_change'
                     'accessible'
                   elsif checkpoint == 'post_change_t0' && actor == 'revoked_user' && route_category == 'direct'
                     'missing'
                   elsif route_category == 'direct'
                     'denied'
                   else
                     'accessible'
                   end

          {
            status: status,
            response: {
              http_status: status == 'denied' ? 403 : 200
            }
          }
        end
      )

      summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(run_obj: run_obj)
      completeness = summary[:route_pack_completeness]

      refute_nil(completeness)
      assert(completeness[:report_blocker_count] >= 1)
      assert(completeness[:gap_findings].any? { |gap| gap[:reason] == 'secondary_visible_without_direct_retest' })
      assert(completeness.dig(:checklists, :post_change, :item_count) >= 1)
      assert(summary[:totals][:route_report_blockers] >= 1)
      assert(summary[:totals][:route_completion_score] < 100)
    end
  end
end
