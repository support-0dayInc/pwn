# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class ScopeIntelDeltaQueueSmokeTest < Minitest::Test
  def test_delta_queue_ranks_new_scope_and_emits_burp_seeds
    old_scope = {
      program_name: 'example-program',
      rows: [
        {
          identifier: 'https://app.example.test',
          display_name: 'Main App',
          asset_type: 'web',
          eligible_for_bounty: true,
          eligible_for_submission: true,
          requires_owned_account: true,
          requires_staging: false,
          third_party_excluded: false,
          signup_mode: 'researcher_owned_account',
          acquired_brand: nil,
          instruction: 'auth app',
          notes: 'owned_account_required'
        }
      ]
    }

    new_scope = {
      program_name: 'example-program',
      rows: [
        old_scope[:rows].first,
        {
          identifier: 'https://admin-beta.example.test',
          display_name: 'Admin Beta',
          asset_type: 'web',
          eligible_for_bounty: true,
          eligible_for_submission: true,
          requires_owned_account: true,
          requires_staging: true,
          third_party_excluded: false,
          signup_mode: 'researcher_owned_account',
          acquired_brand: nil,
          instruction: 'beta admin panel with authenticated access',
          notes: 'staging_or_beta_surface | owned_account_required'
        }
      ]
    }

    Dir.mktmpdir('scope-intel-delta-queue-smoke-') do |tmp_dir|
      report = PWN::Bounty::ScopeIntel::DeltaQueue.run(
        old_scope_intel: old_scope,
        new_scope_intel: new_scope,
        output_dir: tmp_dir,
        snapshot_dir: File.join(tmp_dir, 'snapshots')
      )

      assert_equal('example-program', report[:program_name])
      assert(report[:queue_count] >= 1)
      assert_equal(1, report.dig(:diff_summary, :added_count))
      top = report[:delta_queue].first
      assert_equal('https://admin-beta.example.test', top[:identifier])
      assert_includes(report[:burp_target_seeds], 'https://admin-beta.example.test')
      assert(File.exist?(report.dig(:snapshot, :current_snapshot_path)))

      assert(File.exist?(File.join(tmp_dir, 'scope_intel_delta_queue.json')))
      assert(File.exist?(File.join(tmp_dir, 'scope_intel_delta_queue.md')))
      assert(File.exist?(File.join(tmp_dir, 'scope_intel_delta_queue_burp_targets.txt')))
    end
  end

  def test_delta_queue_uses_persisted_snapshot_when_old_scope_not_provided
    first_scope = {
      program_name: 'persisted-program',
      rows: [
        {
          identifier: 'https://app.persisted.test',
          display_name: 'Persisted App',
          asset_type: 'web',
          eligible_for_bounty: true,
          eligible_for_submission: true,
          requires_owned_account: true,
          requires_staging: false,
          third_party_excluded: false,
          signup_mode: 'researcher_owned_account',
          acquired_brand: nil,
          instruction: 'auth app',
          notes: 'owned_account_required'
        }
      ]
    }

    second_scope = {
      program_name: 'persisted-program',
      rows: first_scope[:rows] + [
        {
          identifier: 'https://staging.persisted.test',
          display_name: 'Persisted Staging',
          asset_type: 'web',
          eligible_for_bounty: true,
          eligible_for_submission: true,
          requires_owned_account: true,
          requires_staging: true,
          third_party_excluded: false,
          signup_mode: 'researcher_owned_account',
          acquired_brand: nil,
          instruction: 'staging admin api',
          notes: 'staging_or_beta_surface'
        }
      ]
    }

    Dir.mktmpdir('scope-intel-delta-queue-persisted-') do |tmp_dir|
      snapshot_dir = File.join(tmp_dir, 'snapshots')

      first_report = PWN::Bounty::ScopeIntel::DeltaQueue.run(
        new_scope_intel: first_scope,
        snapshot_dir: snapshot_dir,
        output_dir: tmp_dir
      )

      assert_equal('', first_report.dig(:snapshot, :previous_snapshot_path))

      second_report = PWN::Bounty::ScopeIntel::DeltaQueue.run(
        new_scope_intel: second_scope,
        snapshot_dir: snapshot_dir,
        output_dir: tmp_dir
      )

      refute_equal('', second_report.dig(:snapshot, :previous_snapshot_path))
      assert(second_report[:queue_count] >= 1)
      assert_includes(second_report[:burp_target_seeds], 'https://staging.persisted.test')
    end
  end
end
