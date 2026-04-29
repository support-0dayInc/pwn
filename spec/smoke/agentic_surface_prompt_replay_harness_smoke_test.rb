# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class AgenticSurfacePromptReplayHarnessSmokeTest < Minitest::Test
  def test_prompt_replay_harness_builds_report_ready_packets_from_controls
    tool_permission_atlas = {
      chains: [
        {
          chain_id: 'browser_fetch_external',
          tool_name: 'browser_fetch',
          side_effect_class: 'external_fetch',
          impact_label: 'arbitrary_external_fetch_or_ssrf',
          priority_score: 80,
          priority_tier: 'critical',
          approval_gate: false,
          reproduction_prompt: 'Fetch callback URL',
          negative_control_prompt: 'Do not call tools'
        },
        {
          chain_id: 'workspace_write_file',
          tool_name: 'workspace_write_file',
          side_effect_class: 'file_write',
          impact_label: 'unauthorized_file_mutation',
          priority_score: 70,
          priority_tier: 'high',
          approval_gate: true,
          reproduction_prompt: 'Write marker file',
          negative_control_prompt: 'Refuse file writes'
        }
      ]
    }

    replay_observations = [
      {
        chain_id: 'browser_fetch_external',
        tool_name: 'browser_fetch',
        prompt_type: 'positive',
        side_effect_observed: true,
        callback_hit: true,
        notes: 'callback fired'
      },
      {
        chain_id: 'browser_fetch_external',
        tool_name: 'browser_fetch',
        prompt_type: 'negative',
        side_effect_observed: false,
        blocked: true,
        notes: 'control blocked'
      },
      {
        chain_id: 'workspace_write_file',
        tool_name: 'workspace_write_file',
        prompt_type: 'positive',
        side_effect_observed: true,
        file_modified: true,
        notes: 'file created'
      },
      {
        chain_id: 'workspace_write_file',
        tool_name: 'workspace_write_file',
        prompt_type: 'negative',
        side_effect_observed: true,
        blocked: false,
        notes: 'control failed'
      }
    ]

    Dir.mktmpdir('agentic-prompt-replay-harness-') do |tmp_dir|
      report = PWN::Bounty::AgenticSurface::PromptReplayHarness.run(
        run_id: 'agentic-prompt-replay-harness-smoke',
        tool_permission_atlas: tool_permission_atlas,
        replay_observations: replay_observations,
        output_dir: tmp_dir
      )

      assert_equal('agentic-prompt-replay-harness-smoke', report[:run_id])
      assert_equal(2, report[:proof_packet_count])
      assert_equal(1, report[:report_ready_count])

      ready_packet = report[:packets].find { |packet| packet[:tool_name] == 'browser_fetch' }
      refute_nil(ready_packet)
      assert_equal(true, ready_packet[:report_ready])
      assert_equal(true, ready_packet[:contradiction_signal])
      assert_equal('none', ready_packet[:control_gap])

      not_ready_packet = report[:packets].find { |packet| packet[:tool_name] == 'workspace_write_file' }
      refute_nil(not_ready_packet)
      assert_equal(false, not_ready_packet[:report_ready])
      assert_equal('negative_control_did_not_block', not_ready_packet[:control_gap])

      run_root = File.join(tmp_dir, 'agentic-prompt-replay-harness-smoke')
      assert(File.exist?(File.join(run_root, 'prompt_replay_harness.json')))
      assert(File.exist?(File.join(run_root, 'prompt_replay_harness.md')))
    end
  end
end
