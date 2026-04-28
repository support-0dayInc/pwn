# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class BrowserChainsOneClickStateChangePackSmokeTest < Minitest::Test
  def test_one_click_pack_marks_report_candidate_when_chain_and_controls_are_present
    Dir.mktmpdir('browser-chains-one-click-smoke-') do |tmp_dir|
      report = PWN::Bounty::BrowserChains::OneClickStateChangePack.run(
        run_id: 'browser-chains-one-click-smoke',
        target: 'https://app.example.test',
        campaign: 'stored-xss-one-click-email-change',
        observations: [
          {
            checkpoint: 'attacker_prepare',
            primitive: 'xss',
            status: 'triggered',
            notes: 'Stored XSS payload executed in victim dashboard.'
          },
          {
            checkpoint: 'victim_click',
            status: 'confirmed',
            signals: ['victim_action_triggered'],
            notes: 'Victim click single link path.'
          },
          {
            checkpoint: 'post_action',
            status: 'confirmed',
            signals: ['state_change_account', 'csrf_token_reuse_present'],
            notes: 'Email changed to attacker-controlled mailbox.'
          }
        ],
        controls: [
          {
            id: 'logged_out_replay',
            kind: 'negative',
            passed: true,
            notes: 'Logged-out replay blocked.'
          }
        ],
        output_dir: tmp_dir
      )

      assert_equal('browser-chains-one-click-smoke', report[:run_id])
      assert_equal(true, report[:one_click_account_or_state_change])
      assert_equal(true, report[:report_candidate])
      assert_equal('one_click_account_change', report.dig(:best_chain, :chain_id))
      assert_equal('critical_candidate', report.dig(:best_chain, :confidence))

      run_root = File.join(tmp_dir, 'browser-chains-one-click-smoke')
      assert(File.exist?(File.join(run_root, 'one_click_state_change_pack.json')))
      assert(File.exist?(File.join(run_root, 'one_click_state_change_pack.md')))
      assert(File.exist?(File.join(run_root, 'one_click_state_change_observations.json')))
    end
  end
end
