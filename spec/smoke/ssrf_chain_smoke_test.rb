# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class SSRFChainSmokeTest < Minitest::Test
  def test_ssrf_chain_plans_and_reports_high_signal_findings
    Dir.mktmpdir('ssrf-chain-smoke-') do |tmp_dir|
      report = PWN::HTTP::SSRFChain.run(
        sink_family: 'webhook',
        sink_url: 'https://target.example/api/webhook',
        collaborator_domain: 'oast.test',
        cloud_focus: %w[aws gcp],
        max_payloads: 10,
        observations: [
          {
            payload_id: 'aws_imds_role_list',
            http_status: 200,
            body: "prod-app-role\n"
          },
          {
            payload_id: 'blind_oob_callback',
            collaborator_hit: true,
            http_status: 0,
            body: ''
          }
        ],
        output_dir: tmp_dir,
        run_id: 'ssrf-chain-smoke'
      )

      assert_equal('ssrf-chain-smoke', report[:run_id])
      assert(report[:payload_count] <= 10)
      assert(report[:findings].any? { |finding| finding[:classification] == 'metadata' })
      assert(report[:findings].any? { |finding| finding[:classification] == 'blind-only' })

      run_root = File.join(tmp_dir, 'ssrf-chain-smoke')
      assert(File.exist?(File.join(run_root, 'ssrf_chain_plan.json')))
      assert(File.exist?(File.join(run_root, 'ssrf_chain_report.json')))
      assert(File.exist?(File.join(run_root, 'ssrf_chain_report.md')))
      assert(File.exist?(File.join(run_root, 'ssrf_chain_observations.json')))
    end
  end
end
