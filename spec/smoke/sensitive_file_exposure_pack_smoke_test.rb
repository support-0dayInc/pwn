# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class SensitiveFileExposurePackSmokeTest < Minitest::Test
  def test_sensitive_file_pack_ranks_report_candidates_and_redacts_preview
    Dir.mktmpdir('sensitive-file-pack-smoke-') do |tmp_dir|
      report = PWN::Bounty::SensitiveFileExposurePack.run(
        run_id: 'sensitive-file-pack-smoke',
        target: 'https://staging.example.test',
        hosts: ['staging.example.test'],
        observations: [
          {
            id: 'env_leak',
            url: 'https://staging.example.test/.env',
            http_status: 200,
            auth_state: 'unauthenticated',
            body: <<~BODY
              APP_ENV=staging
              AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
              AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
              DB_PASSWORD=sup3rsecret
            BODY
          }
        ],
        output_dir: tmp_dir
      )

      assert_equal('sensitive-file-pack-smoke', report[:run_id])
      assert(report[:candidate_count] > 0)
      assert(report[:report_candidate_count] > 0)
      top = report[:top_findings].first
      assert_equal(true, top[:report_candidate])
      assert_equal('cloud_credentials', top[:secret_class])
      assert_equal('unauthenticated', top[:auth_state])
      assert(top[:score] >= 80)
      refute_match(/AKIA[0-9A-Z]{16}/, top[:redacted_preview])
      assert(top[:redacted_preview].include?('[REDACTED]'))

      run_root = File.join(tmp_dir, 'sensitive-file-pack-smoke')
      assert(File.exist?(File.join(run_root, 'sensitive_file_exposure_plan.json')))
      assert(File.exist?(File.join(run_root, 'sensitive_file_exposure_report.json')))
      assert(File.exist?(File.join(run_root, 'sensitive_file_exposure_observations.json')))
      assert(File.exist?(File.join(run_root, 'sensitive_file_exposure_report.md')))
    end
  end
end
