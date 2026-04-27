# frozen_string_literal: true

require 'minitest/autorun'
require 'pwn'

class SSRFChainCloudImpactProfilerSmokeTest < Minitest::Test
  def test_cloud_impact_profiler_extracts_aws_identity_and_critical_candidate
    observations = [
      {
        payload_id: 'aws_imds_identity',
        url: 'http://169.254.169.254/latest/dynamic/instance-identity/document',
        body: '{"accountId":"123456789012","region":"us-east-1","instanceId":"i-0abc123","availabilityZone":"us-east-1a"}'
      },
      {
        payload_id: 'aws_imds_role_creds',
        url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/app-prod-role',
        body: '{"AccessKeyId":"ASIAXXX","SecretAccessKey":"secret","Token":"token"}'
      }
    ]

    findings = [
      {
        payload_id: 'aws_imds_identity',
        classification: 'metadata'
      },
      {
        payload_id: 'aws_imds_role_creds',
        classification: 'metadata'
      }
    ]

    profile = PWN::HTTP::SSRFChain::CloudImpactProfiler.profile(
      observations: observations,
      findings: findings,
      sink_url: 'https://target.example/webhook'
    )

    assert_equal('critical_candidate', profile[:highest_impact_label])
    assert_equal(1, profile[:provider_count])
    assert_equal('aws', profile.dig(:primary_assessment, :provider))
    assert_equal('123456789012', profile.dig(:primary_assessment, :identity, :account_id))
    assert(profile.dig(:primary_assessment, :credentials_exposed))
    assert(profile.dig(:primary_assessment, :follow_up_requests).any? { |entry| entry.include?('sts get-caller-identity') })
  end
end
