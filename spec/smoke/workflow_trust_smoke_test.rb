# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class WorkflowTrustSmokeTest < Minitest::Test
  def test_scan_repo_ranks_workflow_and_oidc_trust_findings
    Dir.mktmpdir('workflow-trust-smoke-') do |tmp_dir|
      repo_dir = File.join(tmp_dir, 'repo')
      workflows_dir = File.join(repo_dir, '.github', 'workflows')
      FileUtils.mkdir_p(workflows_dir)

      File.write(
        File.join(workflows_dir, 'ci.yml'),
        <<~YAML
          name: CI
          on:
            pull_request_target:
            issue_comment:
            workflow_run:
              workflows: ["Build"]
          permissions:
            contents: write
            id-token: write
          jobs:
            validate:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/checkout@v4
                  with:
                    ref: ${{ github.event.pull_request.head.sha }}
                - run: echo "${{ github.event.comment.body }}" | bash
                - uses: actions/download-artifact@v4
        YAML
      )

      oidc_claims = [
        {
          sub: 'repo:acme/repo:ref:refs/heads/feature-x',
          aud: 'sts.amazonaws.com',
          event_name: 'pull_request_target',
          workflow_ref: 'acme/repo/.github/workflows/ci.yml@refs/heads/main'
        }
      ]

      trust_policies = [
        {
          provider: 'aws',
          name: 'broad-oidc-role',
          statements: [
            {
              condition: {
                StringLike: {
                  'token.actions.githubusercontent.com:sub' => 'repo:acme/repo:*',
                  'token.actions.githubusercontent.com:aud' => 'sts.amazonaws.com'
                }
              }
            }
          ]
        }
      ]

      out_dir = File.join(tmp_dir, 'report')
      report = PWN::Targets::GitHub::WorkflowTrust.scan_repo(
        repo_path: repo_dir,
        oidc_claims: oidc_claims,
        trust_policies: trust_policies,
        output_dir: out_dir
      )

      assert_equal(1, report[:workflow_count])
      assert(report[:finding_count] >= 3)
      assert(report[:findings].any? { |finding| finding[:id].include?('pr_target_untrusted_checkout') })
      assert(report[:findings].any? { |finding| finding[:id].include?('broad_oidc_acceptance') })
      assert_equal(1, report[:oidc_acceptance][:broad_acceptance_policy_count])
      assert_equal(1, report[:oidc_acceptance][:untrusted_claim_acceptance_count])

      assert(File.exist?(File.join(out_dir, 'workflow_trust_report.json')))
      assert(File.exist?(File.join(out_dir, 'workflow_trust_report.md')))
    end
  end
end
