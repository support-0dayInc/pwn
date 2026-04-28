# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class WorkflowTrustFixtureUpgradeStepPackSmokeTest < Minitest::Test
  def test_scan_repo_embeds_fixture_upgrade_step_pack
    Dir.mktmpdir('workflow-trust-fixture-pack-smoke-') do |tmp_dir|
      repo_dir = File.join(tmp_dir, 'repo')
      workflows_dir = File.join(repo_dir, '.github', 'workflows')
      FileUtils.mkdir_p(workflows_dir)

      File.write(
        File.join(workflows_dir, 'ci.yml'),
        <<~YAML
          name: CI
          on:
            pull_request_target:
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/upload-artifact@v4
                  with:
                    name: out
                    path: ./out.txt
            call_deploy:
              uses: ./.github/workflows/deploy.yml
              secrets: inherit
        YAML
      )

      File.write(
        File.join(workflows_dir, 'deploy.yml'),
        <<~YAML
          name: Deploy
          on:
            workflow_call:
          permissions:
            id-token: write
            contents: write
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: echo "deploy"
        YAML
      )

      File.write(
        File.join(workflows_dir, 'promote.yml'),
        <<~YAML
          name: Promote
          on:
            workflow_run:
              workflows: ["CI"]
              types: [completed]
          permissions:
            id-token: write
            contents: write
          jobs:
            consume:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                - run: echo "consume"
        YAML
      )

      report = PWN::Targets::GitHub::WorkflowTrust.scan_repo(
        repo_path: repo_dir,
        oidc_claims: [],
        trust_policies: [],
        permission_gate: {
          gate: {
            result: 'passed'
          }
        },
        oidc_claim_context: [
          {
            sub: 'repo:acme/repo:ref:refs/heads/fixture-canary',
            aud: 'sts.amazonaws.com',
            job_workflow_ref: 'acme/repo/.github/workflows/deploy.yml@refs/heads/main'
          }
        ]
      )

      pack = report[:fixture_upgrade_step_pack]
      refute_nil(pack)
      assert(pack[:planned_step_count] >= 2)
      assert(pack[:steps].all? { |step| step[:gate_status] == 'passed' })
      assert(pack[:steps].all? { |step| !Array(step[:upgrade_steps]).empty? })
      assert(pack[:steps].all? { |step| !Array(step[:validation_checks]).empty? })
      assert(pack[:steps].any? { |step| step[:preferred_sink_kind] == 'oidc_role_assumption' })
    end
  end

  def test_fixture_upgrade_step_pack_scan_repo_writes_artifacts
    Dir.mktmpdir('workflow-trust-fixture-pack-run-') do |tmp_dir|
      repo_dir = File.join(tmp_dir, 'repo')
      workflows_dir = File.join(repo_dir, '.github', 'workflows')
      FileUtils.mkdir_p(workflows_dir)

      File.write(
        File.join(workflows_dir, 'ci.yml'),
        <<~YAML
          name: CI
          on:
            issue_comment:
          jobs:
            call_deploy:
              uses: ./.github/workflows/deploy.yml
              secrets: inherit
        YAML
      )

      File.write(
        File.join(workflows_dir, 'deploy.yml'),
        <<~YAML
          name: Deploy
          on:
            workflow_call:
          permissions:
            id-token: write
          jobs:
            deploy:
              runs-on: ubuntu-latest
              steps:
                - run: echo "deploy"
        YAML
      )

      out_dir = File.join(tmp_dir, 'fixture-step-pack')
      pack = PWN::Targets::GitHub::WorkflowTrust::FixtureUpgradeStepPack.scan_repo(
        repo_path: repo_dir,
        output_dir: out_dir
      )

      assert(pack[:planned_step_count] >= 1)
      assert(File.exist?(File.join(out_dir, 'workflow_trust_fixture_upgrade_step_pack.json')))
      assert(File.exist?(File.join(out_dir, 'workflow_trust_fixture_upgrade_step_pack.md')))
    end
  end
end
