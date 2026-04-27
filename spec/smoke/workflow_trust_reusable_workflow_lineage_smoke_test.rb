# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class WorkflowTrustReusableWorkflowLineageSmokeTest < Minitest::Test
  def test_scan_repo_surfaces_cross_workflow_escalation_paths
    Dir.mktmpdir('workflow-trust-lineage-smoke-') do |tmp_dir|
      repo_dir = File.join(tmp_dir, 'repo')
      workflows_dir = File.join(repo_dir, '.github', 'workflows')
      FileUtils.mkdir_p(workflows_dir)

      File.write(
        File.join(workflows_dir, 'ci.yml'),
        <<~YAML
          name: CI
          on:
            pull_request_target:
          permissions:
            contents: read
          jobs:
            build:
              runs-on: ubuntu-latest
              steps:
                - run: echo "attacker controlled build"
                - uses: actions/upload-artifact@v4
                  with:
                    name: build-output
                    path: ./build.out
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
            contents: write
            id-token: write
          jobs:
            deploy:
              runs-on: ubuntu-latest
              environment: production
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
            contents: write
            id-token: write
          jobs:
            consume:
              runs-on: ubuntu-latest
              steps:
                - uses: actions/download-artifact@v4
                - run: echo "consume"
        YAML
      )

      out_dir = File.join(tmp_dir, 'report')
      report = PWN::Targets::GitHub::WorkflowTrust.scan_repo(
        repo_path: repo_dir,
        oidc_claims: [],
        trust_policies: [],
        output_dir: out_dir
      )

      lineage = report[:reusable_workflow_lineage]
      refute_nil(lineage)
      assert(lineage[:path_count] >= 2)
      assert(lineage[:paths].any? { |path| path[:chain_type] == 'reusable_workflow_call' })
      assert(lineage[:paths].any? { |path| path[:chain_type] == 'workflow_run_artifact_fan_in' })
      assert(lineage[:paths].all? { |path| !path[:preferred_sink_kind].to_s.empty? })
      assert(lineage[:paths].all? { |path| !path[:upgrade_priority].to_s.empty? })
      assert(lineage[:paths].all? { |path| !path[:best_next_owned_test].to_s.empty? })

      assert(File.exist?(File.join(out_dir, 'workflow_trust_report.json')))
      assert(File.exist?(File.join(out_dir, 'workflow_trust_report.md')))
    end
  end

  def test_lineage_module_scan_repo_writes_standalone_artifacts
    Dir.mktmpdir('workflow-trust-lineage-module-smoke-') do |tmp_dir|
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

      out_dir = File.join(tmp_dir, 'lineage-report')
      report = PWN::Targets::GitHub::WorkflowTrust::ReusableWorkflowLineage.scan_repo(
        repo_path: repo_dir,
        output_dir: out_dir
      )

      assert(report[:path_count] >= 1)
      assert(File.exist?(File.join(out_dir, 'workflow_trust_reusable_workflow_lineage.json')))
      assert(File.exist?(File.join(out_dir, 'workflow_trust_reusable_workflow_lineage.md')))
    end
  end
end
