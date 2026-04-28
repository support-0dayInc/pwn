# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Bounty
    # YAML-driven helper for capturing lifecycle authz evidence across
    # pre/post state transitions (e.g., collaborator removal, role change,
    # project visibility flips) with report-ready artifacts.
    module LifecycleAuthzReplay
      autoload :ArtifactAccessDriftMatrix, 'pwn/bounty/lifecycle_authz_replay/artifact_access_drift_matrix'
      autoload :CaptureAdapters, 'pwn/bounty/lifecycle_authz_replay/capture_adapters'
      autoload :OwnedAccountStateMatrix, 'pwn/bounty/lifecycle_authz_replay/owned_account_state_matrix'
      autoload :RoutePackCompleteness, 'pwn/bounty/lifecycle_authz_replay/route_pack_completeness'
      autoload :SubmissionBundle, 'pwn/bounty/lifecycle_authz_replay/submission_bundle'

      DEFAULT_CHECKPOINTS = %w[pre_change post_change_t0 post_change_tn].freeze
      STATUS_VALUES = %w[missing accessible denied error unknown].freeze
      TRANSITION_TYPES = %w[invite accept promote demote revoke suspend transfer].freeze
      DEFAULT_TRANSITION_CHECKPOINT_OFFSETS_MINUTES = [0, 10, 30, 60].freeze
      ROUTE_PACK_DEFINITIONS = {
        github: {
          reviewer_revocation: {
            transition: 'revoke',
            actors: [
              { id: 'owner', label: 'Repository Owner' },
              { id: 'revoked_user', label: 'Revoked Reviewer' }
            ],
            surfaces: [
              {
                id: 'repo_collaborator_api',
                label: 'Repository Collaborator API (direct)',
                metadata: {
                  route_category: 'direct',
                  adapter: {
                    type: 'http',
                    request: {
                      method: 'GET',
                      url: '%{api_base}/repos/%{owner}/%{repo}/collaborators/%{subject_actor}'
                    }
                  }
                }
              },
              {
                id: 'repo_settings_html',
                label: 'Repository Settings HTML (direct)',
                metadata: {
                  route_category: 'direct',
                  adapter: {
                    type: 'browser',
                    use_transparent_browser: false,
                    request: {
                      method: 'GET',
                      url: '%{target}/settings/access'
                    }
                  }
                }
              },
              {
                id: 'repo_notification_feed',
                label: 'Repository Notification Feed (secondary)',
                metadata: {
                  route_category: 'secondary',
                  adapter: {
                    type: 'http',
                    request: {
                      method: 'GET',
                      url: '%{target}/notifications'
                    }
                  }
                }
              },
              {
                id: 'repo_mentions_graphql',
                label: 'Repository Mentions GraphQL (secondary)',
                metadata: {
                  route_category: 'secondary',
                  adapter: {
                    type: 'graphql',
                    url: '%{api_base}/graphql',
                    operation_name: 'RepoMentionsTimeline',
                    query: %q(query RepoMentionsTimeline($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    name
    discussions(first: 5) {
      nodes { id title }
    }
  }
}
),
                    variables: {
                      owner: '%{owner}',
                      name: '%{repo}'
                    }
                  }
                }
              }
            ]
          }
        },
        gitlab: {
          member_revocation: {
            transition: 'revoke',
            actors: [
              { id: 'maintainer', label: 'Project Maintainer' },
              { id: 'revoked_member', label: 'Revoked Project Member' }
            ],
            surfaces: [
              {
                id: 'project_members_api',
                label: 'Project Members API (direct)',
                metadata: {
                  route_category: 'direct',
                  adapter: {
                    type: 'http',
                    request: {
                      method: 'GET',
                      url: '%{api_base}/projects/%{project_id}/members/%{subject_actor_id}'
                    }
                  }
                }
              },
              {
                id: 'project_settings_members',
                label: 'Project Members Settings HTML (direct)',
                metadata: {
                  route_category: 'direct',
                  adapter: {
                    type: 'browser',
                    use_transparent_browser: false,
                    request: {
                      method: 'GET',
                      url: '%{target}/-/project_members'
                    }
                  }
                }
              },
              {
                id: 'project_activity_feed',
                label: 'Project Activity Feed (secondary)',
                metadata: {
                  route_category: 'secondary',
                  adapter: {
                    type: 'http',
                    request: {
                      method: 'GET',
                      url: '%{target}/-/activity'
                    }
                  }
                }
              }
            ]
          }
        }
      }.freeze

      # Supported Method Parameters::
      # plan = PWN::Bounty::LifecycleAuthzReplay.load_plan(
      #   yaml_path: '/path/to/lifecycle_authz_replay.yaml'
      # )
      public_class_method def self.load_plan(opts = {})
        yaml_path = opts[:yaml_path]
        raise 'yaml_path is required' if yaml_path.to_s.strip.empty?
        raise "YAML plan does not exist: #{yaml_path}" unless File.exist?(yaml_path)

        raw_plan = YAML.safe_load_file(yaml_path, aliases: true) || {}
        normalize_plan(plan: symbolize_obj(raw_plan), plan_id_hint: File.basename(yaml_path, File.extname(yaml_path)))
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
      #   yaml_path: '/path/to/lifecycle_authz_replay.yaml',
      #   output_dir: '/tmp/evidence_bundle'
      # )
      #
      # OR
      # run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
      #   plan: normalized_plan_hash,
      #   output_dir: '/tmp/evidence_bundle'
      # )
      public_class_method def self.start_run(opts = {})
        output_dir = opts[:output_dir].to_s.strip
        output_dir = Dir.pwd if output_dir.empty?

        plan = opts[:plan]
        plan = load_plan(yaml_path: opts[:yaml_path]) if plan.nil?
        plan = normalize_plan(plan: plan) if plan.is_a?(Hash)

        run_id = opts[:run_id].to_s.strip
        run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-#{plan[:campaign][:id]}" if run_id.empty?

        run_root = File.expand_path(File.join(output_dir, run_id))
        artifacts_dir = File.join(run_root, 'artifacts')
        FileUtils.mkdir_p(artifacts_dir)

        run_obj = {
          run_id: run_id,
          run_root: run_root,
          artifacts_dir: artifacts_dir,
          started_at: Time.now.utc.iso8601,
          plan: plan,
          coverage_matrix: build_coverage_matrix(plan: plan),
          observations: []
        }

        write_json(path: File.join(run_root, 'coverage_matrix.json'), obj: run_obj[:coverage_matrix])
        write_yaml(path: File.join(run_root, 'plan.normalized.yaml'), obj: plan)
        write_runbook(run_obj: run_obj)

        run_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # route_pack = PWN::Bounty::LifecycleAuthzReplay.route_pack(
      #   provider: :github,
      #   lane: :reviewer_revocation
      # )
      public_class_method def self.route_pack(opts = {})
        provider = normalize_token(opts[:provider])
        lane = normalize_token(opts[:lane])

        raise 'provider is required' if provider.empty?
        raise 'lane is required' if lane.empty?

        pack = symbolize_obj(ROUTE_PACK_DEFINITIONS.dig(provider.to_sym, lane.to_sym))
        raise "unsupported route pack provider=#{provider} lane=#{lane}" if pack.nil?

        pack[:provider] = provider
        pack[:lane] = lane
        pack
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # timeline = PWN::Bounty::LifecycleAuthzReplay.transition_timeline(
      #   transition: 'revoke',
      #   checkpoint_offsets_minutes: [0, 10, 30, 60]
      # )
      public_class_method def self.transition_timeline(opts = {})
        transition = normalize_token(opts[:transition])
        transition = 'revoke' if transition.empty?
        raise "unsupported transition=#{transition}" unless TRANSITION_TYPES.include?(transition)

        offsets = Array(opts[:checkpoint_offsets_minutes]).map(&:to_i)
        offsets = DEFAULT_TRANSITION_CHECKPOINT_OFFSETS_MINUTES if offsets.empty?
        offsets = offsets.uniq.sort

        timeline = [
          {
            checkpoint: 'pre_change',
            phase: 'pre',
            offset_minutes: nil,
            expected_status: 'accessible'
          }
        ]

        offsets.each do |offset|
          checkpoint = checkpoint_for_offset(offset_minutes: offset)
          timeline << {
            checkpoint: checkpoint,
            phase: 'post',
            offset_minutes: offset,
            expected_status: 'denied'
          }
        end

        {
          transition: transition,
          checkpoint_offsets_minutes: offsets,
          timeline: timeline
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # plan = PWN::Bounty::LifecycleAuthzReplay.build_transition_plan(
      #   provider: :github,
      #   lane: :reviewer_revocation,
      #   transition: :revoke,
      #   target: 'https://github.example/org/repo',
      #   route_vars: {
      #     api_base: 'https://api.github.example',
      #     owner: 'org',
      #     repo: 'repo',
      #     subject_actor: 'revoked_user'
      #   }
      # )
      public_class_method def self.build_transition_plan(opts = {})
        pack = route_pack(provider: opts[:provider], lane: opts[:lane])

        transition = normalize_token(opts[:transition])
        transition = normalize_token(pack[:transition]) if transition.empty?
        transition = 'revoke' if transition.empty?

        timeline_obj = transition_timeline(
          transition: transition,
          checkpoint_offsets_minutes: opts[:checkpoint_offsets_minutes]
        )

        route_vars = symbolize_obj(opts[:route_vars] || {})
        target = opts[:target].to_s.strip
        route_vars[:target] = target unless target.empty?

        provider = pack[:provider]
        lane = pack[:lane]
        campaign_id = normalize_token(opts[:campaign_id])
        campaign_id = "#{provider}_#{lane}_#{transition}" if campaign_id.empty?

        campaign_label = opts[:campaign_label].to_s.strip
        campaign_label = "#{provider} #{lane} #{transition}" if campaign_label.empty?

        actors = symbolize_obj(opts[:actors] || pack[:actors])
        surfaces = symbolize_obj(opts[:surfaces] || pack[:surfaces])
        surfaces = render_surface_templates(surfaces: surfaces, route_vars: route_vars)

        checkpoints = timeline_obj[:timeline].map { |entry| entry[:checkpoint] }
        expected_denied_after = checkpoints.reject { |checkpoint| checkpoint == 'pre_change' }

        plan = {
          campaign: {
            id: campaign_id,
            label: campaign_label,
            target: target,
            change_event: transition,
            notes: opts[:notes].to_s
          },
          actors: actors,
          surfaces: surfaces,
          checkpoints: checkpoints,
          expected_denied_after: expected_denied_after,
          metadata: {
            transition_replay: {
              provider: provider,
              lane: lane,
              transition: transition,
              timeline: timeline_obj[:timeline],
              route_vars: route_vars
            }
          }
        }

        normalize_plan(plan: plan)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # run_obj = PWN::Bounty::LifecycleAuthzReplay.start_transition_run(
      #   provider: :github,
      #   lane: :reviewer_revocation,
      #   output_dir: '/tmp/evidence-bundles'
      # )
      public_class_method def self.start_transition_run(opts = {})
        transition_plan = opts[:plan]
        transition_plan ||= build_transition_plan(opts)

        run_obj = start_run(
          plan: transition_plan,
          output_dir: opts[:output_dir],
          run_id: opts[:run_id]
        )

        write_json(
          path: File.join(run_obj[:run_root], 'transition_replay.json'),
          obj: transition_plan[:metadata][:transition_replay]
        )

        run_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # execution = PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
      #   run_obj: run_obj,
      #   checkpoint: 'post_change_t0', # optional filter
      #   actor: 'revoked_user', # optional filter
      #   surface: 'repo_settings_page', # optional filter
      #   fail_fast: false
      # )
      public_class_method def self.execute_capture_matrix(opts = {})
        run_obj = opts[:run_obj]
        raise 'run_obj is required' unless run_obj.is_a?(Hash)

        checkpoint_filter = normalize_token(opts[:checkpoint])
        actor_filter = normalize_token(opts[:actor])
        surface_filter = normalize_token(opts[:surface])
        fail_fast = opts[:fail_fast] == true
        capture_proc = opts[:capture_proc]

        target_cells = run_obj[:coverage_matrix][:cells].select do |cell|
          checkpoint_match = checkpoint_filter.empty? || cell[:checkpoint] == checkpoint_filter
          actor_match = actor_filter.empty? || cell[:actor] == actor_filter
          surface_match = surface_filter.empty? || cell[:surface] == surface_filter
          checkpoint_match && actor_match && surface_match
        end

        execution = {
          run_id: run_obj[:run_id],
          started_at: Time.now.utc.iso8601,
          attempted_cells: target_cells.length,
          completed_cells: 0,
          failed_cells: 0,
          cell_results: []
        }

        target_cells.each do |cell|
          result = execute_capture_cell(
            run_obj: run_obj,
            checkpoint: cell[:checkpoint],
            actor: cell[:actor],
            surface: cell[:surface],
            capture_proc: capture_proc
          )
          execution[:completed_cells] += 1
          execution[:failed_cells] += 1 if result[:status] == 'error'
          execution[:cell_results] << result
        rescue StandardError => e
          execution[:completed_cells] += 1
          execution[:failed_cells] += 1
          execution[:cell_results] << {
            checkpoint: cell[:checkpoint],
            actor: cell[:actor],
            surface: cell[:surface],
            status: 'error',
            notes: e.message
          }
          raise e if fail_fast
        end

        execution[:completed_at] = Time.now.utc.iso8601
        write_json(path: File.join(run_obj[:run_root], 'capture_execution.json'), obj: execution)
        execution
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # result = PWN::Bounty::LifecycleAuthzReplay.execute_capture_cell(
      #   run_obj: run_obj,
      #   checkpoint: 'post_change_t0',
      #   actor: 'revoked_user',
      #   surface: 'repo_settings_page'
      # )
      public_class_method def self.execute_capture_cell(opts = {})
        run_obj = opts[:run_obj]
        raise 'run_obj is required' unless run_obj.is_a?(Hash)

        checkpoint = normalize_token(opts[:checkpoint])
        actor = normalize_token(opts[:actor])
        surface = normalize_token(opts[:surface])
        capture_proc = opts[:capture_proc]

        raise 'checkpoint is required' if checkpoint.empty?
        raise 'actor is required' if actor.empty?
        raise 'surface is required' if surface.empty?

        actor_record = find_named_record(records: run_obj[:plan][:actors], id: actor)
        raise "unknown actor: #{actor}" if actor_record.nil?

        surface_record = find_named_record(records: run_obj[:plan][:surfaces], id: surface)
        raise "unknown surface: #{surface}" if surface_record.nil?

        adapter_result = if capture_proc.respond_to?(:call)
                           capture_proc.call(
                             run_obj: run_obj,
                             checkpoint: checkpoint,
                             actor: actor,
                             surface: surface,
                             actor_record: actor_record,
                             surface_record: surface_record
                           )
                         else
                           execute_capture_adapter(
                             run_obj: run_obj,
                             checkpoint: checkpoint,
                             actor_record: actor_record,
                             surface_record: surface_record
                           )
                         end

        adapter_result = symbolize_obj(adapter_result || {})
        adapter_status = normalize_token(adapter_result[:status])
        adapter_status = 'unknown' if adapter_status.empty?
        adapter_status = 'error' unless STATUS_VALUES.include?(adapter_status)

        evidence = record_observation(
          run_obj: run_obj,
          checkpoint: checkpoint,
          actor: actor,
          surface: surface,
          status: adapter_status,
          request: adapter_result[:request] || {},
          response: adapter_result[:response] || {},
          notes: adapter_result[:notes].to_s,
          artifact_paths: adapter_result[:artifact_paths] || []
        )

        {
          checkpoint: checkpoint,
          actor: actor,
          surface: surface,
          status: adapter_status,
          evidence_path: File.join(run_obj[:artifacts_dir], checkpoint, actor, "#{surface}.json"),
          adapter_result: adapter_result,
          evidence: evidence
        }
      rescue StandardError => e
        error_evidence = {
          request: {},
          response: {},
          notes: "capture error: #{e.message}",
          artifact_paths: []
        }

        if run_obj.is_a?(Hash)
          begin
            record_observation(
              run_obj: run_obj,
              checkpoint: checkpoint,
              actor: actor,
              surface: surface,
              status: 'error',
              request: error_evidence[:request],
              response: error_evidence[:response],
              notes: error_evidence[:notes],
              artifact_paths: error_evidence[:artifact_paths]
            )
          rescue StandardError
            # ignore nested observation failures here and re-raise root issue
          end
        end

        raise e
      end

      # Supported Method Parameters::
      # PWN::Bounty::LifecycleAuthzReplay.record_observation(
      #   run_obj: run_obj,
      #   checkpoint: 'post_change_t0',
      #   actor: 'revoked_user',
      #   surface: 'repo_settings_page',
      #   status: :accessible,
      #   request: { method: 'GET', path: '/org/repo/settings' },
      #   response: { http_status: 200 },
      #   notes: 'Still reachable after collaborator removal',
      #   artifact_paths: ['/tmp/screen.png']
      # )
      public_class_method def self.record_observation(opts = {})
        run_obj = opts[:run_obj]
        raise 'run_obj is required' unless run_obj.is_a?(Hash)

        checkpoint = normalize_token(opts[:checkpoint])
        actor = normalize_token(opts[:actor])
        surface = normalize_token(opts[:surface])
        status = normalize_token(opts[:status])

        raise 'checkpoint is required' if checkpoint.empty?
        raise 'actor is required' if actor.empty?
        raise 'surface is required' if surface.empty?

        status = 'unknown' if status.empty?
        raise "unsupported status: #{status} (supported: #{STATUS_VALUES.join(', ')})" unless STATUS_VALUES.include?(status)

        coverage_cell = find_coverage_cell(
          coverage_matrix: run_obj[:coverage_matrix],
          checkpoint: checkpoint,
          actor: actor,
          surface: surface
        )

        raise "unknown coverage cell checkpoint=#{checkpoint} actor=#{actor} surface=#{surface}" if coverage_cell.nil?

        evidence = {
          observed_at: Time.now.utc.iso8601,
          checkpoint: checkpoint,
          actor: actor,
          surface: surface,
          status: status,
          request: symbolize_obj(opts[:request] || {}),
          response: symbolize_obj(opts[:response] || {}),
          notes: opts[:notes].to_s,
          artifact_paths: Array(opts[:artifact_paths]).map(&:to_s)
        }

        evidence_path = File.join(
          run_obj[:artifacts_dir],
          checkpoint,
          actor,
          "#{surface}.json"
        )
        write_json(path: evidence_path, obj: evidence)

        coverage_cell[:status] = status
        coverage_cell[:observed_at] = evidence[:observed_at]
        coverage_cell[:evidence_path] = evidence_path

        run_obj[:observations] << evidence.merge(evidence_path: evidence_path)

        write_json(path: File.join(run_obj[:run_root], 'coverage_matrix.json'), obj: run_obj[:coverage_matrix])
        write_coverage_markdown(run_obj: run_obj)

        evidence
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(
      #   run_obj: run_obj
      # )
      public_class_method def self.finalize_run(opts = {})
        run_obj = opts[:run_obj]
        raise 'run_obj is required' unless run_obj.is_a?(Hash)

        coverage_cells = run_obj[:coverage_matrix][:cells]
        missing_cells = coverage_cells.select { |cell| cell[:status] == 'missing' }
        stale_access_findings = find_stale_access_findings(run_obj: run_obj)
        mixed_surface_findings = find_mixed_surface_findings(run_obj: run_obj)
        artifact_access_drift = PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix.evaluate(
          run_obj: run_obj
        )

        route_pack_completeness = PWN::Bounty::LifecycleAuthzReplay::RoutePackCompleteness.evaluate(
          run_obj: run_obj
        )

        summary = {
          run_id: run_obj[:run_id],
          completed_at: Time.now.utc.iso8601,
          campaign: run_obj[:plan][:campaign],
          totals: {
            checkpoints: run_obj[:plan][:checkpoints].length,
            actors: run_obj[:plan][:actors].length,
            surfaces: run_obj[:plan][:surfaces].length,
            cells: coverage_cells.length,
            captured_cells: coverage_cells.count { |cell| cell[:status] != 'missing' },
            missing_cells: missing_cells.length,
            stale_access_findings: stale_access_findings.length,
            mixed_surface_findings: mixed_surface_findings.length,
            artifact_access_drift_findings: artifact_access_drift[:reportable_candidate_count],
            route_report_blockers: route_pack_completeness[:report_blocker_count],
            route_confidence_drops: route_pack_completeness[:confidence_drop_count],
            route_completion_score: route_pack_completeness[:completion_score]
          },
          stale_access_findings: stale_access_findings,
          mixed_surface_findings: mixed_surface_findings,
          artifact_access_drift: artifact_access_drift,
          missing_cells: missing_cells,
          route_pack_completeness: route_pack_completeness
        }

        submission_bundle = PWN::Bounty::LifecycleAuthzReplay::SubmissionBundle.evaluate(
          run_obj: run_obj,
          summary: summary,
          output_dir: File.dirname(run_obj[:run_root])
        )
        summary[:submission_bundle] = submission_bundle
        summary[:totals][:submission_ready] = submission_bundle[:ready_to_submit] == true ? 1 : 0
        summary[:totals][:submission_missing_proof_count] = Array(submission_bundle[:missing_proof]).length

        write_json(path: File.join(run_obj[:run_root], 'SUMMARY.json'), obj: summary)
        write_report(run_obj: run_obj, summary: summary)

        summary
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # plan = PWN::Bounty::LifecycleAuthzReplay.normalize_plan(
      #   plan: {
      #     campaign: { id: 'acme-revoke' },
      #     actors: ['owner', 'revoked_user'],
      #     surfaces: ['repo_settings'],
      #     checkpoints: ['pre_change', 'post_change_t0']
      #   }
      # )
      public_class_method def self.normalize_plan(opts = {})
        plan = symbolize_obj(opts[:plan] || {})
        plan_id_hint = normalize_token(opts[:plan_id_hint])

        campaign = symbolize_obj(plan[:campaign] || {})
        campaign_id = normalize_token(campaign[:id])
        campaign_id = normalize_token(campaign[:name]) if campaign_id.empty?
        campaign_id = plan_id_hint if campaign_id.empty?
        campaign_id = 'lifecycle-authz-replay' if campaign_id.empty?

        actors = normalize_named_records(
          list: Array(plan[:actors]),
          fallback: [{ id: 'primary_actor', label: 'Primary Actor' }],
          default_prefix: 'actor'
        )

        surfaces = normalize_named_records(
          list: Array(plan[:surfaces]),
          fallback: [{ id: 'primary_surface', label: 'Primary Surface' }],
          default_prefix: 'surface'
        )

        checkpoints = Array(plan[:checkpoints]).map { |checkpoint| normalize_token(checkpoint) }.reject(&:empty?)
        checkpoints = DEFAULT_CHECKPOINTS if checkpoints.empty?

        expected_denied_after = Array(plan[:expected_denied_after]).map { |checkpoint| normalize_token(checkpoint) }.reject(&:empty?)
        expected_denied_after = checkpoints.select { |checkpoint| checkpoint.start_with?('post_change') } if expected_denied_after.empty?

        {
          campaign: {
            id: campaign_id,
            label: campaign[:label].to_s.strip,
            target: campaign[:target].to_s.strip,
            change_event: campaign[:change_event].to_s.strip,
            notes: campaign[:notes].to_s.strip
          },
          actors: actors,
          surfaces: surfaces,
          checkpoints: checkpoints,
          expected_denied_after: expected_denied_after,
          metadata: symbolize_obj(plan[:metadata] || {})
        }
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage Information

      public_class_method def self.help
        <<~HELP
          Usage:
            plan = PWN::Bounty::LifecycleAuthzReplay.load_plan(
              yaml_path: '/path/to/lifecycle_authz_replay.yaml'
            )

            run_obj = PWN::Bounty::LifecycleAuthzReplay.start_run(
              plan: plan,
              output_dir: '/tmp/evidence-bundles'
            )

            transition_plan = PWN::Bounty::LifecycleAuthzReplay.build_transition_plan(
              provider: :github,
              lane: :reviewer_revocation,
              transition: :revoke,
              target: 'https://github.example/acme/private-repo',
              route_vars: {
                api_base: 'https://api.github.example',
                owner: 'acme',
                repo: 'private-repo',
                subject_actor: 'revoked_user'
              }
            )

            run_obj = PWN::Bounty::LifecycleAuthzReplay.start_transition_run(
              plan: transition_plan,
              output_dir: '/tmp/evidence-bundles'
            )

            PWN::Bounty::LifecycleAuthzReplay.record_observation(
              run_obj: run_obj,
              checkpoint: 'post_change_t0',
              actor: 'revoked_user',
              surface: 'repo_settings_page',
              status: :accessible,
              request: { method: 'GET', path: '/org/repo/settings' },
              response: { http_status: 200 },
              notes: 'Still reachable after remove action',
              artifact_paths: ['/tmp/screenshot.png']
            )

            PWN::Bounty::LifecycleAuthzReplay.execute_capture_matrix(
              run_obj: run_obj,
              checkpoint: 'post_change_t0' # optional filter
            )

            summary = PWN::Bounty::LifecycleAuthzReplay.finalize_run(
              run_obj: run_obj
            )

            owned_account_matrix = PWN::Bounty::LifecycleAuthzReplay::OwnedAccountStateMatrix.run(
              yaml_path: '/path/to/lifecycle_authz_replay.owned_account_state_matrix.example.yaml',
              output_dir: '/tmp/evidence-bundles'
            )

            completeness = PWN::Bounty::LifecycleAuthzReplay::RoutePackCompleteness.evaluate(
              run_obj: run_obj
            )

            artifact_drift = PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix.evaluate(
              run_obj: run_obj
            )

            submission_bundle = PWN::Bounty::LifecycleAuthzReplay::SubmissionBundle.evaluate(
              run_obj: run_obj,
              summary: summary
            )
        HELP
      end

      private_class_method def self.find_stale_access_findings(opts = {})
        run_obj = opts[:run_obj]
        expected_denied_after = run_obj[:plan][:expected_denied_after]

        run_obj[:coverage_matrix][:cells].select do |cell|
          expected_denied_after.include?(cell[:checkpoint]) && cell[:status] == 'accessible'
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.find_mixed_surface_findings(opts = {})
        run_obj = opts[:run_obj]
        expected_denied_after = Array(run_obj.dig(:plan, :expected_denied_after))
        return [] if expected_denied_after.empty?

        surface_metadata = Array(run_obj.dig(:plan, :surfaces)).each_with_object({}) do |surface, acc|
          surface_hash = symbolize_obj(surface || {})
          acc[surface_hash[:id].to_s] = symbolize_obj(surface_hash[:metadata] || {})
        end

        findings = []
        expected_denied_after.each do |checkpoint|
          checkpoint_cells = run_obj[:coverage_matrix][:cells].select { |cell| cell[:checkpoint] == checkpoint }
          actors = checkpoint_cells.map { |cell| cell[:actor] }.uniq

          actors.each do |actor|
            actor_cells = checkpoint_cells.select { |cell| cell[:actor] == actor }

            direct_denied = actor_cells.select do |cell|
              metadata = symbolize_obj(surface_metadata[cell[:surface]] || {})
              normalize_token(metadata[:route_category]) == 'direct' && cell[:status] == 'denied'
            end

            secondary_accessible = actor_cells.select do |cell|
              metadata = symbolize_obj(surface_metadata[cell[:surface]] || {})
              normalize_token(metadata[:route_category]) == 'secondary' && cell[:status] == 'accessible'
            end

            next if direct_denied.empty? || secondary_accessible.empty?

            findings << {
              checkpoint: checkpoint,
              actor: actor,
              direct_denied_surfaces: direct_denied.map { |cell| cell[:surface] },
              secondary_accessible_surfaces: secondary_accessible.map { |cell| cell[:surface] },
              direct_evidence_paths: direct_denied.map { |cell| cell[:evidence_path] }.compact,
              secondary_evidence_paths: secondary_accessible.map { |cell| cell[:evidence_path] }.compact
            }
          end
        end

        findings
      rescue StandardError => e
        raise e
      end

      private_class_method def self.find_coverage_cell(opts = {})
        coverage_matrix = opts[:coverage_matrix]
        checkpoint = opts[:checkpoint]
        actor = opts[:actor]
        surface = opts[:surface]

        coverage_matrix[:cells].find do |cell|
          cell[:checkpoint] == checkpoint && cell[:actor] == actor && cell[:surface] == surface
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.find_named_record(opts = {})
        records = Array(opts[:records])
        id = normalize_token(opts[:id])
        records.find { |record| normalize_token(record[:id]) == id }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.execute_capture_adapter(opts = {})
        run_obj = opts[:run_obj]
        checkpoint = opts[:checkpoint]
        actor_record = opts[:actor_record]
        surface_record = opts[:surface_record]

        adapter_cfg = symbolize_obj(surface_record[:metadata][:adapter] || {})
        adapter_type = normalize_token(adapter_cfg[:type] || adapter_cfg[:adapter_type])
        raise "surface #{surface_record[:id]} missing adapter.type" if adapter_type.empty?

        case adapter_type
        when 'http'
          CaptureAdapters::HTTP.capture(
            run_obj: run_obj,
            checkpoint: checkpoint,
            actor_record: actor_record,
            surface_record: surface_record,
            adapter_cfg: adapter_cfg
          )
        when 'graphql'
          CaptureAdapters::GraphQL.capture(
            run_obj: run_obj,
            checkpoint: checkpoint,
            actor_record: actor_record,
            surface_record: surface_record,
            adapter_cfg: adapter_cfg
          )
        when 'browser'
          CaptureAdapters::Browser.capture(
            run_obj: run_obj,
            checkpoint: checkpoint,
            actor_record: actor_record,
            surface_record: surface_record,
            adapter_cfg: adapter_cfg
          )
        else
          raise "unsupported adapter.type=#{adapter_type} for surface #{surface_record[:id]}"
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.build_coverage_matrix(opts = {})
        plan = opts[:plan]

        cells = []
        plan[:checkpoints].each do |checkpoint|
          plan[:actors].each do |actor|
            plan[:surfaces].each do |surface|
              cells << {
                checkpoint: checkpoint,
                actor: actor[:id],
                surface: surface[:id],
                status: 'missing',
                observed_at: nil,
                evidence_path: nil
              }
            end
          end
        end

        {
          generated_at: Time.now.utc.iso8601,
          status_values: STATUS_VALUES,
          cells: cells
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_runbook(opts = {})
        run_obj = opts[:run_obj]
        plan = run_obj[:plan]
        runbook_path = File.join(run_obj[:run_root], 'RUNBOOK.md')

        runbook_lines = []
        runbook_lines << '# Lifecycle Authz Replay Runbook'
        runbook_lines <<
          "Run ID: `#{run_obj[:run_id]}`  " \
          "Campaign: `#{plan[:campaign][:id]}`  " \
          "Target: `#{plan[:campaign][:target]}`"

        transition_replay = symbolize_obj(plan.dig(:metadata, :transition_replay) || {})
        unless transition_replay.empty?
          runbook_lines << ''
          runbook_lines << '## Transition Replay Context'
          runbook_lines << "- provider: `#{transition_replay[:provider]}`"
          runbook_lines << "- lane: `#{transition_replay[:lane]}`"
          runbook_lines << "- transition: `#{transition_replay[:transition]}`"

          timeline = Array(transition_replay[:timeline])
          unless timeline.empty?
            runbook_lines << '- timeline:'
            timeline.each do |entry|
              checkpoint = entry[:checkpoint]
              phase = entry[:phase]
              offset = entry[:offset_minutes]
              expected_status = entry[:expected_status]
              runbook_lines << "  - #{checkpoint} phase=#{phase} offset_min=#{offset.inspect} expected=#{expected_status}"
            end
          end
        end

        runbook_lines << ''
        runbook_lines << '## Checkpoint capture checklist'

        plan[:checkpoints].each do |checkpoint|
          expected_status = plan[:expected_denied_after].include?(checkpoint) ? 'denied' : 'accessible'
          runbook_lines << ''
          runbook_lines << "### #{checkpoint} (expected status: #{expected_status})"

          plan[:actors].each do |actor|
            plan[:surfaces].each do |surface|
              runbook_lines << "- [ ] actor=`#{actor[:id]}` surface=`#{surface[:id]}`"
            end
          end
        end

        runbook_lines << ''
        runbook_lines << '## Artifact locations'
        runbook_lines << '- coverage matrix: `coverage_matrix.json` + `coverage_matrix.md`'
        runbook_lines << '- evidence: `artifacts/<checkpoint>/<actor>/<surface>.json`'
        runbook_lines << '- report output: `SUMMARY.json` + `REPORT.md`'

        File.write(runbook_path, runbook_lines.join("\n"))

        write_coverage_markdown(run_obj: run_obj)
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_coverage_markdown(opts = {})
        run_obj = opts[:run_obj]
        coverage_path = File.join(run_obj[:run_root], 'coverage_matrix.md')

        lines = []
        lines << '# Coverage Matrix'
        lines << ''
        lines << '| Checkpoint | Actor | Surface | Status | Evidence |'
        lines << '| --- | --- | --- | --- | --- |'

        run_obj[:coverage_matrix][:cells].each do |cell|
          evidence = cell[:evidence_path].to_s
          evidence = File.basename(evidence) unless evidence.empty?
          lines << "| #{cell[:checkpoint]} | #{cell[:actor]} | #{cell[:surface]} | #{cell[:status]} | #{evidence} |"
        end

        File.write(coverage_path, lines.join("\n"))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_report(opts = {})
        run_obj = opts[:run_obj]
        summary = opts[:summary]

        lines = []
        lines << '# Lifecycle Authz Replay Report'
        lines << ''
        lines << "- Run ID: `#{summary[:run_id]}`"
        lines << "- Campaign: `#{summary[:campaign][:id]}`"
        lines << "- Completed At (UTC): `#{summary[:completed_at]}`"
        lines << "- Captured Cells: `#{summary[:totals][:captured_cells]}` / `#{summary[:totals][:cells]}`"
        lines << "- Missing Cells: `#{summary[:totals][:missing_cells]}`"
        lines << ''

        lines << '## Stale Access Findings'
        if summary[:stale_access_findings].empty?
          lines << '- No stale-access cells confirmed in expected-denied checkpoints.'
        else
          summary[:stale_access_findings].each do |finding|
            lines << "- checkpoint=`#{finding[:checkpoint]}` actor=`#{finding[:actor]}` surface=`#{finding[:surface]}` evidence=`#{finding[:evidence_path]}`"
          end
        end

        lines << ''
        lines << '## Missing Coverage Cells'
        if summary[:missing_cells].empty?
          lines << '- Coverage complete for planned cells.'
        else
          summary[:missing_cells].each do |cell|
            lines << "- checkpoint=`#{cell[:checkpoint]}` actor=`#{cell[:actor]}` surface=`#{cell[:surface]}`"
          end
        end

        lines << ''
        lines << '## Mixed Surface Findings (Direct Denied + Secondary Visible)'
        if summary[:mixed_surface_findings].to_a.empty?
          lines << '- No mixed direct-denied/secondary-visible findings observed.'
        else
          summary[:mixed_surface_findings].each do |finding|
            lines << "- checkpoint=`#{finding[:checkpoint]}` actor=`#{finding[:actor]}` direct_denied=`#{finding[:direct_denied_surfaces].join(',')}` secondary_visible=`#{finding[:secondary_accessible_surfaces].join(',')}`"
          end
        end

        lines << ''
        lines << '## Artifact Access Drift Matrix'
        artifact_drift = symbolize_obj(summary[:artifact_access_drift] || {})
        lines << "- Object Families: `#{artifact_drift[:family_count] || 0}`"
        lines << "- Reportable Candidates: `#{artifact_drift[:reportable_candidate_count] || 0}`"

        if Array(artifact_drift[:families]).empty?
          lines << '- No direct-denied/derived-accessible artifact drift observed in this run.'
        else
          Array(artifact_drift[:families]).each do |family|
            family_hash = symbolize_obj(family)
            lines << "- family=`#{family_hash[:family_key]}` angle=`#{family_hash[:report_angle]}`"
            lines << "  - direct_denied=`#{family_hash[:direct_denied]}` derived_accessible=`#{family_hash[:derived_accessible]}`"
            lines << "  - surviving_derived_routes=`#{Array(family_hash[:surviving_derived_routes]).join(',')}`"
          end
        end

        lines << ''
        lines << '## Submission Bundle'
        submission_bundle = symbolize_obj(summary[:submission_bundle] || {})
        lines << "- Decision: `#{submission_bundle[:decision]}`"
        lines << "- Ready To Submit: `#{submission_bundle[:ready_to_submit]}`"

        if Array(submission_bundle[:missing_proof]).empty?
          lines << '- Missing Proof: none'
        else
          lines << "- Missing Proof: `#{Array(submission_bundle[:missing_proof]).join(', ')}`"
        end

        lines << ''
        lines << '## Route Pack Completeness'
        completeness = symbolize_obj(summary[:route_pack_completeness] || {})
        lines << "- Completion Score: `#{completeness[:completion_score]}`"
        lines << "- Report Blockers: `#{completeness[:report_blocker_count]}`"
        lines << "- Confidence Drops: `#{completeness[:confidence_drop_count]}`"

        if Array(completeness[:gap_findings]).empty?
          lines << '- No route completeness gaps detected for configured families.'
        else
          Array(completeness[:gap_findings]).each do |gap|
            gap_hash = symbolize_obj(gap)
            lines << "- [#{gap_hash[:impact_level]}] family=`#{gap_hash[:route_family]}` reason=`#{gap_hash[:reason]}`"
          end
        end

        lines << ''
        lines << '### Post-change checklist'
        post_checklist = symbolize_obj(completeness.dig(:checklists, :post_change) || {})
        if Array(post_checklist[:items]).empty?
          lines << '- No post-change checklist items pending.'
        else
          Array(post_checklist[:items]).each do |item|
            item_hash = symbolize_obj(item)
            lines << "- [#{item_hash[:impact_level]}] checkpoint=`#{item_hash[:checkpoint]}` actor=`#{item_hash[:actor]}` surface=`#{item_hash[:surface]}`"
          end
        end

        File.write(File.join(run_obj[:run_root], 'REPORT.md'), lines.join("\n"))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.checkpoint_for_offset(opts = {})
        offset_minutes = opts[:offset_minutes].to_i
        return 'post_change_t0' if offset_minutes <= 0

        "post_change_t#{offset_minutes}m"
      rescue StandardError => e
        raise e
      end

      private_class_method def self.render_surface_templates(opts = {})
        surfaces = symbolize_obj(opts[:surfaces] || [])
        route_vars = symbolize_obj(opts[:route_vars] || {})

        surfaces.map do |surface|
          surface_hash = symbolize_obj(surface)
          render_obj_templates(obj: surface_hash, route_vars: route_vars)
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.render_obj_templates(opts = {})
        obj = opts[:obj]
        route_vars = symbolize_obj(opts[:route_vars] || {})

        case obj
        when Array
          obj.map { |entry| render_obj_templates(obj: entry, route_vars: route_vars) }
        when Hash
          obj.each_with_object({}) do |(key, value), accum|
            accum[key] = render_obj_templates(obj: value, route_vars: route_vars)
          end
        when String
          render_template_str(template: obj, route_vars: route_vars)
        else
          obj
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.render_template_str(opts = {})
        template = opts[:template].to_s
        route_vars = symbolize_obj(opts[:route_vars] || {})
        return template unless template.include?('%{')

        template.gsub(/%\{([^}]+)\}/) do |match|
          key = Regexp.last_match(1).to_s
          sym_key = key.to_sym
          val = route_vars[sym_key]
          val = route_vars[key] if val.nil?
          val.nil? ? match : val.to_s
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_named_records(opts = {})
        list = opts[:list]
        fallback = opts[:fallback]
        default_prefix = normalize_token(opts[:default_prefix])

        list = fallback if list.empty?

        normalized = []
        list.each_with_index do |entry, index|
          item = entry
          item = { id: entry.to_s, label: entry.to_s } unless item.is_a?(Hash)
          item = symbolize_obj(item)

          id = normalize_token(item[:id])
          id = normalize_token(item[:name]) if id.empty?
          id = "#{default_prefix}_#{index + 1}" if id.empty?

          label = item[:label].to_s.strip
          label = item[:name].to_s.strip if label.empty?
          label = id if label.empty?

          metadata = symbolize_obj(item[:metadata] || {})
          item.each do |key, value|
            next if %i[id label name metadata].include?(key)

            metadata[key] = symbolize_obj(value)
          end

          normalized << {
            id: id,
            label: label,
            metadata: metadata
          }
        end

        normalized
      rescue StandardError => e
        raise e
      end

      private_class_method def self.symbolize_obj(obj)
        case obj
        when Array
          obj.map { |entry| symbolize_obj(entry) }
        when Hash
          obj.each_with_object({}) do |(key, value), accum|
            symbolized_key = key.respond_to?(:to_sym) ? key.to_sym : key
            accum[symbolized_key] = symbolize_obj(value)
          end
        else
          obj
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_token(token)
        token.to_s.strip.downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_+|_+$/, '')
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_json(opts = {})
        path = opts[:path]
        obj = opts[:obj]
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, JSON.pretty_generate(obj))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.write_yaml(opts = {})
        path = opts[:path]
        obj = opts[:obj]
        FileUtils.mkdir_p(File.dirname(path))
        yaml_obj = YAML.dump(obj).gsub(/^\s*:(\w+):/, '\\1:')
        File.write(path, yaml_obj)
      rescue StandardError => e
        raise e
      end
    end
  end
end
