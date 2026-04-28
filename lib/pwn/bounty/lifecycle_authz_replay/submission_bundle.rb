# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'time'

module PWN
  module Bounty
    module LifecycleAuthzReplay
      # Converts lifecycle replay outputs into a triager-ready submission packet.
      module SubmissionBundle
        SENSITIVE_PAYLOAD_HINTS = %w[
          password
          passwd
          token
          secret
          api_key
          private_key
          ssn
          social_security
          dob
          pii
          email
          phone
          address
          billing
          invoice
          customer
        ].freeze

        # Supported Method Parameters::
        # bundle = PWN::Bounty::LifecycleAuthzReplay::SubmissionBundle.evaluate(
        #   run_obj: run_obj,
        #   summary: summary,
        #   output_dir: '/tmp/evidence-bundles'
        # )
        public_class_method def self.evaluate(opts = {})
          run_obj = opts[:run_obj]
          summary = symbolize_obj(opts[:summary] || {})
          summary = derive_summary_from_run(run_obj: run_obj) if summary.empty?

          raise 'summary is required' if summary.empty?

          direct_denied_cells = direct_cells_with_status(
            run_obj: run_obj,
            checkpoints: Array(run_obj&.dig(:plan, :expected_denied_after)),
            statuses: ['denied']
          )

          direct_accessible_cells = direct_cells_with_status(
            run_obj: run_obj,
            checkpoints: Array(run_obj&.dig(:plan, :expected_denied_after)),
            statuses: ['accessible']
          )

          surviving_access_groups = surviving_access_groups(summary: summary)
          sensitive_payload_observed = sensitive_payload_observed?(run_obj: run_obj)
          contradictions = contradictions(
            direct_denied_cells: direct_denied_cells,
            direct_accessible_cells: direct_accessible_cells,
            summary: summary,
            sensitive_payload_observed: sensitive_payload_observed
          )

          missing_proof = missing_proof(
            direct_denied_cells: direct_denied_cells,
            surviving_access_groups: surviving_access_groups,
            summary: summary,
            contradictions: contradictions,
            sensitive_payload_observed: sensitive_payload_observed
          )

          decision = decide(summary: summary, contradictions: contradictions, missing_proof: missing_proof)
          ready_to_submit = decision == 'submit_now'

          bundle = {
            generated_at: Time.now.utc.iso8601,
            run_id: summary[:run_id].to_s,
            ready_to_submit: ready_to_submit,
            decision: decision,
            claim: claim(
              summary: summary,
              direct_denied_cells: direct_denied_cells,
              surviving_access_groups: surviving_access_groups,
              contradictions: contradictions
            ),
            evidence_groups: evidence_groups(
              summary: summary,
              direct_denied_cells: direct_denied_cells,
              direct_accessible_cells: direct_accessible_cells,
              surviving_access_groups: surviving_access_groups
            ),
            impact_bullets: impact_bullets(
              summary: summary,
              surviving_access_groups: surviving_access_groups
            ),
            repro_skeleton: repro_skeleton(
              summary: summary,
              direct_denied_cells: direct_denied_cells,
              surviving_access_groups: surviving_access_groups
            ),
            missing_proof: missing_proof,
            contradictions: contradictions,
            cvss_draft: cvss_draft(
              summary: summary,
              contradictions: contradictions,
              missing_proof: missing_proof,
              surviving_access_groups: surviving_access_groups
            ),
            cwe_draft: cwe_draft(summary: summary, surviving_access_groups: surviving_access_groups),
            nist_800_53_candidate: nist_800_53_candidate(
              summary: summary,
              contradictions: contradictions,
              missing_proof: missing_proof
            )
          }

          output_dir = opts[:output_dir].to_s.scrub.strip
          unless output_dir.empty?
            run_id = bundle[:run_id].to_s
            run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-submission-bundle" if run_id.empty?
            run_root = File.expand_path(File.join(output_dir, run_id))
            FileUtils.mkdir_p(run_root)
            write_report(run_root: run_root, bundle: bundle)
            bundle[:run_root] = run_root
          end

          bundle
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
              bundle = PWN::Bounty::LifecycleAuthzReplay::SubmissionBundle.evaluate(
                run_obj: run_obj,
                summary: summary,
                output_dir: '/tmp/evidence-bundles'
              )
          HELP
        end

        private_class_method def self.derive_summary_from_run(opts = {})
          run_obj = opts[:run_obj]
          return {} unless run_obj.is_a?(Hash)

          route_pack_completeness = PWN::Bounty::LifecycleAuthzReplay::RoutePackCompleteness.evaluate(run_obj: run_obj)
          artifact_access_drift = PWN::Bounty::LifecycleAuthzReplay::ArtifactAccessDriftMatrix.evaluate(run_obj: run_obj)

          stale_access_findings = Array(run_obj.dig(:coverage_matrix, :cells)).select do |cell|
            expected = Array(run_obj.dig(:plan, :expected_denied_after)).map { |entry| normalize_token(entry) }
            expected.include?(normalize_token(cell[:checkpoint])) && normalize_token(cell[:status]) == 'accessible'
          end

          {
            run_id: run_obj[:run_id],
            campaign: symbolize_obj(run_obj.dig(:plan, :campaign) || {}),
            stale_access_findings: stale_access_findings,
            mixed_surface_findings: [],
            missing_cells: Array(run_obj.dig(:coverage_matrix, :cells)).select { |cell| normalize_token(cell[:status]) == 'missing' },
            artifact_access_drift: artifact_access_drift,
            route_pack_completeness: route_pack_completeness,
            totals: {
              route_report_blockers: route_pack_completeness[:report_blocker_count],
              route_confidence_drops: route_pack_completeness[:confidence_drop_count],
              artifact_access_drift_findings: artifact_access_drift[:reportable_candidate_count]
            }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.direct_cells_with_status(opts = {})
          run_obj = opts[:run_obj]
          checkpoints = Array(opts[:checkpoints]).map { |entry| normalize_token(entry) }
          statuses = Array(opts[:statuses]).map { |entry| normalize_token(entry) }
          return [] unless run_obj.is_a?(Hash)

          surface_lookup = build_surface_lookup(surfaces: Array(run_obj.dig(:plan, :surfaces)))
          Array(run_obj.dig(:coverage_matrix, :cells)).map { |cell| symbolize_obj(cell) }.select do |cell|
            checkpoint = normalize_token(cell[:checkpoint])
            next false unless checkpoints.include?(checkpoint)

            surface = symbolize_obj(surface_lookup[cell[:surface].to_s] || {})
            route_family = normalize_route_family(route_family: surface[:route_family], surface_id: cell[:surface])
            route_family == 'direct' && statuses.include?(normalize_token(cell[:status]))
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.surviving_access_groups(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          groups = []

          mixed_surface_findings = Array(summary[:mixed_surface_findings]).map { |finding| symbolize_obj(finding) }
          mixed_surface_findings.each do |finding|
            groups << {
              category: 'mixed_surface',
              checkpoint: finding[:checkpoint],
              actor: finding[:actor],
              surfaces: Array(finding[:secondary_accessible_surfaces]),
              evidence_paths: Array(finding[:secondary_evidence_paths])
            }
          end

          artifact_drift = symbolize_obj(summary[:artifact_access_drift] || {})
          Array(artifact_drift[:families]).map { |family| symbolize_obj(family) }.each do |family|
            next unless normalize_token(family[:report_angle]) == 'direct_denied_derived_accessible'

            groups << {
              category: 'artifact_drift',
              checkpoint: nil,
              actor: family[:family_key].to_s.split(':').last,
              surfaces: Array(family[:surviving_derived_routes]),
              evidence_paths: Array(family[:observations]).map { |entry| symbolize_obj(entry)[:evidence_path].to_s }.reject(&:empty?)
            }
          end

          stale_access_findings = Array(summary[:stale_access_findings]).map { |finding| symbolize_obj(finding) }
          stale_access_findings.each do |finding|
            groups << {
              category: 'stale_access',
              checkpoint: finding[:checkpoint],
              actor: finding[:actor],
              surfaces: [finding[:surface]],
              evidence_paths: [finding[:evidence_path]].compact
            }
          end

          groups.uniq { |group| [group[:category], group[:checkpoint], group[:actor], Array(group[:surfaces]).join(',')] }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.contradictions(opts = {})
          direct_denied_cells = Array(opts[:direct_denied_cells]).map { |cell| symbolize_obj(cell) }
          direct_accessible_cells = Array(opts[:direct_accessible_cells]).map { |cell| symbolize_obj(cell) }
          summary = symbolize_obj(opts[:summary] || {})
          sensitive_payload_observed = opts[:sensitive_payload_observed] == true

          contradictions = []
          contradictions << 'repo_still_readable' unless direct_accessible_cells.empty?
          contradictions << 'direct_route_never_died' if direct_denied_cells.empty?

          artifact_drift = symbolize_obj(summary[:artifact_access_drift] || {})
          reportable_drift = artifact_drift[:reportable_candidate_count].to_i
          if reportable_drift.positive? && !sensitive_payload_observed
            contradictions << 'artifact_only_no_sensitive_payload'
          end

          contradictions
        rescue StandardError => e
          raise e
        end

        private_class_method def self.missing_proof(opts = {})
          direct_denied_cells = Array(opts[:direct_denied_cells]).map { |cell| symbolize_obj(cell) }
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }
          summary = symbolize_obj(opts[:summary] || {})
          contradictions = Array(opts[:contradictions]).map { |entry| normalize_token(entry) }
          sensitive_payload_observed = opts[:sensitive_payload_observed] == true

          missing = []
          missing << 'direct_route_denial_proof' if direct_denied_cells.empty?
          missing << 'post_change_surviving_access_proof' if surviving_access_groups.empty?

          route_pack = symbolize_obj(summary[:route_pack_completeness] || {})
          missing << 'route_pack_report_blockers' if route_pack[:report_blocker_count].to_i.positive?

          missing << 'sensitive_payload_or_scope_proof' if contradictions.include?('artifact_only_no_sensitive_payload') && !sensitive_payload_observed
          missing << 'complete_coverage_cells' if Array(summary[:missing_cells]).length.positive?

          missing.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.decide(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          contradictions = Array(opts[:contradictions]).map { |entry| normalize_token(entry) }
          missing_proof = Array(opts[:missing_proof]).map { |entry| normalize_token(entry) }

          return 'control_only' if contradictions.include?('repo_still_readable')
          return 'capture_more_proof' if contradictions.include?('direct_route_never_died')

          route_report_blockers = summary.dig(:totals, :route_report_blockers).to_i
          return 'capture_more_proof' if route_report_blockers.positive?
          return 'capture_more_proof' unless missing_proof.empty?

          'submit_now'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.claim(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          direct_denied_cells = Array(opts[:direct_denied_cells]).map { |cell| symbolize_obj(cell) }
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }
          contradictions = Array(opts[:contradictions]).map { |entry| normalize_token(entry) }

          campaign = symbolize_obj(summary[:campaign] || {})
          target = campaign[:target].to_s
          target = 'target_unknown' if target.empty?

          boundary_change = if direct_denied_cells.empty?
                              'Direct route denial after the authz change is not yet proven.'
                            else
                              "Direct routes denied after change on #{direct_denied_cells.length} captured cell(s)."
                            end

          survivor_summary = if surviving_access_groups.empty?
                               'No surviving secondary/artifact route access is currently proven.'
                             else
                               surfaces = surviving_access_groups.flat_map { |group| Array(group[:surfaces]) }.uniq
                               "Surviving post-change access still observed via #{surfaces.first(5).join(', ')}#{surfaces.length > 5 ? ', ...' : ''}."
                             end

          {
            target: target,
            boundary_change: boundary_change,
            survivor_summary: survivor_summary,
            contradiction_flags: contradictions,
            narrative: "After lifecycle authorization change, direct access is removed while alternate surfaces may still expose data/actions."
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evidence_groups(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          direct_denied_cells = Array(opts[:direct_denied_cells]).map { |cell| symbolize_obj(cell) }
          direct_accessible_cells = Array(opts[:direct_accessible_cells]).map { |cell| symbolize_obj(cell) }
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }

          {
            direct_route_denials: {
              count: direct_denied_cells.length,
              cells: direct_denied_cells.map { |cell| compact_cell(cell: cell) }
            },
            direct_route_still_accessible: {
              count: direct_accessible_cells.length,
              cells: direct_accessible_cells.map { |cell| compact_cell(cell: cell) }
            },
            surviving_secondary_or_artifact_access: {
              count: surviving_access_groups.length,
              groups: surviving_access_groups
            },
            route_pack_gaps: {
              report_blockers: summary.dig(:route_pack_completeness, :report_blocker_count).to_i,
              confidence_drops: summary.dig(:route_pack_completeness, :confidence_drop_count).to_i,
              gap_findings: Array(summary.dig(:route_pack_completeness, :gap_findings)).first(10)
            }
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.impact_bullets(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }
          bullets = []

          unless surviving_access_groups.empty?
            bullets << "Revoked actor retained post-change reachability through #{surviving_access_groups.length} non-canonical surface group(s)."
          end

          artifact_findings = summary.dig(:artifact_access_drift, :reportable_candidate_count).to_i
          if artifact_findings.positive?
            bullets << "Artifact drift confirms direct route denial with derived artifact/export visibility on #{artifact_findings} object family group(s)."
          end

          stale_count = Array(summary[:stale_access_findings]).length
          bullets << "Stale post-change accessibility remained on #{stale_count} captured cell(s)." if stale_count.positive?

          blockers = summary.dig(:route_pack_completeness, :report_blocker_count).to_i
          bullets << "Coverage still has #{blockers} report-blocking gap(s); severity claim should stay provisional until resolved." if blockers.positive?

          bullets = ['Evidence currently supports a lifecycle access-control boundary-change hypothesis.'] if bullets.empty?
          bullets
        rescue StandardError => e
          raise e
        end

        private_class_method def self.repro_skeleton(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          direct_denied_cells = Array(opts[:direct_denied_cells]).map { |cell| symbolize_obj(cell) }
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }

          campaign = symbolize_obj(summary[:campaign] || {})

          {
            preconditions: [
              "Target: #{campaign[:target].to_s.empty? ? 'target_unknown' : campaign[:target]}",
              "Lifecycle event: #{campaign[:change_event].to_s.empty? ? 'authz_change' : campaign[:change_event]}",
              'Two actor contexts: control actor and revoked/reduced actor.'
            ],
            steps: [
              'Capture pre-change direct route accessibility for revoked actor.',
              'Apply authz boundary change (remove role/membership/capability).',
              'Capture post-change direct route denial for same actor/context.',
              'Probe secondary/artifact/export routes for the same object family.',
              'Persist response status, headers, body hash, and timestamps in one timeline bundle.'
            ],
            expected: [
              "Direct denied captures: #{direct_denied_cells.length}",
              "Surviving access groups: #{surviving_access_groups.length}",
              "Route completeness score: #{summary.dig(:route_pack_completeness, :completion_score)}"
            ],
            artifacts: [
              'SUMMARY.json',
              'REPORT.md',
              'coverage_matrix.json',
              'artifacts/<checkpoint>/<actor>/<surface>.json'
            ]
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.cvss_draft(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          contradictions = Array(opts[:contradictions]).map { |entry| normalize_token(entry) }
          missing_proof = Array(opts[:missing_proof]).map { |entry| normalize_token(entry) }
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }

          artifact_findings = summary.dig(:artifact_access_drift, :reportable_candidate_count).to_i

          if contradictions.include?('repo_still_readable')
            return {
              score: 3.1,
              vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
              confidence: 'low',
              rationale: 'Control-only state; repo remains readable after claimed revocation.'
            }
          end

          if artifact_findings.positive? && surviving_access_groups.any? && missing_proof.empty?
            return {
              score: 8.6,
              vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
              confidence: 'medium',
              rationale: 'Direct denial with surviving derived access indicates meaningful confidentiality impact.'
            }
          end

          {
            score: 6.5,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:M/I:L/A:N',
            confidence: 'medium',
            rationale: 'Lifecycle authz drift likely, but additional proof is still required for full severity.'
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.cwe_draft(opts = {})
          summary = symbolize_obj(opts[:summary] || {})
          surviving_access_groups = Array(opts[:surviving_access_groups]).map { |group| symbolize_obj(group) }
          artifact_findings = summary.dig(:artifact_access_drift, :reportable_candidate_count).to_i

          cwes = []
          cwes << 'CWE-639: Authorization Bypass Through User-Controlled Key' if surviving_access_groups.any?
          cwes << 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor' if artifact_findings.positive?
          cwes << 'CWE-284: Improper Access Control'
          cwes.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.nist_800_53_candidate(opts = {})
          contradictions = Array(opts[:contradictions]).map { |entry| normalize_token(entry) }
          missing_proof = Array(opts[:missing_proof]).map { |entry| normalize_token(entry) }

          baseline = [
            'AC-2 Account Management',
            'AC-3 Access Enforcement',
            'AC-6 Least Privilege',
            'AU-12 Audit Generation'
          ]

          baseline << 'SI-4 System Monitoring' if missing_proof.include?('route_pack_report_blockers')
          baseline << 'CA-7 Continuous Monitoring' unless contradictions.empty?
          baseline.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.sensitive_payload_observed?(opts = {})
          run_obj = opts[:run_obj]
          return false unless run_obj.is_a?(Hash)

          observations = Array(run_obj[:observations]).map { |entry| symbolize_obj(entry) }
          observations.any? do |observation|
            strings = []
            strings << observation[:notes].to_s
            strings << observation.dig(:response, :body).to_s
            strings << observation.dig(:response, :body_preview).to_s
            strings << observation.dig(:response, :content_type).to_s

            evidence_path = observation[:evidence_path].to_s
            unless evidence_path.empty? || !File.exist?(evidence_path)
              begin
                evidence = symbolize_obj(JSON.parse(File.read(evidence_path)))
                strings << evidence[:notes].to_s
                strings << evidence.dig(:response, :body).to_s
                strings << evidence.dig(:response, :body_preview).to_s
                strings << evidence.dig(:response, :content_type).to_s
              rescue StandardError
                nil
              end
            end

            blob = strings.join(' ').downcase
            SENSITIVE_PAYLOAD_HINTS.any? { |hint| blob.include?(hint) }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_report(opts = {})
          run_root = opts[:run_root].to_s
          bundle = symbolize_obj(opts[:bundle] || {})

          json_path = File.join(run_root, 'SUBMISSION_BUNDLE.json')
          markdown_path = File.join(run_root, 'SUBMISSION_BUNDLE.md')

          File.write(json_path, JSON.pretty_generate(bundle))
          File.write(markdown_path, build_markdown(bundle: bundle))

          {
            json_path: json_path,
            markdown_path: markdown_path
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_markdown(opts = {})
          bundle = symbolize_obj(opts[:bundle] || {})

          lines = []
          lines << '# Lifecycle Authz Replay Submission Bundle'
          lines << ''
          lines << "- Generated At (UTC): `#{bundle[:generated_at]}`"
          lines << "- Run ID: `#{bundle[:run_id]}`"
          lines << "- Decision: `#{bundle[:decision]}`"
          lines << "- Ready To Submit: `#{bundle[:ready_to_submit]}`"
          lines << ''

          lines << '## Claim'
          claim = symbolize_obj(bundle[:claim] || {})
          lines << "- boundary_change: #{claim[:boundary_change]}"
          lines << "- survivor_summary: #{claim[:survivor_summary]}"
          lines << "- narrative: #{claim[:narrative]}"

          lines << ''
          lines << '## Impact Bullets'
          Array(bundle[:impact_bullets]).each { |entry| lines << "- #{entry}" }

          lines << ''
          lines << '## Missing Proof'
          if Array(bundle[:missing_proof]).empty?
            lines << '- None'
          else
            Array(bundle[:missing_proof]).each { |entry| lines << "- #{entry}" }
          end

          lines.join("\n")
        rescue StandardError => e
          raise e
        end

        private_class_method def self.compact_cell(opts = {})
          cell = symbolize_obj(opts[:cell] || {})
          {
            checkpoint: cell[:checkpoint],
            actor: cell[:actor],
            surface: cell[:surface],
            status: cell[:status],
            evidence_path: cell[:evidence_path]
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_surface_lookup(opts = {})
          surfaces = Array(opts[:surfaces]).map { |surface| symbolize_obj(surface) }

          surfaces.each_with_object({}) do |surface, accum|
            metadata = symbolize_obj(surface[:metadata] || {})
            route_family = normalize_route_family(
              route_family: metadata[:route_family] || metadata[:route_category],
              surface_id: surface[:id],
              surface_label: surface[:label]
            )

            accum[surface[:id].to_s] = {
              id: surface[:id].to_s,
              route_family: route_family
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_route_family(opts = {})
          route_family = normalize_token(opts[:route_family])
          return route_family unless route_family.empty?

          token_space = [opts[:surface_id], opts[:surface_label]].map { |entry| normalize_token(entry) }.join('_')
          return 'direct' if token_space.include?('direct') || token_space.include?('settings') || token_space.include?('member') || token_space.include?('collaborator') || token_space.include?('api')
          return 'artifact' if token_space.include?('artifact')
          return 'export' if token_space.include?('export') || token_space.include?('download')
          return 'notification' if token_space.include?('notification') || token_space.include?('activity')

          'secondary'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.symbolize_obj(obj)
          case obj
          when Array
            obj.map { |entry| symbolize_obj(entry) }
          when Hash
            obj.each_with_object({}) do |(key, value), accum|
              sym_key = key.respond_to?(:to_sym) ? key.to_sym : key
              accum[sym_key] = symbolize_obj(value)
            end
          else
            obj
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_token(token)
          token.to_s.scrub.strip.downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_+|_+$/, '')
        rescue StandardError => e
          raise e
        end
      end
    end
  end
end
