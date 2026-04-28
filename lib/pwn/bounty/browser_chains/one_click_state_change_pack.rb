# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'
require 'time'
require 'yaml'

module PWN
  module Bounty
    module BrowserChains
      # Converts browser-side primitives (XSS/state confusion/token replay) into
      # report-ready one-click account/approval/privilege change chains.
      module OneClickStateChangePack
        DEFAULT_CHAIN_TEMPLATES = [
          {
            id: 'one_click_account_change',
            label: 'One-click account takeover/state-change',
            required_signals: %w[client_primitive_present victim_action_triggered state_change_account],
            optional_signals: %w[csrf_token_reuse_present cookie_scope_confusion_present],
            impact_label: 'account_takeover',
            recommended_proof: 'Show attacker payload, victim single click/open, and post-action account mutation evidence in one timeline.'
          },
          {
            id: 'one_click_privilege_change',
            label: 'One-click privilege mutation',
            required_signals: %w[client_primitive_present victim_action_triggered state_change_privilege],
            optional_signals: %w[csrf_token_reuse_present cookie_scope_confusion_present],
            impact_label: 'privilege_escalation',
            recommended_proof: 'Capture role/collaborator/admin state before + after victim click with stable object IDs.'
          },
          {
            id: 'one_click_approval_change',
            label: 'One-click approval bypass/state confusion',
            required_signals: %w[client_primitive_present victim_action_triggered state_change_approval],
            optional_signals: %w[csrf_token_reuse_present],
            impact_label: 'approval_bypass',
            recommended_proof: 'Correlate victim click to approval/workflow state transition and include negative controls.'
          }
        ].freeze

        TEXT_SIGNAL_MARKERS = {
          xss_present: [
            'xss',
            '<script',
            'onerror=',
            'javascript:'
          ],
          state_confusion_present: [
            'state confusion',
            'session confusion',
            'origin confusion',
            'ui redress'
          ],
          victim_action_triggered: [
            'victim click',
            'single click',
            'one click',
            'victim opened',
            'auto-submit',
            'autopost'
          ],
          state_change_account: [
            'email changed',
            'password changed',
            'pat created',
            'token created',
            'api key created',
            'account recovery updated'
          ],
          state_change_privilege: [
            'role changed',
            'member added',
            'owner added',
            'permission changed',
            'privilege changed',
            'admin granted'
          ],
          state_change_approval: [
            'approval granted',
            'approved',
            'merge approved',
            'workflow approved',
            'deployment approved'
          ],
          csrf_token_reuse_present: [
            'csrf',
            'double submit',
            'token replay',
            'reused token',
            'csrf bypass'
          ],
          cookie_scope_confusion_present: [
            'samesite',
            'cookie scope',
            'session fixation',
            'cookie confusion'
          ]
        }.freeze

        CHECKPOINT_ORDER = {
          'attacker_prepare' => 0,
          'payload_delivery' => 1,
          'victim_click' => 2,
          'post_action' => 3,
          'negative_control' => 4,
          'positive_control' => 5
        }.freeze

        # Supported Method Parameters::
        # profile = PWN::Bounty::BrowserChains::OneClickStateChangePack.load_profile(
        #   yaml_path: '/path/to/one_click_state_change_pack.yaml'
        # )
        public_class_method def self.load_profile(opts = {})
          yaml_path = opts[:yaml_path].to_s.scrub.strip
          raise 'ERROR: yaml_path is required' if yaml_path.empty?
          raise "ERROR: profile YAML does not exist: #{yaml_path}" unless File.exist?(yaml_path)

          raw_profile = YAML.safe_load_file(yaml_path, aliases: true) || {}
          normalize_profile(profile: symbolize_obj(raw_profile))
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::BrowserChains::OneClickStateChangePack.analyze(
        #   observations: [...],
        #   controls: [...]
        # )
        public_class_method def self.analyze(opts = {})
          profile = resolve_profile(opts)
          analyze_profile(profile: profile)
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::BrowserChains::OneClickStateChangePack.run(
        #   yaml_path: '/path/to/one_click_state_change_pack.yaml'
        # )
        public_class_method def self.run(opts = {})
          profile = resolve_profile(opts)
          report = analyze_profile(profile: profile)

          output_dir = profile[:output_dir]
          return report if output_dir.empty?

          run_root = File.expand_path(File.join(output_dir, report[:run_id]))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'one_click_state_change_pack.json'), obj: report)
          write_json(path: File.join(run_root, 'one_click_state_change_observations.json'), obj: profile[:observations])
          write_markdown(path: File.join(run_root, 'one_click_state_change_pack.md'), report: report)

          report[:run_root] = run_root
          report
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
              profile = PWN::Bounty::BrowserChains::OneClickStateChangePack.load_profile(
                yaml_path: '/path/to/one_click_state_change_pack.example.yaml'
              )

              report = PWN::Bounty::BrowserChains::OneClickStateChangePack.run(
                yaml_path: '/path/to/one_click_state_change_pack.example.yaml',
                output_dir: '/tmp/browser-chain-pack'
              )

              report = PWN::Bounty::BrowserChains::OneClickStateChangePack.analyze(
                observations: [
                  {
                    checkpoint: 'attacker_prepare',
                    primitive: 'xss',
                    status: 'triggered',
                    notes: 'Stored XSS in profile bio.'
                  },
                  {
                    checkpoint: 'victim_click',
                    status: 'triggered',
                    signals: ['victim_action_triggered'],
                    notes: 'Victim clicked attacker-generated share link.'
                  },
                  {
                    checkpoint: 'post_action',
                    status: 'confirmed',
                    signals: ['state_change_account'],
                    notes: 'Victim email changed to attacker-controlled mailbox.'
                  }
                ],
                controls: [
                  {
                    id: 'logged_out_replay',
                    kind: 'negative',
                    passed: true
                  }
                ]
              )
          HELP
        end

        private_class_method def self.resolve_profile(opts = {})
          input_hash = symbolize_obj(opts || {})

          profile = if input_hash[:yaml_path].to_s.scrub.strip.empty?
                      normalize_profile(profile: input_hash)
                    else
                      loaded = load_profile(yaml_path: input_hash[:yaml_path])
                      normalize_profile(
                        profile: loaded.merge(input_hash.reject { |key, _value| key == :yaml_path })
                      )
                    end

          profile
        rescue StandardError => e
          raise e
        end

        private_class_method def self.analyze_profile(opts = {})
          profile = symbolize_obj(opts[:profile] || {})

          signal_summary = build_signal_summary(observations: profile[:observations])
          control_summary = summarize_controls(controls: profile[:controls])
          chain_templates = resolve_chain_templates(chain_templates: profile[:chain_templates])

          chain_candidates = chain_templates.map do |template|
            evaluate_chain_candidate(
              template: template,
              signal_summary: signal_summary,
              control_summary: control_summary,
              observations: profile[:observations]
            )
          end

          chain_candidates.sort_by! do |candidate|
            [
              -candidate[:score].to_i,
              candidate[:missing_required_signals].length,
              candidate[:chain_id].to_s
            ]
          end

          best_chain = symbolize_obj(chain_candidates.first || {})
          one_click = best_chain[:ready] == true
          report_candidate = one_click && control_summary[:failed_negative_controls].empty?

          {
            generated_at: Time.now.utc.iso8601,
            run_id: profile[:run_id],
            target: profile[:target],
            campaign: profile[:campaign],
            observation_count: profile[:observations].length,
            chain_template_count: chain_templates.length,
            signal_summary: signal_summary,
            control_summary: control_summary,
            one_click_account_or_state_change: one_click,
            report_candidate: report_candidate,
            best_chain: best_chain,
            chain_candidates: chain_candidates,
            timeline: build_timeline(observations: profile[:observations]),
            next_steps: next_steps(
              report_candidate: report_candidate,
              best_chain: best_chain,
              control_summary: control_summary
            )
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolve_chain_templates(opts = {})
          templates = Array(opts[:chain_templates]).map { |template| symbolize_obj(template || {}) }
          templates = DEFAULT_CHAIN_TEMPLATES if templates.empty?

          templates.each_with_index.map do |template, index|
            chain_id = normalize_token(template[:id] || template[:chain_id])
            chain_id = "chain_#{index + 1}" if chain_id.empty?

            label = template[:label].to_s.scrub.strip
            label = chain_id if label.empty?

            required_signals = Array(template[:required_signals]).map { |signal| normalize_token(signal) }.reject(&:empty?).uniq
            optional_signals = Array(template[:optional_signals]).map { |signal| normalize_token(signal) }.reject(&:empty?).uniq

            {
              id: chain_id,
              label: label,
              impact_label: normalize_token(template[:impact_label]),
              required_signals: required_signals,
              optional_signals: optional_signals,
              recommended_proof: template[:recommended_proof].to_s.scrub.strip
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evaluate_chain_candidate(opts = {})
          template = symbolize_obj(opts[:template] || {})
          signal_summary = symbolize_obj(opts[:signal_summary] || {})
          control_summary = symbolize_obj(opts[:control_summary] || {})
          observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }

          required_signals = Array(template[:required_signals]).map { |entry| normalize_token(entry) }
          optional_signals = Array(template[:optional_signals]).map { |entry| normalize_token(entry) }

          required_hits = required_signals.select { |signal| signal_present?(signal_summary: signal_summary, signal: signal) }
          optional_hits = optional_signals.select { |signal| signal_present?(signal_summary: signal_summary, signal: signal) }

          missing_required = required_signals - required_hits

          score = 30
          score += required_hits.length * 22
          score += optional_hits.length * 8
          score -= missing_required.length * 28
          score += [control_summary[:negative_controls_passed_count].to_i, 3].min * 4
          score += [control_summary[:positive_controls_passed_count].to_i, 2].min * 3
          score -= control_summary[:failed_negative_controls].length * 18
          score = [[score, 0].max, 100].min

          supporting_events = observations.select do |observation|
            observation_signals = Array(observation[:signals]).map { |entry| normalize_token(entry) }
            (required_hits + optional_hits).any? { |signal| observation_signals.include?(signal) }
          end

          ready = missing_required.empty? && control_summary[:failed_negative_controls].empty?

          {
            chain_id: template[:id],
            chain_label: template[:label],
            impact_label: template[:impact_label],
            score: score,
            confidence: confidence_from_score(score: score, ready: ready),
            ready: ready,
            required_signals: required_signals,
            optional_signals: optional_signals,
            required_signal_hits: required_hits,
            optional_signal_hits: optional_hits,
            missing_required_signals: missing_required,
            supporting_event_count: supporting_events.length,
            supporting_evidence_paths: supporting_events.map { |event| event[:evidence_path] }.reject(&:empty?).uniq,
            recommended_proof: template[:recommended_proof]
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.confidence_from_score(opts = {})
          score = opts[:score].to_i
          ready = opts[:ready] == true

          return 'critical_candidate' if ready && score >= 92
          return 'high_candidate' if ready && score >= 80
          return 'medium_candidate' if score >= 60

          'low_confidence'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_signal_summary(opts = {})
          observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }
          signal_flags = {
            xss_present: false,
            state_confusion_present: false,
            victim_action_triggered: false,
            state_change_account: false,
            state_change_privilege: false,
            state_change_approval: false,
            csrf_token_reuse_present: false,
            cookie_scope_confusion_present: false,
            browser_artifact_present: false
          }

          artifact_evidence_paths = []

          observations.each do |observation|
            positive = observation[:positive] == true
            signals = Array(observation[:signals]).map { |entry| normalize_token(entry) }

            artifact_path = observation[:evidence_path].to_s
            unless artifact_path.empty?
              artifact_evidence_paths << artifact_path
              signal_flags[:browser_artifact_present] = true
            end

            next unless positive

            signal_flags.each_key do |signal_key|
              signal_flags[signal_key] = true if signals.include?(signal_key.to_s)
            end
          end

          signal_flags[:client_primitive_present] = (
            signal_flags[:xss_present] ||
            signal_flags[:state_confusion_present] ||
            signal_flags[:csrf_token_reuse_present]
          )
          signal_flags[:state_change_any] = (
            signal_flags[:state_change_account] ||
            signal_flags[:state_change_privilege] ||
            signal_flags[:state_change_approval]
          )
          signal_flags[:artifact_evidence_count] = artifact_evidence_paths.uniq.length

          signal_flags
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_controls(opts = {})
          controls = Array(opts[:controls]).map { |control| symbolize_obj(control || {}) }

          failed_negative_controls = controls.select do |control|
            normalize_token(control[:kind]) == 'negative' && control[:passed] != true
          end

          {
            total_controls: controls.length,
            negative_controls_count: controls.count { |control| normalize_token(control[:kind]) == 'negative' },
            positive_controls_count: controls.count { |control| normalize_token(control[:kind]) == 'positive' },
            negative_controls_passed_count: controls.count { |control| normalize_token(control[:kind]) == 'negative' && control[:passed] == true },
            positive_controls_passed_count: controls.count { |control| normalize_token(control[:kind]) == 'positive' && control[:passed] == true },
            failed_negative_controls: failed_negative_controls.map do |control|
              {
                id: control[:id],
                notes: control[:notes],
                evidence_path: control[:evidence_path]
              }
            end
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_timeline(opts = {})
          observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }

          sorted = observations.sort_by do |observation|
            checkpoint = normalize_token(observation[:checkpoint])
            checkpoint_order = CHECKPOINT_ORDER.fetch(checkpoint, 999)
            [checkpoint_order, checkpoint, observation[:id].to_s]
          end

          sorted.map do |observation|
            {
              checkpoint: observation[:checkpoint],
              actor: observation[:actor],
              primitive: observation[:primitive],
              status: observation[:status],
              positive: observation[:positive],
              signals: observation[:signals],
              notes: observation[:notes],
              evidence_path: observation[:evidence_path]
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.next_steps(opts = {})
          report_candidate = opts[:report_candidate] == true
          best_chain = symbolize_obj(opts[:best_chain] || {})
          control_summary = symbolize_obj(opts[:control_summary] || {})

          return [
            'Prepare submission narrative using timeline + control evidence hashes.',
            'Attach before/after state screenshots and one raw request/response pair per chain step.',
            'Preserve negative control proof showing action is blocked without victim click/path.'
          ] if report_candidate

          steps = []

          Array(best_chain[:missing_required_signals]).each do |signal|
            case normalize_token(signal)
            when 'client_primitive_present'
              steps << 'Capture a reproducible browser primitive trigger (XSS/state confusion/token replay) with artifact path.'
            when 'victim_action_triggered'
              steps << 'Capture explicit victim open/click step and associated request timestamp.'
            when 'state_change_account'
              steps << 'Capture post-click account mutation evidence (email/token/password/session change).'
            when 'state_change_privilege'
              steps << 'Capture post-click privilege delta (role/member/admin change) with before/after IDs.'
            when 'state_change_approval'
              steps << 'Capture approval/workflow state before and after victim action.'
            else
              steps << "Capture signal: #{signal}"
            end
          end

          unless control_summary[:failed_negative_controls].empty?
            steps << 'Fix failing negative controls so chain only succeeds on intended victim path.'
          end

          steps << 'Add at least one clean negative control replay artifact.' if control_summary[:negative_controls_count].to_i.zero?

          steps.uniq
        rescue StandardError => e
          raise e
        end

        private_class_method def self.signal_present?(opts = {})
          signal_summary = symbolize_obj(opts[:signal_summary] || {})
          signal = normalize_token(opts[:signal])
          return false if signal.empty?

          value = signal_summary[signal.to_sym]
          value = signal_summary[signal] if value.nil?
          value == true
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_profile(opts = {})
          profile = symbolize_obj(opts[:profile] || {})

          observations = resolve_structured_input(input: profile[:observations])
          controls = resolve_structured_input(input: profile[:controls])

          {
            run_id: normalized_run_id(profile: profile),
            target: profile[:target].to_s.scrub.strip,
            campaign: profile[:campaign].to_s.scrub.strip,
            output_dir: profile[:output_dir].to_s.scrub.strip,
            observations: normalize_observations(observations: observations),
            controls: normalize_controls(controls: controls, observations: observations),
            chain_templates: resolve_structured_input(input: profile[:chain_templates])
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_run_id(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          run_id = profile[:run_id].to_s.scrub.strip
          run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-one-click-state-change-pack" if run_id.empty?
          run_id
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_observations(opts = {})
          observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }

          observations.each_with_index.map do |observation, index|
            observation_id = normalize_token(observation[:id])
            observation_id = "observation_#{index + 1}" if observation_id.empty?

            checkpoint = normalize_token(observation[:checkpoint] || observation[:phase] || observation[:step])
            checkpoint = 'unknown' if checkpoint.empty?

            actor = normalize_token(observation[:actor] || observation[:persona] || observation[:user])
            primitive = normalize_token(observation[:primitive] || observation[:finding_type] || observation[:type])

            status = normalize_token(observation[:status])
            status = status_from_boolean_observation(observation: observation) if status.empty?

            note_fragments = [
              observation[:notes],
              observation[:summary],
              observation[:description],
              observation[:primitive],
              observation[:state_change],
              observation[:action]
            ].map(&:to_s)

            evidence_path = observation[:evidence_path].to_s.scrub.strip
            evidence_blob = evidence_blob_from_path(evidence_path: evidence_path)
            note_fragments << evidence_blob unless evidence_blob.empty?

            signal_candidates = []
            signal_candidates.concat(Array(observation[:signals]).map { |signal| normalize_token(signal) })
            signal_candidates.concat(signals_for_primitive(primitive: primitive))
            signal_candidates.concat(signals_from_text(text: note_fragments.join(' ')))

            positive = if observation.key?(:positive)
                         observation[:positive] == true
                       elsif observation.key?(:passed)
                         observation[:passed] == true
                       elsif observation.key?(:triggered)
                         observation[:triggered] == true
                       elsif observation.key?(:success)
                         observation[:success] == true
                       else
                         %w[triggered success confirmed accessible exploited passed].include?(status)
                       end

            {
              id: observation_id,
              checkpoint: checkpoint,
              actor: actor,
              primitive: primitive,
              status: status,
              positive: positive,
              signals: signal_candidates.reject(&:empty?).uniq,
              notes: truncate_text(text: note_fragments.join(' ').strip, max_chars: 260),
              evidence_path: evidence_path
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_controls(opts = {})
          controls = Array(opts[:controls]).map { |control| symbolize_obj(control || {}) }
          observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }

          observation_controls = observations.filter_map do |observation|
            control_kind = normalize_token(observation[:control_kind] || observation[:control] || observation[:kind])
            next if control_kind.empty?

            {
              id: normalize_token(observation[:control_id] || observation[:id] || "control_#{SecureRandom.hex(3)}"),
              kind: control_kind == 'negative' ? 'negative' : 'positive',
              passed: observation[:passed] == true || observation[:positive] == true,
              notes: observation[:notes].to_s.scrub.strip,
              evidence_path: observation[:evidence_path].to_s.scrub.strip
            }
          end

          merged_controls = controls + observation_controls
          merged_controls = merged_controls.map { |control| symbolize_obj(control || {}) }

          merged_controls.each_with_index.map do |control, index|
            control_id = normalize_token(control[:id])
            control_id = "control_#{index + 1}" if control_id.empty?

            kind = normalize_token(control[:kind] || control[:type])
            kind = 'negative' if kind.empty?
            kind = 'negative' unless %w[negative positive].include?(kind)

            passed = if control.key?(:passed)
                       control[:passed] == true
                     elsif control.key?(:success)
                       control[:success] == true
                     else
                       false
                     end

            {
              id: control_id,
              kind: kind,
              passed: passed,
              notes: control[:notes].to_s.scrub.strip,
              evidence_path: control[:evidence_path].to_s.scrub.strip
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.status_from_boolean_observation(opts = {})
          observation = symbolize_obj(opts[:observation] || {})

          return 'confirmed' if observation[:positive] == true
          return 'confirmed' if observation[:passed] == true
          return 'triggered' if observation[:triggered] == true
          return 'success' if observation[:success] == true

          'unknown'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.signals_for_primitive(opts = {})
          primitive = normalize_token(opts[:primitive])
          return [] if primitive.empty?

          signals = []

          if primitive.include?('xss')
            signals << 'xss_present'
            signals << 'client_primitive_present'
          end

          if primitive.include?('state_confusion') || primitive.include?('origin_confusion')
            signals << 'state_confusion_present'
            signals << 'client_primitive_present'
          end

          if primitive.include?('csrf') || primitive.include?('token_replay')
            signals << 'csrf_token_reuse_present'
            signals << 'client_primitive_present'
          end

          signals
        rescue StandardError => e
          raise e
        end

        private_class_method def self.signals_from_text(opts = {})
          text = opts[:text].to_s.downcase
          return [] if text.empty?

          TEXT_SIGNAL_MARKERS.each_with_object([]) do |(signal_key, markers), accum|
            next unless Array(markers).any? { |marker| text.include?(marker) }

            accum << signal_key.to_s
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evidence_blob_from_path(opts = {})
          evidence_path = opts[:evidence_path].to_s
          return '' if evidence_path.empty?
          return '' unless File.exist?(evidence_path)

          content = File.read(evidence_path)
          begin
            parsed = symbolize_obj(JSON.parse(content))
            values = collect_string_values(obj: parsed)
            truncate_text(text: values.join(' '), max_chars: 800)
          rescue JSON::ParserError
            truncate_text(text: content, max_chars: 800)
          end
        rescue StandardError
          ''
        end

        private_class_method def self.collect_string_values(opts = {})
          obj = opts[:obj]

          case obj
          when Hash
            obj.values.flat_map { |value| collect_string_values(obj: value) }
          when Array
            obj.flat_map { |value| collect_string_values(obj: value) }
          else
            obj.to_s
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.truncate_text(opts = {})
          text = opts[:text].to_s
          max_chars = opts[:max_chars].to_i
          max_chars = 300 if max_chars <= 0

          return text if text.length <= max_chars

          "#{text[0...max_chars]}..."
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolve_structured_input(opts = {})
          input = opts[:input]

          case input
          when nil
            []
          when Array
            input.map { |entry| symbolize_obj(entry) }
          when Hash
            [symbolize_obj(input)]
          when String
            path = input.to_s.scrub.strip
            return [] if path.empty?

            if File.exist?(path)
              content = File.read(path)
              parsed = begin
                JSON.parse(content)
              rescue JSON::ParserError
                YAML.safe_load(content, aliases: true)
              end
              return resolve_structured_input(input: parsed)
            end

            parsed = begin
              JSON.parse(path)
            rescue JSON::ParserError
              YAML.safe_load(path, aliases: true)
            end
            resolve_structured_input(input: parsed)
          else
            [symbolize_obj(input)]
          end
        rescue Psych::SyntaxError, JSON::ParserError
          []
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_json(opts = {})
          path = opts[:path].to_s
          obj = symbolize_obj(opts[:obj] || {})

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, JSON.pretty_generate(obj))
        rescue StandardError => e
          raise e
        end

        private_class_method def self.write_markdown(opts = {})
          path = opts[:path].to_s
          report = symbolize_obj(opts[:report] || {})

          lines = []
          lines << '# One-Click State Change Pack'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Run ID: `#{report[:run_id]}`"
          lines << "- Target: `#{report[:target]}`"
          lines << "- One-click account/state change: `#{report[:one_click_account_or_state_change]}`"
          lines << "- Report candidate: `#{report[:report_candidate]}`"
          lines << ''

          best_chain = symbolize_obj(report[:best_chain] || {})
          lines << '## Best Chain Candidate'
          if best_chain.empty?
            lines << '- No chain candidates evaluated.'
          else
            lines << "- chain_id: `#{best_chain[:chain_id]}`"
            lines << "- chain_label: `#{best_chain[:chain_label]}`"
            lines << "- impact_label: `#{best_chain[:impact_label]}`"
            lines << "- confidence: `#{best_chain[:confidence]}` score=`#{best_chain[:score]}`"
            lines << "- missing_required_signals: `#{Array(best_chain[:missing_required_signals]).join(', ')}`"
            lines << "- supporting_event_count: `#{best_chain[:supporting_event_count]}`"
          end

          lines << ''
          lines << '## Controls'
          control_summary = symbolize_obj(report[:control_summary] || {})
          lines << "- total_controls: `#{control_summary[:total_controls]}`"
          lines << "- negative_controls_passed_count: `#{control_summary[:negative_controls_passed_count]}`"
          lines << "- positive_controls_passed_count: `#{control_summary[:positive_controls_passed_count]}`"

          failed_controls = Array(control_summary[:failed_negative_controls])
          if failed_controls.empty?
            lines << '- failed_negative_controls: none'
          else
            failed_controls.each do |control|
              control_hash = symbolize_obj(control)
              lines << "- failed_negative_control: `#{control_hash[:id]}` evidence=`#{control_hash[:evidence_path]}`"
            end
          end

          lines << ''
          lines << '## Timeline'
          timeline = Array(report[:timeline]).map { |event| symbolize_obj(event) }
          if timeline.empty?
            lines << '- No timeline events captured.'
          else
            timeline.each do |event|
              lines << "- [#{event[:checkpoint]}] primitive=`#{event[:primitive]}` status=`#{event[:status]}` signals=`#{Array(event[:signals]).join(',')}`"
              lines << "  - notes: #{event[:notes]}" unless event[:notes].to_s.empty?
              lines << "  - evidence: `#{event[:evidence_path]}`" unless event[:evidence_path].to_s.empty?
            end
          end

          lines << ''
          lines << '## Next Steps'
          Array(report[:next_steps]).each do |step|
            lines << "- #{step}"
          end

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, lines.join("\n"))
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
