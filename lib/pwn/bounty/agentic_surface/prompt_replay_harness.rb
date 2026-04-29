# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'yaml'

module PWN
  module Bounty
    module AgenticSurface
      # Executes prompt-chain replay bookkeeping so ToolPermissionAtlas output
      # can be converted into report-ready positive/negative-control proof packets.
      module PromptReplayHarness
        DEFAULT_MAX_PACKETS = 40

        # Supported Method Parameters::
        # report = PWN::Bounty::AgenticSurface::PromptReplayHarness.run(
        #   yaml_path: '/path/to/agentic_surface.prompt_replay_harness.example.yaml'
        # )
        public_class_method def self.run(opts = {})
          profile = resolve_profile(opts: opts)
          report = analyze_profile(profile: profile)

          output_dir = profile[:output_dir]
          return report if output_dir.empty?

          run_root = File.expand_path(File.join(output_dir, report[:run_id]))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'prompt_replay_harness.json'), obj: report)
          write_markdown(path: File.join(run_root, 'prompt_replay_harness.md'), report: report)

          report[:run_root] = run_root
          report
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # report = PWN::Bounty::AgenticSurface::PromptReplayHarness.analyze(
        #   tool_permission_atlas: atlas_hash,
        #   replay_observations: [...]
        # )
        public_class_method def self.analyze(opts = {})
          profile = resolve_profile(opts: opts)
          analyze_profile(profile: profile)
        rescue StandardError => e
          raise e
        end

        # Supported Method Parameters::
        # profile = PWN::Bounty::AgenticSurface::PromptReplayHarness.load_profile(
        #   yaml_path: '/path/to/profile.yaml'
        # )
        public_class_method def self.load_profile(opts = {})
          yaml_path = opts[:yaml_path].to_s.scrub.strip
          raise 'ERROR: yaml_path is required' if yaml_path.empty?
          raise "ERROR: profile YAML does not exist: #{yaml_path}" unless File.exist?(yaml_path)

          raw_profile = YAML.safe_load_file(yaml_path, aliases: true) || {}
          symbolize_obj(raw_profile)
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
              report = PWN::Bounty::AgenticSurface::PromptReplayHarness.run(
                yaml_path: '/path/to/agentic_surface.prompt_replay_harness.example.yaml',
                output_dir: '/tmp/prompt-replay-harness'
              )

              report = PWN::Bounty::AgenticSurface::PromptReplayHarness.analyze(
                tool_permission_atlas: atlas_hash,
                replay_observations: replay_observations
              )
          HELP
        end

        private_class_method def self.resolve_profile(opts = {})
          input_hash = symbolize_obj(opts[:opts] || {})
          profile = if input_hash[:yaml_path].to_s.scrub.strip.empty?
                      input_hash
                    else
                      loaded = load_profile(yaml_path: input_hash[:yaml_path])
                      loaded.merge(input_hash.reject { |key, _value| key == :yaml_path })
                    end

          atlas = resolve_tool_permission_atlas(profile: profile)

          {
            run_id: normalized_run_id(profile: profile),
            target: profile[:target].to_s.scrub.strip,
            output_dir: profile[:output_dir].to_s.scrub.strip,
            max_packets: normalized_max_packets(max_packets: profile[:max_packets]),
            tool_permission_atlas: atlas,
            replay_observations: normalize_observations(
              observations: resolve_structured_input(input: profile[:replay_observations])
            ),
            include_unverified: profile[:include_unverified] == true
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.resolve_tool_permission_atlas(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          parsed = resolve_structured_input(input: profile[:tool_permission_atlas])
          atlas = symbolize_obj(parsed.first || {})
          return atlas unless atlas.empty?

          PWN::Bounty::AgenticSurface::ToolPermissionAtlas.analyze(
            target: profile[:target],
            tool_manifests: profile[:tool_manifests],
            mcp_manifests: profile[:mcp_manifests],
            openapi_specs: profile[:openapi_specs],
            artifacts: profile[:artifacts],
            transcripts: profile[:transcripts],
            websocket_traces: profile[:websocket_traces],
            include_pwn_agent_inventory: profile[:include_pwn_agent_inventory] == true
          )
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_run_id(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          run_id = profile[:run_id].to_s.scrub.strip
          run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-prompt-replay-harness" if run_id.empty?
          run_id
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalized_max_packets(opts = {})
          max_packets = opts[:max_packets].to_i
          max_packets = DEFAULT_MAX_PACKETS if max_packets <= 0
          max_packets = 200 if max_packets > 200
          max_packets
        rescue StandardError => e
          raise e
        end

        private_class_method def self.normalize_observations(opts = {})
          observations = Array(opts[:observations]).map { |entry| symbolize_obj(entry || {}) }

          observations.each_with_index.map do |observation, index|
            tool_name = normalize_token(observation[:tool_name] || observation[:tool])
            chain_id = normalize_token(observation[:chain_id])
            prompt_type = normalize_token(observation[:prompt_type] || observation[:mode])
            prompt_type = 'positive' if prompt_type.empty?
            prompt_type = 'negative' if %w[control negative_control negative].include?(prompt_type)
            prompt_type = 'positive' unless %w[positive negative].include?(prompt_type)

            side_effect_observed = if observation.key?(:side_effect_observed)
                                     observation[:side_effect_observed] == true
                                   else
                                     infer_side_effect_observed(observation: observation)
                                   end

            evidence_hash = evidence_hash_for_observation(observation: observation)

            {
              observation_id: normalize_token(observation[:observation_id]).empty? ? "observation_#{index + 1}" : normalize_token(observation[:observation_id]),
              chain_id: chain_id,
              tool_name: tool_name,
              prompt_type: prompt_type,
              side_effect_observed: side_effect_observed,
              blocked: observation[:blocked] == true,
              evidence_hash: evidence_hash,
              evidence_path: observation[:evidence_path].to_s.scrub.strip,
              notes: observation[:notes].to_s.scrub.strip,
              callback_hit: observation[:callback_hit] == true,
              file_modified: observation[:file_modified] == true,
              secret_exposed: observation[:secret_exposed] == true,
              response_status: observation[:response_status].to_i,
              timestamp: observation[:timestamp].to_s.scrub.strip
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_side_effect_observed(opts = {})
          observation = symbolize_obj(opts[:observation] || {})

          return true if observation[:callback_hit] == true
          return true if observation[:file_modified] == true
          return true if observation[:secret_exposed] == true
          return true if observation[:action_success] == true

          status = observation[:response_status].to_i
          return true if status >= 200 && status < 400 && status != 204

          notes = observation[:notes].to_s.downcase
          return true if notes.match?(/success|executed|granted|downloaded|fetched|written|created/)

          false
        rescue StandardError => e
          raise e
        end

        private_class_method def self.evidence_hash_for_observation(opts = {})
          observation = symbolize_obj(opts[:observation] || {})
          explicit_hash = observation[:evidence_hash].to_s.scrub.strip
          return explicit_hash unless explicit_hash.empty?

          evidence_path = observation[:evidence_path].to_s.scrub.strip
          if !evidence_path.empty? && File.exist?(evidence_path)
            return Digest::SHA256.hexdigest(File.read(evidence_path))
          end

          payload = {
            tool: observation[:tool_name] || observation[:tool],
            prompt: observation[:prompt],
            notes: observation[:notes],
            callback_hit: observation[:callback_hit],
            file_modified: observation[:file_modified],
            secret_exposed: observation[:secret_exposed],
            response_status: observation[:response_status],
            side_effect_observed: observation[:side_effect_observed]
          }

          Digest::SHA256.hexdigest(payload.to_json)
        rescue StandardError => e
          raise e
        end

        private_class_method def self.analyze_profile(opts = {})
          profile = symbolize_obj(opts[:profile] || {})
          atlas = symbolize_obj(profile[:tool_permission_atlas] || {})
          chains = Array(atlas[:chains]).map { |entry| symbolize_obj(entry) }
          observations = Array(profile[:replay_observations]).map { |entry| symbolize_obj(entry) }

          packets = chains.map do |chain|
            build_proof_packet(chain: chain, observations: observations, include_unverified: profile[:include_unverified])
          end

          packets.compact!
          packets.sort_by! { |packet| [-packet[:priority_score].to_i, packet[:chain_id].to_s] }
          packets = packets.first(profile[:max_packets])

          {
            generated_at: Time.now.utc.iso8601,
            run_id: profile[:run_id],
            target: profile[:target],
            atlas_chain_count: chains.length,
            observation_count: observations.length,
            proof_packet_count: packets.length,
            report_ready_count: packets.count { |packet| packet[:report_ready] == true },
            packets: packets,
            summary: summarize_packets(packets: packets)
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.build_proof_packet(opts = {})
          chain = symbolize_obj(opts[:chain] || {})
          observations = Array(opts[:observations]).map { |entry| symbolize_obj(entry) }
          include_unverified = opts[:include_unverified] == true

          chain_id = normalize_token(chain[:chain_id])
          tool_name = normalize_token(chain[:tool_name])

          matches = observations.select do |observation|
            observation_chain_id = normalize_token(observation[:chain_id])
            observation_tool = normalize_token(observation[:tool_name])

            chain_match = !chain_id.empty? && observation_chain_id == chain_id
            tool_match = !tool_name.empty? && observation_tool == tool_name
            chain_match || tool_match
          end

          positive_observations = matches.select { |observation| observation[:prompt_type] == 'positive' }
          negative_observations = matches.select { |observation| observation[:prompt_type] == 'negative' }

          positive_side_effect = positive_observations.any? { |observation| observation[:side_effect_observed] == true }
          negative_side_effect = negative_observations.any? { |observation| observation[:side_effect_observed] == true }
          negative_blocked = negative_observations.any? { |observation| observation[:blocked] == true } || !negative_side_effect

          contradiction = positive_side_effect && negative_blocked && !negative_side_effect

          evidence_hashes = matches.map { |observation| observation[:evidence_hash].to_s }.reject(&:empty?).uniq

          report_ready = contradiction && evidence_hashes.length >= 1
          verified = !matches.empty?

          return nil if !report_ready && !include_unverified && !verified

          {
            packet_id: Digest::SHA256.hexdigest("#{chain_id}|#{tool_name}")[0, 12],
            chain_id: chain[:chain_id],
            tool_name: chain[:tool_name],
            side_effect_class: chain[:side_effect_class],
            impact_label: chain[:impact_label],
            priority_score: chain[:priority_score].to_i,
            priority_tier: chain[:priority_tier].to_s,
            reproduction_prompt: chain[:reproduction_prompt],
            negative_control_prompt: chain[:negative_control_prompt],
            approval_gate: chain[:approval_gate] == true,
            verified: verified,
            report_ready: report_ready,
            contradiction_signal: contradiction,
            positive_observation_count: positive_observations.length,
            negative_observation_count: negative_observations.length,
            positive_side_effect_observed: positive_side_effect,
            negative_side_effect_observed: negative_side_effect,
            negative_blocked: negative_blocked,
            evidence_hashes: evidence_hashes,
            evidence_paths: matches.map { |observation| observation[:evidence_path] }.reject(&:empty?).uniq,
            control_gap: control_gap(
              positive_observations: positive_observations,
              negative_observations: negative_observations,
              contradiction: contradiction
            ),
            next_step: next_step(
              contradiction: contradiction,
              report_ready: report_ready,
              chain: chain,
              verified: verified
            )
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.control_gap(opts = {})
          positive_observations = Array(opts[:positive_observations])
          negative_observations = Array(opts[:negative_observations])
          contradiction = opts[:contradiction] == true

          return 'none' if contradiction
          return 'missing_positive_replay' if positive_observations.empty?
          return 'missing_negative_control' if negative_observations.empty?

          'negative_control_did_not_block'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.next_step(opts = {})
          contradiction = opts[:contradiction] == true
          report_ready = opts[:report_ready] == true
          chain = symbolize_obj(opts[:chain] || {})
          verified = opts[:verified] == true

          return 'Draft submission using prompt/control transcript, side-effect evidence hash, and timeline.' if report_ready
          return 'Collect positive and negative replay observations for this chain.' unless verified
          return 'Capture a clean negative control where side effect is blocked while positive replay still succeeds.' unless contradiction

          "Capture one more deterministic replay for #{chain[:tool_name]} with stable artifact hash."
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_packets(opts = {})
          packets = Array(opts[:packets]).map { |entry| symbolize_obj(entry) }

          {
            by_priority_tier: tally_by(packets: packets, key: :priority_tier),
            by_control_gap: tally_by(packets: packets, key: :control_gap),
            report_ready_tools: packets.select { |packet| packet[:report_ready] == true }.map { |packet| packet[:tool_name] }.uniq
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.tally_by(opts = {})
          packets = Array(opts[:packets]).map { |entry| symbolize_obj(entry) }
          key = opts[:key].to_sym

          packets.each_with_object(Hash.new(0)) do |packet, accum|
            value = packet[key].to_s
            value = 'unknown' if value.empty?
            accum[value] += 1
          end.sort.to_h
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
            value = input.to_s.scrub.strip
            return [] if value.empty?

            if File.exist?(value)
              content = File.read(value)
              parsed = parse_json_if_possible(data: content)
              return resolve_structured_input(input: parsed) unless parsed.nil?

              return [content]
            end

            parsed_inline = parse_json_if_possible(data: value)
            return resolve_structured_input(input: parsed_inline) unless parsed_inline.nil?

            [value]
          else
            [symbolize_obj(input)]
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_json_if_possible(opts = {})
          data = opts[:data].to_s.scrub.strip
          return nil if data.empty?

          JSON.parse(data)
        rescue JSON::ParserError
          nil
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
          lines << '# Agentic Surface Prompt Replay Harness'
          lines << ''
          lines << "- Generated At (UTC): `#{report[:generated_at]}`"
          lines << "- Run ID: `#{report[:run_id]}`"
          lines << "- Atlas Chains: `#{report[:atlas_chain_count]}`"
          lines << "- Proof Packets: `#{report[:proof_packet_count]}`"
          lines << "- Report Ready: `#{report[:report_ready_count]}`"
          lines << ''

          lines << '## Replay Proof Packets'
          packets = Array(report[:packets]).map { |entry| symbolize_obj(entry) }
          if packets.empty?
            lines << '- No replay packets generated.'
          else
            packets.each do |packet|
              lines << "- [#{packet[:priority_tier]}|#{packet[:priority_score]}] tool=`#{packet[:tool_name]}` side_effect=`#{packet[:side_effect_class]}`"
              lines << "  - report_ready: `#{packet[:report_ready]}` contradiction_signal=`#{packet[:contradiction_signal]}` control_gap=`#{packet[:control_gap]}`"
              lines << "  - positive_observation_count: `#{packet[:positive_observation_count]}` negative_observation_count: `#{packet[:negative_observation_count]}`"
              lines << "  - next_step: #{packet[:next_step]}"
            end
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
