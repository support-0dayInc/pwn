# frozen_string_literal: true

require 'base64'
require 'fileutils'
require 'json'
require 'time'

module PWN
  module Targets
    module GitHub
      module WorkflowTrust
        # Converts TransitionBundle stale-acceptance candidates into
        # provider-specific replay readiness and next-proof guidance.
        module LiveProofPack
          DEFAULT_MIN_TTL_SECONDS = 120

          PROVIDER_AUDIENCE_EXPECTATIONS = {
            aws: ['sts.amazonaws.com'],
            gcp: ['//iam.googleapis.com/', 'https://iam.googleapis.com/'],
            azure: ['api://AzureADTokenExchange', 'https://management.azure.com/'],
            vault: ['vault', 'https://vault']
          }.freeze

          TOKEN_KEYS = %w[id_token access_token token jwt assertion].freeze

          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.analyze(
          #   transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
          #   later_snapshot: '/tmp/later_token_snapshot.json'
          # )
          public_class_method def self.analyze(opts = {})
            transition_bundle = resolve_transition_bundle(
              transition_bundle: opts[:transition_bundle],
              claim_snapshots: opts[:claim_snapshots],
              trust_policies: opts[:trust_policies],
              transition_fields: opts[:transition_fields]
            )

            stale_candidates = Array(transition_bundle[:stale_acceptance_candidates]).map { |candidate| symbolize_obj(candidate) }
            primary_candidate = select_primary_candidate(
              stale_candidates: stale_candidates,
              candidate_id: opts[:candidate_id]
            )

            token_snapshot = normalize_token_snapshot(
              input: opts[:later_snapshot] || opts[:token_snapshot]
            )

            provider = select_provider(
              provider_hint: opts[:provider],
              primary_candidate: primary_candidate,
              token_claims: token_snapshot[:claims],
              trust_policies: opts[:trust_policies]
            )

            audience_validation = validate_audience(
              provider: provider,
              token_claims: token_snapshot[:claims],
              allowed_audiences: opts[:allowed_audiences]
            )

            token_ttl = evaluate_token_ttl(
              token_claims: token_snapshot[:claims],
              min_ttl_seconds: opts[:min_ttl_seconds]
            )

            replay_readiness = evaluate_replay_readiness(
              primary_candidate: primary_candidate,
              token_snapshot: token_snapshot,
              provider: provider,
              audience_validation: audience_validation,
              token_ttl: token_ttl
            )

            next_exchange = next_exchange_template(
              provider: provider,
              token_snapshot: token_snapshot,
              primary_candidate: primary_candidate,
              audience_validation: audience_validation
            )

            negative_control = negative_control_template(
              provider: provider,
              primary_candidate: primary_candidate
            )

            impact_label = impact_label_for(
              replay_readiness: replay_readiness,
              provider: provider,
              primary_candidate: primary_candidate
            )

            {
              generated_at: Time.now.utc.iso8601,
              provider: provider,
              impact_label: impact_label,
              replay_readiness: replay_readiness,
              replay_ready: replay_readiness[:ready],
              primary_candidate: primary_candidate,
              transition_bundle_summary: {
                stale_acceptance_candidate_count: stale_candidates.length,
                trust_policy_count: transition_bundle[:trust_policy_count],
                claim_snapshot_count: transition_bundle[:claim_snapshot_count]
              },
              token_snapshot: {
                snapshot_type: token_snapshot[:snapshot_type],
                token_present: token_snapshot[:token_present],
                claim_keys: symbolize_obj(token_snapshot[:claims] || {}).keys.map(&:to_s),
                claims_preview: claims_preview(claims: token_snapshot[:claims])
              },
              audience_validation: audience_validation,
              token_ttl: token_ttl,
              next_exchange: next_exchange,
              negative_control: negative_control,
              operator_notes: operator_notes(
                replay_readiness: replay_readiness,
                audience_validation: audience_validation,
                provider: provider
              )
            }
          rescue StandardError => e
            raise e
          end

          # Supported Method Parameters::
          # report = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.run(
          #   transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
          #   later_snapshot: '/tmp/later_token_snapshot.json',
          #   output_dir: '/tmp/workflow-trust-live-proof-pack'
          # )
          public_class_method def self.run(opts = {})
            report = analyze(opts)

            output_dir = opts[:output_dir].to_s.scrub.strip
            return report if output_dir.empty?

            write_report(output_dir: output_dir, report: report)
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
                report = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.analyze(
                  transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
                  later_snapshot: '/tmp/later_token_snapshot.json'
                )

                report = PWN::Targets::GitHub::WorkflowTrust::LiveProofPack.run(
                  transition_bundle: '/tmp/workflow_trust_transition_bundle.json',
                  later_snapshot: '/tmp/later_token_snapshot.json',
                  output_dir: '/tmp/workflow-trust-live-proof-pack'
                )
            HELP
          end

          private_class_method def self.resolve_transition_bundle(opts = {})
            transition_bundle_input = opts[:transition_bundle]
            transition_bundle = resolve_structured_input(input: transition_bundle_input)
            transition_bundle = symbolize_obj(transition_bundle.first || {})

            if transition_bundle.empty? && !opts[:claim_snapshots].nil? && !opts[:trust_policies].nil?
              transition_bundle = PWN::Targets::GitHub::WorkflowTrust::TransitionBundle.analyze(
                claim_snapshots: opts[:claim_snapshots],
                trust_policies: opts[:trust_policies],
                transition_fields: opts[:transition_fields]
              )
            end

            transition_bundle
          rescue StandardError => e
            raise e
          end

          private_class_method def self.select_primary_candidate(opts = {})
            stale_candidates = Array(opts[:stale_candidates]).map { |candidate| symbolize_obj(candidate) }
            candidate_id = normalize_token(opts[:candidate_id])

            return stale_candidates.first if candidate_id.empty?

            stale_candidates.find { |candidate| normalize_token(candidate[:id]) == candidate_id }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.normalize_token_snapshot(opts = {})
            input = opts[:input]
            return { snapshot_type: 'missing', token_present: false, token: nil, claims: {} } if input.nil?

            if input.is_a?(String)
              value = input.to_s.scrub.strip
              return { snapshot_type: 'missing', token_present: false, token: nil, claims: {} } if value.empty?

              if File.exist?(value)
                file_data = File.read(value)
                parsed = parse_json_if_possible(data: file_data)
                return normalize_token_snapshot(input: parsed.nil? ? file_data : parsed)
              end

              parsed_inline = parse_json_if_possible(data: value)
              return normalize_token_snapshot(input: parsed_inline) unless parsed_inline.nil?

              if jwt_like?(value)
                return {
                  snapshot_type: 'raw_jwt',
                  token_present: true,
                  token: value,
                  claims: decode_jwt_claims(jwt: value)
                }
              end

              return {
                snapshot_type: 'raw_text',
                token_present: false,
                token: nil,
                claims: {}
              }
            end

            if input.is_a?(Array)
              return normalize_token_snapshot(input: input.first)
            end

            snapshot_hash = symbolize_obj(input)

            token_value = TOKEN_KEYS.map { |key| snapshot_hash[key.to_sym] || snapshot_hash[key] }
              .find { |candidate| candidate.to_s.scrub.strip.length.positive? }

            if token_value.to_s.scrub.strip.length.positive?
              claims = jwt_like?(token_value.to_s) ? decode_jwt_claims(jwt: token_value.to_s) : {}
              claims = symbolize_obj(snapshot_hash[:claims] || snapshot_hash['claims'] || claims)

              return {
                snapshot_type: 'wrapped_token_json',
                token_present: true,
                token: token_value.to_s,
                claims: claims
              }
            end

            claims_hash = symbolize_obj(snapshot_hash[:claims] || snapshot_hash['claims'] || {})
            claims_hash = snapshot_hash if claims_hash.empty? && claims_like_hash?(snapshot_hash)

            {
              snapshot_type: claims_hash.empty? ? 'unknown_json' : 'claims_only_json',
              token_present: false,
              token: nil,
              claims: claims_hash
            }
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

          private_class_method def self.jwt_like?(jwt)
            value = jwt.to_s.scrub.strip
            parts = value.split('.')
            return false unless parts.length == 3

            parts.all? { |part| part.match?(/^[A-Za-z0-9_\-]+$/) }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.decode_jwt_claims(opts = {})
            jwt = opts[:jwt].to_s
            payload_segment = jwt.split('.')[1].to_s
            return {} if payload_segment.empty?

            padding = '=' * ((4 - payload_segment.length % 4) % 4)
            decoded_payload = Base64.urlsafe_decode64(payload_segment + padding)
            parsed = JSON.parse(decoded_payload)
            symbolize_obj(parsed)
          rescue JSON::ParserError, ArgumentError
            {}
          rescue StandardError => e
            raise e
          end

          private_class_method def self.claims_like_hash?(hash)
            claim_keys = %i[sub aud iss exp iat workflow_ref job_workflow_ref event_name repository]
            claim_keys.any? { |key| hash.key?(key) || hash.key?(key.to_s) }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.select_provider(opts = {})
            provider_hint = normalize_token(opts[:provider_hint])
            return provider_hint unless provider_hint.empty?

            primary_candidate = symbolize_obj(opts[:primary_candidate] || {})
            candidate_provider = normalize_token(primary_candidate[:provider])
            return candidate_provider unless candidate_provider.empty?

            token_claims = symbolize_obj(opts[:token_claims] || {})
            aud_values = Array(token_claims[:aud] || token_claims['aud']).map(&:to_s)
            aud_string = aud_values.join(' ').downcase
            return 'aws' if aud_string.include?('sts.amazonaws.com')
            return 'gcp' if aud_string.include?('iam.googleapis.com') || aud_string.include?('googleapis')
            return 'azure' if aud_string.include?('azureadtokenexchange') || aud_string.include?('management.azure.com')
            return 'vault' if aud_string.include?('vault')

            trust_policies = resolve_structured_input(input: opts[:trust_policies])
            policy_blob = trust_policies.to_json.downcase
            return 'aws' if policy_blob.include?('token.actions.githubusercontent.com') || policy_blob.include?('sts.amazonaws.com')
            return 'gcp' if policy_blob.include?('iam.googleapis.com') || policy_blob.include?('workloadidentity')
            return 'azure' if policy_blob.include?('federatedidentitycredential') || policy_blob.include?('azure')
            return 'vault' if policy_blob.include?('vault')

            'generic'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.validate_audience(opts = {})
            provider = normalize_token(opts[:provider])
            token_claims = symbolize_obj(opts[:token_claims] || {})
            allowed_audiences = Array(opts[:allowed_audiences]).map(&:to_s)

            expected_audiences = allowed_audiences
            if expected_audiences.empty?
              expected_audiences = Array(PROVIDER_AUDIENCE_EXPECTATIONS[provider.to_sym]).map(&:to_s)
            end

            token_aud = token_claims[:aud]
            token_audiences = token_aud.is_a?(Array) ? token_aud.map(&:to_s) : [token_aud.to_s].reject(&:empty?)

            audience_match = if expected_audiences.empty?
                               !token_audiences.empty?
                             else
                               token_audiences.any? do |observed_aud|
                                 expected_audiences.any? { |expected_aud| aud_match?(observed: observed_aud, expected: expected_aud) }
                               end
                             end

            {
              expected_audiences: expected_audiences,
              token_audiences: token_audiences,
              audience_match: audience_match,
              requires_new_audience: !audience_match && !expected_audiences.empty?
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.aud_match?(opts = {})
            observed = opts[:observed].to_s.scrub.strip
            expected = opts[:expected].to_s.scrub.strip
            return false if observed.empty? || expected.empty?

            if expected.include?('*') || expected.include?('?')
              pattern = Regexp.escape(expected).gsub('\\*', '.*').gsub('\\?', '.')
              return observed.match?(/^#{pattern}$/i)
            end

            return true if observed.casecmp(expected).zero?
            return true if expected.end_with?('/') && observed.start_with?(expected)

            false
          rescue StandardError => e
            raise e
          end

          private_class_method def self.evaluate_token_ttl(opts = {})
            token_claims = symbolize_obj(opts[:token_claims] || {})
            min_ttl_seconds = opts[:min_ttl_seconds].to_i
            min_ttl_seconds = DEFAULT_MIN_TTL_SECONDS if min_ttl_seconds <= 0

            exp = token_claims[:exp]
            exp = exp.to_i if exp.to_s.match?(/^\d+$/)

            return {
              exp: nil,
              seconds_remaining: nil,
              usable: true,
              min_ttl_seconds: min_ttl_seconds,
              status: 'exp_missing'
            } if exp.nil? || exp.to_i <= 0

            seconds_remaining = exp.to_i - Time.now.to_i
            usable = seconds_remaining > min_ttl_seconds

            {
              exp: Time.at(exp.to_i).utc.iso8601,
              seconds_remaining: seconds_remaining,
              usable: usable,
              min_ttl_seconds: min_ttl_seconds,
              status: usable ? 'usable' : 'too_close_to_expiry'
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.evaluate_replay_readiness(opts = {})
            primary_candidate = symbolize_obj(opts[:primary_candidate] || {})
            token_snapshot = symbolize_obj(opts[:token_snapshot] || {})
            provider = normalize_token(opts[:provider])
            audience_validation = symbolize_obj(opts[:audience_validation] || {})
            token_ttl = symbolize_obj(opts[:token_ttl] || {})

            reasons = []
            reasons << 'no_stale_acceptance_candidate' if primary_candidate.empty?
            reasons << 'missing_later_snapshot' if normalize_token(token_snapshot[:snapshot_type]) == 'missing'
            reasons << 'missing_token_claims' if symbolize_obj(token_snapshot[:claims] || {}).empty?
            reasons << 'unknown_provider' if provider.empty? || provider == 'generic'

            candidate_provider = normalize_token(primary_candidate[:provider])
            if !candidate_provider.empty? && candidate_provider != provider
              reasons << "provider_mismatch_#{candidate_provider}_vs_#{provider}"
            end

            reasons << 'audience_mismatch' unless audience_validation[:audience_match] == true
            reasons << 'token_ttl_too_short' unless token_ttl[:usable] == true

            ready = reasons.empty?

            {
              ready: ready,
              status: ready ? 'replay_ready' : 'needs_follow_up',
              blocking_reasons: reasons,
              recommendation: replay_recommendation(
                ready: ready,
                reasons: reasons,
                provider: provider,
                audience_validation: audience_validation,
                token_ttl: token_ttl
              )
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.replay_recommendation(opts = {})
            ready = opts[:ready] == true
            return 'Run provider exchange now and capture response + negative control artifacts.' if ready

            reasons = Array(opts[:reasons]).map(&:to_s)
            audience_validation = symbolize_obj(opts[:audience_validation] || {})
            token_ttl = symbolize_obj(opts[:token_ttl] || {})
            provider = opts[:provider].to_s

            if reasons.include?('audience_mismatch') && audience_validation[:requires_new_audience]
              expected = Array(audience_validation[:expected_audiences]).join(', ')
              return "Mint a new token with audience expected by #{provider}: #{expected}."
            end

            return 'Collect a fresh token snapshot; current token is too close to expiry.' if reasons.include?('token_ttl_too_short') && token_ttl[:status] == 'too_close_to_expiry'
            return 'Generate a later token snapshot with claims (sub/aud/exp) to continue proofing.' if reasons.include?('missing_token_claims')

            'Address blocking reasons, then rerun LiveProofPack to verify replay readiness.'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.next_exchange_template(opts = {})
            provider = normalize_token(opts[:provider])
            audience_validation = symbolize_obj(opts[:audience_validation] || {})

            case provider
            when 'aws'
              {
                provider: 'aws',
                title: 'AWS STS AssumeRoleWithWebIdentity',
                command: "aws sts assume-role-with-web-identity --role-arn '<ROLE_ARN>' --role-session-name 'pwn-live-proof' --web-identity-token '<OIDC_TOKEN>'",
                negative_control_hint: "Repeat with --web-identity-token '<TOKEN_WITH_WRONG_AUD>' and expect AccessDenied/InvalidIdentityToken."
              }
            when 'gcp'
              audience = Array(audience_validation[:expected_audiences]).first || '//iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>'
              {
                provider: 'gcp',
                title: 'GCP STS Token Exchange',
                command: "curl -sS https://sts.googleapis.com/v1/token -H 'Content-Type: application/json' -d '{\"audience\":\"#{audience}\",\"grantType\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\"requestedTokenType\":\"urn:ietf:params:oauth:token-type:access_token\",\"subjectTokenType\":\"urn:ietf:params:oauth:token-type:jwt\",\"subjectToken\":\"<OIDC_TOKEN>\"}'",
                negative_control_hint: 'Repeat with mismatched audience and expect invalid_target / permission denial.'
              }
            when 'azure'
              {
                provider: 'azure',
                title: 'Azure Entra federated token exchange',
                command: "curl -sS -X POST 'https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token' -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'client_id=<APP_ID>' --data-urlencode 'scope=https://management.azure.com/.default' --data-urlencode 'grant_type=client_credentials' --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' --data-urlencode 'client_assertion=<OIDC_TOKEN>'",
                negative_control_hint: 'Repeat with token from mismatched branch/subject and expect unauthorized_client / invalid_grant.'
              }
            when 'vault'
              {
                provider: 'vault',
                title: 'Vault JWT auth login',
                command: "vault write auth/jwt/login role='<ROLE_NAME>' jwt='<OIDC_TOKEN>'",
                negative_control_hint: 'Repeat with wrong role or mismatched aud and expect permission denied.'
              }
            else
              {
                provider: provider.empty? ? 'generic' : provider,
                title: 'Provider exchange',
                command: "Exchange '<OIDC_TOKEN>' against the configured trust endpoint for provider #{provider}.",
                negative_control_hint: 'Repeat with mismatched audience/subject token and capture denial response.'
              }
            end
          rescue StandardError => e
            raise e
          end

          private_class_method def self.negative_control_template(opts = {})
            provider = normalize_token(opts[:provider])
            primary_candidate = symbolize_obj(opts[:primary_candidate] || {})

            {
              provider: provider.empty? ? 'generic' : provider,
              control_goal: 'Prove trust narrowing should deny token reuse but acceptance currently survives.',
              control_mutation: {
                mutate_field: Array(primary_candidate[:narrowing_fields]).first || 'aud',
                mutation_example: 'Use non-matching audience/subject token for the same exchange request.'
              },
              expected_outcome: 'Token exchange/login denied with provider trust-policy mismatch response.'
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.impact_label_for(opts = {})
            replay_readiness = symbolize_obj(opts[:replay_readiness] || {})
            provider = normalize_token(opts[:provider])
            primary_candidate = symbolize_obj(opts[:primary_candidate] || {})

            return 'needs_more_evidence' unless replay_readiness[:ready] == true

            provider_critical = %w[aws gcp azure].include?(provider)
            return 'critical_candidate' if provider_critical && !primary_candidate.empty?

            'high_candidate'
          rescue StandardError => e
            raise e
          end

          private_class_method def self.claims_preview(opts = {})
            claims = symbolize_obj(opts[:claims] || {})

            {
              sub: claims[:sub],
              aud: claims[:aud],
              iss: claims[:iss],
              exp: claims[:exp],
              workflow_ref: claims[:workflow_ref] || claims[:job_workflow_ref],
              event_name: claims[:event_name]
            }.reject { |_key, value| value.nil? || (value.respond_to?(:empty?) && value.empty?) }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.operator_notes(opts = {})
            replay_readiness = symbolize_obj(opts[:replay_readiness] || {})
            audience_validation = symbolize_obj(opts[:audience_validation] || {})
            provider = opts[:provider].to_s

            notes = []
            notes << replay_readiness[:recommendation].to_s
            if audience_validation[:requires_new_audience]
              notes << "Expected audience for #{provider}: #{Array(audience_validation[:expected_audiences]).join(', ')}"
            end
            notes << 'Capture full request/response, status code, and provider error body for both positive and negative controls.'
            notes.uniq.reject(&:empty?)
          rescue StandardError => e
            raise e
          end

          private_class_method def self.write_report(opts = {})
            output_dir = opts[:output_dir].to_s.scrub.strip
            report = symbolize_obj(opts[:report] || {})
            FileUtils.mkdir_p(output_dir)

            json_path = File.join(output_dir, 'workflow_trust_live_proof_pack.json')
            markdown_path = File.join(output_dir, 'workflow_trust_live_proof_pack.md')

            File.write(json_path, JSON.pretty_generate(report))
            File.write(markdown_path, build_markdown_report(report: report))

            {
              json_path: json_path,
              markdown_path: markdown_path
            }
          rescue StandardError => e
            raise e
          end

          private_class_method def self.build_markdown_report(opts = {})
            report = symbolize_obj(opts[:report] || {})
            replay = symbolize_obj(report[:replay_readiness] || {})
            audience = symbolize_obj(report[:audience_validation] || {})
            ttl = symbolize_obj(report[:token_ttl] || {})
            next_exchange = symbolize_obj(report[:next_exchange] || {})
            negative_control = symbolize_obj(report[:negative_control] || {})
            primary_candidate = symbolize_obj(report[:primary_candidate] || {})

            lines = []
            lines << '# GitHub Workflow Trust Live Proof Pack'
            lines << ''
            lines << "- Generated At (UTC): `#{report[:generated_at]}`"
            lines << "- Provider: `#{report[:provider]}`"
            lines << "- Impact Label: `#{report[:impact_label]}`"
            lines << "- Replay Ready: `#{replay[:ready]}`"
            lines << "- Replay Status: `#{replay[:status]}`"
            lines << ''

            lines << '## Stale Acceptance Candidate'
            if primary_candidate.empty?
              lines << '- No stale-acceptance candidate selected.'
            else
              lines << "- Candidate ID: `#{primary_candidate[:id]}`"
              lines << "- Policy: `#{primary_candidate[:policy_name]}`"
              lines << "- Transition: `#{primary_candidate[:from_snapshot]} -> #{primary_candidate[:to_snapshot]}`"
              lines << "- Narrowing Fields: `#{Array(primary_candidate[:narrowing_fields]).join(', ')}`"
            end

            lines << ''
            lines << '## Token Snapshot'
            token_snapshot = symbolize_obj(report[:token_snapshot] || {})
            lines << "- Snapshot Type: `#{token_snapshot[:snapshot_type]}`"
            lines << "- Token Present: `#{token_snapshot[:token_present]}`"
            lines << "- Claims Preview: `#{symbolize_obj(token_snapshot[:claims_preview] || {}).to_json}`"

            lines << ''
            lines << '## Audience + TTL Validation'
            lines << "- Expected Audiences: `#{Array(audience[:expected_audiences]).join(', ')}`"
            lines << "- Token Audiences: `#{Array(audience[:token_audiences]).join(', ')}`"
            lines << "- Audience Match: `#{audience[:audience_match]}`"
            lines << "- Token TTL Status: `#{ttl[:status]}`"
            lines << "- Seconds Remaining: `#{ttl[:seconds_remaining]}`"

            lines << ''
            lines << '## Next Exchange Step'
            lines << "- #{next_exchange[:title]}"
            lines << "```bash\n#{next_exchange[:command]}\n```"
            lines << "- Negative control hint: #{next_exchange[:negative_control_hint]}"

            lines << ''
            lines << '## Negative Control Definition'
            lines << "- Goal: #{negative_control[:control_goal]}"
            lines << "- Mutation: #{symbolize_obj(negative_control[:control_mutation] || {}).to_json}"
            lines << "- Expected Outcome: #{negative_control[:expected_outcome]}"

            lines << ''
            lines << '## Operator Notes'
            Array(report[:operator_notes]).each do |note|
              lines << "- #{note}"
            end

            lines.join("\n")
          rescue StandardError => e
            raise e
          end

          private_class_method def self.resolve_structured_input(opts = {})
            input = opts[:input]

            case input
            when nil
              []
            when Array
              symbolize_obj(input)
            when Hash
              hash_input = symbolize_obj(input)
              if hash_input.key?(:items)
                Array(hash_input[:items]).map { |entry| symbolize_obj(entry) }
              else
                [hash_input]
              end
            when String
              str = input.to_s.scrub.strip
              return [] if str.empty?

              if File.exist?(str)
                parsed = JSON.parse(File.read(str))
                return resolve_structured_input(input: parsed)
              end

              parsed = JSON.parse(str)
              resolve_structured_input(input: parsed)
            else
              [symbolize_obj(input)]
            end
          rescue JSON::ParserError => e
            raise "ERROR: unable to parse structured input: #{e.message}"
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
end
