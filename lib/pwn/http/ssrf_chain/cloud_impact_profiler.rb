# frozen_string_literal: true

require 'json'
require 'time'
require 'uri'

module PWN
  module HTTP
    module SSRFChain
      # Provider-aware cloud impact profiler for SSRF metadata/token responses.
      module CloudImpactProfiler
        PRIVILEGE_HINT_MARKERS = {
          admin_or_owner_likely: %w[admin owner root organizationaccountaccessrole administrator poweruser],
          elevated_service_principal: %w[computeadmin contributor editor roles/owner roles/editor],
          standard_service_identity: %w[default serviceaccount ec2-instance-profile vmidentity]
        }.freeze

        # Supported Method Parameters::
        # profile = PWN::HTTP::SSRFChain::CloudImpactProfiler.profile(
        #   observations: observations,
        #   findings: findings
        # )
        public_class_method def self.profile(opts = {})
          observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }
          findings = Array(opts[:findings]).map { |finding| symbolize_obj(finding || {}) }

          finding_lookup = findings.each_with_object({}) do |finding, accum|
            key = normalize_token(finding[:payload_id] || finding[:id])
            accum[key] ||= []
            accum[key] << finding
          end

          assessments = observations.each_with_index.map do |observation, index|
            assess_observation(
              observation: observation,
              index: index,
              finding_lookup: finding_lookup,
              sink_url: opts[:sink_url]
            )
          end.compact

          provider_summaries = summarize_by_provider(assessments: assessments)
          provider_summaries.sort_by! { |summary| [-impact_rank(summary[:impact_label]), summary[:provider].to_s] }

          primary_assessment = symbolize_obj(provider_summaries.first || {})
          highest_impact_label = primary_assessment[:impact_label]
          highest_impact_label = 'needs_more_evidence' if highest_impact_label.to_s.empty?

          {
            generated_at: Time.now.utc.iso8601,
            observation_count: observations.length,
            assessed_observation_count: assessments.length,
            provider_count: provider_summaries.length,
            highest_impact_label: highest_impact_label,
            critical_candidate_count: provider_summaries.count { |summary| summary[:impact_label] == 'critical_candidate' },
            high_candidate_count: provider_summaries.count { |summary| summary[:impact_label] == 'high_candidate' },
            provider_summaries: provider_summaries,
            primary_assessment: primary_assessment,
            report_ready_summary: primary_assessment[:report_ready_summary].to_s
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
              profile = PWN::HTTP::SSRFChain::CloudImpactProfiler.profile(
                observations: [
                  {
                    payload_id: 'aws_imds_identity',
                    body: '{"accountId":"123456789012","region":"us-east-1"}'
                  }
                ],
                findings: [
                  {
                    payload_id: 'aws_imds_identity',
                    classification: 'metadata'
                  }
                ]
              )
          HELP
        end

        private_class_method def self.assess_observation(opts = {})
          observation = symbolize_obj(opts[:observation] || {})
          index = opts[:index].to_i
          finding_lookup = symbolize_obj(opts[:finding_lookup] || {})
          sink_url = opts[:sink_url].to_s

          payload_id = normalize_token(observation[:payload_id] || observation[:id])
          payload_id = "observation_#{index + 1}" if payload_id.empty?

          finding = Array(finding_lookup[payload_id]).first
          classification = normalize_token(finding&.dig(:classification))

          body = observation[:body].to_s
          body = observation[:response_body].to_s if body.empty?
          headers = symbolize_obj(observation[:headers] || observation[:response_headers] || {})
          observed_url = observation[:url].to_s
          observed_url = finding.dig(:evidence, :observed_url).to_s if observed_url.empty? && !finding.nil?
          observed_url = sink_url if observed_url.empty?

          provider = infer_provider(
            observation: observation,
            payload_id: payload_id,
            body: body,
            headers: headers,
            observed_url: observed_url,
            classification: classification
          )

          parsed_json = parse_json_body(body: body)
          identity = extract_identity(
            provider: provider,
            parsed_json: parsed_json,
            body: body,
            payload_id: payload_id,
            observed_url: observed_url
          )

          credentials_exposed = credentials_exposed?(
            provider: provider,
            parsed_json: parsed_json,
            body: body,
            headers: headers
          )

          metadata_signal = classification == 'metadata' || provider != 'generic'
          return nil if !metadata_signal && !credentials_exposed && identity.empty?

          privilege_guess = guess_privilege(
            identity: identity,
            body: body,
            credentials_exposed: credentials_exposed
          )

          impact_label = impact_label_for(
            credentials_exposed: credentials_exposed,
            metadata_signal: metadata_signal,
            privilege_guess: privilege_guess,
            provider: provider
          )

          follow_up_requests = provider_follow_up_requests(
            provider: provider,
            identity: identity,
            payload_id: payload_id
          )

          negative_controls = provider_negative_controls(provider: provider)

          {
            observation_id: payload_id,
            provider: provider,
            classification: classification.empty? ? nil : classification,
            identity: identity,
            credentials_exposed: credentials_exposed,
            privilege_guess: privilege_guess,
            impact_label: impact_label,
            follow_up_requests: follow_up_requests,
            negative_controls: negative_controls,
            report_ready_summary: report_ready_summary(
              provider: provider,
              impact_label: impact_label,
              identity: identity,
              credentials_exposed: credentials_exposed,
              privilege_guess: privilege_guess
            )
          }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.summarize_by_provider(opts = {})
          assessments = Array(opts[:assessments]).map { |assessment| symbolize_obj(assessment) }
          grouped = assessments.group_by { |assessment| assessment[:provider] }

          grouped.map do |provider, provider_assessments|
            sorted = provider_assessments.sort_by { |assessment| -impact_rank(assessment[:impact_label]) }
            primary = symbolize_obj(sorted.first || {})
            merged_identity = provider_assessments.each_with_object({}) do |assessment, accum|
              identity = symbolize_obj(assessment[:identity] || {})
              identity.each do |key, value|
                next if value.nil?
                next if value.respond_to?(:empty?) && value.empty?
                next if accum.key?(key) && !(accum[key].respond_to?(:empty?) && accum[key].empty?)

                accum[key] = value
              end
            end

            {
              provider: provider,
              observation_count: provider_assessments.length,
              observation_ids: provider_assessments.map { |assessment| assessment[:observation_id] },
              impact_label: primary[:impact_label],
              identity: merged_identity,
              credentials_exposed: provider_assessments.any? { |assessment| assessment[:credentials_exposed] == true },
              privilege_guess: primary[:privilege_guess],
              follow_up_requests: primary[:follow_up_requests],
              negative_controls: primary[:negative_controls],
              report_ready_summary: primary[:report_ready_summary]
            }
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.infer_provider(opts = {})
          observation = symbolize_obj(opts[:observation] || {})
          payload_id = normalize_token(opts[:payload_id])
          body = opts[:body].to_s.downcase
          headers = symbolize_obj(opts[:headers] || {})
          observed_url = opts[:observed_url].to_s.downcase
          classification = normalize_token(opts[:classification])

          provider_hint = normalize_token(observation[:provider])
          return provider_hint unless provider_hint.empty?
          return 'aws' if payload_id.start_with?('aws_')
          return 'gcp' if payload_id.start_with?('gcp_')
          return 'azure' if payload_id.start_with?('azure_')
          return 'aws' if observed_url.include?('169.254.169.254') && (body.include?('instanceidentitydocument') || body.include?('security-credentials') || body.include?('accountid'))
          return 'gcp' if observed_url.include?('metadata.google.internal') || body.include?('metadata-flavor') || body.include?('googleapis.com')
          return 'azure' if body.include?('subscriptionid') || body.include?('management.azure.com') || headers.to_json.downcase.include?('metadata:true')
          return 'aws' if body.include?('accesskeyid') || body.include?('arn:aws:iam')
          return 'gcp' if body.include?('ya29.') || body.include?('serviceaccount:')
          return 'azure' if body.include?('xms_mirid') || body.include?('tenantid')
          return 'generic' if classification.empty?

          'generic'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_json_body(opts = {})
          body = opts[:body].to_s.scrub.strip
          return {} if body.empty?

          parsed = JSON.parse(body)
          symbolize_obj(parsed)
        rescue JSON::ParserError
          {}
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_identity(opts = {})
          provider = normalize_token(opts[:provider])
          parsed_json = symbolize_obj(opts[:parsed_json] || {})
          body = opts[:body].to_s
          payload_id = normalize_token(opts[:payload_id])
          observed_url = opts[:observed_url].to_s

          case provider
          when 'aws'
            extract_aws_identity(
              parsed_json: parsed_json,
              body: body,
              payload_id: payload_id,
              observed_url: observed_url
            )
          when 'gcp'
            extract_gcp_identity(parsed_json: parsed_json, body: body)
          when 'azure'
            extract_azure_identity(parsed_json: parsed_json)
          else
            host_hint = parse_host(url: observed_url)
            {}.tap do |identity|
              identity[:host_hint] = host_hint unless host_hint.empty?
              identity[:provider_guess] = 'unknown'
            end
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_aws_identity(opts = {})
          parsed_json = symbolize_obj(opts[:parsed_json] || {})
          body = opts[:body].to_s
          payload_id = normalize_token(opts[:payload_id])
          observed_url = opts[:observed_url].to_s

          account_id = parsed_json[:accountId] || parsed_json[:account_id]
          account_id = body[/\b\d{12}\b/, 0] if account_id.to_s.empty?

          role_names = []
          if payload_id.include?('role_list') || observed_url.include?('security-credentials')
            role_names = body.split(/\r?\n/).map(&:strip).reject(&:empty?).reject { |line| line.start_with?('{', '[') }
          end

          role_name = parsed_json[:role] || parsed_json[:role_name]
          role_name = role_names.first if role_name.to_s.empty? && !role_names.empty?

          {
            account_id: account_id,
            instance_id: parsed_json[:instanceId] || parsed_json[:instance_id],
            region: parsed_json[:region],
            availability_zone: parsed_json[:availabilityZone] || parsed_json[:availability_zone],
            role_name: role_name,
            role_candidates: role_names
          }.reject { |_key, value| value.nil? || (value.respond_to?(:empty?) && value.empty?) }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_gcp_identity(opts = {})
          parsed_json = symbolize_obj(opts[:parsed_json] || {})
          body = opts[:body].to_s

          service_account_email = parsed_json[:email] || body[/[a-z0-9\-_]+@[a-z0-9\-_]+\.iam\.gserviceaccount\.com/i, 0]
          project_id = parsed_json[:project_id] || parsed_json[:projectId]

          {
            project_id: project_id,
            service_account_email: service_account_email,
            token_type: parsed_json[:token_type],
            expires_in: parsed_json[:expires_in]
          }.reject { |_key, value| value.nil? || (value.respond_to?(:empty?) && value.empty?) }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.extract_azure_identity(opts = {})
          parsed_json = symbolize_obj(opts[:parsed_json] || {})
          compute = symbolize_obj(parsed_json[:compute] || {})

          {
            subscription_id: compute[:subscriptionId] || compute[:subscription_id] || parsed_json[:subscriptionId],
            tenant_id: parsed_json[:tenantId] || parsed_json[:tenant_id],
            resource_group: compute[:resourceGroupName] || compute[:resource_group_name],
            vm_id: compute[:vmId] || compute[:vm_id],
            vm_name: compute[:name] || parsed_json[:name],
            location: compute[:location] || parsed_json[:location]
          }.reject { |_key, value| value.nil? || (value.respond_to?(:empty?) && value.empty?) }
        rescue StandardError => e
          raise e
        end

        private_class_method def self.credentials_exposed?(opts = {})
          provider = normalize_token(opts[:provider])
          parsed_json = symbolize_obj(opts[:parsed_json] || {})
          body = opts[:body].to_s.downcase
          headers = symbolize_obj(opts[:headers] || {})

          keys = parsed_json.keys.map(&:to_s).map(&:downcase)
          credential_key_hit = (keys & %w[accesskeyid secretaccesskey token access_token refresh_token client_secret password]).any?

          provider_specific_hit = case provider
                                  when 'aws'
                                    body.include?('accesskeyid') || body.include?('secretaccesskey') || body.include?('x-aws-ec2-metadata-token')
                                  when 'gcp'
                                    body.include?('access_token') || body.include?('ya29.')
                                  when 'azure'
                                    body.include?('access_token') || body.include?('xms_mirid') || headers.to_json.downcase.include?('bearer')
                                  else
                                    false
                                  end

          credential_key_hit || provider_specific_hit
        rescue StandardError => e
          raise e
        end

        private_class_method def self.guess_privilege(opts = {})
          identity = symbolize_obj(opts[:identity] || {})
          body = opts[:body].to_s.downcase
          credentials_exposed = opts[:credentials_exposed] == true

          marker_text = ([body] + identity.values.map(&:to_s)).join(' ').downcase

          if PRIVILEGE_HINT_MARKERS[:admin_or_owner_likely].any? { |marker| marker_text.include?(marker) }
            return 'admin_or_owner_likely'
          end

          if PRIVILEGE_HINT_MARKERS[:elevated_service_principal].any? { |marker| marker_text.include?(marker) }
            return 'elevated_service_principal'
          end

          return 'credentialed_principal' if credentials_exposed
          return 'cloud_identity_exposed' unless identity.empty?

          'unknown'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.impact_label_for(opts = {})
          credentials_exposed = opts[:credentials_exposed] == true
          metadata_signal = opts[:metadata_signal] == true
          privilege_guess = normalize_token(opts[:privilege_guess])
          provider = normalize_token(opts[:provider])

          if credentials_exposed
            return 'critical_candidate' if %w[aws gcp azure].include?(provider)
            return 'high_candidate'
          end

          if %w[admin_or_owner_likely elevated_service_principal].include?(privilege_guess)
            return 'critical_candidate'
          end

          return 'high_candidate' if metadata_signal

          'needs_more_evidence'
        rescue StandardError => e
          raise e
        end

        private_class_method def self.provider_follow_up_requests(opts = {})
          provider = normalize_token(opts[:provider])
          identity = symbolize_obj(opts[:identity] || {})
          payload_id = opts[:payload_id].to_s

          case provider
          when 'aws'
            role_name = identity[:role_name] || '<ROLE_NAME_FROM_IMDS>'
            [
              "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/#{role_name}",
              'Capture credential JSON fields (AccessKeyId/SecretAccessKey/Token/Expiration).',
              "Use extracted creds for `aws sts get-caller-identity` and record returned ARN/account."
            ]
          when 'gcp'
            [
              'GET http://metadata.google.internal/computeMetadata/v1/project/project-id (Metadata-Flavor: Google).',
              'GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email.',
              'If token recovered, run OAuth tokeninfo and capture scopes/project linkage.'
            ]
          when 'azure'
            [
              'GET http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Metadata: true).',
              'GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/ (Metadata: true).',
              'Attempt ARM read-only call with token to confirm tenant/subscription scope.'
            ]
          else
            [
              "Re-run payload #{payload_id} with full response capture (status, headers, body).",
              'Attempt nearest metadata/control-plane endpoint variant and compare response delta.',
              'Preserve OOB callback logs aligned to request timestamps.'
            ]
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.provider_negative_controls(opts = {})
          provider = normalize_token(opts[:provider])

          case provider
          when 'aws'
            [
              'Request an invalid IMDS path and capture 404/no credential response.',
              'If credentials work, call an unrelated account ARN and capture AccessDenied for boundary proof.'
            ]
          when 'gcp'
            [
              'Drop Metadata-Flavor header and capture denial/error response.',
              'Use token against unrelated project and capture permission denial.'
            ]
          when 'azure'
            [
              'Call metadata endpoint without Metadata:true header and capture rejection.',
              'Use token against unauthorized resource scope and capture denial.'
            ]
          else
            [
              'Replay with malformed internal URL and capture non-sensitive failure response.',
              'Use mismatched collaborator token/path and capture absence of privileged data.'
            ]
          end
        rescue StandardError => e
          raise e
        end

        private_class_method def self.report_ready_summary(opts = {})
          provider = normalize_token(opts[:provider])
          impact_label = normalize_token(opts[:impact_label])
          identity = symbolize_obj(opts[:identity] || {})
          credentials_exposed = opts[:credentials_exposed] == true
          privilege_guess = opts[:privilege_guess].to_s

          provider_label = provider.empty? ? 'generic' : provider
          identity_summary = identity.empty? ? 'identity unresolved' : identity.to_json

          summary = "SSRF cloud impact profile indicates #{impact_label} on #{provider_label}; #{identity_summary}; privilege_guess=#{privilege_guess}."
          if credentials_exposed
            summary += ' Credential material appears exposed; prioritize provider token/identity replay proof immediately.'
          else
            summary += ' Validate with one credential/token follow-up request before final severity decision.'
          end
          summary
        rescue StandardError => e
          raise e
        end

        private_class_method def self.parse_host(opts = {})
          url = opts[:url].to_s
          uri = URI.parse(url)
          uri.host.to_s.downcase
        rescue URI::InvalidURIError, TypeError
          ''
        rescue StandardError => e
          raise e
        end

        private_class_method def self.impact_rank(label)
          case normalize_token(label)
          when 'critical_candidate'
            3
          when 'high_candidate'
            2
          when 'needs_more_evidence'
            1
          else
            0
          end
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
