# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'uri'
require 'yaml'

module PWN
  module Bounty
    # Config-driven sensitive file exposure triage pack that turns noisy
    # fetch results into report-ready secret evidence with safe previews.
    module SensitiveFileExposurePack
      DEFAULT_MAX_CANDIDATES = 80

      CURATED_CANDIDATE_PATHS = [
        '/.env',
        '/.env.production',
        '/.env.staging',
        '/.git/config',
        '/.git-credentials',
        '/config/application.yml',
        '/config/secrets.yml',
        '/config/database.yml',
        '/config/settings.yml',
        '/config/.env',
        '/app/config/.env',
        '/backup.zip',
        '/backup.tar.gz',
        '/db.sql',
        '/dump.sql',
        '/debug.log',
        '/logs/debug.log',
        '/admin/config.json',
        '/swagger.json',
        '/openapi.json',
        '/server-status',
        '/actuator/env'
      ].freeze

      PATH_PRIORITY_HINTS = {
        '/.env' => 100,
        '/.git-credentials' => 99,
        '/config/secrets.yml' => 95,
        '/config/database.yml' => 93,
        '/backup.zip' => 91,
        '/dump.sql' => 90,
        '/db.sql' => 89,
        '/actuator/env' => 86,
        '/debug.log' => 84
      }.freeze

      SECRET_PATTERNS = [
        {
          id: 'aws_access_key',
          secret_class: 'cloud_credentials',
          confidence: 'high',
          regex: /\bAKIA[0-9A-Z]{16}\b/
        },
        {
          id: 'aws_secret_key',
          secret_class: 'cloud_credentials',
          confidence: 'high',
          regex: /\b(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*[A-Za-z0-9\/+=]{20,}\b/i
        },
        {
          id: 'private_key_block',
          secret_class: 'private_key',
          confidence: 'high',
          regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/
        },
        {
          id: 'github_pat',
          secret_class: 'api_token',
          confidence: 'high',
          regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/
        },
        {
          id: 'slack_token',
          secret_class: 'api_token',
          confidence: 'high',
          regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/
        },
        {
          id: 'jwt_bearer',
          secret_class: 'api_token',
          confidence: 'medium',
          regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/
        },
        {
          id: 'db_password_assignment',
          secret_class: 'database_credentials',
          confidence: 'medium',
          regex: /\b(?:db_)?password\s*[=:]\s*[^\s'"&]{6,}\b/i
        },
        {
          id: 'connection_string',
          secret_class: 'database_credentials',
          confidence: 'medium',
          regex: /\b(?:postgres|mysql|mongodb|redis):\/\/[^\s'"<>]{8,}/i
        },
        {
          id: 'api_key_assignment',
          secret_class: 'config_secret',
          confidence: 'medium',
          regex: /\b(?:api[_-]?key|secret|token)\s*[=:]\s*[^\s'"&]{8,}\b/i
        },
        {
          id: 'email_address',
          secret_class: 'pii',
          confidence: 'low',
          regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i
        },
        {
          id: 'us_ssn',
          secret_class: 'pii',
          confidence: 'medium',
          regex: /\b\d{3}-\d{2}-\d{4}\b/
        }
      ].freeze

      REDACTION_PATTERNS = [
        /\bAKIA[0-9A-Z]{16}\b/,
        /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
        /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
        /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
        /\b(?:api[_-]?key|token|secret|password|passwd|private[_-]?key|aws_secret_access_key)\s*[=:]\s*[^\s'"&]{6,}\b/i,
        /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----(?:.|\n)+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/m
      ].freeze

      # Supported Method Parameters::
      # profile = PWN::Bounty::SensitiveFileExposurePack.load_profile(
      #   yaml_path: '/path/to/sensitive_file_exposure_pack.yaml'
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
      # plan = PWN::Bounty::SensitiveFileExposurePack.build_probe_plan(
      #   hosts: ['staging.example.com']
      # )
      public_class_method def self.build_probe_plan(opts = {})
        profile = normalize_profile(profile: symbolize_obj(opts || {}))
        hosts = resolve_hosts(profile: profile)
        candidate_paths = resolve_candidate_paths(profile: profile)

        candidates = hosts.flat_map do |host_entry|
          host = host_entry[:host]
          source = host_entry[:source]
          candidate_paths.map do |candidate_path|
            build_candidate_entry(
              host: host,
              candidate_path: candidate_path,
              source: source,
              scheme: host_entry[:scheme]
            )
          end
        end

        ranked = candidates.uniq { |entry| entry[:url] }.sort_by do |entry|
          [
            -entry[:priority].to_i,
            entry[:path].to_s,
            entry[:url].to_s
          ]
        end

        ranked = ranked.first(profile[:max_candidates])

        {
          generated_at: Time.now.utc.iso8601,
          host_count: hosts.length,
          candidate_path_count: candidate_paths.length,
          candidate_count: ranked.length,
          candidates: ranked,
          quickstart: [
            'Probe top-ranked unauth endpoints first and preserve full response body + headers.',
            'Promote only secret-bearing responses with stable hash + redacted preview into report queue.',
            'Capture one negative control request where endpoint denies access without vulnerable path.'
          ]
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # analysis = PWN::Bounty::SensitiveFileExposurePack.analyze_observations(
      #   observations: [{ url: 'https://app.example/.env', http_status: 200, body: '...' }]
      # )
      public_class_method def self.analyze_observations(opts = {})
        observations = Array(opts[:observations]).map { |observation| symbolize_obj(observation || {}) }

        findings = observations.map do |observation|
          analyze_observation(observation: observation)
        end.compact

        findings.sort_by! do |finding|
          [
            -severity_rank(severity: finding[:severity]),
            -finding[:score].to_i,
            finding[:url].to_s
          ]
        end

        {
          observed_at: Time.now.utc.iso8601,
          observation_count: observations.length,
          finding_count: findings.length,
          report_candidate_count: findings.count { |finding| finding[:report_candidate] == true },
          findings_by_secret_class: tally_by(findings: findings, key: :secret_class),
          findings_by_auth_state: tally_by(findings: findings, key: :auth_state),
          findings: findings
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # report = PWN::Bounty::SensitiveFileExposurePack.run(
      #   yaml_path: '/path/to/sensitive_file_exposure_pack.example.yaml',
      #   output_dir: '/tmp/sensitive-file-pack'
      # )
      public_class_method def self.run(opts = {})
        input_hash = symbolize_obj(opts || {})
        profile = if input_hash[:yaml_path].to_s.scrub.strip.empty?
                    normalize_profile(profile: input_hash)
                  else
                    loaded = load_profile(yaml_path: input_hash[:yaml_path])
                    normalize_profile(
                      profile: loaded.merge(input_hash.reject { |key, _value| key == :yaml_path })
                    )
                  end

        plan = build_probe_plan(profile)
        analysis = analyze_observations(observations: profile[:observations])

        report = {
          generated_at: Time.now.utc.iso8601,
          run_id: profile[:run_id],
          target: profile[:target],
          campaign: profile[:campaign],
          candidate_count: plan[:candidate_count],
          observation_count: analysis[:observation_count],
          finding_count: analysis[:finding_count],
          report_candidate_count: analysis[:report_candidate_count],
          findings_by_secret_class: analysis[:findings_by_secret_class],
          findings_by_auth_state: analysis[:findings_by_auth_state],
          top_findings: Array(analysis[:findings]).first(20),
          next_steps: next_steps(analysis: analysis),
          plan: plan
        }

        output_dir = profile[:output_dir]
        unless output_dir.empty?
          run_root = File.expand_path(File.join(output_dir, report[:run_id]))
          FileUtils.mkdir_p(run_root)

          write_json(path: File.join(run_root, 'sensitive_file_exposure_plan.json'), obj: plan)
          write_json(path: File.join(run_root, 'sensitive_file_exposure_report.json'), obj: report)
          write_json(path: File.join(run_root, 'sensitive_file_exposure_observations.json'), obj: profile[:observations])
          write_markdown(path: File.join(run_root, 'sensitive_file_exposure_report.md'), report: report)

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
            profile = PWN::Bounty::SensitiveFileExposurePack.load_profile(
              yaml_path: '/path/to/sensitive_file_exposure_pack.example.yaml'
            )

            plan = PWN::Bounty::SensitiveFileExposurePack.build_probe_plan(
              hosts: ['staging.example.test', 'admin.example.test'],
              max_candidates: 60
            )

            report = PWN::Bounty::SensitiveFileExposurePack.run(
              yaml_path: '/path/to/sensitive_file_exposure_pack.example.yaml',
              output_dir: '/tmp/sensitive-file-pack'
            )
        HELP
      end

      private_class_method def self.analyze_observation(opts = {})
        observation = symbolize_obj(opts[:observation] || {})

        url = observation[:url].to_s.scrub.strip
        path = observation[:path].to_s.scrub.strip
        if path.empty? && !url.empty?
          begin
            path = URI.parse(url).path.to_s
          rescue URI::InvalidURIError
            path = ''
          end
        end

        body = observation[:body]
        body = observation[:response_body] if body.nil?
        body = observation[:raw] if body.nil?
        body = body.to_s

        return nil if body.empty?

        http_status = observation[:http_status].to_i
        auth_state = normalize_auth_state(state: observation[:auth_state])
        auth_state = infer_auth_state(observation: observation) if auth_state == 'unknown'

        secret_hits = detect_secret_hits(body: body)
        return nil if secret_hits.empty?

        secret_class = primary_secret_class(secret_hits: secret_hits)
        confidence = primary_confidence(secret_hits: secret_hits)
        evidence_strength = evidence_strength(secret_hits: secret_hits, body: body)
        score = exposure_score(
          secret_class: secret_class,
          confidence: confidence,
          auth_state: auth_state,
          http_status: http_status,
          evidence_strength: evidence_strength,
          path: path
        )

        severity = classify_severity(
          score: score,
          auth_state: auth_state,
          secret_class: secret_class,
          http_status: http_status
        )

        report_candidate = report_candidate?(
          http_status: http_status,
          auth_state: auth_state,
          secret_class: secret_class,
          evidence_strength: evidence_strength,
          score: score
        )

        {
          id: normalize_token(observation[:id]).empty? ? Digest::SHA256.hexdigest("#{url}|#{path}|#{http_status}")[0, 12] : normalize_token(observation[:id]),
          url: url,
          path: path,
          http_status: http_status,
          auth_state: auth_state,
          secret_class: secret_class,
          confidence: confidence,
          evidence_strength: evidence_strength,
          score: score,
          severity: severity,
          report_candidate: report_candidate,
          secret_hits: secret_hits,
          evidence_hash: Digest::SHA256.hexdigest(body),
          redacted_preview: redact_preview(text: body),
          content_type: observation[:content_type].to_s.scrub.strip
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.detect_secret_hits(opts = {})
        body = opts[:body].to_s
        return [] if body.empty?

        hits = SECRET_PATTERNS.filter_map do |pattern|
          matches = body.scan(pattern[:regex])
          next if matches.empty?

          {
            marker: pattern[:id],
            secret_class: pattern[:secret_class],
            confidence: pattern[:confidence],
            match_count: matches.length
          }
        end

        hits.sort_by do |hit|
          [
            -secret_class_weight(secret_class: hit[:secret_class]),
            -confidence_weight(confidence: hit[:confidence]),
            -hit[:match_count].to_i,
            hit[:marker].to_s
          ]
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.primary_secret_class(opts = {})
        secret_hits = Array(opts[:secret_hits]).map { |hit| symbolize_obj(hit) }
        return 'unknown' if secret_hits.empty?

        secret_hits.first[:secret_class].to_s
      rescue StandardError => e
        raise e
      end

      private_class_method def self.primary_confidence(opts = {})
        secret_hits = Array(opts[:secret_hits]).map { |hit| symbolize_obj(hit) }
        return 'low' if secret_hits.empty?

        ranked = secret_hits.sort_by do |hit|
          [
            -confidence_weight(confidence: hit[:confidence]),
            -hit[:match_count].to_i
          ]
        end

        ranked.first[:confidence].to_s
      rescue StandardError => e
        raise e
      end

      private_class_method def self.evidence_strength(opts = {})
        secret_hits = Array(opts[:secret_hits]).map { |hit| symbolize_obj(hit) }
        body = opts[:body].to_s

        return 'weak' if secret_hits.empty?

        total_hits = secret_hits.map { |hit| hit[:match_count].to_i }.sum
        strong_markers = secret_hits.count { |hit| confidence_weight(confidence: hit[:confidence]) >= 3 }

        return 'strong' if strong_markers >= 2
        return 'strong' if strong_markers >= 1 && total_hits >= 2
        return 'strong' if body.length > 800 && total_hits >= 3
        return 'moderate' if strong_markers >= 1 || total_hits >= 2

        'weak'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.exposure_score(opts = {})
        secret_class = opts[:secret_class].to_s
        confidence = opts[:confidence].to_s
        auth_state = opts[:auth_state].to_s
        http_status = opts[:http_status].to_i
        evidence_strength = opts[:evidence_strength].to_s
        path = opts[:path].to_s

        score = 20
        score += secret_class_weight(secret_class: secret_class) * 9
        score += confidence_weight(confidence: confidence) * 6
        score += evidence_strength_weight(evidence_strength: evidence_strength) * 7

        score += case auth_state
                 when 'unauthenticated'
                   18
                 when 'weakly_authenticated'
                   10
                 when 'authenticated'
                   6
                 else
                   0
                 end

        score += case http_status
                 when 200
                   14
                 when 206
                   11
                 when 401, 403
                   -6
                 else
                   0
                 end

        score += path_priority(path: path) / 6

        [[score, 0].max, 100].min
      rescue StandardError => e
        raise e
      end

      private_class_method def self.classify_severity(opts = {})
        score = opts[:score].to_i
        auth_state = opts[:auth_state].to_s
        secret_class = opts[:secret_class].to_s
        http_status = opts[:http_status].to_i

        return 'critical_candidate' if score >= 88 && auth_state == 'unauthenticated' && http_status == 200 && %w[private_key cloud_credentials].include?(secret_class)
        return 'high_candidate' if score >= 76
        return 'medium_candidate' if score >= 58

        'low_confidence'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.report_candidate?(opts = {})
        http_status = opts[:http_status].to_i
        auth_state = opts[:auth_state].to_s
        secret_class = opts[:secret_class].to_s
        evidence_strength = opts[:evidence_strength].to_s
        score = opts[:score].to_i

        return false unless [200, 206].include?(http_status)
        return false if auth_state == 'unknown'
        return false if evidence_strength == 'weak'
        return false if secret_class == 'unknown'

        score >= 65
      rescue StandardError => e
        raise e
      end

      private_class_method def self.redact_preview(opts = {})
        text = opts[:text].to_s
        sanitized = text.dup

        REDACTION_PATTERNS.each do |pattern|
          sanitized.gsub!(pattern, '[REDACTED]')
        end

        sanitized = sanitized.gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F]/, '')
        sanitized = sanitized.lines.first(18).join
        sanitized = sanitized[0...900] if sanitized.length > 900
        sanitized.strip
      rescue StandardError => e
        raise e
      end

      private_class_method def self.next_steps(opts = {})
        analysis = symbolize_obj(opts[:analysis] || {})
        findings = Array(analysis[:findings]).map { |finding| symbolize_obj(finding) }
        reportable = findings.select { |finding| finding[:report_candidate] == true }

        return ['No high-signal secret exposures yet. Capture richer responses for top probe-plan paths.'] if reportable.empty?

        top = reportable.first

        [
          "Prioritize triage draft for `#{top[:url]}` (`#{top[:secret_class]}`, #{top[:auth_state]}).",
          'Attach raw response artifact privately and include evidence hash + redacted preview in report body.',
          'Capture one negative control proving protected access path blocks the same secret endpoint.'
        ]
      rescue StandardError => e
        raise e
      end

      private_class_method def self.resolve_hosts(opts = {})
        profile = symbolize_obj(opts[:profile] || {})

        explicit_hosts = Array(profile[:hosts]).map do |entry|
          normalize_host_entry(entry: entry, source: 'explicit_hosts')
        end.compact

        scope_hosts = extract_hosts_from_scope_intel(scope_intel: profile[:scope_intel])
        burp_hosts = extract_hosts_from_burp_targets(burp_targets: profile[:burp_targets])

        merged = (explicit_hosts + scope_hosts + burp_hosts).uniq { |entry| entry[:host] }
        merged = [{ host: 'example.test', scheme: 'https', source: 'fallback' }] if merged.empty?

        merged
      rescue StandardError => e
        raise e
      end

      private_class_method def self.extract_hosts_from_scope_intel(opts = {})
        scope_input = opts[:scope_intel]
        rows = if scope_input.is_a?(Hash)
                 Array(symbolize_obj(scope_input)[:rows])
               else
                 resolve_structured_input(input: scope_input)
               end

        rows.filter_map do |row|
          row_hash = symbolize_obj(row)
          identifier = row_hash[:identifier].to_s.scrub.strip
          next if identifier.empty?

          host_from_identifier(identifier: identifier, source: 'scope_intel')
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.extract_hosts_from_burp_targets(opts = {})
        burp_input = opts[:burp_targets]
        entries = if burp_input.is_a?(String)
                    parse_burp_targets_from_path(path: burp_input)
                  else
                    resolve_structured_input(input: burp_input)
                  end

        entries.filter_map do |entry|
          if entry.is_a?(Hash)
            entry_hash = symbolize_obj(entry)
            host = entry_hash[:host].to_s.scrub.strip
            host = URI.parse(entry_hash[:url].to_s).host.to_s rescue host
            source = 'burp_targets'
            normalize_host_entry(entry: host, source: source)
          else
            normalize_host_entry(entry: entry, source: 'burp_targets')
          end
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.parse_burp_targets_from_path(opts = {})
        path = opts[:path].to_s.scrub.strip
        return [] if path.empty?
        return [] unless File.exist?(path)

        content = File.read(path)

        parsed = begin
          JSON.parse(content)
        rescue JSON::ParserError
          nil
        end

        return resolve_structured_input(input: parsed) unless parsed.nil?

        content.lines.map(&:strip).reject(&:empty?)
      rescue StandardError => e
        raise e
      end

      private_class_method def self.host_from_identifier(opts = {})
        identifier = opts[:identifier].to_s.scrub.strip
        source = opts[:source].to_s

        if identifier.start_with?('*.')
          return {
            host: identifier[2..],
            scheme: 'https',
            source: source
          }
        end

        if identifier.match?(%r{\Ahttps?://}i)
          uri = URI.parse(identifier)
          return {
            host: uri.host.to_s,
            scheme: uri.scheme.to_s.empty? ? 'https' : uri.scheme.to_s,
            source: source
          }
        end

        if identifier.match?(/\A[a-z0-9.-]+\.[a-z]{2,}\z/i)
          return {
            host: identifier,
            scheme: 'https',
            source: source
          }
        end

        nil
      rescue URI::InvalidURIError
        nil
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_host_entry(opts = {})
        entry = opts[:entry]
        source = opts[:source].to_s

        host = entry.to_s.scrub.strip
        scheme = 'https'

        if host.match?(%r{\Ahttps?://}i)
          begin
            uri = URI.parse(host)
            host = uri.host.to_s.scrub.strip
            scheme = uri.scheme.to_s.scrub.strip
          rescue URI::InvalidURIError
            host = ''
          end
        end

        return nil if host.empty?

        {
          host: host,
          scheme: scheme.empty? ? 'https' : scheme,
          source: source
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.resolve_candidate_paths(opts = {})
        profile = symbolize_obj(opts[:profile] || {})

        configured = Array(profile[:candidate_paths]).map do |path|
          normalize_candidate_path(path: path)
        end.reject(&:empty?)

        candidate_paths = (configured + CURATED_CANDIDATE_PATHS).uniq

        candidate_paths.sort_by do |path|
          [-path_priority(path: path), path]
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.build_candidate_entry(opts = {})
        host = opts[:host].to_s
        candidate_path = normalize_candidate_path(path: opts[:candidate_path])
        scheme = opts[:scheme].to_s.scrub.strip
        scheme = 'https' if scheme.empty?

        {
          id: Digest::SHA256.hexdigest("#{host}|#{candidate_path}")[0, 12],
          host: host,
          path: candidate_path,
          url: "#{scheme}://#{host}#{candidate_path}",
          priority: path_priority(path: candidate_path),
          source: opts[:source].to_s,
          tags: candidate_tags(path: candidate_path)
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.path_priority(opts = {})
        path = normalize_candidate_path(path: opts[:path])
        return 50 if path.empty?

        explicit = PATH_PRIORITY_HINTS[path]
        return explicit unless explicit.nil?

        score = 40
        score += 25 if path.match?(/\.env|secret|token|credential|key/i)
        score += 18 if path.match?(/backup|dump|sql|tar|zip/i)
        score += 12 if path.match?(/config|settings|debug|log|admin/i)
        score += 8 if path.match?(/\.git|svn|hg/i)
        score
      rescue StandardError => e
        raise e
      end

      private_class_method def self.candidate_tags(opts = {})
        path = normalize_candidate_path(path: opts[:path])
        tags = []
        tags << 'secret' if path.match?(/\.env|secret|token|credential|key/i)
        tags << 'backup' if path.match?(/backup|dump|sql|tar|zip/i)
        tags << 'debug' if path.match?(/debug|log|actuator|status/i)
        tags << 'config' if path.match?(/config|settings|swagger|openapi/i)
        tags << 'repo' if path.match?(/\.git|svn|hg/i)
        tags = ['generic'] if tags.empty?
        tags.uniq
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_candidate_path(opts = {})
        path = opts[:path].to_s.scrub.strip
        return '' if path.empty?

        path = "/#{path}" unless path.start_with?('/')
        path.gsub(%r{//+}, '/')
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_profile(opts = {})
        profile = symbolize_obj(opts[:profile] || {})

        observations = if profile[:observations].is_a?(String)
                         resolve_structured_input(input: profile[:observations])
                       else
                         Array(profile[:observations]).map { |entry| symbolize_obj(entry || {}) }
                       end

        {
          run_id: normalized_run_id(profile: profile),
          target: profile[:target].to_s.scrub.strip,
          campaign: profile[:campaign].to_s.scrub.strip,
          output_dir: profile[:output_dir].to_s.scrub.strip,
          max_candidates: normalized_max_candidates(max_candidates: profile[:max_candidates]),
          hosts: Array(profile[:hosts]),
          candidate_paths: Array(profile[:candidate_paths]),
          observations: observations,
          burp_targets: profile[:burp_targets],
          scope_intel: profile[:scope_intel]
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalized_run_id(opts = {})
        profile = symbolize_obj(opts[:profile] || {})
        run_id = profile[:run_id].to_s.scrub.strip
        run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}-sensitive-file-exposure-pack" if run_id.empty?
        run_id
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalized_max_candidates(opts = {})
        max_candidates = opts[:max_candidates].to_i
        max_candidates = DEFAULT_MAX_CANDIDATES if max_candidates <= 0
        max_candidates = 300 if max_candidates > 300
        max_candidates
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_auth_state(opts = {})
        state = normalize_token(opts[:state])

        return 'unauthenticated' if %w[unauth unauthenticated public anonymous no_auth].include?(state)
        return 'weakly_authenticated' if %w[weak_auth partially_authenticated sessionless].include?(state)
        return 'authenticated' if %w[auth authenticated logged_in privileged].include?(state)

        'unknown'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.infer_auth_state(opts = {})
        observation = symbolize_obj(opts[:observation] || {})
        notes = [
          observation[:notes],
          observation[:description],
          observation[:summary]
        ].join(' ').downcase

        return 'unauthenticated' if notes.match?(/unauth|public|anonymous|no auth/)
        return 'authenticated' if notes.match?(/authenticated|logged in|session|cookie/)

        http_status = observation[:http_status].to_i
        return 'unauthenticated' if [200, 206].include?(http_status) && notes.empty?

        'unknown'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.secret_class_weight(opts = {})
        secret_class = normalize_token(opts[:secret_class])

        case secret_class
        when 'private_key'
          6
        when 'cloud_credentials'
          6
        when 'api_token'
          5
        when 'database_credentials'
          4
        when 'config_secret'
          3
        when 'pii'
          2
        else
          1
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.confidence_weight(opts = {})
        confidence = normalize_token(opts[:confidence])

        case confidence
        when 'high'
          3
        when 'medium'
          2
        else
          1
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.evidence_strength_weight(opts = {})
        evidence_strength = normalize_token(opts[:evidence_strength])

        case evidence_strength
        when 'strong'
          3
        when 'moderate'
          2
        else
          1
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.severity_rank(opts = {})
        severity = normalize_token(opts[:severity])

        case severity
        when 'critical_candidate'
          4
        when 'high_candidate'
          3
        when 'medium_candidate'
          2
        when 'low_confidence'
          1
        else
          0
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.tally_by(opts = {})
        findings = Array(opts[:findings]).map { |entry| symbolize_obj(entry) }
        key = opts[:key].to_sym

        findings.each_with_object(Hash.new(0)) do |finding, accum|
          token = finding[key].to_s
          token = 'unknown' if token.empty?
          accum[token] += 1
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
        lines << '# Sensitive File Exposure Pack'
        lines << ''
        lines << "- Generated At (UTC): `#{report[:generated_at]}`"
        lines << "- Run ID: `#{report[:run_id]}`"
        lines << "- Candidate URLs: `#{report[:candidate_count]}`"
        lines << "- Findings: `#{report[:finding_count]}`"
        lines << "- Report Candidates: `#{report[:report_candidate_count]}`"
        lines << ''

        lines << '## Top Findings'
        top_findings = Array(report[:top_findings]).map { |entry| symbolize_obj(entry) }
        if top_findings.empty?
          lines << '- No secret-bearing exposures confirmed in this run.'
        else
          top_findings.each do |finding|
            lines << "- [#{finding[:severity]}] `#{finding[:url]}` class=`#{finding[:secret_class]}` auth=`#{finding[:auth_state]}` score=`#{finding[:score]}`"
            lines << "  - evidence_hash: `#{finding[:evidence_hash]}`"
            lines << "  - hit_markers: `#{Array(finding[:secret_hits]).map { |hit| symbolize_obj(hit)[:marker] }.join(', ')}`"
            lines << "  - preview: #{finding[:redacted_preview].to_s.gsub("\n", ' ')[0, 220]}"
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
