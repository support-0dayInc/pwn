# frozen_string_literal: true

require 'time'
require 'uri'

module PWN
  module Bounty
    # ScopeIntel compiles HackerOne scope payloads into normalized rows and
    # helper utilities for filtering and delta analysis.
    module ScopeIntel
      # Supported Method Parameters::
      # scope_intel = PWN::Bounty::ScopeIntel.compile(
      #   program_name: 'required if scope_details omitted',
      #   scope_details: 'optional - hash from PWN::WWW::HackerOne.get_scope_details',
      #   include_ai_analysis: 'optional - bool, defaults to false',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )
      public_class_method def self.compile(opts = {})
        include_ai_analysis = opts[:include_ai_analysis] || false
        raise 'ERROR: include_ai_analysis should be true or false' unless [true, false].include?(include_ai_analysis)

        program_name = opts[:program_name].to_s.scrub.strip
        scope_details = opts[:scope_details]
        proxy = opts[:proxy]

        scope_details = symbolize_obj(scope_details) unless scope_details.nil?

        if scope_details.nil?
          raise 'ERROR: program_name is required when scope_details is omitted' if program_name.empty?

          scope_details = PWN::WWW::HackerOne.get_scope_details(
            program_name: program_name,
            proxy: proxy,
            ai_analysis_enabled: include_ai_analysis
          )
        end

        scope_details = symbolize_obj(scope_details)
        program_name = scope_details[:name].to_s.scrub.strip if program_name.empty?

        raw_nodes = extract_scope_nodes(scope_details: scope_details)
        rows = raw_nodes.map do |node|
          normalize_scope_row(
            node: node,
            program_name: program_name
          )
        end

        rows.sort_by! do |row|
          [
            row[:eligible_for_bounty] ? 0 : 1,
            row[:requires_owned_account] ? 0 : 1,
            row[:requires_staging] ? 0 : 1,
            row[:identifier].to_s
          ]
        end

        summary = summarize_rows(rows: rows)

        {
          generated_at: Time.now.utc.iso8601,
          program_name: program_name,
          source: {
            raw_node_count: raw_nodes.length,
            normalized_row_count: rows.length
          },
          counts: summary[:counts],
          rules: summary[:rules],
          rows: rows
        }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # filtered_rows = PWN::Bounty::ScopeIntel.filter_rows(
      #   scope_intel: scope_intel,
      #   eligible_for_bounty: true,
      #   requires_owned_account: true,
      #   requires_staging: true,
      #   third_party_excluded: false,
      #   asset_type: 'web',
      #   query: 'beta'
      # )
      public_class_method def self.filter_rows(opts = {})
        scope_intel = opts[:scope_intel]
        scope_intel ||= compile(
          scope_details: opts[:scope_details],
          program_name: opts[:program_name],
          include_ai_analysis: opts[:include_ai_analysis] || false,
          proxy: opts[:proxy]
        )

        rows = extract_rows(scope_intel: scope_intel)

        eligible_for_bounty = opts[:eligible_for_bounty]
        requires_owned_account = opts[:requires_owned_account]
        requires_staging = opts[:requires_staging]
        third_party_excluded = opts[:third_party_excluded]

        [
          eligible_for_bounty,
          requires_owned_account,
          requires_staging,
          third_party_excluded
        ].each do |bool_val|
          next if bool_val.nil?

          raise 'ERROR: filter boolean values should be true, false, or nil' unless [true, false].include?(bool_val)
        end

        asset_type = normalize_token(opts[:asset_type])
        query = opts[:query].to_s.scrub.strip.downcase

        rows.select do |row|
          row = symbolize_obj(row)

          keep = true
          keep &&= row[:eligible_for_bounty] == eligible_for_bounty unless eligible_for_bounty.nil?
          keep &&= row[:requires_owned_account] == requires_owned_account unless requires_owned_account.nil?
          keep &&= row[:requires_staging] == requires_staging unless requires_staging.nil?
          keep &&= row[:third_party_excluded] == third_party_excluded unless third_party_excluded.nil?
          keep &&= normalize_token(row[:asset_type]) == asset_type unless asset_type.empty?

          unless query.empty?
            haystack = [
              row[:identifier],
              row[:display_name],
              row[:instruction],
              row[:notes],
              row[:asset_type],
              row[:acquired_brand],
              row[:signup_mode],
              Array(row[:asm_system_tags]).join(' ')
            ].join(' ').downcase
            keep &&= haystack.include?(query)
          end

          keep
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # search_results = PWN::Bounty::ScopeIntel.search_rows(
      #   scope_intel: scope_intel,
      #   query: 'staging'
      # )
      public_class_method def self.search_rows(opts = {})
        query = opts[:query].to_s.scrub.strip
        raise 'ERROR: query is required' if query.empty?

        filter_rows(
          scope_intel: opts[:scope_intel],
          scope_details: opts[:scope_details],
          program_name: opts[:program_name],
          include_ai_analysis: opts[:include_ai_analysis] || false,
          proxy: opts[:proxy],
          query: query
        )
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # diff = PWN::Bounty::ScopeIntel.diff_rows(
      #   old_scope_intel: old_scope_intel,
      #   new_scope_intel: new_scope_intel
      # )
      public_class_method def self.diff_rows(opts = {})
        old_scope_intel = opts[:old_scope_intel]
        new_scope_intel = opts[:new_scope_intel]

        raise 'ERROR: old_scope_intel is required' unless old_scope_intel.is_a?(Hash)
        raise 'ERROR: new_scope_intel is required' unless new_scope_intel.is_a?(Hash)

        old_rows = extract_rows(scope_intel: old_scope_intel)
        new_rows = extract_rows(scope_intel: new_scope_intel)

        old_by_identifier = index_rows_by_identifier(rows: old_rows)
        new_by_identifier = index_rows_by_identifier(rows: new_rows)

        added_identifiers = (new_by_identifier.keys - old_by_identifier.keys).sort
        removed_identifiers = (old_by_identifier.keys - new_by_identifier.keys).sort

        shared_identifiers = (new_by_identifier.keys & old_by_identifier.keys).sort
        changed = []
        shared_identifiers.each do |identifier|
          before = old_by_identifier[identifier]
          after = new_by_identifier[identifier]
          next if before == after

          changed << {
            identifier: identifier,
            before: before,
            after: after
          }
        end

        {
          compared_at: Time.now.utc.iso8601,
          old_count: old_rows.length,
          new_count: new_rows.length,
          added_count: added_identifiers.length,
          removed_count: removed_identifiers.length,
          changed_count: changed.length,
          added: added_identifiers.map { |identifier| new_by_identifier[identifier] },
          removed: removed_identifiers.map { |identifier| old_by_identifier[identifier] },
          changed: changed
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
            scope_intel = PWN::Bounty::ScopeIntel.compile(
              program_name: 'github',
              include_ai_analysis: false
            )

            scoped_rows = PWN::Bounty::ScopeIntel.filter_rows(
              scope_intel: scope_intel,
              eligible_for_bounty: true,
              requires_owned_account: true,
              query: 'staging'
            )

            diff = PWN::Bounty::ScopeIntel.diff_rows(
              old_scope_intel: old_scope_intel,
              new_scope_intel: new_scope_intel
            )
        HELP
      end

      private_class_method def self.extract_scope_nodes(opts = {})
        scope_details = symbolize_obj(opts[:scope_details] || {})

        nodes = scope_details.dig(:scope_details, :data, :team, :structured_scopes_search, :nodes)
        nodes = scope_details.dig(:data, :team, :structured_scopes_search, :nodes) unless nodes.is_a?(Array)
        nodes = scope_details.dig(:scope_details, :team, :structured_scopes_search, :nodes) unless nodes.is_a?(Array)

        Array(nodes).map { |node| symbolize_obj(node) }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_scope_row(opts = {})
        node = symbolize_obj(opts[:node] || {})
        program_name = opts[:program_name].to_s.scrub.strip

        identifier = node[:identifier].to_s.scrub.strip
        display_name = node[:display_name].to_s.scrub.strip
        instruction = node[:instruction].to_s.scrub.strip

        asm_tags = Array(node[:asm_system_tags]).map do |tag|
          tag_hash = symbolize_obj(tag)
          tag_hash[:name].to_s.scrub.strip
        end.reject(&:empty?)

        cvss_score = node[:cvss_score]
        cvss_score = cvss_score.to_f unless cvss_score.nil? || cvss_score.to_s.strip.empty?

        full_text = [identifier, display_name, instruction, asm_tags.join(' ')].join(' ').downcase

        requires_owned_account = full_text.match?(/owned\s*account|own\s*account|your\s*account|authenticated|logged\s*in|account\s*required|self[-\s]*register/)
        requires_staging = full_text.match?(/staging|stage\.|beta|sandbox|preprod|pre-prod|test\b/)
        third_party_excluded = full_text.match?(/third[-\s]*party|vendor|maintained\s+by\s+.*third/) &&
                               full_text.match?(/excluded|out\s+of\s+scope|not\s+eligible|do\s+not\s+test/)

        signup_mode = infer_signup_mode(full_text: full_text, requires_owned_account: requires_owned_account)
        acquired_brand = infer_acquired_brand(
          identifier: identifier,
          instruction: instruction,
          program_name: program_name
        )

        eligible_for_bounty = node[:eligible_for_bounty] == true
        eligible_for_submission = node[:eligible_for_submission] == true

        notes = []
        notes << 'submission_only' if eligible_for_submission && !eligible_for_bounty
        notes << 'not_submission_eligible' unless eligible_for_submission
        notes << 'third_party_constraints' if third_party_excluded
        notes << 'owned_account_required' if requires_owned_account
        notes << 'staging_or_beta_surface' if requires_staging
        notes << "acquired_brand=#{acquired_brand}" unless acquired_brand.nil?

        {
          identifier: identifier,
          display_name: display_name,
          asset_type: infer_asset_type(node: node, identifier: identifier, display_name: display_name),
          eligible_for_bounty: eligible_for_bounty,
          eligible_for_submission: eligible_for_submission,
          cvss_score: cvss_score,
          requires_owned_account: requires_owned_account,
          requires_staging: requires_staging,
          third_party_excluded: third_party_excluded,
          signup_mode: signup_mode,
          acquired_brand: acquired_brand,
          asm_system_tags: asm_tags,
          instruction: instruction,
          notes: notes.join(' | '),
          raw: {
            id: node[:id],
            created_at: node[:created_at],
            updated_at: node[:updated_at],
            eligible_for_submission: eligible_for_submission,
            eligible_for_bounty: eligible_for_bounty
          }
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.summarize_rows(opts = {})
        rows = Array(opts[:rows]).map { |row| symbolize_obj(row) }

        counts_by_asset_type = {}
        rows.each do |row|
          asset_type = normalize_token(row[:asset_type])
          asset_type = 'unknown' if asset_type.empty?
          counts_by_asset_type[asset_type] ||= 0
          counts_by_asset_type[asset_type] += 1
        end

        counts = {
          total_rows: rows.length,
          eligible_for_bounty: rows.count { |row| row[:eligible_for_bounty] == true },
          eligible_for_submission: rows.count { |row| row[:eligible_for_submission] == true },
          requires_owned_account: rows.count { |row| row[:requires_owned_account] == true },
          requires_staging: rows.count { |row| row[:requires_staging] == true },
          third_party_excluded: rows.count { |row| row[:third_party_excluded] == true },
          by_asset_type: counts_by_asset_type.sort.to_h
        }

        rules = {
          owned_account_required_identifiers: rows.select { |row| row[:requires_owned_account] }.map { |row| row[:identifier] },
          staging_or_beta_identifiers: rows.select { |row| row[:requires_staging] }.map { |row| row[:identifier] },
          third_party_excluded_identifiers: rows.select { |row| row[:third_party_excluded] }.map { |row| row[:identifier] },
          submission_only_identifiers: rows.select { |row| row[:eligible_for_submission] && !row[:eligible_for_bounty] }.map { |row| row[:identifier] }
        }

        {
          counts: counts,
          rules: rules
        }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.extract_rows(opts = {})
        scope_intel = symbolize_obj(opts[:scope_intel] || {})
        rows = scope_intel[:rows]
        raise 'ERROR: scope_intel must include :rows array' unless rows.is_a?(Array)

        rows.map { |row| symbolize_obj(row) }
      rescue StandardError => e
        raise e
      end

      private_class_method def self.index_rows_by_identifier(opts = {})
        rows = Array(opts[:rows]).map { |row| symbolize_obj(row) }
        rows.each_with_object({}) do |row, acc|
          identifier = row[:identifier].to_s.scrub.strip
          identifier = "__missing_identifier__#{acc.length + 1}" if identifier.empty?
          acc[identifier] = row
        end
      rescue StandardError => e
        raise e
      end

      private_class_method def self.infer_signup_mode(opts = {})
        full_text = opts[:full_text].to_s
        requires_owned_account = opts[:requires_owned_account] == true

        return 'invite_only' if full_text.match?(/invite\s*only|invitation\s*only|must\s*be\s*invited/)
        return 'researcher_owned_account' if requires_owned_account
        return 'self_service_signup' if full_text.match?(/self[-\s]*service|sign\s*up|register/)

        'unknown'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.infer_acquired_brand(opts = {})
        identifier = opts[:identifier].to_s.scrub.strip
        instruction = opts[:instruction].to_s.scrub.strip
        program_name = normalize_token(opts[:program_name])

        phrase = instruction.match(/(?:acquired|acquisition|formerly)\s+([a-z0-9\.-]+)/i)
        return phrase[1] unless phrase.nil?

        host = nil
        if identifier.match?(%r{\Ahttps?://}i)
          host = URI.parse(identifier).host.to_s.scrub.strip
        elsif identifier.start_with?('*.')
          host = identifier[2..]
        elsif identifier.match?(/\A[a-z0-9\.-]+\.[a-z]{2,}\z/i)
          host = identifier
        end

        return nil if host.nil? || host.empty?
        return nil if !program_name.empty? && normalize_token(host).include?(program_name)

        host
      rescue URI::InvalidURIError
        nil
      rescue StandardError => e
        raise e
      end

      private_class_method def self.infer_asset_type(opts = {})
        node = symbolize_obj(opts[:node] || {})
        identifier = opts[:identifier].to_s.scrub.strip
        display_name = opts[:display_name].to_s.scrub.strip

        explicit_type = normalize_token(node[:asset_type] || node[:asset_identifier_type] || node[:asset_kind])
        return explicit_type unless explicit_type.empty?

        text = [identifier, display_name].join(' ').downcase
        return 'graphql' if text.include?('graphql')
        return 'api' if text.include?('/api') || text.include?(' api ')
        return 'mobile' if text.match?(/android|ios|mobile|ipa|apk|bundle\s*id/)
        return 'desktop' if text.match?(/desktop|client|electron/)
        return 'agent' if text.match?(/agent|daemon|runner/)
        return 'web' if text.match?(%r{https?://|\*\.[a-z0-9\.-]+|[a-z0-9\.-]+\.[a-z]{2,}})

        'other'
      rescue StandardError => e
        raise e
      end

      private_class_method def self.normalize_token(token)
        token.to_s.scrub.strip.downcase.gsub(/[^a-z0-9]+/, '_').gsub(/^_+|_+$/, '')
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
    end
  end
end
