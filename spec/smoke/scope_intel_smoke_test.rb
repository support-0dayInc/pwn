# frozen_string_literal: true

require 'minitest/autorun'
require 'pwn'

class ScopeIntelSmokeTest < Minitest::Test
  def test_compile_filter_and_diff_with_fixture_scope
    base_scope = {
      name: 'acronis',
      scope_details: {
        data: {
          team: {
            structured_scopes_search: {
              nodes: [
                {
                  id: '1',
                  identifier: 'https://beta-cloud.acronis.com',
                  display_name: 'Acronis Beta Cloud',
                  instruction: 'Use researcher owned account. third-party integrations are out of scope.',
                  cvss_score: 9.1,
                  eligible_for_bounty: true,
                  eligible_for_submission: true,
                  asm_system_tags: [{ name: 'web' }]
                },
                {
                  id: '2',
                  identifier: 'https://account.acronis.com',
                  display_name: 'Account Portal',
                  instruction: 'Requires owned account and invite-only onboarding.',
                  cvss_score: 8.3,
                  eligible_for_bounty: true,
                  eligible_for_submission: true,
                  asm_system_tags: [{ name: 'auth' }]
                },
                {
                  id: '3',
                  identifier: 'https://support.vendor-example.com',
                  display_name: 'Vendor Support',
                  instruction: 'Third-party vendor maintained system is out of scope and not eligible.',
                  cvss_score: nil,
                  eligible_for_bounty: false,
                  eligible_for_submission: false,
                  asm_system_tags: [{ name: 'other' }]
                }
              ]
            }
          }
        }
      }
    }

    scope_intel = PWN::Bounty::ScopeIntel.compile(scope_details: base_scope)

    assert_equal('acronis', scope_intel[:program_name])
    assert_equal(3, scope_intel[:rows].length)
    assert_equal(2, scope_intel[:counts][:eligible_for_bounty])

    owned_account_rows = PWN::Bounty::ScopeIntel.filter_rows(
      scope_intel: scope_intel,
      eligible_for_bounty: true,
      requires_owned_account: true
    )
    assert_equal(2, owned_account_rows.length)

    beta_rows = PWN::Bounty::ScopeIntel.search_rows(
      scope_intel: scope_intel,
      query: 'beta'
    )
    assert_equal(1, beta_rows.length)
    assert_equal('https://beta-cloud.acronis.com', beta_rows.first[:identifier])

    newer_scope = Marshal.load(Marshal.dump(base_scope))
    newer_scope[:scope_details][:data][:team][:structured_scopes_search][:nodes][1][:instruction] = 'Requires owned account with SSO.'
    newer_scope[:scope_details][:data][:team][:structured_scopes_search][:nodes] << {
      id: '4',
      identifier: 'https://api-staging.acronis.com',
      display_name: 'Acronis Staging API',
      instruction: 'Staging API surface for authenticated testing.',
      cvss_score: 8.9,
      eligible_for_bounty: true,
      eligible_for_submission: true,
      asm_system_tags: [{ name: 'api' }]
    }

    new_scope_intel = PWN::Bounty::ScopeIntel.compile(scope_details: newer_scope)

    diff = PWN::Bounty::ScopeIntel.diff_rows(
      old_scope_intel: scope_intel,
      new_scope_intel: new_scope_intel
    )

    assert_equal(1, diff[:added_count])
    assert_equal(0, diff[:removed_count])
    assert_equal(1, diff[:changed_count])
  end

  def test_hackerone_optional_ai_analysis_does_not_raise
    result = PWN::WWW::HackerOne.send(
      :run_optional_ai_analysis,
      enabled: true,
      request: '{}',
      type: :scope_details,
      suppress_progress: true
    )

    assert([NilClass, String].any? { |klass| result.is_a?(klass) })
  end
end
