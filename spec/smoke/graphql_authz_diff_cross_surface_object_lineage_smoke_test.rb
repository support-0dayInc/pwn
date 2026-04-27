# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class GraphQLAuthzDiffCrossSurfaceObjectLineageSmokeTest < Minitest::Test
  def test_lineage_clusters_direct_denied_and_alternate_accessible_surfaces
    Dir.mktmpdir('graphql-cross-surface-lineage-smoke-') do |tmp_dir|
      direct_evidence_path = File.join(tmp_dir, 'direct.json')
      alternate_evidence_path = File.join(tmp_dir, 'alternate.json')

      File.write(
        direct_evidence_path,
        JSON.pretty_generate(
          {
            response: {
              graphql: {
                data: {
                  team: {
                    id: 't1'
                  }
                },
                errors: [
                  { message: 'Forbidden' }
                ]
              }
            }
          }
        )
      )

      File.write(
        alternate_evidence_path,
        JSON.pretty_generate(
          {
            response: {
              graphql: {
                data: {
                  adminSecrets: [
                    {
                      id: 't1',
                      token: 'leaked'
                    }
                  ]
                },
                errors: []
              }
            }
          }
        )
      )

      diff_report = {
        run_id: 'cross-surface-lineage-smoke',
        matrix: [
          {
            checkpoint: 'post_change_t0',
            operation_id: 'team_private',
            operation_name: 'TeamPrivate',
            actor_results: [
              {
                actor: 'revoked_user',
                expected_access: false,
                status: 'denied',
                evidence_path: direct_evidence_path
              }
            ]
          },
          {
            checkpoint: 'post_change_t0',
            operation_id: 'admin_secrets',
            operation_name: 'AdminSecrets',
            actor_results: [
              {
                actor: 'revoked_user',
                expected_access: false,
                status: 'accessible',
                evidence_path: alternate_evidence_path
              }
            ]
          }
        ],
        findings: [
          {
            id: 'post_change_t0:admin_secrets:revoked_user:unexpected_access',
            checkpoint: 'post_change_t0',
            operation_id: 'admin_secrets',
            operation_name: 'AdminSecrets',
            actor: 'revoked_user'
          }
        ]
      }

      lineage = PWN::Bounty::GraphQLAuthzDiff::CrossSurfaceObjectLineage.run(
        diff_report: diff_report,
        surface_evidence: [
          { operation_id: 'team_private', route_family: 'direct' },
          { operation_id: 'admin_secrets', route_family: 'alternate' }
        ],
        object_seeds: [
          { id: 't1', aliases: ['team_private', 'admin_secrets'] }
        ],
        output_dir: tmp_dir
      )

      assert_equal(1, lineage[:family_count])
      assert_equal(1, lineage[:reportable_candidate_count])
      assert_equal('cross_surface_authz_drift', lineage.dig(:families, 0, :report_angle))
      assert_equal(true, lineage.dig(:families, 0, :direct_denied))
      assert_equal(true, lineage.dig(:families, 0, :alternate_accessible))

      assert(File.exist?(File.join(tmp_dir, 'cross_surface_object_lineage.json')))
      assert(File.exist?(File.join(tmp_dir, 'cross_surface_object_lineage.md')))
    end
  end
end
