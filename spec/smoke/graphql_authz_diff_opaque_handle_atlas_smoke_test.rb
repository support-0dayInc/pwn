# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class GraphQLAuthzDiffOpaqueHandleAtlasSmokeTest < Minitest::Test
  def test_atlas_clusters_handle_family_from_graphql_and_rest_evidence
    Dir.mktmpdir('graphql-opaque-handle-atlas-smoke-') do |tmp_dir|
      direct_evidence_path = File.join(tmp_dir, 'direct.json')
      alternate_evidence_path = File.join(tmp_dir, 'alternate.json')

      File.write(
        direct_evidence_path,
        JSON.pretty_generate(
          {
            request: {
              url: 'https://example.test/api/repos/acme/private-repo/issues/123'
            },
            response: {
              graphql: {
                data: {
                  issue: {
                    id: 'gid://github/Issue/123',
                    node_id: 'MDU6SXNzdWUxMjM=',
                    databaseId: 123
                  }
                },
                errors: [{ message: 'Forbidden' }]
              }
            }
          }
        )
      )

      File.write(
        alternate_evidence_path,
        JSON.pretty_generate(
          {
            request: {
              url: 'https://example.test/attachments/123/download'
            },
            response: {
              body_preview: 'issue export attachment for object 123',
              graphql: {
                data: {
                  export: {
                    slug: 'acme/private-repo',
                    attachment_id: '123'
                  }
                }
              }
            }
          }
        )
      )

      diff_report = {
        run_id: 'opaque-handle-atlas-smoke',
        matrix: [
          {
            checkpoint: 'post_change_t0',
            operation_id: 'issue_direct',
            operation_name: 'IssueDirect',
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
            operation_id: 'issue_export',
            operation_name: 'IssueExport',
            actor_results: [
              {
                actor: 'revoked_user',
                expected_access: false,
                status: 'accessible',
                evidence_path: alternate_evidence_path
              }
            ]
          }
        ]
      }

      atlas = PWN::Bounty::GraphQLAuthzDiff::OpaqueHandleAtlas.run(
        diff_report: diff_report,
        object_seeds: [
          {
            id: 'gid://github/Issue/123',
            aliases: ['123', 'acme/private-repo', 'issue_direct', 'issue_export']
          }
        ],
        surface_evidence: [
          {
            checkpoint: 'post_change_t0',
            actor: 'revoked_user',
            surface: 'issue_direct',
            route_family: 'direct',
            evidence_path: direct_evidence_path,
            object_refs: ['gid://github/Issue/123']
          },
          {
            checkpoint: 'post_change_t0',
            actor: 'revoked_user',
            surface: 'issue_export',
            route_family: 'alternate',
            evidence_path: alternate_evidence_path,
            url: 'https://example.test/attachments/123/download',
            object_refs: ['acme/private-repo']
          }
        ],
        output_dir: tmp_dir
      )

      assert_equal(1, atlas[:reportable_candidate_count])
      assert_equal('direct_denied_alternate_accessible', atlas.dig(:best_candidate, :report_angle))
      assert(atlas.dig(:best_candidate, :refs).any? { |ref| ref.include?('gid://github/issue/123') || ref.include?('123') })
      assert(File.exist?(File.join(tmp_dir, 'opaque_handle_atlas.json')))
      assert(File.exist?(File.join(tmp_dir, 'opaque_handle_atlas.md')))
    end
  end
end
