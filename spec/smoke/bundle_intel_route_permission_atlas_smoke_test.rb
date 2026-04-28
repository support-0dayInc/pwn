# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class BundleIntelRoutePermissionAtlasSmokeTest < Minitest::Test
  def test_route_permission_atlas_extracts_ranked_route_and_graphql_candidates
    Dir.mktmpdir('bundle-intel-route-permission-atlas-') do |tmp_dir|
      report = PWN::Bounty::BundleIntel::RoutePermissionAtlas.run(
        run_id: 'bundle-intel-route-permission-atlas-smoke',
        base_url: 'https://app.example.test',
        html: [
          '<a href="/admin/users">Admin</a><a href="/api/v1/projects">Projects</a>'
        ],
        js_bundles: [
          'const feature_admin_portal_enabled=true; const PERM="project:write"; query AdminUsers { users { id } } ; const route="/beta/admin/roles";'
        ],
        source_maps: [
          'mutation PromoteMember { promoteMember(id:"1"){id} } https://api.example.test/internal/reports/export'
        ],
        output_dir: tmp_dir
      )

      assert_equal('bundle-intel-route-permission-atlas-smoke', report[:run_id])
      assert(report[:entry_count] >= 4)
      assert(report[:route_count] >= 2)
      assert(report[:graphql_operation_count] >= 2)

      lanes = report[:entries].map { |entry| entry[:recommended_replay_lane] }
      assert(lanes.include?('lifecycle_authz_replay'))
      assert(lanes.include?('graphql_authz_diff'))

      assert(report[:burp_seeds].any? { |seed| seed.include?('/admin/users') || seed.include?('/beta/admin/roles') })
      assert(report[:lifecycle_replay_starters].any?)
      assert(report[:graphql_diff_starters].any?)

      run_root = File.join(tmp_dir, 'bundle-intel-route-permission-atlas-smoke')
      assert(File.exist?(File.join(run_root, 'route_permission_atlas.json')))
      assert(File.exist?(File.join(run_root, 'route_permission_atlas.md')))
      assert(File.exist?(File.join(run_root, 'route_permission_atlas_burp_seeds.txt')))
    end
  end
end
