# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'pwn'

class BundleIntelDerivedArtifactSurfaceAtlasSmokeTest < Minitest::Test
  def test_derived_artifact_surface_atlas_pairs_generate_and_download_routes
    route_permission_atlas = {
      entries: [
        {
          entry_type: 'route',
          identifier: '/api/v1/reports/generate',
          role_hint: 'admin',
          object_family: 'report',
          recommended_replay_lane: 'lifecycle_authz_replay',
          evidence_sources: [{ source_id: 'js_1', source_type: 'js_bundle' }]
        },
        {
          entry_type: 'route',
          identifier: '/api/v1/reports/status',
          role_hint: 'admin',
          object_family: 'report',
          recommended_replay_lane: 'lifecycle_authz_replay',
          evidence_sources: [{ source_id: 'js_1', source_type: 'js_bundle' }]
        },
        {
          entry_type: 'route',
          identifier: '/exports/reports/download',
          role_hint: 'admin',
          object_family: 'report',
          recommended_replay_lane: 'sensitive_file_exposure_pack',
          evidence_sources: [{ source_id: 'sm_1', source_type: 'source_map' }]
        }
      ]
    }

    Dir.mktmpdir('bundle-intel-derived-artifact-atlas-') do |tmp_dir|
      report = PWN::Bounty::BundleIntel::DerivedArtifactSurfaceAtlas.run(
        run_id: 'bundle-intel-derived-artifact-surface-atlas-smoke',
        base_url: 'https://app.example.test',
        route_permission_atlas: route_permission_atlas,
        output_dir: tmp_dir
      )

      assert_equal('bundle-intel-derived-artifact-surface-atlas-smoke', report[:run_id])
      assert(report[:chain_count] >= 1)

      chain = report[:chains].first
      assert_equal('report', chain[:object_family])
      assert_equal(true, chain[:route_pair_ready])
      assert_equal('lifecycle_authz_replay_artifact_access_drift_matrix', chain[:recommended_follow_on_pack])
      assert_includes(chain[:generate_routes], '/api/v1/reports/generate')
      assert_includes(chain[:download_routes], '/exports/reports/download')

      assert(report[:artifact_access_drift_matrix_starters].any?)
      assert(report[:sensitive_file_exposure_starters].any?)
      assert(report[:burp_seeds].any? { |seed| seed.include?('/exports/reports/download') })

      run_root = File.join(tmp_dir, 'bundle-intel-derived-artifact-surface-atlas-smoke')
      assert(File.exist?(File.join(run_root, 'derived_artifact_surface_atlas.json')))
      assert(File.exist?(File.join(run_root, 'derived_artifact_surface_atlas.md')))
      assert(File.exist?(File.join(run_root, 'derived_artifact_surface_atlas_burp_seeds.txt')))
    end
  end
end
