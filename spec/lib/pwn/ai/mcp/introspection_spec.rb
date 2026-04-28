# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::MCP::Introspection do
  it 'can inventory a specific module methods' do
    result = described_class.method_inventory(constant_path: 'PWN::AI')
    expect(result[:constant_path]).to eq('PWN::AI')
    expect(result[:singleton_methods]).to include('help')
  end

  it 'can recurse through PWN namespace' do
    result = described_class.recursive_inventory(root: 'PWN', max_depth: 2)
    expect(result[:root]).to eq('PWN')
    expect(result[:inventory]).to be_a(Array)
    expect(result[:constants_count]).to be > 0
  end
end
