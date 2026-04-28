# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::MCP::Registry do
  it 'lists MCP tools' do
    tools = described_class.list_tools
    names = tools.map { |t| t[:name] }
    expect(names).to include('pwn.help', 'pwn.inventory_recursive', 'pwn.methods', 'pwn.invoke')
  end

  it 'invokes pwn.help tool' do
    response = described_class.call_tool(name: 'pwn.help', arguments: {})
    expect(response[:ok]).to eq(true)
    expect(response[:result]).to include(:AI)
  end

  it 'invokes read-only method safely through pwn.invoke' do
    response = described_class.call_tool(
      name: 'pwn.invoke',
      arguments: {
        'constant_path' => 'PWN::AI',
        'method' => 'help'
      }
    )

    expect(response[:ok]).to eq(true)
    expect(response[:result]).to include(:MCP)
  end
end
