# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::MCP do
  it 'responds to help' do
    expect(PWN::AI::MCP).to respond_to :help
  end

  it 'exposes core MCP components' do
    expect(PWN::AI::MCP.help).to include(:Introspection, :Policy, :Registry, :Server)
  end
end
