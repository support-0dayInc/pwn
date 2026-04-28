# frozen_string_literal: true

require 'spec_helper'

describe PWN::AI::MCP::Policy do
  it 'marks help as read_only and allowed without confirmation' do
    expect(described_class.method_safety('help')).to eq(:read_only)
    allowed, reason = described_class.invocation_allowed?(method_name: 'help', confirm_dangerous: false)
    expect(allowed).to eq(true)
    expect(reason).to eq('allowed')
  end

  it 'requires confirmation for dangerous methods' do
    allowed, = described_class.invocation_allowed?(method_name: 'delete_target', confirm_dangerous: false)
    expect(allowed).to eq(false)

    allowed_confirmed, = described_class.invocation_allowed?(method_name: 'delete_target', confirm_dangerous: true)
    expect(allowed_confirmed).to eq(true)
  end
end
