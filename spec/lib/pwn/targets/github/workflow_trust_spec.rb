# frozen_string_literal: true

require 'spec_helper'

describe 'spec/lib/pwn/targets/github/workflow_trust_spec.rb' do
  it 'exists as coverage scaffold' do
    expect(File.exist?('spec/lib/pwn/targets/github/workflow_trust_spec.rb')).to eq(true)
  end
end
