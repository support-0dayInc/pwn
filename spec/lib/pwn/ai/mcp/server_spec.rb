# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

describe PWN::AI::MCP::Server do
  it 'handles initialize requests' do
    request = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {}
    }

    response = described_class.handle_request(request)
    expect(response[:id]).to eq(1)
    expect(response[:result][:serverInfo][:name]).to eq('pwn-ai-mcp')
  end

  it 'reads and writes framed json-rpc messages' do
    body = JSON.dump({ jsonrpc: '2.0', id: 2, method: 'ping' })
    input = StringIO.new("Content-Length: #{body.bytesize}\r\n\r\n#{body}")

    parsed = described_class.read_message(input)
    expect(parsed['method']).to eq('ping')

    out = StringIO.new
    described_class.write_message(out, jsonrpc: '2.0', id: 2, result: {})
    out.rewind
    framed = out.read

    expect(framed).to include('Content-Length:')
    expect(framed).to include('{"jsonrpc":"2.0","id":2,"result":{}}')
  end
end
