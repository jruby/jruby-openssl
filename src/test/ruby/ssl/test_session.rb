# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLSession < TestCase
  include SSLTestHelper

  def test_session
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ctx = OpenSSL::SSL::SSLContext.new("TLSv1_2")
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect

      assert ssl.session.is_a?(OpenSSL::SSL::Session)
      assert ssl.session.equal? session = ssl.session

      assert session.id.is_a?(String)
      assert_equal 32, session.id.length
      assert session.time.is_a?(Time)

      assert session.timeout >= 0

      session.timeout = 5
      assert_equal 5, session.timeout

      assert session == OpenSSL::SSL::Session.new(ssl)

      ssl.close
    end
  end

  def test_alpn_protocol_selection_ary
    advertised = ["h2", "http/1.1"]
    ctx_proc = Proc.new { |ctx|
      ctx.alpn_select_cb = -> (protocols) {
        assert_equal Array, protocols.class
        assert_equal advertised, protocols
        protocols.first
      }
    }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ctx = OpenSSL::SSL::SSLContext.new("TLSv1_2")
      ctx.alpn_protocols = advertised
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      assert_equal("h2", ssl.alpn_protocol)
      ssl.puts "abc"; assert_equal "abc\n", ssl.gets
    end
  end

  def test_exposes_session_error
    OpenSSL::SSL::Session::SessionError
  end

end