# coding: US-ASCII

require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLSession < TestCase
  include SSLTestHelper

  def test_session
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
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
    advertised = ['h2', 'http/1.1']
    ctx_proc = proc do |ctx|
      ctx.alpn_select_cb = lambda { |protocols|
        assert_equal Array, protocols.class
        assert_equal advertised, protocols
        protocols.first
      }
    end
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ctx.alpn_protocols = advertised
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      assert_equal('h2', ssl.alpn_protocol)
      ssl.puts 'abc'
      assert_equal "abc\n", ssl.gets
    end
  end

  def test_session_reuse
    ctx_proc = proc { |ctx|
      ctx.options &= ~OpenSSL::SSL::OP_NO_TICKET
    }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      # first connection: establish session
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      ssl.puts 'ping'
      assert_equal "ping\n", ssl.gets
      sess1 = ssl.session
      assert_instance_of OpenSSL::SSL::Session, sess1
      ssl.close

      # second connection: resume with captured session
      sock2 = TCPSocket.new('127.0.0.1', port)
      ctx2 = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl2 = OpenSSL::SSL::SSLSocket.new(sock2, ctx2)
      ssl2.sync_close = true
      ssl2.session = sess1
      ssl2.connect
      ssl2.puts 'pong'
      assert_equal "pong\n", ssl2.gets

      assert_equal sess1.id, ssl2.session.id, 'session id should match after resumption'
      assert ssl2.session_reused?, 'session_reused? should be truthy for resumed session'
      ssl2.close

      # third connection without session set: should NOT reuse
      sock3 = TCPSocket.new('127.0.0.1', port)
      ctx3 = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl3 = OpenSSL::SSL::SSLSocket.new(sock3, ctx3)
      ssl3.sync_close = true
      ssl3.connect
      ssl3.puts 'fresh'
      assert_equal "fresh\n", ssl3.gets
      # new connection without session= gets a different session
      refute_equal sess1.id, ssl3.session.id, 'fresh connection should get new session'
      ssl3.close
    end
  end

  def test_session_reconnect_with_default_context
    assert_session_reconnect
  end

  def test_session_reconnect_from_default_to_tls_context
    assert_session_reconnect([nil, 'TLSv1_2'])
  end

  def test_session_reconnect_from_tls_to_default_context
    assert_session_reconnect(['TLSv1_2', nil])
  end

  def assert_session_reconnect(methods = [nil, nil])
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |_server, port|
      session = nil

      2.times do |i|
        method = methods[i]
        ctx = method ? OpenSSL::SSL::SSLContext.new(method) : OpenSSL::SSL::SSLContext.new
        ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
        ctx.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_CLIENT |
                                 OpenSSL::SSL::SSLContext::SESSION_CACHE_NO_INTERNAL_STORE
        ctx.session_new_cb = proc { |_socket, value| session = value }

        sock = TCPSocket.new('127.0.0.1', port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        ssl.sync_close = true
        ssl.hostname = 'localhost'
        ssl.session = session if i > 0
        begin
          assert_nothing_raised { ssl.connect }
          ssl.puts 'ping'
          assert_equal "ping\n", ssl.gets
          assert_instance_of OpenSSL::SSL::Session, session
          assert_equal ssl.session.id, session.id
          assert_not_empty session.id
        ensure
          ssl.close
        end
      end
    end
  end
  private :assert_session_reconnect

  def test_session_reused_before_handshake_raises
    sock = File.new(__FILE__)
    ssl = OpenSSL::SSL::SSLSocket.new(sock)
    err = assert_raise(RuntimeError) { ssl.session_reused? }
    assert_equal 'SSL is not initialized', err.message
  end

  def test_session_to_der_and_to_pem
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect

      session = ssl.session
      pem = session.to_pem
      der = session.to_der

      assert_match(/\A-----BEGIN SSL SESSION PARAMETERS-----/, pem)
      assert_match(/-----END SSL SESSION PARAMETERS-----\n?\Z/, pem)

      body = pem.gsub(/-----(BEGIN|END) SSL SESSION PARAMETERS-----/, '').gsub(/[\r\n]+/m, '')
      assert_equal der, body.unpack1('m')
      assert der.bytesize > 0

      ssl.close
    end
  end

  def test_session_to_text
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect

      text = ssl.session.to_text

      assert_match(/\ASSL-Session:\n/, text)
      assert_match(/Protocol\s+: /, text)
      assert_match(/Session-ID: [0-9A-F]+\n/, text)
      assert_match(/Time\s+: /, text)
      assert_match(/Timeout\s+: \d+ \(sec\)/, text)

      ssl.close
    end
  end

  def test_session_new_cb_client
    called = {}
    ctx_proc = proc { |ctx|
      ctx.options &= ~OpenSSL::SSL::OP_NO_TICKET
    }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ctx.session_new_cb = lambda { |ary|
        sock, sess = ary
        called[:new] = [sock, sess]
      }

      sock = TCPSocket.new('127.0.0.1', port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      ssl.puts 'hello'
      assert_equal "hello\n", ssl.gets

      # session_new_cb should have been called with [ssl_socket, session]
      assert_not_nil called[:new], 'session_new_cb should have been called'
      cb_sock, cb_sess = called[:new]
      assert_same ssl, cb_sock
      assert_instance_of OpenSSL::SSL::Session, cb_sess
      assert_equal ssl.session.id, cb_sess.id

      # session_cache_stats should reflect the connection
      stats = ctx.session_cache_stats
      assert_operator stats[:connect_good], :>=, 1

      ssl.close
    end
  end

  def test_session_new_cb_server
    called = {}
    ctx_proc = proc { |ctx|
      ctx.options &= ~OpenSSL::SSL::OP_NO_TICKET
      ctx.session_new_cb = lambda { |ary|
        _sock, sess = ary
        called[:new] = sess
      }
    }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      sock = TCPSocket.new('127.0.0.1', port)
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      ssl.puts 'hello'
      assert_equal "hello\n", ssl.gets
      ssl.close
    end
    # server-side session_new_cb should have fired
    assert_not_nil called[:new], 'server session_new_cb should have been called'
    assert_instance_of OpenSSL::SSL::Session, called[:new]
  end

  def test_session_new_cb_not_called_without_setting
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |_server, port|
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      # no session_new_cb set
      sock = TCPSocket.new('127.0.0.1', port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      ssl.puts 'test'
      assert_equal "test\n", ssl.gets
      # should not raise
      ssl.close
    end
  end

  def test_session_cache_mode
    ctx = OpenSSL::SSL::SSLContext.new
    # should not raise when getting/setting
    ctx.session_cache_mode
    ctx.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_CLIENT
  end

  def test_session_cache_stats_keys
    ctx = OpenSSL::SSL::SSLContext.new
    stats = ctx.session_cache_stats
    %i[connect connect_good accept accept_good cache_num].each do |key|
      assert stats.key?(key), "session_cache_stats should contain :#{key}"
    end
  end

  def test_exposes_session_error
    OpenSSL::SSL::Session::SessionError
  end
end
