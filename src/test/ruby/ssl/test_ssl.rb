# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSL < TestCase

  include SSLTestHelper

  def test_context_default_constants
    assert OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
    assert_equal 'SSLv23', OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ssl_version]
    # assert_equal "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW", OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
    assert_equal OpenSSL::SSL::VERIFY_PEER, OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:verify_mode]

    assert OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE
    assert OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE.is_a?(OpenSSL::X509::Store)
  end

  def test_post_connection_check
    sslerr = OpenSSL::SSL::SSLError

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert_raise(sslerr) { ssl.post_connection_check("localhost.localdomain") }
      assert_raise(sslerr) { ssl.post_connection_check("127.0.0.1") }
      assert ssl.post_connection_check("localhost")
      assert_raise(sslerr) { ssl.post_connection_check("foo.example.com") }

      cert = ssl.peer_cert
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "localhost.localdomain")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "127.0.0.1")
      assert OpenSSL::SSL.verify_certificate_identity(cert, "localhost")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "foo.example.com")
    end

    now = Time.now
    exts = [
      ["keyUsage","keyEncipherment,digitalSignature",true],
      ["subjectAltName","DNS:localhost.localdomain",false],
      ["subjectAltName","IP:127.0.0.1",false],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 4, now, now + 1800, exts,
                           @ca_cert, @ca_key, OpenSSL::Digest::SHA1.new)
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect

      assert ssl.post_connection_check("localhost.localdomain")
      assert ssl.post_connection_check("127.0.0.1")
      assert_raise(sslerr) { ssl.post_connection_check("localhost") }
      assert_raise(sslerr) { ssl.post_connection_check("foo.example.com") }

      cert = ssl.peer_cert
      assert OpenSSL::SSL.verify_certificate_identity(cert, "localhost.localdomain")
      assert OpenSSL::SSL.verify_certificate_identity(cert, "127.0.0.1")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "localhost")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "foo.example.com")
    end

    now = Time.now
    exts = [
      [ "keyUsage", "keyEncipherment,digitalSignature", true ],
      [ "subjectAltName", "DNS:*.localdomain", false ],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 5, now, now + 1800, exts,
                           @ca_cert, @ca_key, OpenSSL::Digest::SHA1.new)
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert ssl.post_connection_check("localhost.localdomain")
      assert_raise(sslerr) { ssl.post_connection_check("127.0.0.1") }
      assert_raise(sslerr) { ssl.post_connection_check("localhost") }
      assert_raise(sslerr) { ssl.post_connection_check("foo.example.com") }
      cert = ssl.peer_cert
      assert OpenSSL::SSL.verify_certificate_identity(cert, "localhost.localdomain")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "127.0.0.1")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "localhost")
      assert ! OpenSSL::SSL.verify_certificate_identity(cert, "foo.example.com")
    end
  end

  def test_post_connect_check_with_anon_ciphers
    unless OpenSSL::ExtConfig::TLS_DH_anon_WITH_AES_256_GCM_SHA384
      return skip('OpenSSL::ExtConfig::TLS_DH_anon_WITH_AES_256_GCM_SHA384 not enabled')
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true, { use_anon_cipher: true }) { |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ciphers = "aNULL"
      server_connect(port, ctx) { |ssl|
        msg = "Peer verification enabled, but no certificate received. Anonymous cipher suite " \
          "ADH-AES256-GCM-SHA384 was negotiated. Anonymous suites must be disabled to use peer verification."
        assert_raise_with_message(OpenSSL::SSL::SSLError, msg){ssl.post_connection_check("localhost.localdomain")}
      }
    }
  end

  def test_ssl_version_tlsv1
    ctx_proc = Proc.new do |ctx|
      ctx.ssl_version = "TLSv1"
    end
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert_equal("TLSv1", ssl.ssl_version)
      ssl.close
    end
  end

  def test_ssl_version_tlsv1_1
    ctx_proc = Proc.new do |ctx|
      ctx.ssl_version = "TLSv1_1"
    end
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert_equal("TLSv1.1", ssl.ssl_version)
      ssl.close
    end
  end unless java6? # TLS1_1 is not supported by JDK 6

  def test_ssl_version_tlsv1_2
    ctx_proc = Proc.new do |ctx|
      ctx.ssl_version = "TLSv1_2"
    end
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert_equal("TLSv1.2", ssl.ssl_version)
      ssl.close
    end
  end unless java6? # TLS1_2 is not supported by JDK 6

  def test_read_nonblock_would_block
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect

      if defined? OpenSSL::SSL::SSLErrorWaitReadable
        begin
          ssl.read_nonblock(2)
          fail 'read would block error not raised!'
        rescue OpenSSL::SSL::SSLErrorWaitReadable => e
          assert_equal 'read would block', e.message
        end
      else
        begin
          ssl.read_nonblock(2)
          fail 'read would block error not raised!'
        rescue => e
          assert_equal 'read would block', e.message
        end
      end
      if RUBY_VERSION > '2.2'
        result = eval "ssl.read_nonblock(5, 'buff', exception: false)"
        assert_equal :wait_readable, result
      end
      result = ssl.send :sysread_nonblock, 5, :exception => false
      assert_equal :wait_readable, result

      ssl.close
    end
  end if RUBY_VERSION > '1.9'

  def test_connect_nonblock_would_block
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)

      if defined? OpenSSL::SSL::SSLErrorWaitReadable
        begin
          ssl.connect_nonblock
          fail 'read would block error not raised!'
        rescue OpenSSL::SSL::SSLErrorWaitReadable => e
          assert_equal 'read would block', e.message
        end
      else
        begin
          ssl.connect_nonblock
          fail 'read would block error not raised!'
        rescue => e
          assert_equal 'read would block', e.message
        end
      end

      if RUBY_VERSION > '2.2'
        result = eval "ssl.connect_nonblock(exception: false)"
        assert_equal :wait_readable, result
      end
      result = ssl.connect_nonblock(:exception => false)
      assert_equal :wait_readable, result

      ssl.close
    end
  end if RUBY_VERSION > '1.9'

  def test_renegotiation_cb
    num_handshakes = 0
    renegotiation_cb = Proc.new { |ssl| num_handshakes += 1 }
    ctx_proc = Proc.new { |ctx| ctx.renegotiation_cb = renegotiation_cb }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, {:ctx_proc => ctx_proc}) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert_equal(1, num_handshakes)
      ssl.close
    end
  end

  def test_tlsext_hostname
    return unless OpenSSL::SSL::SSLSocket.instance_methods.include?(:hostname)

    ctx_proc = Proc.new do |ctx, ssl|
      foo_ctx = ctx.dup

      ctx.servername_cb = Proc.new do |ssl2, hostname|
        case hostname
          when 'foo.example.com'
            foo_ctx
          when 'bar.example.com'
            nil
          else
            raise "unknown hostname #{hostname.inspect}"
        end
      end
    end

    server_proc = Proc.new { |ctx, ssl| readwrite_loop(ctx, ssl) }

    start_server(OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      2.times do |i|
        ctx = OpenSSL::SSL::SSLContext.new
        if defined?(OpenSSL::SSL::OP_NO_TICKET)
          # disable RFC4507 support
          ctx.options = OpenSSL::SSL::OP_NO_TICKET
        end
        server_connect(port, ctx) { |ssl|
          ssl.hostname = (i & 1 == 0) ? 'foo.example.com' : 'bar.example.com'
          str = "x" * 100 + "\n"
          ssl.puts(str)
          assert_equal(str, ssl.gets)
        }
      end
    end
  end

end
