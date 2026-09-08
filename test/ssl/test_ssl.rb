# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSL < TestCase

  include SSLTestHelper

  def test_context_default_constants
    assert OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
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
    @svr_cert = issue_cert(@svr, @svr_key, 4, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800, digest: sha1_or_approved)
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
      refute OpenSSL::SSL.verify_certificate_identity(cert, "localhost")
      refute OpenSSL::SSL.verify_certificate_identity(cert, "foo.example.com")
    end

    now = Time.now
    exts = [
      [ "keyUsage", "keyEncipherment,digitalSignature", true ],
      [ "subjectAltName", "DNS:*.localdomain", false ],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 5, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800, digest: sha1_or_approved)
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
      refute OpenSSL::SSL.verify_certificate_identity(cert, "127.0.0.1")
      refute OpenSSL::SSL.verify_certificate_identity(cert, "localhost")
      refute OpenSSL::SSL.verify_certificate_identity(cert, "foo.example.com")
    end
  end

  # ported from CRuby's test/openssl/test_ssl.rb
  def test_verify_certificate_identity_ipv4
    cert = create_cert_with_san("IP:192.168.7.1")
    assert_equal true,  OpenSSL::SSL.verify_certificate_identity(cert, "192.168.7.1")
    assert_equal false, OpenSSL::SSL.verify_certificate_identity(cert, "192.168.7.255")
    assert_equal false, OpenSSL::SSL.verify_certificate_identity(cert, "192.168.7.2")
  end

  # ported from CRuby's test/openssl/test_ssl.rb
  def test_verify_certificate_identity_ipv6
    cert = create_cert_with_san("IP:13::17")
    assert_equal true,  OpenSSL::SSL.verify_certificate_identity(cert, "13::17")
    assert_equal false, OpenSSL::SSL.verify_certificate_identity(cert, "13::18")
    # expanded form
    assert_equal true,  OpenSSL::SSL.verify_certificate_identity(cert, "13:0:0:0:0:0:0:17")
    assert_equal false, OpenSSL::SSL.verify_certificate_identity(cert, "44:0:0:0:0:0:0:17")
    # fully expanded with leading zeros
    assert_equal true,  OpenSSL::SSL.verify_certificate_identity(cert, "0013:0000:0000:0000:0000:0000:0000:0017")
    assert_equal false, OpenSSL::SSL.verify_certificate_identity(cert, "1313:0000:0000:0000:0000:0000:0000:0017")
  end

  def test_verify_certificate_identity_dns_no_ip_match
    cert = create_cert_with_san("DNS:example.com")
    assert_equal true,  OpenSSL::SSL.verify_certificate_identity(cert, "example.com")
    assert_equal false, OpenSSL::SSL.verify_certificate_identity(cert, "192.168.7.1")
  end

  private

  def create_cert_with_san(san)
    ef = OpenSSL::X509::ExtensionFactory.new
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/DC=some/DC=site/CN=Some Site")
    cert.add_extension ef.create_ext("subjectAltName", san)
    cert
  end

  public

  # Ported from CRuby's test_verify_hostname_on_connect (test/openssl/test_ssl.rb).
  # Verifies that SSLSocket#connect enforces verify_hostname automatically.
  # On CRuby this is checked inside the OpenSSL verify callback during handshake;
  # on JRuby it is checked after the JSSE handshake completes (equivalent effect).
  def test_verify_hostname_on_connect
    now = Time.now
    exts = [
      ["keyUsage", "keyEncipherment,digitalSignature", true],
      ["subjectAltName", "DNS:a.example.com,DNS:*.b.example.com", false],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 4, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800)

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_hostname = true
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER

      [
        ["a.example.com", true],
        ["A.Example.Com", true],
        ["x.example.com", false],
        ["b.example.com", false],
        ["x.b.example.com", true],
      ].each do |name, expected_ok|
        begin
          sock = TCPSocket.new("127.0.0.1", port)
          ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
          ssl.hostname = name
          if expected_ok
            ssl.connect
          else
            assert_raise(OpenSSL::SSL::SSLError) { ssl.connect }
          end
        ensure
          ssl&.close rescue nil
          sock&.close rescue nil
        end
      end
    end
  end

  # verify_hostname must NOT be enforced under VERIFY_NONE (MRI checks it only inside the
  # peer-verify callback, which never runs when verification is disabled)
  def test_verify_hostname_not_enforced_when_verify_none
    now = Time.now
    exts = [
      ["keyUsage", "keyEncipherment,digitalSignature", true],
      ["subjectAltName", "DNS:a.example.com", false],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 4, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800)

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_hostname = true
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.hostname = "wrong.example.com" # mismatch, but VERIFY_NONE -> no check
      ssl.connect
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  def test_verify_hostname_not_enforced_when_disabled
    now = Time.now
    exts = [
      ["keyUsage", "keyEncipherment,digitalSignature", true],
      ["subjectAltName", "DNS:a.example.com", false],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 4, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800)

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      # verify_hostname defaults to false/nil - mismatched hostname should succeed
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER

      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.hostname = "wrong.example.com"
      ssl.connect # should succeed - verify_hostname is not set
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  # GH-25: verify_result should report the actual verification error even
  # when VERIFY_NONE is set. C OpenSSL always runs ssl_verify_cert_chain
  # and stores the result; VERIFY_NONE only suppresses the handshake abort.

  def test_verify_result_with_verify_none_self_signed
    # Self-signed cert: verify_result should be V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    self_key = OpenSSL::PKey::RSA.new(2048)
    now = Time.now
    self_cert = issue_cert(
      OpenSSL::X509::Name.parse("/CN=Self Signed"), self_key, 10,
      [["keyUsage", "keyEncipherment,digitalSignature", true]],
      nil, nil, not_before: now, not_after: now + 1800)

    @svr_cert = self_cert
    @svr_key = self_key
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.connect
      assert_equal OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, ssl.verify_result
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  def test_verify_result_with_verify_none_valid_cert
    # Valid cert signed by trusted CA: verify_result should be V_OK
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.connect
      assert_equal OpenSSL::X509::V_OK, ssl.verify_result
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  def test_verify_result_with_verify_peer_valid_cert
    # VERIFY_PEER with trusted CA: connect succeeds, verify_result is V_OK
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.connect
      assert_equal OpenSSL::X509::V_OK, ssl.verify_result
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  # verify_callback must be honored on the ca_file/ca_path path (not only when a cert_store is set):
  # a callback rejecting an otherwise valid chain must fail the connection
  def test_verify_callback_honored_with_ca_file
    require 'tempfile'
    ca_file = Tempfile.new(['ca', '.pem'])
    ca_file.write(@ca_cert.to_pem); ca_file.flush; ca_file.close

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      # callback rejects -> connection must fail
      called = false
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ca_file = ca_file.path
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.verify_callback = lambda { |ok, sctx| called = true; false }
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      assert_raise(OpenSSL::SSL::SSLError) { ssl.connect }
      assert called, "verify_callback was not invoked on the ca_file path"
      ssl.close rescue nil; sock.close rescue nil

      # callback accepts (passes preverify through) -> connection succeeds
      called = false
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ca_file = ca_file.path
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.verify_callback = lambda { |ok, sctx| called = true; ok }
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.connect
      assert called
      assert_equal OpenSSL::X509::V_OK, ssl.verify_result
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
      ca_file.unlink rescue nil
    end
  end

  # a verify_callback on one context must not be clobbered by another context
  # sharing the same X509::Store (e.g. the process-global DEFAULT_CERT_STORE)
  def test_verify_callback_not_clobbered_by_shared_store
    shared_store = OpenSSL::X509::Store.new # DEFAULT_CERT_STORE
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      seen = []
      mkctx = lambda do |tag|
        c = OpenSSL::SSL::SSLContext.new
        c.cert_store = shared_store
        c.verify_mode = OpenSSL::SSL::VERIFY_PEER
        c.verify_callback = lambda { |ok, sctx| seen << tag; true } # accept regardless
        c.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF
        c.max_version = OpenSSL::SSL::TLS1_2_VERSION # force a full handshake (no 1.3 resumption)
        c
      end
      ctx_a = mkctx.call(:a)
      ctx_b = mkctx.call(:b)

      connect = lambda do |ctx|
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        ssl.connect
        ssl.close rescue nil; sock.close rescue nil
      end

      connect.call(ctx_a) # sets up ctx_a
      connect.call(ctx_b) # sets up ctx_b -> would clobber the shared store
      seen.clear
      connect.call(ctx_a) # must still use ctx_a's own callback
      assert_equal [:a], seen.uniq, "ctx_a verify_callback was clobbered by ctx_b via shared store"
    end
  end

  def test_verify_result_with_verify_peer_self_signed
    # VERIFY_PEER with self-signed cert: connect should fail
    self_key = OpenSSL::PKey::RSA.new(2048)
    now = Time.now
    self_cert = issue_cert(
      OpenSSL::X509::Name.parse("/CN=Self Signed"), self_key, 10,
      [["keyUsage", "keyEncipherment,digitalSignature", true]],
      nil, nil, not_before: now, not_after: now + 1800)

    @svr_cert = self_cert
    @svr_key = self_key
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      assert_raise(OpenSSL::SSL::SSLError) { ssl.connect }
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  # Server-side verify_mode (ported from Ruby OpenSSL test_ssl.rb#test_verify_mode :
  # VERIFY_PEER|VERIFY_FAIL_IF_NO_PEER_CERT requires the client to present a cert the server trusts
  # TLS 1.2 pinned so a rejected client cert fails during the handshake (1.3 auths post-handshake)
  def test_server_verify_mode_requires_trusted_client_cert
    now = Time.now
    ee = [["keyUsage", "digitalSignature", true]]
    cli_key = OpenSSL::PKey::RSA.new(2048)
    cli_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=Client"), cli_key, 11, ee,
                          @ca_cert, @ca_key, not_before: now, not_after: now + 1800)
    rogue_key = OpenSSL::PKey::RSA.new(2048)
    rogue_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=Rogue"), rogue_key, 12, ee,
                            nil, nil, not_before: now, not_after: now + 1800) # self-signed, untrusted

    vmode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    tls12 = proc { |c| c.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server(vmode, true, ignore_listener_error: true, ctx_proc: tls12) do |server, port|
      connect = lambda do |cert, key|
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE # isolate the server-side check
        ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
        if cert then ctx.cert = cert; ctx.key = key end
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        begin
          ssl.connect
          :ok
        ensure
          ssl.close rescue nil
          sock.close rescue nil
        end
      end

      assert_raise(OpenSSL::SSL::SSLError) { connect.call(nil, nil) }              # no client cert
      assert_raise(OpenSSL::SSL::SSLError) { connect.call(rogue_cert, rogue_key) } # untrusted cert
      assert_equal :ok, connect.call(cli_cert, cli_key)                           # trusted cert
    end
  end

  # VERIFY_PEER without FAIL_IF_NO_PEER_CERT: client cert is requested but optional, so a client
  # presenting none still connects (setWantClientAuth vs setNeedClientAuth).
  def test_server_verify_peer_allows_missing_client_cert
    tls12 = proc { |c| c.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server(OpenSSL::SSL::VERIFY_PEER, true, ignore_listener_error: true, ctx_proc: tls12) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.connect # no client cert - VERIFY_PEER alone must not require one
      assert ssl.peer_cert # server cert still available
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  def test_unexpected_eof_is_not_accepted_by_default
    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
    tcp_server = TCPServer.new("127.0.0.1", 0)
    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)

    server_thread = Thread.new do
      ssl = ssl_server.accept
      ssl.write("payload")
      ssl.flush
      ssl.to_io.close
    end

    client_ctx = OpenSSL::SSL::SSLContext.new
    client_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    client_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
    sock = TCPSocket.new("127.0.0.1", tcp_server.addr[1])
    ssl = OpenSSL::SSL::SSLSocket.new(sock, client_ctx)
    ssl.connect

    assert_raise(OpenSSL::SSL::SSLError) { ssl.read }
  ensure
    ssl&.close rescue nil
    sock&.close rescue nil
    server_thread&.join rescue nil
    ssl_server&.close rescue nil
    tcp_server&.close rescue nil
  end

  def test_unexpected_eof_can_be_ignored_with_option
    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
    tcp_server = TCPServer.new("127.0.0.1", 0)
    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)

    server_thread = Thread.new do
      ssl = ssl_server.accept
      ssl.write("payload")
      ssl.flush
      ssl.to_io.close
    end

    client_ctx = OpenSSL::SSL::SSLContext.new
    client_ctx.options |= OpenSSL::SSL::OP_IGNORE_UNEXPECTED_EOF
    client_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    client_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
    sock = TCPSocket.new("127.0.0.1", tcp_server.addr[1])
    ssl = OpenSSL::SSL::SSLSocket.new(sock, client_ctx)
    ssl.connect

    assert_equal "payload", ssl.read
  ensure
    ssl&.close rescue nil
    sock&.close rescue nil
    server_thread&.join rescue nil
    ssl_server&.close rescue nil
    tcp_server&.close rescue nil
  end

  # verify_result should report V_ERR_HOSTNAME_MISMATCH when hostname
  # verification fails during connect (matches CRuby behavior).
  def test_verify_result_hostname_mismatch
    now = Time.now
    exts = [
      ["keyUsage", "keyEncipherment,digitalSignature", true],
      ["subjectAltName", "DNS:a.example.com", false],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 4, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800)

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_hostname = true
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)

      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.hostname = "b.example.com"
      assert_raise(OpenSSL::SSL::SSLError) { ssl.connect }
      assert_equal OpenSSL::X509::V_ERR_HOSTNAME_MISMATCH, ssl.verify_result
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  # Ported from CRuby's test_verify_hostname_failure_error_code.
  # CRuby invokes verify_callback with V_ERR_HOSTNAME_MISMATCH because the
  # hostname check runs inside OpenSSL's verify callback during handshake.
  # JRuby checks hostname post-handshake (JSSE limitation), so the callback
  # doesn't see the error. Skipped on JRuby; runs on CRuby for parity check.
  def test_verify_hostname_failure_error_code_via_callback
    skip 'verify_callback not invoked for hostname mismatch (JSSE limitation)' if defined?(JRUBY_VERSION)

    now = Time.now
    exts = [
      ["keyUsage", "keyEncipherment,digitalSignature", true],
      ["subjectAltName", "DNS:a.example.com", false],
    ]
    @svr_cert = issue_cert(@svr, @svr_key, 4, exts, @ca_cert, @ca_key,
                           not_before: now, not_after: now + 1800)

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      verify_callback_ok = verify_callback_err = nil

      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_hostname = true
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.verify_callback = -> (preverify_ok, store_ctx) {
        verify_callback_ok = preverify_ok
        verify_callback_err = store_ctx.error
        preverify_ok
      }

      begin
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        ssl.hostname = "b.example.com"
        assert_raise(OpenSSL::SSL::SSLError) { ssl.connect }
        assert_equal false, verify_callback_ok
        assert_equal OpenSSL::X509::V_ERR_HOSTNAME_MISMATCH, verify_callback_err
      ensure
        ssl&.close rescue nil
        sock&.close rescue nil
      end
    end
  end

  # SSL_get_peer_cert_chain behavior differs between C OpenSSL and JSSE:
  #   C OpenSSL server-side: excludes the peer's leaf cert (use peer_cert for that)
  #   C OpenSSL client-side: includes the server's leaf cert
  #   JSSE (both sides):     always includes the leaf cert
  # This test documents the difference; both are valid TLS implementations.
  def test_peer_cert_chain_server_side
    now = Time.now
    int_key = OpenSSL::PKey::RSA.new(2048)
    int_cert = issue_cert(
      OpenSSL::X509::Name.parse("/CN=Intermediate"), int_key, 10,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]],
      @ca_cert, @ca_key, not_before: now, not_after: now + 3600)
    leaf_key = OpenSSL::PKey::RSA.new(2048)
    leaf_cert = issue_cert(
      OpenSSL::X509::Name.parse("/CN=Leaf"), leaf_key, 11,
      [["keyUsage","keyEncipherment,digitalSignature",true]],
      int_cert, int_key, not_before: now, not_after: now + 1800)

    server_peer_cert = nil
    server_peer_chain = nil

    ctx_proc = Proc.new do |ctx|
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
    end

    server_proc = Proc.new do |sctx, ssl|
      server_peer_cert = ssl.peer_cert
      server_peer_chain = ssl.peer_cert_chain
      readwrite_loop(sctx, ssl)
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true,
                 ctx_proc: ctx_proc, server_proc: server_proc) do |server, port|
      cctx = OpenSSL::SSL::SSLContext.new
      cctx.cert = leaf_cert
      cctx.key = leaf_key
      cctx.extra_chain_cert = [int_cert]
      cctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      server_connect(port, cctx) do |ssl|
        ssl.puts "hello"; ssl.gets
      end
    end

    # Both: peer_cert is the leaf
    assert_equal "/CN=Leaf", server_peer_cert.subject.to_s

    chain_subjects = server_peer_chain.map { |c| c.subject.to_s }
    if defined?(JRUBY_VERSION)
      # JSSE's getPeerCertificates always includes the leaf
      assert_equal ["/CN=Leaf", "/CN=Intermediate"], chain_subjects
    else
      # C OpenSSL's SSL_get_peer_cert_chain on server side excludes the leaf
      assert_equal ["/CN=Intermediate"], chain_subjects
    end
  end

  # OpenSSL::SSL::SSLContext#add_certificate registers credentials that BCJSSE selects
  # per negotiated cipher (key type), mirroring C OpenSSL's SSL_CTX_add1_credential
  def test_add_certificate
    ctx_proc = -> ctx {
      ctx.cert = ctx.key = ctx.extra_chain_cert = nil
      ctx.add_certificate(@svr_cert, @svr_key, [@ca_cert]) # RSA
    }
    start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) { |server, port|
      server_connect(port) { |ssl|
        assert_equal @svr_cert.subject.to_s, ssl.peer_cert.subject.to_s
        assert_equal [@svr_cert.subject.to_s, @ca_cert.subject.to_s],
          ssl.peer_cert_chain.map { |c| c.subject.to_s }
        ssl.puts "abc"; assert_equal "abc\n", ssl.gets
      }
    }
  end

  def test_add_certificate_multiple_certs
    ca2_key = OpenSSL::PKey::RSA.new(2048)
    ca2_dn = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA2")
    ca2_cert = issue_cert(ca2_dn, ca2_key, 123,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]], nil, nil)

    ec_key = OpenSSL::PKey::EC.generate("prime256v1")
    ec_dn = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost2")
    ec_cert = issue_cert(ec_dn, ec_key, 456,
      [["keyUsage","digitalSignature",true]], ca2_cert, ca2_key)

    ctx_proc = -> ctx {
      ctx.cert = @svr_cert
      ctx.key = @svr_key
      ctx.extra_chain_cert = [@ca_cert]
      ctx.add_certificate(ec_cert, ec_key, [ca2_cert]) # ECDSA
    }
    start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) { |server, port|
      # BCJSSE in approved-only mode does not offer ECDHE-ECDSA, so only assert EC
      # credential selection where the suite is actually available
      unless fips?
        ec_ctx = OpenSSL::SSL::SSLContext.new
        ec_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
        ec_ctx.ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256"
        server_connect(port, ec_ctx) { |ssl|
          assert_equal ec_dn.to_s, ssl.peer_cert.subject.to_s
          assert_equal [ec_dn.to_s, ca2_dn.to_s], ssl.peer_cert_chain.map { |c| c.subject.to_s }
        }
      end

      rsa_ctx = OpenSSL::SSL::SSLContext.new
      rsa_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
      rsa_ctx.ciphers = "ECDHE-RSA-AES128-GCM-SHA256"
      server_connect(port, rsa_ctx) { |ssl|
        assert_equal @svr_cert.subject.to_s, ssl.peer_cert.subject.to_s
        assert_equal [@svr_cert.subject.to_s, @ca_cert.subject.to_s], ssl.peer_cert_chain.map { |c| c.subject.to_s }
      }
    }
  end

  def test_add_certificate_validates_private_key_and_chain
    ctx = OpenSSL::SSL::SSLContext.new
    public_key = OpenSSL::PKey.read(@svr_key.public_to_der)
    assert_raise(ArgumentError) { ctx.add_certificate(@svr_cert, public_key) }
    assert_raise(TypeError) { ctx.add_certificate(@svr_cert, @svr_key, Object.new) }

    chain = [@ca_cert]
    ctx.add_certificate(@svr_cert, @svr_key, chain)
    chain << Object.new
    assert_equal true, ctx.setup
  end

  def test_post_connect_check_with_anon_ciphers
    unless OpenSSL::ExtConfig::TLS_DH_anon_WITH_AES_256_GCM_SHA384
      return skip('OpenSSL::ExtConfig::TLS_DH_anon_WITH_AES_256_GCM_SHA384 not enabled')
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true, { use_anon_cipher: true }) { |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ciphers = "aNULL"
      ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION # anon suites exist only <= TLS 1.2
      server_connect(port, ctx) { |ssl|
        msg = "Peer verification enabled, but no certificate received. Anonymous cipher suite " \
          "ADH-AES256-GCM-SHA384 was negotiated. Anonymous suites must be disabled to use peer verification."
        assert_raise_with_message(OpenSSL::SSL::SSLError, msg){ssl.post_connection_check("localhost.localdomain")}
      }
    }
  end

  def test_ciphers_does_not_disable_tls13
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ciphers = "ECDHE-RSA-AES128-GCM-SHA256" # a TLS 1.2 suite; TLS 1.3 must stay enabled
      server_connect(port, ctx) do |ssl|
        assert_equal "TLSv1.3", ssl.ssl_version
      end
    end
  end

  def test_parallel
    start_server(OpenSSL::SSL::VERIFY_PEER, true) { |_, port|
      ssls = []
      10.times{
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock)
        ssl.connect
        ssl.sync_close = true
        ssls << ssl
      }
      str = "x" * 1000 + "\n"
      ITERATIONS.times{
        ssls.each{|ssl|
          ssl.puts(str)
          assert_equal(str, ssl.gets)
        }
      }
      ssls.each{|ssl| ssl.close }
    }
  end

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
  end

  def test_ssl_version_tlsv1_3
    ctx_proc = Proc.new do |ctx|
      ctx.ssl_version = "TLSv1_3"
    end
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      assert_equal("TLSv1.3", ssl.ssl_version)
      ssl.close
    end
  end

  # GH-204: a handshake that JSSE aborts with a plain runtime exception
  # (nothing left to negotiate) used to escape SSLSocket#connect as a raw Java exception
  def test_connect_raises_ssl_error_on_disabled_protocol
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      # disabling the only enabled protocol leaves an empty set, no matter what
      # the JDK's jdk.tls.disabledAlgorithms happens to allow
      ctx.ssl_version = "TLSv1"
      ctx.options |= OpenSSL::SSL::OP_NO_TLSv1

      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      err = assert_raise(OpenSSL::SSL::SSLError) { ssl.connect }
      assert err.message && !err.message.empty?
    ensure
      ssl&.close rescue nil
      sock&.close rescue nil
    end
  end

  MAX_SSL_VERSION = "TLSv1.3"

  [
    [OpenSSL::SSL::TLS1_VERSION, nil,   MAX_SSL_VERSION, "(TLSv1,)"],
    [OpenSSL::SSL::TLS1_1_VERSION, nil, MAX_SSL_VERSION, "(TLSv1.1,)"],
    [OpenSSL::SSL::TLS1_2_VERSION, nil, MAX_SSL_VERSION, "(TLSv1.2,)"],
    [nil, OpenSSL::SSL::TLS1_2_VERSION, "TLSv1.2",       "(,TLSv1.2)"],
    [OpenSSL::SSL::TLS1_VERSION, OpenSSL::SSL::TLS1_2_VERSION, "TLSv1.2", "(TLSv1,TLSv1.2)"]
  ].each do |min_version, max_version, expected_version, desc|
    define_method("test_ssl_minmax_#{desc}") do
      ctx_proc = Proc.new do |ctx|
        ctx.min_version = min_version unless min_version.nil?
        ctx.max_version = max_version unless max_version.nil?
      end
      start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock)
        ssl.connect
        assert_equal(expected_version, ssl.ssl_version)
        ssl.close
      end
    end
  end

  def test_read_nonblock_would_block
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect

      begin
        ssl.read_nonblock(2)
        fail 'read would block error not raised!'
      rescue OpenSSL::SSL::SSLErrorWaitReadable => e
        assert_equal 'read would block', e.message
      end

      if RUBY_VERSION > '2.2'
        result = eval "ssl.read_nonblock(5, 'buff', exception: false)"
        assert_equal :wait_readable, result
      end
      result = ssl.send :sysread_nonblock, 5, :exception => false
      assert_equal :wait_readable, result

      ssl.close
    end
  end

  def test_read_nonblock
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION # avoid TLS 1.3 post-handshake records (see test_read_nonblock_tls13)
      server_connect(port, ctx) do |ssl|
        assert_equal :wait_readable, ssl.read_nonblock(100, exception: false)
        ssl.write("abc\n")
        IO.select [ssl]
        assert_equal('a', ssl.read_nonblock(1))
        assert_equal("bc\n", ssl.read_nonblock(100))
        assert_equal :wait_readable, ssl.read_nonblock(100, exception: false)
      end
    end
  end

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

  def test_renegotiation_cb_is_server_only
    server_called = 0
    client_called = 0
    ctx_proc = Proc.new { |ctx|
      ctx.renegotiation_cb = Proc.new { |ssl| server_called += 1 }
    }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc) do |_server, port|
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      ctx.renegotiation_cb = Proc.new { |ssl| client_called += 1 }
      sock = TCPSocket.new('127.0.0.1', port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true
      ssl.connect
      ssl.puts 'hello'; assert_equal "hello\n", ssl.gets

      # CRuby only fires renegotiation_cb server-side
      assert_equal 1, server_called, 'server renegotiation_cb should fire once'
      assert_equal 0, client_called, 'client renegotiation_cb should not fire'
      ssl.close
    end
  end

  def test_tlsext_hostname
    return unless OpenSSL::SSL::SSLSocket.instance_methods.include?(:hostname)

    called = {}
    fooctx = OpenSSL::SSL::SSLContext.new
    fooctx.cert = @cli_cert
    fooctx.key = @cli_key

    ctx_proc = Proc.new do |ctx, ssl|
      ctx.servername_cb = Proc.new do |ssl2, hostname|
        called[hostname] = true
        case hostname
          when 'foo.example.com'
            fooctx
          when 'bar.example.com'
            nil
          else
            raise "unknown hostname #{hostname.inspect}"
        end
      end
    end

    server_proc = Proc.new { |ctx, ssl| readwrite_loop(ctx, ssl) }

    start_server(OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      ['foo.example.com', 'bar.example.com'].each do |host|
        ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
        sock = TCPSocket.new('127.0.0.1', port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        ssl.sync_close = true
        ssl.hostname = host # must be set before connect for SNI
        ssl.connect
        str = "x" * 100 + "\n"
        ssl.puts(str)
        assert_equal(str, ssl.gets)
        ssl.close
      end
    end
    assert called['foo.example.com'], 'servername_cb should be called for foo.example.com'
    assert called['bar.example.com'], 'servername_cb should be called for bar.example.com'
  end

  def test_servername_cb_not_called_without_sni
    called = []
    ctx_proc = Proc.new do |ctx|
      ctx.servername_cb = Proc.new { |_, hostname| called << hostname; nil }
    end
    server_proc = Proc.new { |ctx, ssl| readwrite_loop(ctx, ssl) }

    start_server(OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new('TLSv1_2')
      sock = TCPSocket.new('127.0.0.1', port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.sync_close = true # no #hostname set -> no SNI sent
      ssl.connect
      str = "x" * 100 + "\n"
      ssl.puts(str)
      assert_equal(str, ssl.gets) # connection still works without SNI
      ssl.close
    end
    assert_equal([], called, "servername_cb should not be called without SNI (got: #{called.inspect})")
  end

  CUSTOM_CIPHERS = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:" +
      "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:" +
      "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:" +
      "ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:" +
      "DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:" +
      "DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:" +
      "AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:" +
      "!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"

  def test_set_custom_params
    ops = OpenSSL::SSL::OP_ALL
    ops &= ~OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS if defined?(OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS)
    ops |= OpenSSL::SSL::OP_NO_COMPRESSION if defined?(OpenSSL::SSL::OP_NO_COMPRESSION)
    ops |= OpenSSL::SSL::OP_NO_SSLv2
    ops |= OpenSSL::SSL::OP_NO_SSLv3

    params = { :ssl_version => "TLSv1_2", :ciphers => CUSTOM_CIPHERS, :options => ops }
    params.merge!( :verify_mode => OpenSSL::SSL::VERIFY_NONE )

    ctx_proc = Proc.new { |ctx, ssl| ctx.set_params(params) }

    start_server(OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      context = OpenSSL::SSL::SSLContext.new.tap { |ctx| ctx.set_params(params) }
      socket = TCPSocket.new("127.0.0.1", port)
      client = OpenSSL::SSL::SSLSocket.new socket, context

      client.connect

      client.close rescue nil
    end
  end

  LEAF_CERTIFICATE = OpenSSL::X509::Certificate.new <<-EOF
-----BEGIN CERTIFICATE-----
MIIFKDCCBBCgAwIBAgISBP+uKglvwxGq302F+yCqxvnXMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMTA4MTEwOTAxMzdaFw0yMTExMDkwOTAxMzVaMBwxGjAYBgNVBAMT
EWdlb2lwLmVsYXN0aWMuZGV2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAtazxd/2FWW1O5evHkDnPi4vcZJDFxs8V0tlI2ppf/OTymlBHMbzBE3BsUEP7
SkT+6kPnqQoy85S66zT4f2XyQfSWUZJeMPMcODl5P0SXEBlKv+ElRYvrsUpuc0ZH
ZTIM3+ueUY5M3Xmo9ao+I5evahr4Pf1laRWhHRLzFdKiMn7r1/qXf+PzKqZlzLng
cULtVpCTZlOk7CwrsAxwTYdFe1Z0b2ebKs793Ghag2V3D2YtCMuqLa1GP1sBsFRT
v1XPehXb5UOWffp3RJnUoG3n7K5cPI6G+fUAGRF3wxKuH+PYyW6/irb5+v4CVVSi
z+f29zDYeOc+baWGWFfymktslwIDAQABo4ICTDCCAkgwDgYDVR0PAQH/BAQDAgWg
MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBQ23ntd4n192uVjxt9C0B18QYWMyzAfBgNVHSMEGDAWgBQULrMXt1hW
y65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6
Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iu
b3JnLzAcBgNVHREEFTATghFnZW9pcC5lbGFzdGljLmRldjBMBgNVHSAERTBDMAgG
BmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vY3Bz
LmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB1AH0+8viP
/4hVaCTCwMqeUol5K8UOeAl/LmqXaJl+IvDXAAABezSpB0oAAAQDAEYwRAIgC5B1
huzXAJCbtfWO5GGMVj930XNoNPGQj6o8yJfMQnMCIBdlncSV2rymFbZG7Q2PSAim
7/PkW/2qD3Vt8Ald8u3DAHcARJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2
gagAAAF7NKkJHAAABAMASDBGAiEAnWU3nUNjdHdrE62v0y45WDLj6eyfXkIxAh9Z
GAA2wJACIQDtKZNFze3mAj7pE6m3AZMfnq4N0VvO2Ahr0HbpN/xWzDANBgkqhkiG
9w0BAQsFAAOCAQEABWFFyolbYnyqDA8ckU0Lm7btCM78CeljjKxVCGTqhlntJhhH
NBJcRArzCBkres7Z4yySiJ1vSUXNVvGITVCi2d/zJ5SxBDoT5v8IjEb98KH//9u3
Jb1CfuEADhnEUXjyf4GeIiTHtdKX36jGwTRO3YIa52G6HONbOnQBgcwn8FpYJdIj
3C58o5AxWRcVVQbaCFxjGcCLSUSQsJxzilsYE+xVqc+d5GftG3Nmy6l3Ht84693n
UwMrb/rlsQC163gtdVEN/GFCeLU+UfFGuSeCmUM3SmAIVfD/yjLvisVpf70pV0Jg
p1Px196NI71smu8LxrhX78ErTrR4GpDkx4W+uw==
-----END CERTIFICATE-----
  EOF


  EXPIRED_DST_ROOT_CA_X3 = OpenSSL::X509::Certificate.new <<-EOF
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
  EOF

  require 'time'
  VERIFY_EXPIRED_TIME = Time.parse("2021/10/20 09:10:00")

  def test_cert_verify_expired1_lets_encrypt_cross_signed_root
    # reproducer for https://github.com/jruby/jruby-openssl/issues/236
    #
    # In this reproducer we have a leaf certificate with two possible chains:
    # a) leaf -> intermediate cert A -> ISRG Root X1 cross-signed by (expired) DST ROOT CA X3 -> (expired) DST ROOT CA X3
    # b) leaf -> intermediate cert B -> ISRG Root X1
    # JRuby will produce chain a) causing an error, while CRuby produces a valid chain b)

    root_bundle = [
        # Expired DST ROOT CA X3
        EXPIRED_DST_ROOT_CA_X3,
        # active ISRG Root X1
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrgrootx1.pem', __FILE__))),
        # ISRG Root X1 cross-signed by (expired) DST ROOT CA X3
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrg-root-x1-cross-signed.pem', __FILE__)))
    ]

    cert_store = OpenSSL::X509::Store.new
    cert_store.time = VERIFY_EXPIRED_TIME
    root_bundle.each { |cert| cert_store.add_cert cert }

    # the endpoint will send the leaf node + these two intermediate certs
    chain = [
        # Intermediate cert from expired CA
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/lets-encrypt-r3-cross-signed.pem', __FILE__))),
        # Valid Intermediate cert
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/lets-encrypt-r3.pem', __FILE__))),
    ]

    # let's try to validate the leaf+chain against the root bundle
    ok = cert_store.verify(LEAF_CERTIFICATE, chain)

    # pp cert_store.chain if $VERBOSE

    assert_equal true, ok
    assert_equal 'ok', cert_store.error_string
    assert_equal ["/CN=geoip.elastic.dev",
                  "/C=US/O=Let's Encrypt/CN=R3",
                  "/C=US/O=Internet Security Research Group/CN=ISRG Root X1"],
                 cert_store.chain.map { |cert| cert.subject.to_s }

    # 0.10.7
    # [#<OpenSSL::X509::Certificate
    #     subject=#<OpenSSL::X509::Name CN=geoip.elastic.dev>,
    #         issuer=#<OpenSSL::X509::Name CN=R3,O=Let's Encrypt,C=US>,
    #             serial=#<OpenSSL::BN 435452651231011312001825766803379554023895>,
    #                 not_before=2021-08-11 09:01:37 UTC,
    #     not_after=2021-11-09 09:01:35 UTC>,
    # #<OpenSSL::X509::Certificate
    #     subject=#<OpenSSL::X509::Name CN=R3,O=Let's Encrypt,C=US>,
    #         issuer=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
    #             serial=#<OpenSSL::BN 85078157426496920958827089468591623647>,
    #                 not_before=2020-10-07 19:21:40 UTC,
    #     not_after=2021-09-29 19:21:40 UTC>,
    # #<OpenSSL::X509::Certificate
    #     subject=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
    #         issuer=#<OpenSSL::X509::Name CN=DST Root CA X3,O=Digital Signature Trust Co.>,
    #             serial=#<OpenSSL::BN 91299735575339953335919266965803778155>,
    #                 not_before=2000-09-30 21:12:19 UTC,
    #     not_after=2021-09-30 14:01:15 UTC>]
    # 10
    # certificate has expired
  end

  def test_cert_verify_expired2_lets_encrypt_cross_signed_intermediate

    root_bundle = [
        # Expired DST ROOT CA X3
        EXPIRED_DST_ROOT_CA_X3,
        # active ISRG Root X1
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrgrootx1.pem', __FILE__))),
        # ISRG Root X1 cross-signed by DST ROOT CA X3 (which is expired)
        #OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrg-root-x1-cross-signed.pem', __FILE__)))
    ]

    cert_store = OpenSSL::X509::Store.new
    cert_store.time = VERIFY_EXPIRED_TIME
    root_bundle.each { |cert| cert_store.add_cert cert }

    # cross-signed cert is sent from the server :
    chain = [
        #LEAF_CERTIFICATE,
        # Valid Intermediate cert
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/lets-encrypt-r3.pem', __FILE__))),
        # ISRG Root X1 cross-signed by DST ROOT CA X3
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrg-root-x1-cross-signed.pem', __FILE__)))
    ]

    ok = cert_store.verify(LEAF_CERTIFICATE, chain)

    # pp cert_store.chain if $VERBOSE

    assert_equal ["/CN=geoip.elastic.dev",
                  "/C=US/O=Let's Encrypt/CN=R3",
                  "/C=US/O=Internet Security Research Group/CN=ISRG Root X1"],
                 cert_store.chain.map { |cert| cert.subject.to_s }

    assert_equal true, ok # fails in JOSSL 0.10.7 error: 10 (certificate has expired)
    assert_equal 'ok', cert_store.error_string
  end

  def test_cert_verify_expired0_lets_encrypt # base_line
    root_bundle = [
        # Expired DST ROOT CA X3
        #EXPIRED_DST_ROOT_CA_X3, # should be fine since we do not have the expired around
        # active ISRG Root X1
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrgrootx1.pem', __FILE__))),
        # ISRG Root X1 cross-signed by (expired) DST ROOT CA X3
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/isrg-root-x1-cross-signed.pem', __FILE__)))
    ]

    cert_store = OpenSSL::X509::Store.new
    cert_store.time = VERIFY_EXPIRED_TIME
    root_bundle.each { |cert| cert_store.add_cert cert }

    chain = [
        # Intermediate cert from expired CA
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/lets-encrypt-r3-cross-signed.pem', __FILE__))),
        # Valid Intermediate cert
        OpenSSL::X509::Certificate.new(File.read(File.expand_path('../letsencrypt/lets-encrypt-r3.pem', __FILE__))),
    ]

    ok = cert_store.verify(LEAF_CERTIFICATE, chain)

    assert ok # works in JOSSL 0.10.7
    assert_equal 'ok', cert_store.error_string
    assert_equal ["/CN=geoip.elastic.dev",
                  "/C=US/O=Let's Encrypt/CN=R3",
                  "/C=US/O=Internet Security Research Group/CN=ISRG Root X1"],
                 cert_store.chain.map { |cert| cert.subject.to_s }

    cert_store = OpenSSL::X509::Store.new
    cert_store.time = VERIFY_EXPIRED_TIME
    cert_store.add_cert root_bundle[1] # only the expired one

    ok = cert_store.verify(LEAF_CERTIFICATE, chain)

    assert !ok
    assert_equal 'unable to get issuer certificate', cert_store.error_string
  end

  def test_getbyte
    start_server(OpenSSL::SSL::VERIFY_NONE, true) { |_, port|
      server_connect(port) { |ssl|
        str = +("x" * 100 + "\n")
        ssl.syswrite(str)
        newstr = str.bytesize.times.map { |i|
          ssl.getbyte
        }.pack("C*")
        assert_equal(str, newstr)
      }
    }
  end

  def test_sync_close
    start_server(OpenSSL::SSL::VERIFY_NONE, true) do |_, port|
      begin
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock)
        ssl.connect
        ssl.puts "abc"; assert_equal "abc\n", ssl.gets
        ssl.close
        assert_not_predicate sock, :closed?
      ensure
        sock&.close
      end

      begin
        sock = TCPSocket.new("127.0.0.1", port)
        ssl = OpenSSL::SSL::SSLSocket.new(sock)
        ssl.sync_close = true  # !!
        ssl.connect
        ssl.puts "abc"; assert_equal "abc\n", ssl.gets
        ssl.close
        assert_predicate sock, :closed?
      ensure
        sock&.close
      end
    end
  end

  # GH-181: extra_chain_cert must include the leaf cert when sent over the wire
  def test_extra_chain_cert_sends_leaf
    # Create CA -> Intermediate -> Leaf
    now = Time.now
    int_key = OpenSSL::PKey::RSA.new(2048)
    int_cert = issue_cert(
      OpenSSL::X509::Name.parse("/CN=Intermediate"), int_key, 10,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]],
      @ca_cert, @ca_key, not_before: now, not_after: now + 3600)
    leaf_key = OpenSSL::PKey::RSA.new(2048)
    leaf_cert = issue_cert(
      OpenSSL::X509::Name.parse("/CN=Leaf"), leaf_key, 11,
      [["keyUsage","keyEncipherment,digitalSignature",true]],
      int_cert, int_key, not_before: now, not_after: now + 1800)

    # Server trusts CA and verifies client certs
    ctx_proc = Proc.new do |ctx|
      ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ctx.cert_store = OpenSSL::X509::Store.new
      ctx.cert_store.add_cert(@ca_cert)
    end

    server_proc = Proc.new do |sctx, ssl|
      # Server should see the leaf as peer_cert
      assert_equal "/CN=Leaf", ssl.peer_cert.subject.to_s
      readwrite_loop(sctx, ssl)
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true,
                 ctx_proc: ctx_proc, server_proc: server_proc) do |server, port|
      cctx = OpenSSL::SSL::SSLContext.new
      cctx.cert = leaf_cert
      cctx.key = leaf_key
      cctx.extra_chain_cert = [int_cert]
      cctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      server_connect(port, cctx) do |ssl|
        ssl.puts "hello"
        assert_equal "hello\n", ssl.gets
      end
    end
  end

  def test_sysread_syswrite_raise_before_handshake
    require 'socket'
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    begin
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      begin
        err = assert_raise(OpenSSL::SSL::SSLError) { ssl.syswrite("plaintext") }
        assert_match(/SSL session is not started/, err.message)
        err = assert_raise(OpenSSL::SSL::SSLError) { ssl.sysread(16) }
        assert_match(/SSL session is not started/, err.message)
      ensure
        ssl.close rescue nil
        sock.close rescue nil
      end
    ensure
      server.close rescue nil
    end
  end

end
