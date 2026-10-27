# coding: US-ASCII
require File.expand_path('../test/test_helper', File.dirname(__FILE__))

require 'openssl'
require 'socket'
require 'timeout'

# Integration tests against https://badssl.com - a service maintained (by the Chrome
# security team) specifically to expose *known*, stable and intentionally (mis)configured
# TLS endpoints. Because the expected outcome of every endpoint is defined, these assert
# exact verification results (X509 error codes, negotiated protocol) instead of the usual
# "the request did not blow up" smoke check.
#
# Every verification failure is checked twice, which is where the CRuby-parity value is:
#   1. VERIFY_PEER - the handshake must raise OpenSSL::SSL::SSLError (fail closed)
#   2. VERIFY_NONE - the handshake must succeed *and* still report the right verify_result
#
# Connectivity problems are omitted (not failed) so an outage or a TLS-intercepting proxy
# does not look like a jruby-openssl regression; a completed-but-wrong outcome always fails.
class TLSVerifyTest < TestCase

  CONNECT_TIMEOUT = 15

  V_OK                         = OpenSSL::X509::V_OK                                # 0
  V_ERR_CERT_HAS_EXPIRED       = OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED              # 10
  V_ERR_DEPTH_ZERO_SELF_SIGNED = OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT   # 18
  V_ERR_SELF_SIGNED_IN_CHAIN   = OpenSSL::X509::V_ERR_SELF_SIGNED_CERT_IN_CHAIN     # 19

  # -- valid endpoint ---------------------------------------------------------

  def test_valid_certificate_verifies
    with_service do
      ssl_connect('badssl.com') do |ssl|
        assert_equal V_OK, ssl.verify_result
        assert_match(/badssl\.com/, ssl.peer_cert.subject.to_s)
        assert ssl.peer_cert_chain.size >= 2, "expected a chain, got #{ssl.peer_cert_chain.size}"
        assert OpenSSL::SSL.verify_certificate_identity(ssl.peer_cert, 'badssl.com')
      end
    end
  end

  # badssl.com serves a different (default) certificate when SNI is absent
  def test_sni_selects_the_requested_certificate
    with_service do
      ssl_connect('sha256.badssl.com') do |ssl|
        assert_equal V_OK, ssl.verify_result
        assert_match(/badssl\.com/, ssl.peer_cert.subject.to_s)
      end
    end
  end

  # -- verification failures --------------------------------------------------

  def test_expired_certificate
    assert_verify_error 'expired.badssl.com', V_ERR_CERT_HAS_EXPIRED
  end

  def test_self_signed_certificate
    assert_verify_error 'self-signed.badssl.com', V_ERR_DEPTH_ZERO_SELF_SIGNED
  end

  def test_untrusted_root_certificate
    assert_verify_error 'untrusted-root.badssl.com', V_ERR_SELF_SIGNED_IN_CHAIN
  end

  # the chain is valid here - only the identity does not match, which isolates hostname
  # verification from chain verification
  def test_hostname_mismatch_is_rejected
    with_service do
      # hostname checking is opt-in (verify_hostname is false on a bare context, same as CRuby)
      configure = lambda { |ctx| ctx.verify_hostname = true }
      err = assert_raise(OpenSSL::SSL::SSLError) do
        ssl_connect('wrong.host.badssl.com', configure: configure) { |ssl| ssl }
      end
      assert_match(/hostname|certificate verify failed/i, err.message)

      ssl_connect('wrong.host.badssl.com', verify_mode: OpenSSL::SSL::VERIFY_NONE) do |ssl|
        assert_equal V_OK, ssl.verify_result # chain alone is fine (trusted CA)
        assert_equal false,
                     OpenSSL::SSL.verify_certificate_identity(ssl.peer_cert, 'wrong.host.badssl.com')
      end
    end
  end

  # without verify_hostname the identity is *not* checked - CRuby behaves the same, so this
  # pins the default rather than leaving it implied
  def test_hostname_not_checked_unless_requested
    with_service do
      ssl_connect('wrong.host.badssl.com') do |ssl|
        assert_equal V_OK, ssl.verify_result
      end
    end
  end

  # -- negotiated protocol ----------------------------------------------------

  def test_tls_v1_2_only_endpoint
    with_service do
      ssl_connect('tls-v1-2.badssl.com', 1012) do |ssl|
        assert_equal 'TLSv1.2', ssl.ssl_version
        assert_equal V_OK, ssl.verify_result
      end
    end
  end

  def test_max_version_is_honoured
    with_service do
      configure = lambda { |ctx| ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION }
      ssl_connect('badssl.com', configure: configure) do |ssl|
        assert_equal 'TLSv1.2', ssl.ssl_version
        assert_equal V_OK, ssl.verify_result
      end
    end
  end

  # a TLS 1.3-only client must fail (not silently fall back) against a TLS 1.2 server
  def test_min_version_above_server_maximum_fails
    with_service do
      configure = lambda { |ctx| ctx.min_version = OpenSSL::SSL::TLS1_3_VERSION }
      assert_raise(OpenSSL::SSL::SSLError) do
        ssl_connect('tls-v1-2.badssl.com', 1012, configure: configure) { |ssl| ssl }
      end
    end
  end

  private

  # asserts both directions: fail-closed under VERIFY_PEER, exact code under VERIFY_NONE
  def assert_verify_error(host, expected_code)
    with_service do
      assert_raise(OpenSSL::SSL::SSLError, "#{host} must not verify") do
        ssl_connect(host) { |ssl| ssl }
      end

      ssl_connect(host, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |ssl|
        assert_equal expected_code, ssl.verify_result,
                     "#{host}: unexpected verify_result (#{ssl.verify_result})"
      end
    end
  end

  def ssl_connect(host, port = 443, verify_mode: OpenSSL::SSL::VERIFY_PEER, configure: nil)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = verify_mode
    ctx.cert_store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
    configure.call(ctx) if configure

    tcp = Timeout.timeout(CONNECT_TIMEOUT) { TCPSocket.new(host, port) }
    ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
    ssl.hostname = host # SNI
    ssl.sync_close = true
    begin
      Timeout.timeout(CONNECT_TIMEOUT) { ssl.connect }
      yield ssl if block_given?
    ensure
      begin
        ssl.close
      rescue StandardError, IOError
        # connection may already be torn down after a failed handshake
      end
    end
  end

  # network/service trouble must not look like a TLS regression
  def with_service
    yield
  rescue SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH,
         Errno::ENETUNREACH, Errno::ETIMEDOUT, Timeout::Error => e
    omit "badssl.com not reachable (#{e.class}: #{e.message})"
  rescue OpenSSL::SSL::SSLError => e
    # JRuby reports a peer dropping the connection mid-handshake as SSLError (MRI: Errno::ECONNRESET)
    raise unless e.message.match?(/Connection reset|closing inbound before receiving peer's close_notify/i)
    omit "badssl.com dropped the connection (#{e.message})"
  end

end
