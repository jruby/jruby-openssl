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

  def test_read_nonblock_without_session
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, false) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true

      assert_equal :wait_readable, ssl.read_nonblock(100, exception: false)
      ssl.write("abc\n")
      IO.select [ssl]
      assert_equal('a', ssl.read_nonblock(1))
      assert_equal("bc\n", ssl.read_nonblock(100))
      assert_equal :wait_readable, ssl.read_nonblock(100, exception: false)
      ssl.close
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

  def test_tlsext_hostname
    return unless OpenSSL::SSL::SSLSocket.instance_methods.include?(:hostname)

    fooctx = OpenSSL::SSL::SSLContext.new
    fooctx.cert = @cli_cert
    fooctx.key = @cli_key

    ctx_proc = Proc.new do |ctx, ssl|
      ctx.servername_cb = Proc.new do |ssl2, hostname|
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

end
