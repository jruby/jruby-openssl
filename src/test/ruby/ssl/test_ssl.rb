# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSL < TestCase

  include SSLTestHelper

  def test_context_default_constants
    assert OpenSSL::SSL::SSLContext::DEFAULT_PARAMS
    assert_equal 'SSLv23', OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ssl_version]
    assert_equal "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW", OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
    assert_equal OpenSSL::SSL::VERIFY_PEER, OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:verify_mode]

    assert OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE
    assert OpenSSL::SSL::SSLContext::DEFAULT_CERT_STORE.is_a?(OpenSSL::X509::Store)
  end

  def test_post_connection_check
    sslerr = OpenSSL::SSL::SSLError

    start_server(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
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
    start_server(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
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
    start_server(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
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

end