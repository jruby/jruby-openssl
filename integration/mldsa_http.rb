require_relative '../test/test_helper'
require 'net/http'
require 'socket'
require 'timeout'

class TestMLDSAHTTP < TestCase
  def setup
    super
    @ca_key = Fixtures.pkey('rsa2048')
    @ca = issue_cert(distinguished_name('trusted CA'), @ca_key, 1,
                     [['basicConstraints', 'CA:TRUE', true],
                      ['keyUsage', 'keyCertSign,cRLSign', true]], nil, nil)
    @server_key = Fixtures.pkey('rsa2048')
    @server_cert = server_certificate
  end

  def test_get_and_post_authenticate_each_mldsa_parameter_set
    [44, 65, 87].each do |parameter|
      # Exercise imported keys as Net::HTTP users do, including public derivation.
      path = File.expand_path("../test/fixtures/mldsa/ml-dsa-#{parameter}-seed.pem", File.dirname(__FILE__))
      key = OpenSSL::PKey.read(File.binread(path))
      cert = client_certificate(key)
      [Net::HTTP::Get.new('/vault'), Net::HTTP::Post.new('/vault')].each do |request|
        request.body = "binary\0payload\xff".b if request.is_a?(Net::HTTP::Post)
        with_server do |port, result|
          response = http(port, cert, key).start { |connection| connection.request(request) }
          assert_equal '200', response.code
          peer_der, protocol, method, body = Timeout.timeout(15) { result.pop }
          raise peer_der if peer_der.is_a?(Exception)
          assert_equal cert.to_der, peer_der, 'server must authenticate the intended certificate'
          assert_equal 'TLSv1.3', protocol
          assert_equal request.method, method
          assert_equal request.body.to_s, body
          assert_equal cert.subject.to_s, response.body
        end
      end
    end
  end

  def test_rejects_untrusted_server_ca
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    with_server do |port, result|
      connection = http(port, client_certificate(key), key)
      connection.cert_store = OpenSSL::X509::Store.new
      assert_raise(OpenSSL::SSL::SSLError) { connection.get('/vault') }
      assert_server_rejected(result)
    end
  end

  def test_mldsa_server_identity_with_default_context
    client_key = OpenSSL::PKey.generate_key('ML-DSA-44')
    client_cert = client_certificate(client_key)
    [44, 65, 87].each do |parameter|
      @server_key = OpenSSL::PKey.generate_key("ML-DSA-#{parameter}")
      @server_cert = server_certificate
      with_server(context: OpenSSL::SSL::SSLContext.new) do |port, result|
        http(port, client_cert, client_key).start do |connection|
          assert_equal @server_cert.to_der, connection.peer_cert.to_der
          assert_equal '200', connection.get('/vault').code
        end
        peer_der, protocol = Timeout.timeout(15) { result.pop }
        raise peer_der if peer_der.is_a?(Exception)
        assert_equal client_cert.to_der, peer_der
        assert_equal 'TLSv1.3', protocol
      end
    end
  end

  def test_rejects_wrong_hostname
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    with_server(server_certificate('wrong.example')) do |port, result|
      assert_raise(OpenSSL::SSL::SSLError) { http(port, client_certificate(key), key).get('/vault') }
      assert_server_rejected(result)
    end
  end

  def test_rejects_expired_server_certificate
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    with_server(server_certificate('localhost', expired: true)) do |port, result|
      assert_raise(OpenSSL::SSL::SSLError) { http(port, client_certificate(key), key).get('/vault') }
      assert_server_rejected(result)
    end
  end

  def test_rejects_absent_client_identity
    with_server do |port, result|
      assert_raise(OpenSSL::SSL::SSLError) { http(port, nil, nil).get('/vault') }
      assert_server_rejected(result)
    end
  end

  def test_rejects_untrusted_client_identity
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    cert = issue_cert(distinguished_name('untrusted client'), key, 99,
                      [['keyUsage', 'digitalSignature', true]], nil, nil, digest: nil)
    with_server do |port, result|
      assert_raise(OpenSSL::SSL::SSLError) { http(port, cert, key).get('/vault') }
      assert_server_rejected(result)
    end
  end

  def test_rejects_expired_client_identity
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    cert = client_certificate(key, expired: true)
    store = trust_store
    assert_equal false, store.verify(cert)
    assert_equal OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error
    with_server do |port, result|
      assert_raise(OpenSSL::SSL::SSLError, Errno::ECONNRESET) { http(port, cert, key).get('/vault') }
      assert_server_rejected(result)
    end
  end

  def test_rejects_certificate_private_key_mismatch
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    other = OpenSSL::PKey.generate_key('ML-DSA-44')
    with_server do |port, result|
      assert_raise(OpenSSL::SSL::SSLError, Errno::ECONNRESET) { http(port, client_certificate(key), other).get('/vault') }
      assert_server_rejected(result)
    end
  end

  private

  def distinguished_name(value)
    OpenSSL::X509::Name.new([['CN', value]])
  end

  def server_certificate(host = 'localhost', expired: false)
    issue_cert(distinguished_name(host), @server_key, 2,
               [['keyUsage', 'digitalSignature', true],
                ['extendedKeyUsage', 'serverAuth', false],
                ['subjectAltName', "DNS:#{host}", false]], @ca, @ca_key,
               not_after: expired ? Time.now - 60 : Time.now + 3600)
  end

  def client_certificate(key, expired: false)
    issue_cert(distinguished_name("client #{key.oid}"), key, 3,
               [['keyUsage', 'digitalSignature', true],
                ['extendedKeyUsage', 'clientAuth', false]], @ca, @ca_key,
               not_after: expired ? Time.now - 60 : Time.now + 3600)
  end

  def trust_store
    OpenSSL::X509::Store.new.tap { |store| store.add_cert(@ca) }
  end

  def http(port, cert, key)
    Net::HTTP.new('localhost', port, nil).tap do |connection|
      connection.use_ssl = true
      connection.min_version = connection.max_version = OpenSSL::SSL::TLS1_3_VERSION
      connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      connection.verify_hostname = true
      connection.cert_store = trust_store
      connection.cert = cert
      connection.key = key
      connection.open_timeout = connection.read_timeout = 10
      connection.max_retries = 0
    end
  end

  def with_server(cert = @server_cert, context: OpenSSL::SSL::SSLContext.new(:TLS))
    context.cert = cert
    context.key = @server_key
    context.cert_store = trust_store
    context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    context.min_version = context.max_version = OpenSSL::SSL::TLS1_3_VERSION
    tcp = TCPServer.new('127.0.0.1', 0)
    server = OpenSSL::SSL::SSLServer.new(tcp, context)
    result = Queue.new
    thread = Thread.new do
      begin
        ssl = server.accept
        request_line = ssl.gets
        raise EOFError, 'client closed before sending an HTTP request' unless request_line
        method = request_line.split.first
        length = 0
        while (line = ssl.gets) && line != "\r\n"
          length = line.split(':', 2).last.to_i if line.downcase.start_with?('content-length:')
        end
        body = length.zero? ? '' : ssl.read(length)
        peer = ssl.peer_cert
        result << [peer.to_der, ssl.ssl_version, method, body]
        response = peer.subject.to_s
        ssl.write("HTTP/1.1 200 OK\r\nContent-Length: #{response.bytesize}\r\nConnection: close\r\n\r\n#{response}")
      rescue => error
        result << [error]
      ensure
        ssl.close if ssl
      end
    end
    yield tcp.addr[1], result
  ensure
    tcp.close if tcp && !tcp.closed?
    if thread
      thread.kill unless thread.join(15)
      thread.join
    end
  end

  def assert_server_rejected(result)
    outcome = Timeout.timeout(15) { result.pop }
    assert_kind_of Exception, outcome.first
  end
end
