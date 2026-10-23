require File.expand_path('test_helper', File.dirname(__FILE__))
require 'timeout'

class TestSSLCredentials < TestCase
  include SSLTestHelper

  VERSIONS = { 'tls12' => ['TLSv1_2', 'TLSv1.2'], 'tls13' => ['TLSv1_3', 'TLSv1.3'] }
  KEY_TYPES = %w[rsa p256 p384 ed25519]

  KEY_TYPES.each do |key_type|
    VERSIONS.each do |version, (context_version, negotiated_version)|
      %w[legacy add_certificate].each do |registration|
        define_method("test_server_#{key_type}_#{version}_#{registration}") do
          check_support(key_type, context_version)
          key, cert = credential(key_type)
          configure = proc do |ctx|
            set_version(ctx, context_version)
            install_credential(ctx, registration, cert, key)
          end
          start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: configure) do |_server, port|
            server_connect(port, client_context(context_version)) do |ssl|
              assert_equal negotiated_version, ssl.ssl_version
              assert_peer_credential(ssl, cert)
              assert_equal [cert.to_der, @ca_cert.to_der], ssl.peer_cert_chain.map(&:to_der)
              assert_echo(ssl)
            end
          end
        end
      end
    end
  end

  def test_tls12_selects_rsa_and_ec_credentials_by_cipher
    check_support('p256', 'TLSv1_2')
    ec_key, ec_cert = credential('p256')
    configure = proc do |ctx|
      set_version(ctx, 'TLSv1_2')
      ctx.extra_chain_cert = [@ca_cert]
      ctx.add_certificate(ec_cert, ec_key, [@ca_cert])
    end
    start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: configure) do |_server, port|
      { 'ECDHE-RSA-AES128-GCM-SHA256' => @svr_cert,
        'ECDHE-ECDSA-AES128-GCM-SHA256' => ec_cert }.each do |cipher, cert|
        ctx = client_context('TLSv1_2')
        ctx.ciphers = cipher
        server_connect(port, ctx) do |ssl|
          assert_equal 'TLSv1.2', ssl.ssl_version
          assert_equal cipher, ssl.cipher.first
          assert_peer_credential(ssl, cert)
          assert_equal [cert.to_der, @ca_cert.to_der], ssl.peer_cert_chain.map(&:to_der)
          assert_echo(ssl)
        end
      end
    end
  end

  def test_legacy_credential_rejects_mismatched_private_key
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = @svr_cert
    ctx.key = @ca_key
    assert_raise(OpenSSL::SSL::SSLError) { ctx.setup }
  end

  def test_circular_certificate_store_chain_setup_terminates
    ca_extensions = [['basicConstraints', 'CA:TRUE', true], ['keyUsage', 'keyCertSign', true]]
    a_name = OpenSSL::X509::Name.parse('/CN=CA A')
    b_name = OpenSSL::X509::Name.parse('/CN=CA B')
    b_cert = issue_cert(b_name, @svr_key, 40, ca_extensions, nil, nil)
    a_cert = issue_cert(a_name, @ca_key, 41, ca_extensions, b_cert, @svr_key)
    b_cert = issue_cert(b_name, @svr_key, 42, ca_extensions, a_cert, @ca_key)
    leaf = issue_cert(@svr, @svr_key, 43,
      [['keyUsage', 'digitalSignature', true], ['extendedKeyUsage', 'serverAuth', false]], a_cert, @ca_key)
    store = OpenSSL::X509::Store.new
    store.add_cert(a_cert)
    store.add_cert(b_cert)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = leaf
    ctx.key = @svr_key
    ctx.cert_store = store
    assert_equal true, Timeout.timeout(5) { ctx.setup }
  end

  VERSIONS.each do |version, (context_version, negotiated_version)|
    %w[omitted empty].each do |replacement_chain|
      define_method("test_replacement_#{replacement_chain}_chain_#{version}") do
        check_support('rsa', context_version)
        first_key, first_cert = credential('rsa', 50)
        second_key, second_cert = credential('rsa', 51)
        configure = proc do |ctx|
          set_version(ctx, context_version)
          install_credential(ctx, 'add_certificate', first_cert, first_key)
          if replacement_chain == 'omitted'
            ctx.add_certificate(second_cert, second_key)
          else
            ctx.add_certificate(second_cert, second_key, [])
          end
        end
        start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: configure) do |_server, port|
          server_connect(port, client_context(context_version)) do |ssl|
            assert_equal negotiated_version, ssl.ssl_version
            assert_peer_credential(ssl, second_cert)
            expected_chain = [second_cert.to_der]
            expected_chain << @ca_cert.to_der if replacement_chain == 'omitted'
            assert_equal expected_chain, ssl.peer_cert_chain.map(&:to_der)
            assert_echo(ssl)
          end
        end
      end
    end

    %w[rsa p256].each do |key_type|
      define_method("test_last_#{key_type}_credential_replaces_previous_#{version}") do
        check_support(key_type, context_version)
        first_key, first_cert = credential(key_type, 10)
        second_key, second_cert = credential(key_type == 'p256' ? 'p384' : 'rsa', 11)
        configure = proc do |ctx|
          set_version(ctx, context_version)
          install_credential(ctx, 'add_certificate', first_cert, first_key)
          ctx.add_certificate(second_cert, second_key, [@ca_cert])
        end
        start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: configure) do |_server, port|
          server_connect(port, client_context(context_version)) do |ssl|
            assert_equal negotiated_version, ssl.ssl_version
            assert_peer_credential(ssl, second_cert)
            assert_equal [second_cert.to_der, @ca_cert.to_der], ssl.peer_cert_chain.map(&:to_der)
            assert_echo(ssl)
          end
        end
      end

      define_method("test_legacy_#{key_type}_credential_replaces_added_#{version}") do
        check_support(key_type, context_version)
        first_key, first_cert = credential(key_type, 12)
        second_key, second_cert = credential(key_type, 13)
        configure = proc do |ctx|
          set_version(ctx, context_version)
          ctx.add_certificate(first_cert, first_key, [@ca_cert])
          ctx.cert = second_cert
          ctx.key = second_key
          ctx.extra_chain_cert = [@ca_cert]
        end
        start_server(OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: configure) do |_server, port|
          server_connect(port, client_context(context_version)) do |ssl|
            assert_equal negotiated_version, ssl.ssl_version
            assert_peer_credential(ssl, second_cert)
            assert_echo(ssl)
          end
        end
      end
    end

    %w[rsa p256].each do |key_type|
      %w[legacy add_certificate].each do |registration|
        define_method("test_client_auth_#{key_type}_#{version}_#{registration}") do
          check_support(key_type, context_version)
          key, cert = credential(key_type, 20, 'clientAuth')
          configure = proc do |ctx|
            set_version(ctx, context_version)
            ctx.client_ca = [@ca_cert]
          end
          inspect_client = proc do |_ctx, ssl|
            assert_equal negotiated_version, ssl.ssl_version
            assert_peer_credential(ssl, cert)
            assert_equal [cert.to_der, @ca_cert.to_der], ssl.peer_cert_chain.map(&:to_der) if jruby?
            ssl.puts ssl.gets
          end
          verify = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
          start_server(verify, true, ctx_proc: configure, server_proc: inspect_client) do |_server, port|
            ctx = client_context(context_version)
            install_credential(ctx, registration, cert, key)
            server_connect(port, ctx) do |ssl|
              assert_equal negotiated_version, ssl.ssl_version
              assert_echo(ssl)
            end
          end
        end
      end
    end

    define_method("test_client_credential_with_nonmatching_issuer_#{version}") do
      skip 'JSSE filters client certificate issuers' unless jruby?
      check_support('rsa', context_version)
      key, cert = credential('rsa', 30, 'clientAuth')
      other_ca = issue_cert(OpenSSL::X509::Name.parse('/CN=Other CA'), @ca_key, 31,
        [['basicConstraints', 'CA:TRUE', true], ['keyUsage', 'keyCertSign', true]], nil, nil)
      configure = proc do |ctx|
        set_version(ctx, context_version)
        ctx.client_ca = [other_ca]
      end
      inspect_client = proc do |_ctx, ssl|
        assert_nil ssl.peer_cert
        ssl.puts ssl.gets
      end
      start_server(OpenSSL::SSL::VERIFY_PEER, true, ctx_proc: configure,
                   server_proc: inspect_client) do |_server, port|
        ctx = client_context(context_version)
        ctx.add_certificate(cert, key, [@ca_cert])
        server_connect(port, ctx) { |ssl| assert_echo(ssl) }
      end
    end
  end

  private

  def set_version(ctx, version)
    if !jruby? && version == 'TLSv1_3'
      ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION
    else
      ctx.ssl_version = version
    end
  end

  def check_support(key_type, version)
    sunjsse = jruby? && java.lang.System.getProperty('jruby.openssl.provider.ssl') == 'false'
    java_version = self.class.java_version.last.to_i if jruby?
    skip 'SunJSSE requires Java 11 for TLS 1.3' if sunjsse && version == 'TLSv1_3' && java_version < 11
    if key_type == 'ed25519'
      omit_on_fips
      skip 'SunJSSE requires Java 15 for Ed25519' if sunjsse && java_version < 15
    end
    if fips? && version == 'TLSv1_2' && key_type.start_with?('p')
      ctx = OpenSSL::SSL::SSLContext.new
      set_version(ctx, version)
      unless ctx.ciphers.any? { |cipher| cipher.first == 'ECDHE-ECDSA-AES128-GCM-SHA256' }
        skip 'ECDHE-ECDSA is unavailable in approved mode'
      end
    end
  end

  def credential(key_type, serial = 4, purpose = 'serverAuth')
    key = case key_type
          when 'rsa' then @svr_key
          when 'p256' then OpenSSL::PKey::EC.generate('prime256v1')
          when 'p384' then OpenSSL::PKey::EC.generate('secp384r1')
          when 'ed25519' then OpenSSL::PKey.generate_key('ED25519')
          end
    cert = issue_cert(OpenSSL::X509::Name.parse("/CN=#{key_type}-#{serial}"), key, serial,
      [['keyUsage', 'digitalSignature', true], ['extendedKeyUsage', purpose, false]], @ca_cert, @ca_key)
    [key, cert]
  end

  def install_credential(ctx, registration, cert, key)
    ctx.cert = ctx.key = ctx.extra_chain_cert = nil
    if registration == 'legacy'
      ctx.cert = cert
      ctx.key = key
      ctx.extra_chain_cert = [@ca_cert]
    else
      ctx.add_certificate(cert, key, [@ca_cert])
    end
  end

  def client_context(version)
    ctx = OpenSSL::SSL::SSLContext.new
    set_version(ctx, version)
    ctx.cert_store = OpenSSL::X509::Store.new
    ctx.cert_store.add_cert(@ca_cert)
    ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
    ctx
  end

  def assert_peer_credential(ssl, cert)
    assert_equal cert.subject.to_der, ssl.peer_cert.subject.to_der
    assert_equal cert.public_key.oid, ssl.peer_cert.public_key.oid
    assert_equal cert.public_key.public_to_der, ssl.peer_cert.public_key.public_to_der
    if cert.public_key.oid == 'ED25519'
      assert_equal cert.public_key.raw_public_key, ssl.peer_cert.public_key.raw_public_key
    end
    assert_equal cert.to_der, ssl.peer_cert.to_der
  end

  def assert_echo(ssl)
    ssl.puts 'credential echo'
    assert_equal "credential echo\n", ssl.gets
  end
end
