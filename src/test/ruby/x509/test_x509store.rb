# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Store < TestCase

  def setup
    require 'openssl'
    @cert = OpenSSL::X509::Certificate.new(File.read(File.expand_path('../server.crt', __FILE__)))
    @ca_cert = File.expand_path('../ca.crt', __FILE__)
    @javastore = File.expand_path('../store', __FILE__)
    @pem = File.expand_path('../EntrustnetSecureServerCertificationAuthority.pem', __FILE__)
  end

  def test_store_location_with_pem
    ENV['SSL_CERT_FILE'] = nil
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert !store.verify(@cert)
    
    ENV['SSL_CERT_FILE'] = @ca_cert
    store = OpenSSL::X509::Store.new
    assert !store.verify(@cert)
    store.set_default_paths
    assert store.verify(@cert)
  end

  def test_store_location_with_java_truststore
    ENV['SSL_CERT_FILE'] = @javastore
    store = OpenSSL::X509::Store.new
    assert !store.verify(@cert)
    store.set_default_paths
    assert store.verify(@cert)
  end

  def test_use_gibberish_cert_file
    ENV['SSL_CERT_FILE'] = File.expand_path('../gibberish.pem', __FILE__)
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert !store.verify(@cert)
  end

  def test_use_default_cert_file_as_custom_file
    ENV['SSL_CERT_FILE'] = OpenSSL::X509::DEFAULT_CERT_FILE
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    cert = OpenSSL::X509::Certificate.new(File.read(File.expand_path('../digicert.pem', __FILE__)))
    assert store.verify(cert)
  end

  def test_add_file_to_store_with_custom_cert_file
    ENV['SSL_CERT_FILE'] = @ca_cert
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    store.add_file @pem
    assert store.verify( OpenSSL::X509::Certificate.new(File.read(@pem)))
  end

  def test_verfy_with_wrong_argument
    store = OpenSSL::X509::Store.new
    assert_raise(TypeError) { store.verify( 'not an cert object' ) }
  end

  def test_add_cert_concurrently
    store = OpenSSL::X509::Store.new
    t = []
    (0..25).each do |i|

      t << Thread.new do
        (0..2).each do
          store.add_file @pem
        end
      end
    end

    t.each do |t|
      t.join
    end
    # just ensure there is no concurreny error
    assert true
  end

  define_method 'test_add_same_cert_twice jruby/jruby-openssl/issues/3' do
    root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
    root_ca = OpenSSL::X509::Certificate.new
    root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
    root_ca.serial = 1
    root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
    root_ca.issuer = root_ca.subject # root CA's are "self-signed"
    root_ca.public_key = root_key.public_key
    root_ca.not_before = Time.now
    root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = root_ca
    ef.issuer_certificate = root_ca
    root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
    root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

    cert_store = OpenSSL::X509::Store.new
    assert cert_store.add_cert(root_ca) == cert_store
    begin
      cert_store.add_cert(root_ca)
      fail 'added same cert twice'
    rescue OpenSSL::X509::StoreError => e
      assert_equal 'cert already in hash table', e.message
    end
  end

end
