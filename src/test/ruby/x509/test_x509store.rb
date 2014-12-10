# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Store < TestCase

  if defined? JRUBY_VERSION
    def setup; require 'jopenssl/load' end
  else
    def setup; require 'openssl' end
  end

  def test_add_cert_concurrently
    pem = File.expand_path('../EntrustnetSecureServerCertificationAuthority.pem', __FILE__)
    store = OpenSSL::X509::Store.new
    t = []
    (0..25).each do |i|

      t << Thread.new do
        (0..2).each do
          store.add_file pem
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
