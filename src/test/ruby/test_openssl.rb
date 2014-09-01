require File.expand_path('test_helper', File.dirname(__FILE__))

require 'openssl'

class TestOpenSSL < Test::Unit::TestCase

  # only test this when the gem is installed - i.e. during integration tests
  def test_versions
    assert_equal ENV['BC_VERSION'], Java::OrgBouncycastleJceProvider::BouncyCastleProvider.new.info.sub( /[^0-9.]*/, '' )
    # we have a jruby-openssl gem loaded
    assert Gem.loaded_specs[ 'jruby-openssl' ] != nil
    assert Gem.loaded_specs[ 'jruby-openssl' ].full_gem_path.match( /!/ ) == nil
  end if ENV['BC_VERSION']

  def test_csr_request_extensions
    key = OpenSSL::PKey::RSA.new(512)
    csr = OpenSSL::X509::Request.new

    csr.version = 0
    csr.subject = OpenSSL::X509::Name.new([["CN", 'example.com']])
    csr.public_key = key.public_key

    names = OpenSSL::X509::ExtensionFactory.new.
      create_extension("subjectAltName", 'DNS:example.com', false)

    ext_req = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([names])])
    csr.add_attribute(OpenSSL::X509::Attribute.new("extReq", ext_req))

    csr.sign(key, OpenSSL::Digest::SHA256.new)

    # The combination of the extreq and the stringification / revivification
    # is what triggers the bad behaviour in the extension. (Any extended
    # request type should do, but this matches my observed problems)
    csr = OpenSSL::X509::Request.new(csr.to_s)

    assert_equal '/CN=example.com', csr.subject.to_s
  end

end unless defined? OpenSSL::OPENSSL_DUMMY


class TestOpenSSLStub < Test::Unit::TestCase

  def test_autoload_consts_error
    assert_raise(LoadError) { OpenSSL::ASN1 }
    assert_raise(LoadError) { OpenSSL::BN }
    assert_raise(LoadError) { OpenSSL::Cipher }
    assert_raise(LoadError) { OpenSSL::Config }
    assert_raise(LoadError) { OpenSSL::Netscape }
    assert_raise(LoadError) { OpenSSL::PKCS7 }
    assert_raise(LoadError) { OpenSSL::PKey }
    assert_raise(LoadError) { OpenSSL::Random }
    assert_raise(LoadError) { OpenSSL::SSL }
    assert_raise(LoadError) { OpenSSL::X509 }
  end

end if defined? OpenSSL::OPENSSL_DUMMY
# This test only makes sense if the gem isn't installed