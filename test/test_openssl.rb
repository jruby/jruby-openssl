require File.expand_path( '../setup.rb', __FILE__ )
require 'rubygems'
require 'test/unit'
require 'openssl'

class TestOpenssl < Test::Unit::TestCase

  if ENV['BC_VERSION']
    # only test this when the gem is installed - i.e. during integration tests
    def test_versions
      assert_equal ENV['BC_VERSION'], Java::OrgBouncycastleJceProvider::BouncyCastleProvider.new.info.sub( /[^0-9.]*/, '' )
      # we have a jruby-openssl gem loaded
      assert Gem.loaded_specs[ 'jruby-openssl' ] != nil
      assert Gem.loaded_specs[ 'jruby-openssl' ].full_gem_path.match( /!/ ) == nil
    end
  end

  def test_csr_request_extensions
    key = OpenSSL::PKey::RSA.new(512)
    csr = OpenSSL::X509::Request.new

    csr.version = 0
    csr.subject = OpenSSL::X509::Name.new([["CN", 'example.com']])
    csr.public_key = key.public_key

    names = OpenSSL::X509::ExtensionFactory.new.
      create_extension("subjectAltName", 'DNS:example.com', false)

    extReq = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([names])])
    csr.add_attribute(OpenSSL::X509::Attribute.new("extReq", extReq))

    csr.sign(key, OpenSSL::Digest::SHA256.new)

    # The combination of the extreq and the stringification / revivification
    # is what triggers the bad behaviour in the extension. (Any extended
    # request type should do, but this matches my observed problems)
    csr = OpenSSL::X509::Request.new(csr.to_s)

    assert_equal '/CN=example.com', csr.subject.to_s
  end
end
