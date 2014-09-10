require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Request < TestCase

  def test_csr_request_extensions
    key = OpenSSL::PKey::RSA.new(512)
    csr = OpenSSL::X509::Request.new

    csr.version = 0
    csr.subject = OpenSSL::X509::Name.new [ ["CN", 'example.com'] ]
    csr.public_key = key.public_key

    names = OpenSSL::X509::ExtensionFactory.new.
      create_extension("subjectAltName", 'DNS:example.com', false)

    ext_req = OpenSSL::ASN1::Set [ OpenSSL::ASN1::Sequence([names]) ]
    csr.add_attribute OpenSSL::X509::Attribute.new("extReq", ext_req)

    csr.sign(key, OpenSSL::Digest::SHA256.new)

    # The combination of the extreq and the stringification / revivification
    # is what triggers the bad behaviour in the extension. (Any extended
    # request type should do, but this matches my observed problems)
    csr = OpenSSL::X509::Request.new(csr.to_s)

    assert_equal '/CN=example.com', csr.subject.to_s

    assert_equal 0, csr.version
  end

  def test_version
    csr = OpenSSL::X509::Request.new
    assert_equal 0, csr.version

    req = OpenSSL::X509::Request.new
    req.version = 1
    assert_equal 1, req.version
  end

end