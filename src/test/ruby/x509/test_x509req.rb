require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Request < TestCase

  def setup!
    @rsa1024 = Fixtures.pkey("rsa1024")
    @rsa2048 = Fixtures.pkey("rsa2048")
    @dsa256  = Fixtures.pkey("dsa256")
    @dsa512  = Fixtures.pkey("dsa512")
    @dn = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=GOTOU Yuuzou")
  end
  private :setup!

  def test_public_key; setup!
    req = issue_csr(0, @dn, @rsa1024, OpenSSL::Digest.new('SHA256'))
    assert_equal(@rsa1024.public_key.to_der, req.public_key.to_der)
    req = OpenSSL::X509::Request.new(req.to_der)
    assert_equal(@rsa1024.public_key.to_der, req.public_key.to_der)

    req = issue_csr(0, @dn, @dsa512, OpenSSL::Digest.new('SHA256'))
    assert_equal(@dsa512.public_key.to_der, req.public_key.to_der)
    req = OpenSSL::X509::Request.new(req.to_der)
    assert_equal(@dsa512.public_key.to_der, req.public_key.to_der)
  end

  def test_sign_and_verify_rsa_sha1; setup!
    req = issue_csr(0, @dn, @rsa1024, OpenSSL::Digest.new('SHA1'))
    assert_equal(true,  req.verify(@rsa1024))
    assert_equal(false, req.verify(@rsa2048))
    assert_equal(false, request_error_returns_false { req.verify(@dsa256) })
    assert_equal(false, request_error_returns_false { req.verify(@dsa512) })
    # req.version = 1
    # assert_equal(false, req.verify(@rsa1024))
  #rescue OpenSSL::X509::RequestError # RHEL 9 disables SHA1
  end

  def test_sign_and_verify_rsa_md5; setup!
    req = issue_csr(0, @dn, @rsa2048, OpenSSL::Digest.new('MD5'))
    assert_equal(false, req.verify(@rsa1024))
    assert_equal(true,  req.verify(@rsa2048))
    assert_equal(false, request_error_returns_false { req.verify(@dsa256) })
    assert_equal(false, request_error_returns_false { req.verify(@dsa512) })
    req.subject = OpenSSL::X509::Name.parse("/C=JP/CN=FooBar")
    assert_equal(false, req.verify(@rsa2048))
  #rescue OpenSSL::X509::RequestError # RHEL7 disables MD5
  end

  def test_sign_and_verify_dsa; setup!
    req = issue_csr(0, @dn, @dsa512, OpenSSL::Digest.new('SHA256'))
    assert_equal(false, request_error_returns_false { req.verify(@rsa1024) })
    assert_equal(false, request_error_returns_false { req.verify(@rsa2048) })
    assert_equal(false, req.verify(@dsa256))
    assert_equal(true,  req.verify(@dsa512))
    req.public_key = @rsa1024.public_key
    assert_equal(false, req.verify(@dsa512))
  end

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

    assert_equal 'sha256WithRSAEncryption', csr.signature_algorithm

    # The combination of the extreq and the stringification / revivification
    # is what triggers the bad behaviour in the extension. (Any extended
    # request type should do, but this matches my observed problems)
    csr = OpenSSL::X509::Request.new(csr.to_s)

    assert_equal '/CN=example.com', csr.subject.to_s

    assert_equal 0, csr.version
  end

  def test_csr_request_ec_key
    key = OpenSSL::PKey::EC.generate('secp384r1')

    csr = OpenSSL::X509::Request.new
    csr.public_key = key
    csr.subject = OpenSSL::X509::Name.new([['CN', 'foo.bar.cat', OpenSSL::ASN1::UTF8STRING]])
    csr.version = 2

    assert_equal 'NULL', csr.signature_algorithm

    csr.sign key, OpenSSL::Digest::SHA256.new # does not raise

    assert_equal 'ecdsa-with-SHA256', csr.signature_algorithm

    assert_true csr.verify(key)
  end

  def test_version
    csr = OpenSSL::X509::Request.new
    assert_equal -1, csr.version

    req = OpenSSL::X509::Request.new
    req.version = 1
    assert_equal 1, req.version
  end

  # from GH-150
  def test_to_der_new_from_der; require 'base64'
    # Build the CSR
    key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1024
    request = OpenSSL::X509::Request.new
    request.subject = OpenSSL::X509::Name.new([['CN', "common_name",  OpenSSL::ASN1::UTF8STRING]])
    request.public_key = key.public_key
    request.sign(key, OpenSSL::Digest::SHA1.new)
    # One request is decoded from a `encode64` the other one is from `strict_encode64`
    decoded = Base64.decode64(Base64.encode64(request.to_der))
    strictly_decoded = Base64.decode64(Base64.strict_encode64(request.to_der))

    # # Both strings are decoded identically
    # decoded == strictly_decoded #=> true
    # # .. even on byte level
    # decoded.split(//) == strictly_decoded.split(//) #= true

    OpenSSL::X509::Request.new(strictly_decoded) #=> #<OpenSSL::X509::Request:0x4f290f46>
    OpenSSL::X509::Request.new(decoded) #=> OpenSSL::X509::RequestError: invalid certificate request data
  end

  private

  def issue_csr(ver, dn, key, digest)
    req = OpenSSL::X509::Request.new
    req.version = ver
    req.subject = dn
    req.public_key = key.public_key
    req.sign(key, digest)
    req
  end

  def request_error_returns_false
    yield
  rescue OpenSSL::X509::RequestError
    false
  end

  TEST_KEY_RSA1024 = <<-_end_of_pem_
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDLwsSw1ECnPtT+PkOgHhcGA71nwC2/nL85VBGnRqDxOqjVh7Cx
aKPERYHsk4BPCkE3brtThPWc9kjHEQQ7uf9Y1rbCz0layNqHyywQEVLFmp1cpIt/
Q3geLv8ZD9pihowKJDyMDiN6ArYUmZczvW4976MU3+l54E6lF/JfFEU5hwIDAQAB
AoGBAKSl/MQarye1yOysqX6P8fDFQt68VvtXkNmlSiKOGuzyho0M+UVSFcs6k1L0
maDE25AMZUiGzuWHyaU55d7RXDgeskDMakD1v6ZejYtxJkSXbETOTLDwUWTn618T
gnb17tU1jktUtU67xK/08i/XodlgnQhs6VoHTuCh3Hu77O6RAkEA7+gxqBuZR572
74/akiW/SuXm0SXPEviyO1MuSRwtI87B02D0qgV8D1UHRm4AhMnJ8MCs1809kMQE
JiQUCrp9mQJBANlt2ngBO14us6NnhuAseFDTBzCHXwUUu1YKHpMMmxpnGqaldGgX
sOZB3lgJsT9VlGf3YGYdkLTNVbogQKlKpB8CQQDiSwkb4vyQfDe8/NpU5Not0fII
8jsDUCb+opWUTMmfbxWRR3FBNu8wnym/m19N4fFj8LqYzHX4KY0oVPu6qvJxAkEA
wa5snNekFcqONLIE4G5cosrIrb74sqL8GbGb+KuTAprzj5z1K8Bm0UW9lTjVDjDi
qRYgZfZSL+x1P/54+xTFSwJAY1FxA/N3QPCXCjPh5YqFxAMQs2VVYTfg+t0MEcJD
dPMQD5JX6g5HKnHFg2mZtoXQrWmJSn7p8GJK8yNTopEErA==
-----END RSA PRIVATE KEY-----
  _end_of_pem_

end