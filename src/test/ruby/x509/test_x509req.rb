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