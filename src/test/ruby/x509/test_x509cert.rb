# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Certificate < TestCase

  def test_new
    cert = OpenSSL::X509::Certificate.new
    empty_name = OpenSSL::X509::Name.new
    assert_equal empty_name, cert.issuer
    assert_equal empty_name, cert.subject
    bn = OpenSSL::BN.new('0') unless defined? JRUBY_VERSION
    assert_equal bn || OpenSSL::BN.new(0), cert.serial
    assert_equal nil, cert.not_before
    assert_equal nil, cert.not_after
    assert_raise(OpenSSL::X509::CertificateError) { cert.public_key }
  end

  def test_alt_name_extension
    cert = OpenSSL::X509::Certificate.new
    cert.add_extension OpenSSL::X509::Extension.new('subjectAltName', 'email:self@jruby.org, IP:127.0.0.1', false)
    assert_equal 'email:self@jruby.org, IP:127.0.0.1', cert.extensions[0].value
  end

  def test_cert_extensions # JRUBY-3468
    pem_cert = <<END
-----BEGIN CERTIFICATE-----
MIIC/jCCAmegAwIBAgIBATANBgkqhkiG9w0BAQUFADBNMQswCQYDVQQGEwJKUDER
MA8GA1UECgwIY3Rvci5vcmcxFDASBgNVBAsMC0RldmVsb3BtZW50MRUwEwYDVQQD
DAxodHRwLWFjY2VzczIwHhcNMDcwOTExMTM1ODMxWhcNMDkwOTEwMTM1ODMxWjBN
MQswCQYDVQQGEwJKUDERMA8GA1UECgwIY3Rvci5vcmcxFDASBgNVBAsMC0RldmVs
b3BtZW50MRUwEwYDVQQDDAxodHRwLWFjY2VzczIwgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBALi66ujWtUCQm5HpMSyr/AAIFYVXC/dmn7C8TR/HMiUuW3waY4uX
LFqCDAGOX4gf177pX+b99t3mpaiAjJuqc858D9xEECzhDWgXdLbhRqWhUOble4RY
c1yWYC990IgXJDMKx7VAuZ3cBhdBxtlE9sb1ZCzmHQsvTy/OoRzcJCrTAgMBAAGj
ge0wgeowDwYDVR0TAQH/BAUwAwEB/zAxBglghkgBhvhCAQ0EJBYiUnVieS9PcGVu
U1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUJNE0GGaRKmN2qhnO
FyBWVl4Qj6owDgYDVR0PAQH/BAQDAgEGMHUGA1UdIwRuMGyAFCTRNBhmkSpjdqoZ
zhcgVlZeEI+qoVGkTzBNMQswCQYDVQQGEwJKUDERMA8GA1UECgwIY3Rvci5vcmcx
FDASBgNVBAsMC0RldmVsb3BtZW50MRUwEwYDVQQDDAxodHRwLWFjY2VzczKCAQEw
DQYJKoZIhvcNAQEFBQADgYEAH11tstSUuqFpMqoh/vM5l3Nqb8ygblbqEYQs/iG/
UeQkOZk/P1TxB6Ozn2htJ1srqDpUsncFVZ/ecP19GkeOZ6BmIhppcHhE5WyLBcPX
It5q1BW0PiAzT9LlEGoaiW0nw39so0Pr1whJDfc1t4fjdk+kSiMIzRHbTDvHWfpV
nTA=
-----END CERTIFICATE-----
END

    cert   = OpenSSL::X509::Certificate.new(pem_cert)
    keyid = '24:D1:34:18:66:91:2A:63:76:AA:19:CE:17:20:56:56:5E:10:8F:AA'
    cert.extensions.each do |ext|
      value = ext.value
      crit = ext.critical?
      case ext.oid
      when "keyUsage"
        assert_equal true, crit
        assert_equal "Certificate Sign, CRL Sign", value
      when "basicConstraints"
        assert_equal true, crit
        assert_equal "CA:TRUE", value
      when "authorityKeyIdentifier"
        assert_equal false, crit
        expected = "keyid:#{keyid}\n"
        # NOTE: this behavior is matched against MRI 1.8.7/1.9.3/2.1.2 :
        expected << "DirName:/C=JP/O=ctor.org/OU=Development/CN=http-access2\n"
        expected << "serial:01\n"
        assert_equal expected, value
      when "subjectKeyIdentifier"
        assert_equal false, crit
        assert_equal keyid, value
      when "nsComment"
        assert_equal false, crit
        assert_equal "Ruby/OpenSSL Generated Certificate", value
      end
    end
  end

  def test_resolve_extensions
    rsa2048 = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    ca = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")

    ca_exts = [
      [ "basicConstraints", "CA:TRUE", true ],
      [ "keyUsage", "keyCertSign, cRLSign", true ],
      [ "subjectKeyIdentifier", "hash", false ],
      [ "authorityKeyIdentifier", "keyid:always", false ],
      [ "subjectAltName", "email:self@jruby.org", false ],
      [ "subjectAltName", "DNS:jruby.org", false ],
    ]

    now = Time.now
    ca_cert = issue_cert(ca, rsa2048, 1, now, now + 3600, ca_exts,
                         nil, nil, OpenSSL::Digest::SHA1.new)

    assert_equal 6, ca_cert.extensions.size

    cert = OpenSSL::X509::Certificate.new ca_cert.to_der
    assert_equal 6, cert.extensions.size

    # Java 6/7 seems to maintain same order but Java 8 does definitely not :
    # TODO there must be something going on under - maybe not BC parsing ?!?
    if self.class.java6? || self.class.java7?
      assert_equal '97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB', cert.extensions[2].value
      assert_equal 'email:self@jruby.org', cert.extensions[4].value
      assert_equal 'DNS:jruby.org', cert.extensions[5].value
    end

    exts = cert.extensions.dup

    assert ext = exts.find { |ext| ext.oid == 'basicConstraints' }, "missing 'basicConstraints' among: #{exts.join(', ')}"
    assert_equal 'CA:TRUE', ext.value
    assert ext.critical?

    assert ext = exts.find { |ext| ext.oid == 'authorityKeyIdentifier' }, "missing 'authorityKeyIdentifier' among: #{exts.join(', ')}"
    assert_equal "keyid:97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB\n", ext.value
    assert ! ext.critical?

    assert ext = exts.find { |ext| ext.oid == 'subjectKeyIdentifier' }, "missing 'subjectKeyIdentifier' among: #{exts.join(', ')}"
    assert_equal "97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB", ext.value
    assert ! ext.critical?

    assert ext = exts.find { |ext| ext.oid == 'subjectAltName' }, "missing 'subjectAltName' among: #{exts.join(', ')}"
    assert_equal 'email:self@jruby.org', ext.value
    exts.delete(ext)
    assert ext = exts.find { |ext| ext.oid == 'subjectAltName' }, "missing 'subjectAltName' among: #{exts.join(', ')}"
    assert_equal 'DNS:jruby.org', ext.value
  end

  def test_extensions
    rsa2048 = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    ca = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")

    ca_exts = [
      [ "basicConstraints", "CA:TRUE", true ],
      [ "keyUsage", "keyCertSign, cRLSign", true ],
      [ "subjectKeyIdentifier", "hash", false ],
      [ "authorityKeyIdentifier", "keyid:always", false ],
      [ "extendedKeyUsage", "clientAuth, emailProtection, codeSigning", false ],
      [ "subjectAltName", "email:self@jruby.org", false ],
      [ "subjectAltName", "IP:174.129.31.214", false ],
      [ "subjectAltName", "DNS:jruby.org", false ],
    ]

    now = Time.now
    ca_cert = issue_cert(ca, rsa2048, 1, now, now + 3600, ca_exts,
                         nil, nil, OpenSSL::Digest::SHA1.new)

    assert_equal 8, ca_cert.extensions.size
    ca_cert.extensions.each_with_index do |ext, i|

      assert_equal ca_exts[i][0], ext.oid
      assert_equal ca_exts[i][2], ext.critical?

      case ca_exts[i][1]
      when 'keyCertSign, cRLSign'
        assert_equal 'Certificate Sign, CRL Sign', ext.value
      when 'hash'
        #assert_equal '97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB', ext.value
      when 'keyid:always'
        assert_equal "keyid:97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB\n", ext.value
      when 'clientAuth, emailProtection, codeSigning'
        assert_equal 'TLS Web Client Authentication, E-mail Protection, Code Signing', ext.value
      when /IP\:/
        # NOTE: probably fine as "IP:174.129.31.214" on JRuby while on MRI :
        # assert_equal 'IP Address:174.129.31.214', ext.value
        assert_match /IP.*?:174.129.31.214/, ext.value
      else
        assert_equal ca_exts[i][1], ext.value
      end

    end
  end

  def test_inspect_to_text
    subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA")
    key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1024
    now = Time.at 1412840060 # Time.now.to_i suppress usec
    s = 0xdeadbeafdeadbeafdeadbeafdeadbeaf
    exts = [
      [ "basicConstraints", "CA:TRUE,pathlen:1", true ],
      [ "keyUsage", "keyCertSign, cRLSign", true ],
      [ "subjectKeyIdentifier", "hash", false ],
    ]

    dgst = OpenSSL::Digest::SHA1.new # NOTE: does it match MRI ?!

    cert = issue_cert(subj, key, s, now, now + 3600, exts, nil, nil, dgst)

    assert cert.inspect.start_with?('#<OpenSSL::X509::Certificate:')
    assert cert.inspect.index('subject=/DC=org/DC=ruby-lang/CN=TestCA, issuer=/DC=org/DC=ruby-lang/CN=TestCA')
    assert cert.inspect.index('serial=295990750012446699619010157040970350255')
    #assert cert.inspect.index('not_before=2014-10-09 07:34:20 UTC, not_after=2014-10-09 08:34:20 UTC')

    text_without_signature = <<-TEXT
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            de:ad:be:af:de:ad:be:af:de:ad:be:af:de:ad:be:af
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: DC=org, DC=ruby-lang, CN=TestCA
        Validity
            Not Before: Oct  9 07:34:20 2014 GMT
            Not After : Oct  9 08:34:20 2014 GMT
        Subject: DC=org, DC=ruby-lang, CN=TestCA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:cb:c2:c4:b0:d4:40:a7:3e:d4:fe:3e:43:a0:1e:
                    17:06:03:bd:67:c0:2d:bf:9c:bf:39:54:11:a7:46:
                    a0:f1:3a:a8:d5:87:b0:b1:68:a3:c4:45:81:ec:93:
                    80:4f:0a:41:37:6e:bb:53:84:f5:9c:f6:48:c7:11:
                    04:3b:b9:ff:58:d6:b6:c2:cf:49:5a:c8:da:87:cb:
                    2c:10:11:52:c5:9a:9d:5c:a4:8b:7f:43:78:1e:2e:
                    ff:19:0f:da:62:86:8c:0a:24:3c:8c:0e:23:7a:02:
                    b6:14:99:97:33:bd:6e:3d:ef:a3:14:df:e9:79:e0:
                    4e:a5:17:f2:5f:14:45:39:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:\s
                D1:FE:F9:FB:F8:AE:1B:C1:60:CB:FA:03:E2:59:6D:D8:73:08:92:13
    Signature Algorithm: sha1WithRSAEncryption
TEXT

    cert.to_text

    unless defined? JRUBY_VERSION # TODO "/DC=org,/DC=ruby-lang,/CN=TestCA"
      assert_equal text_without_signature, cert.to_text[0, text_without_signature.size]
    end
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

  TEST_KEY_RSA2048 = <<-_end_of_pem_
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuV9ht9J7k4NBs38jOXvvTKY9gW8nLICSno5EETR1cuF7i4pN
s9I1QJGAFAX0BEO4KbzXmuOvfCpD3CU+Slp1enenfzq/t/e/1IRW0wkJUJUFQign
4CtrkJL+P07yx18UjyPlBXb81ApEmAB5mrJVSrWmqbjs07JbuS4QQGGXLc+Su96D
kYKmSNVjBiLxVVSpyZfAY3hD37d60uG+X8xdW5v68JkRFIhdGlb6JL8fllf/A/bl
NwdJOhVr9mESHhwGjwfSeTDPfd8ZLE027E5lyAVX9KZYcU00mOX+fdxOSnGqS/8J
DRh0EPHDL15RcJjV2J6vZjPb0rOYGDoMcH+94wIDAQABAoIBAAzsamqfYQAqwXTb
I0CJtGg6msUgU7HVkOM+9d3hM2L791oGHV6xBAdpXW2H8LgvZHJ8eOeSghR8+dgq
PIqAffo4x1Oma+FOg3A0fb0evyiACyrOk+EcBdbBeLo/LcvahBtqnDfiUMQTpy6V
seSoFCwuN91TSCeGIsDpRjbG1vxZgtx+uI+oH5+ytqJOmfCksRDCkMglGkzyfcl0
Xc5CUhIJ0my53xijEUQl19rtWdMnNnnkdbG8PT3LZlOta5Do86BElzUYka0C6dUc
VsBDQ0Nup0P6rEQgy7tephHoRlUGTYamsajGJaAo1F3IQVIrRSuagi7+YpSpCqsW
wORqorkCgYEA7RdX6MDVrbw7LePnhyuaqTiMK+055/R1TqhB1JvvxJ1CXk2rDL6G
0TLHQ7oGofd5LYiemg4ZVtWdJe43BPZlVgT6lvL/iGo8JnrncB9Da6L7nrq/+Rvj
XGjf1qODCK+LmreZWEsaLPURIoR/Ewwxb9J2zd0CaMjeTwafJo1CZvcCgYEAyCgb
aqoWvUecX8VvARfuA593Lsi50t4MEArnOXXcd1RnXoZWhbx5rgO8/ATKfXr0BK/n
h2GF9PfKzHFm/4V6e82OL7gu/kLy2u9bXN74vOvWFL5NOrOKPM7Kg+9I131kNYOw
Ivnr/VtHE5s0dY7JChYWE1F3vArrOw3T00a4CXUCgYEA0SqY+dS2LvIzW4cHCe9k
IQqsT0yYm5TFsUEr4sA3xcPfe4cV8sZb9k/QEGYb1+SWWZ+AHPV3UW5fl8kTbSNb
v4ng8i8rVVQ0ANbJO9e5CUrepein2MPL0AkOATR8M7t7dGGpvYV0cFk8ZrFx0oId
U0PgYDotF/iueBWlbsOM430CgYEAqYI95dFyPI5/AiSkY5queeb8+mQH62sdcCCr
vd/w/CZA/K5sbAo4SoTj8dLk4evU6HtIa0DOP63y071eaxvRpTNqLUOgmLh+D6gS
Cc7TfLuFrD+WDBatBd5jZ+SoHccVrLR/4L8jeodo5FPW05A+9gnKXEXsTxY4LOUC
9bS4e1kCgYAqVXZh63JsMwoaxCYmQ66eJojKa47VNrOeIZDZvd2BPVf30glBOT41
gBoDG3WMPZoQj9pb7uMcrnvs4APj2FIhMU8U15LcPAj59cD6S6rWnAxO8NFK7HQG
4Jxg3JNNf8ErQoCHb1B3oVdXJkmbJkARoDpBKmTCgKtP8ADYLmVPQw==
-----END RSA PRIVATE KEY-----
  _end_of_pem_

end