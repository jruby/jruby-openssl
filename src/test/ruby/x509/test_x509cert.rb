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