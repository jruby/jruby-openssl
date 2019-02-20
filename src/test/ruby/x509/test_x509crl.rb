# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))
require 'date'

class TestX509CRL < TestCase

  def test_new_crl
    crl = OpenSSL::X509::CRL.new
    assert_equal 0, crl.version
    assert_equal OpenSSL::X509::Name.new, crl.issuer
    assert_equal nil, crl.last_update
    assert_equal nil, crl.next_update
    assert_equal [], crl.revoked
    assert_equal "NULL", crl.signature_algorithm

    if RUBY_VERSION >= '2.0.0' || defined? JRUBY_VERSION
      assert crl.inspect.index('#<OpenSSL::X509::CRL:') == 0, crl.inspect
    end

    assert_raises(OpenSSL::X509::CRLError) { OpenSSL::X509::CRL.new('') }
  end

REVOKED_TEXT = <<EOF
Certificate Revocation List (CRL):
        Version 2 (0x1)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: /C=US/ST=Florida/L=Miami/O=r509-cert-validator/CN=localhost
        Last Update: Jul  7 17:31:35 2014 GMT
        Next Update: Jul  4 18:31:35 2024 GMT
        CRL extensions:
            X509v3 CRL Number:\s
                6
            X509v3 Authority Key Identifier:\s
                keyid:98:36:77:24:CA:8D:A9:FF:AC:FA:D2:D9:D5:5D:D5:50:E6:F7:6A:51

Revoked Certificates:
    Serial Number: 063E173908A9E6233D8EC8CD6A13FE967D9B36
        Revocation Date: Feb 11 15:42:32 2014 GMT
    Serial Number: 063E17DF5DAEEA9E388EB0A1BE4F9F4C5E8202
        Revocation Date: Feb 11 16:19:23 2014 GMT
    Serial Number: 063E1BF8990DA60E62A40D914856CF65434106
        Revocation Date: Feb 11 20:11:49 2014 GMT
    Serial Number: 063E1BFB150099810987B174124ED88C597386
        Revocation Date: Feb 11 20:12:22 2014 GMT
    Serial Number: 063E1BFE77785B99585E8F9D78633C8242F20E
        Revocation Date: Feb 11 20:13:07 2014 GMT
    Serial Number: 064C953E1553EEE1A1005D19C10658A7FFB446
        Revocation Date: Jul  7 18:31:35 2014 GMT
    Signature Algorithm: sha1WithRSAEncryption
         4a:2d:72:0a:c3:f9:66:98:4c:23:b5:ec:4c:4e:b9:5f:00:7d:
         00:13:5c:3f:7e:94:1e:d7:55:9b:d8:b3:fd:94:29:49:e1:68:
         4e:5a:24:27:2c:ba:73:8f:9f:55:52:22:0c:35:1b:38:e0:1d:
         37:44:56:9a:01:2a:92:12:c2:60
EOF

  def test_revoked_to_text
    crl_data = File.read(File.expand_path('../revoked.crl', __FILE__))
    crl = OpenSSL::X509::CRL.new crl_data

    puts "CRL (revoked) text = \n#{crl.to_text}" if $VERBOSE

    expected_text = REVOKED_TEXT.split("\n")[0, 12]

    expected_text.each_with_index do |line, i|
      actual = crl.to_text.split("\n")[i]
      assert_equal line, actual
    end

    expected_text = REVOKED_TEXT.split("\n")[12..-1]

    expected_text.each_with_index do |line, i|
      actual = crl.to_text.split("\n")[12 + i]
      assert_equal line, actual
    end
  end

  def test_revoked_crl_loading
    crl_data = File.read(File.expand_path('../revoked.crl', __FILE__))
    crl = OpenSSL::X509::CRL.new crl_data

    issuer = [["C", "US", 19], ["ST", "Florida", 12], ["L", "Miami", 12], ["O", "r509-cert-validator", 12], ["CN", "localhost", 12]]
    assert_equal issuer, crl.issuer.to_a
    assert_equal 'sha1WithRSAEncryption', crl.signature_algorithm

    assert_equal 2, crl.extensions.size

    assert_equal 'crlNumber = 6', crl.extensions[0].to_s
    assert_equal "keyid:98:36:77:24:CA:8D:A9:FF:AC:FA:D2:D9:D5:5D:D5:50:E6:F7:6A:51\n", crl.extensions[1].value

    assert ! crl.revoked.empty?, "Expected CRL revoked list to not be empty."
    assert_equal 6, crl.revoked.size

    first_serial = '063E173908A9E6233D8EC8CD6A13FE967D9B36'
    revoked = crl.revoked.first
    assert_equal first_serial.to_i(16).to_s, revoked.serial.to_s
    assert_equal [], revoked.extensions

    last_serial = '064C953E1553EEE1A1005D19C10658A7FFB446'
    revoked = crl.revoked.last
    assert_equal last_serial.to_i(16).to_s, revoked.serial.to_s

    assert_equal Date.new(2014, 07, 07), Date.parse(revoked.time.strftime('%Y/%m/%d'))
  end

  # NOTE: same as OpenSSL's test_extension but without extension order requirement ...
  def test_extension
    _rsa2048 = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    _ca = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")

    cert_exts = [
      ["basicConstraints", "CA:TRUE", true],
      ["subjectKeyIdentifier", "hash", false],
      ["authorityKeyIdentifier", "keyid:always", false],
      ["subjectAltName", "email:xyzzy@ruby-lang.org", false],
      ["keyUsage", "cRLSign, keyCertSign", true],
    ]
    crl_exts = [
      ["authorityKeyIdentifier", "keyid:always", false],
      ["issuerAltName", "issuer:copy", false],
    ]

    now = Time.now
    cert = issue_cert(_ca, _rsa2048, 1, now, now + 3600, cert_exts, nil, nil, OpenSSL::Digest::SHA1.new)
    crl = issue_crl([], 1, now, now+1600, crl_exts, cert, _rsa2048, OpenSSL::Digest::SHA1.new)

    exts = crl.extensions
    assert_equal(3, exts.size)
    assert_equal("1", exts[0].value)
    assert_equal("crlNumber", exts[0].oid)
    assert_equal(false, exts[0].critical?)

    assert_equal("authorityKeyIdentifier", exts[1].oid)
    keyid = get_subject_key_id(cert)
    assert_match(/^keyid:#{keyid}/, exts[1].value)
    assert_equal(false, exts[1].critical?)

    assert_equal("issuerAltName", exts[2].oid)
    assert_equal("email:xyzzy@ruby-lang.org", exts[2].value)
    assert_equal(false, exts[2].critical?)

    crl = OpenSSL::X509::CRL.new(crl.to_der)
    exts = crl.extensions

    # MRI expects to retain extension order : crlNumber, authorityKeyIdentifier, issuerAltName
    exts = exts.dup
    ext1 = exts.find { |ext| ext.oid == 'authorityKeyIdentifier' }
    exts.delete(ext1); exts.unshift(ext1)
    ext0 = exts.find { |ext| ext.oid == 'crlNumber' }
    exts.delete(ext0); exts.unshift(ext0)
    # MRI

    assert_equal(3, exts.size)
    assert_equal("1", exts[0].value)
    assert_equal("crlNumber", exts[0].oid)
    assert_equal(false, exts[0].critical?)

    assert_equal("authorityKeyIdentifier", exts[1].oid)
    keyid = get_subject_key_id(cert)
    assert_match(/^keyid:#{keyid}/, exts[1].value)
    assert_equal(false, exts[1].critical?)

    assert_equal("issuerAltName", exts[2].oid)
    assert_equal("email:xyzzy@ruby-lang.org", exts[2].value)
    assert_equal(false, exts[2].critical?)
  end

  private

  def get_subject_key_id(cert)
    asn1_cert = OpenSSL::ASN1.decode(cert)
    tbscert   = asn1_cert.value[0]
    pkinfo    = tbscert.value[6]
    publickey = pkinfo.value[1]
    pkvalue   = publickey.value
    OpenSSL::Digest::SHA1.hexdigest(pkvalue).scan(/../).join(":").upcase
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