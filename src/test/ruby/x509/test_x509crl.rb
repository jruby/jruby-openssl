# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))
require 'date'

class TestX509CRL < TestCase

  if defined? JRUBY_VERSION
    def setup; require 'jopenssl/load' end
  else
    def setup; require 'openssl' end
  end

  def test_new_crl
    crl = OpenSSL::X509::CRL.new
    assert_equal 0, crl.version
    assert_equal OpenSSL::X509::Name.new, crl.issuer
    assert_equal nil, crl.last_update
    assert_equal nil, crl.next_update
    assert_equal [], crl.revoked
    assert_equal "itu-t", crl.signature_algorithm

    if RUBY_VERSION >= '2.0.0' || defined? JRUBY_VERSION
      assert crl.inspect.index('#<OpenSSL::X509::CRL:') == 0, crl.inspect
    end
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

    #puts "CRL (revoked) text = \n#{crl.to_text}"

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

end