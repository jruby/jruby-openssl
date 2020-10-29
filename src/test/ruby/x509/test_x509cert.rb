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
    assert_nil cert.not_before
    assert_nil cert.not_after
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

  def test_aki_extension_to_text
    cert = create_self_signed_cert [ %w[CN localhost] ], __method__.to_s
    keyid = "97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB"

    assert cert.extensions.size > 0
    value = cert.extensions.last.value
    assert_equal "keyid:#{keyid}\nDirName:/CN=localhost\nserial:01\n", value
  end

  def create_self_signed_cert(cn, comment) # cert generation ripped from WEBrick
    key = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    name = (cn.kind_of? String) ? OpenSSL::X509::Name.parse(cn) : OpenSSL::X509::Name.new(cn)
    cert.subject = name
    cert.issuer = name
    cert.not_before = Time.now
    cert.not_after = Time.now + (365*24*60*60)
    cert.public_key = key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
    ef.issuer_certificate = cert
    cert.extensions = [
        ef.create_extension("basicConstraints","CA:FALSE"),
        ef.create_extension("keyUsage", "keyEncipherment"),
        ef.create_extension("subjectKeyIdentifier", "hash"),
        ef.create_extension("extendedKeyUsage", "serverAuth"),
        # ef.create_extension("nsComment", comment),
    ]
    aki = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
    cert.add_extension(aki)
    cert.sign(key, OpenSSL::Digest::SHA1.new)

    cert
  end

  def test_resolve_extensions
    rsa2048 = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    ca = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")

    ca_exts = [
      [ "basicConstraints", "CA:TRUE", true ],
      [ "keyUsage", "keyCertSign, cRLSign", true ],
      [ "subjectKeyIdentifier", "hash", false ],
      [ "authorityKeyIdentifier", "keyid:always", false ],
      [ "subjectAltName", "email:self@jruby.org, DNS:jruby.org", false ],
    ]

    now = Time.now
    ca_cert = issue_cert(ca, rsa2048, 1, now, now + 3600, ca_exts,
                         nil, nil, OpenSSL::Digest::SHA1.new)

    assert_equal 5, ca_cert.extensions.size

    cert = OpenSSL::X509::Certificate.new ca_cert.to_der
    assert_equal 5, cert.extensions.size

    # Java 6/7 seems to maintain same order but Java 8 does definitely not :
    # TODO there must be something going on under - maybe not BC parsing ?!?
    if self.class.java7?
      assert_equal '97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB', cert.extensions[2].value
      assert_equal 'email:self@jruby.org, DNS:jruby.org', cert.extensions[4].value
    end

    exts = cert.extensions.dup

    assert ext = exts.find { |e| e.oid == 'basicConstraints' }, "missing 'basicConstraints' among: #{exts.join(', ')}"
    assert_equal 'CA:TRUE', ext.value
    assert ext.critical?

    assert ext = exts.find { |e| e.oid == 'authorityKeyIdentifier' }, "missing 'authorityKeyIdentifier' among: #{exts.join(', ')}"
    assert_equal "keyid:97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB\n", ext.value
    assert ! ext.critical?

    assert ext = exts.find { |e| e.oid == 'subjectKeyIdentifier' }, "missing 'subjectKeyIdentifier' among: #{exts.join(', ')}"
    assert_equal "97:39:9D:C3:FB:CD:BA:8F:54:0C:90:7B:46:3F:EA:D6:43:75:B1:CB", ext.value
    assert ! ext.critical?

    assert ext = exts.find { |e| e.oid == 'subjectAltName' }, "missing 'subjectAltName' among: #{exts.join(', ')}"
    assert_equal 'email:self@jruby.org, DNS:jruby.org', ext.value
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
        assert_match( /IP.*?:174.129.31.214/, ext.value )
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
    if defined? JRUBY_VERSION
      assert cert.inspect.index('subject=/DC=org/DC=ruby-lang/CN=TestCA, issuer=/DC=org/DC=ruby-lang/CN=TestCA')
      assert cert.inspect.index('serial=295990750012446699619010157040970350255')
      # TODO this isn't MRI compatible, which gives :
      # #<OpenSSL::X509::Certificate:
      #   subject=#<OpenSSL::X509::Name CN=TestCA,DC=ruby-lang,DC=org>,
      #   issuer=#<OpenSSL::X509::Name CN=TestCA,DC=ruby-lang,DC=org>,
      #   serial=#<OpenSSL::BN:0x00005627d4602938>,
      #   not_before=2014-10-09 07:34:20 UTC,
      #   not_after=2014-10-09 08:34:20 UTC>
    end
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
    assert_equal 2, cert.version
    assert_equal 'sha1WithRSAEncryption', cert.signature_algorithm

    unless defined? JRUBY_VERSION # TODO "/DC=org,/DC=ruby-lang,/CN=TestCA"
      assert_equal text_without_signature, cert.to_text[0, text_without_signature.size]
    end
  end

  def test_to_text_regression
    cert = OpenSSL::X509::Certificate.new <<-EOF
-----BEGIN CERTIFICATE-----
MIIFcjCCA1oCCQCa3TLZ9FJORzANBgkqhkiG9w0BAQsFADB6MQswCQYDVQQGEwJV
UzEVMBMGA1UECAwMVGhlIEludGVybmV0MRUwEwYDVQQHDAxUaGUgSW50ZXJuZXQx
FTATBgNVBAoMDE1hbnRpY29yZSBDQTESMBAGA1UECwwJTWFudGljb3JlMRIwEAYD
VQQDDAlsb2NhbGhvc3QwHhcNMTUwNDA2MDc1OTQ2WhcNMTUwNDA3MDc1OTQ2WjB8
MQswCQYDVQQGEwJVUzEVMBMGA1UECAwMVGhlIEludGVybmV0MRUwEwYDVQQHDAxU
aGUgSW50ZXJuZXQxFzAVBgNVBAoMDk1hbnRpY29yZSBIb3N0MRIwEAYDVQQLDAlN
YW50aWNvcmUxEjAQBgNVBAMMCWxvY2FsaG9zdDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBANi9QKfRpmRXkfpcrLaI14gIT6VmDvrphQLhx8+JrEJihKv4
kXR061UFV2K52bfumoD+/vdj9DzQIAKMUXUn+Z8BfAsJR6wgocCE/I0a0NOurzMe
FTgdL6oo8pnxQ5lv7wxhUNMwXJcfcefIqBO91lKwajL9MAiOoHcfK5KNKHyowjqR
+KMUUhps4x0llkqcKZlFnhMuy2bhJDID/6xT07C6fzGH7e0ty+EWVKz7zG0mT4ek
ygZhusSkYOAp7q0FSPdR1KwB/Z5XlUjmrfvsfmSZ1kXWivJchv7cxKwu0c9fRGP5
HHSKmJn8yl5GhFt+RwTlC1O652sJylSyemh46UgNeKn9biBmKO3mgtLdnAT1tY/Z
KGByqRRmzsXcLQCP5HdKAwzjP/Lvf0k4RybmYkY14S9xnDrOojkN8yg9mZ3dzuvZ
ZRxv6EMU/Te86H9FcyBiX7IFR5sXpMTit0T6XOXmhULA9zKlHlEZ13CASjC1nMc1
rWeB6HKFJBS/Ag02it5onbqvkIsbbQqZyTwVT0yH/CYZO1YlNIvDyvmYSNm0avgZ
5pCzdBc3WlX+osVGuWMdilR93kNBI/MQRr+XDnDCXeAb3c43uBaYveYpakUDxJQB
QDSvTmAIFf8GpfyQFgLOO20CZ95LWgr/4PH2C9BPh6hciEbZgomxmuYy3PZ7AgMB
AAEwDQYJKoZIhvcNAQELBQADggIBAErx32pC6o94xIqazKDAJFnevoQjupjaW7Wc
d+QcBD/sZ5Zlfmv/MPeDaO4oGsKHHPecUojwzYg3H+BNLnjg9m7IWwqdaxuVLdt+
5sC3KFHlMtcw42Ux6XfKGecDHisJdEkoP/pPcwcfL7teZbt3dwtUh9h1dOcNFfsl
qMN7mRmDTWZIozncQCmAU6TKreZpGqeN8sTIyjvKXyXFjMhPeP0TOFfIKaUCHbyi
Ze/bREEp67G2XNxdJMAlY407RcQyoAGnbFIf/WBCiR8Y+/pnjc5n1Wc8UXXW6EVm
ObfdNkY/F4w5SPRSthn62msj7yaiAiZQ21Uwl0zb+Axvz2SS6f6NPDEinvyWIAo4
PX0p3ujl5OrYdNCe6/2cft5L73X1mAsBAtkmMXnVACm6cIPv4S3jYUXvpnfOYFCm
r91Lpir5muDzXjtXvXUUCp0Hp7ONr+Y3BI5C+Z+yiq9XHy56jv/az/h/8soEB+g5
7UrdKeDWrSUbOm85VLymiadggX+ZgxxDqCXEUPBFqgLwPe5FMLa07lUSnn2F0sK9
YVdE5HiXeoj+WE+WmRlEM3ZWujqDh8AJgaDip5hltCxWXTEBSLV4gHBKcphBbkf6
XBzK5QOuZdfCC6WJHA2Mesi3yZBbbO5Tw7vPCPdQ97pj0J3Tw1YVRPHMeJKJyF98
7/EXBJpK
-----END CERTIFICATE-----
EOF
    assert_equal 0, cert.version
    assert_equal 'sha256WithRSAEncryption', cert.signature_algorithm
    assert cert.to_text.index('Version: 1 (0x0)')
    assert cert.to_text.index('Signature Algorithm: sha256WithRSAEncryption')
  end

  def test_to_text_read_back
    crt = File.expand_path('ca.crt', File.dirname(__FILE__))
    cert = OpenSSL::X509::Certificate.new File.read(crt)

    p cert if $VERBOSE

    assert cert.to_text.index('X509v3 Authority Key Identifier:')
    assert cert.to_text.match /X509v3 Authority Key Identifier:\s*keyid:B6:24:8F:53:D1:24:66:F2:1D:EA:4F:37:2B:F0:3A:3A:78:BA:5D:45/m
    assert cert.to_text.index('X509v3 Subject Key Identifier:')
    assert cert.to_text.match /X509v3 Subject Key Identifier:\s*B6:24:8F:53:D1:24:66:F2:1D:EA:4F:37:2B:F0:3A:3A:78:BA:5D:45/m
  end

  def test_to_text_npe_regression
    # https://github.com/jruby/jruby-openssl/issues/78
    key = OpenSSL::PKey::RSA.generate(2048)

    issuer = subject = OpenSSL::X509::Name.new
    subject.add_entry('C', 'JP')
    subject.add_entry('ST', 'Tokyo')
    subject.add_entry('L', 'Chiyoda')
    subject.add_entry('CN', 'demo.example.com')

    digest = OpenSSL::Digest::SHA1.new

    cert = OpenSSL::X509::Certificate.new
    cert.not_before = Time.at(0)
    cert.not_after = Time.now + 5 * 365 * 86400 # 5 years after
    cert.public_key = key
    cert.serial = 1
    cert.issuer = issuer
    cert.subject = subject
    cert.add_extension OpenSSL::X509::Extension.new('basicConstraints', OpenSSL::ASN1.Sequence([OpenSSL::ASN1::Boolean(true)]))
    cert.sign(key, digest)

    assert cert.to_text.index('Version: 1 (0x0)')
    assert cert.to_text.index('Serial Number: 1 (0x1)')
    # TODO
    #assert cert.to_text.index('Issuer: C=JP, ST=Tokyo, L=Chiyoda, CN=demo.example.com')

    assert_equal 0, cert.version
    assert_equal OpenSSL::BN.new(1), cert.serial
  end

  def test_sign_invalid_arg
    issuer = subject = OpenSSL::X509::Name.new
    subject.add_entry('C', 'JP')
    subject.add_entry('ST', 'Tokyo')
    subject.add_entry('L', 'Chiyoda')
    subject.add_entry('CN', 'demo.example.com')

    cert = OpenSSL::X509::Certificate.new
    cert.not_before = Time.at(0)
    cert.not_after = Time.now + 1 * 365 * 86400
    cert.public_key = pkey = OpenSSL::PKey::RSA.generate(1024)
    cert.serial = 1
    cert.issuer = issuer
    cert.subject = subject
    cert.add_extension OpenSSL::X509::Extension.new('basicConstraints', OpenSSL::ASN1.Sequence([OpenSSL::ASN1::Boolean(true)]))

    digest = OpenSSL::Digest::SHA1.new
    begin
      cert.sign(nil, digest)
      fail 'expected sign to fail (on pkey)'
    rescue StandardError # expected
      assert :ok
    end

    begin
      cert.sign(pkey, nil)
      fail 'expected sign to fail (on digest)'
    rescue TypeError # expected
      assert :ok
    end
  end

  def test_sign_cert_default_serial # jruby/jruby#1691
    context = OpenSSL::SSL::SSLContext.new
    context.verify_mode = OpenSSL::SSL::VERIFY_NONE

    context.key             = OpenSSL::PKey::RSA.new(1024)
    context.cert            = OpenSSL::X509::Certificate.new
    context.cert.subject    = OpenSSL::X509::Name.new( [['CN', 'localhost']] )
    context.cert.issuer     = context.cert.subject
    context.cert.public_key = context.key
    context.cert.not_before = Time.now
    context.cert.not_after  = Time.now + 60 * 60 * 24

    if defined? JRUBY_VERSION
      begin
        res = context.cert.sign(context.key, OpenSSL::Digest::SHA1.new)
      rescue OpenSSL::X509::CertificateError
        return
      end
    else
      res = context.cert.sign(context.key, OpenSSL::Digest::SHA1.new)
    end
    # MRI allows (invalid) serial == 0 :
    assert res.is_a?(OpenSSL::X509::Certificate)
    assert_equal 0, res.serial
  end

  def test_cert_loading_regression
    cert_text = "0\x82\x01\xAD0\x82\x01\xA1\xA0\x03\x02\x01\x02\x02\x01\x010\x03\x06\x01\x000g1\v0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\b\f\nCalifornia1\x150\x13\x06\x03U\x04\a\f\fSanta Monica1\x110\x0F\x06\x03U\x04\n\f\bOneLogin1\x190\x17\x06\x03U\x04\x03\f\x10app.onelogin.com0\x1E\x17\r100309095845Z\x17\r150309095845Z0g1\v0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\b\f\nCalifornia1\x150\x13\x06\x03U\x04\a\f\fSanta Monica1\x110\x0F\x06\x03U\x04\n\f\bOneLogin1\x190\x17\x06\x03U\x04\x03\f\x10app.onelogin.com0\x81\x9F0\r\x06\t*\x86H\x86\xF7\r\x01\x01\x01\x05\x00\x03\x81\x8D\x000\x81\x89\x02\x81\x81\x00\xE8\xD2\xBBW\xE3?/\x1D\xE7\x0E\x10\xC8\xBD~\xCD\xDE!#\rL\x92G\xDF\xE1f?L\xB1\xBC9\x99\x14\xE5\x84\xD2Zi\x87<>d\xBD\x81\xF9\xBA\x85\xD2\xFF\xAA\x90\xF3Z\x97\xA5\x1D\xB0W\xC0\x93\xA3\x06IP\xB84\xF5\xD7Qu\x19\xFCB\xCA\xA3\xD4\\\x8E\v\x9B%\x13|\xB6m\x9D\xA8\x16\xE6\xBB\xDA\x87\xFF\xE3\xD7\xE9\xBA9\xC5O\xA2\xA7C\xADB\x04\xCA\xA5\x0E\x84\xD0\xA8\xE4\xFA\xDA\xF1\x89\xF2s\xFA1\x95\xAF\x03\xAB1\xAA\xE7y\x02\x03\x01\x00\x010\x03\x06\x01\x00\x03\x01\x00"
    assert cert = OpenSSL::X509::Certificate.new(cert_text)
    debug cert.to_text
    assert cert.to_text.index('Signature Algorithm: 0.0')
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

  def test_cert_subject_hash
    cert = OpenSSL::X509::Certificate.new <<-EOF
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
EOF
    assert_equal '5ad8a5d6', cert.subject.hash.to_s(16)
  end
end
