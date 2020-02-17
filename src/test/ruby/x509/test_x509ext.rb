# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Extension < TestCase

  if defined? JRUBY_VERSION
    def setup; require 'jopenssl/load' end
  else
    def setup; require 'openssl' end
  end

  def test_new
    assert_raise(ArgumentError) { OpenSSL::X509::Extension.new }
    # OpenSSL::X509::ExtensionError: nested asn1 error
    assert_raise(OpenSSL::X509::ExtensionError) { OpenSSL::X509::Extension.new '1' }
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')
    if RUBY_VERSION >= '2.0.0' || defined? JRUBY_VERSION
      assert ext.inspect.index('#<OpenSSL::X509::Extension:') == 0, ext.inspect
    end
    assert_equal '1.1.1.1.1.1 = foo', ext.to_s

    ext.critical = true
    assert_equal '1.1.1.1.1.1 = critical, foo', ext.to_s
  end

  def test_attrs
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')
    assert_equal false, ext.critical?

    ext.critical = nil
    assert_equal false, ext.critical?

    ext.critical = true
    assert_equal true, ext.critical?

    assert_equal 'foo', ext.value

    ext.value = 'bar'
    assert_equal 'bar', ext.value

    assert_equal '1.1.1.1.1.1', ext.oid

    ext.oid = '1.2'
    assert_equal 'member-body', ext.oid
  end

  def test_sym_name
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')
    ext.oid = '1.2'
    assert_equal 'member-body', ext.oid
  end

  def test_set_value
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')
    assert_equal 'foo', ext.value
    ext.oid = '1.2'
    assert_equal 'foo', ext.value

    ext = OpenSSL::X509::Extension.new('keyUsage', 'XXXXXXXXXX')
    assert_equal 'XXXXXXXXXX', ext.value
  end

  def test_subject_alt_name
    ext = OpenSSL::X509::Extension.new('subjectAltName', 'IP:127.0.0.1')
    assert_equal 'subjectAltName', ext.oid
    assert_equal 'IP:127.0.0.1', ext.value

    ext = OpenSSL::X509::Extension.new('2.5.29.17', 'IP Address:127.0.0.1')
    assert_equal 'subjectAltName', ext.oid
    assert_equal 'IP Address:127.0.0.1', ext.value

    ext = OpenSSL::X509::Extension.new('2.5.29.17', 'IP:127.0.0.1,email:some@example.com')
    assert_equal 'subjectAltName', ext.oid
    assert_equal 'IP:127.0.0.1,email:some@example.com', ext.value
  end

  def test_to_a
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')
    assert_equal [ '1.1.1.1.1.1', 'foo', false ], ext.to_a
  end

  def test_to_h
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo', true)
    hash = { 'oid' => '1.1.1.1.1.1', 'value' => 'foo', 'critical' => true }
    assert_equal hash, ext.to_h
  end

  def test_to_der # reproducing #389
    ext = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')

    mri_to_der = "0\f\x06\x05)\x01\x01\x01\x01\x04\x03foo"
    assert_equal mri_to_der, ext.to_der
    # MRI 1.8  "0\f\006\005)\001\001\001\001\004\003foo"
    # MRI 2.x  "0\f\x06\x05)\x01\x01\x01\x01\x04\x03foo"

    dec = OpenSSL::ASN1.decode(ext.to_der)

    assert_instance_of OpenSSL::ASN1::Sequence, dec
    assert_equal 2, ( value = dec.value ).size

    assert_instance_of OpenSSL::ASN1::ObjectId, value[0]
    # assert_equal 4, value[0].tag
    assert_equal '1.1.1.1.1.1', value[0].value

    assert_instance_of OpenSSL::ASN1::OctetString, value[1]
    # assert_equal 6, value[1].tag
    assert_equal 'foo', value[1].value
  end

  def test_to_der_is_the_same_for_non_critical
    ext1 = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo')
    ext2 = OpenSSL::X509::Extension.new('1.1.1.1.1.1', 'foo', false)

    assert_equal ext1.to_der, ext2.to_der

    ext1.critical = nil

    assert_equal ext1.to_der, ext2.to_der

    ext1.critical = false

    assert_equal ext1.to_der, ext2.to_der

    ext1.critical = true

    assert ext1.to_der != ext2.to_der
  end

  def test_subject_key_identifier_hash
    #key = Fixtures.pkey("rsa1024")
    key = OpenSSL::PKey::RSA.new(1024)
    subject = "/C=FR/ST=IDF/L=PARIS/O=Company/CN=myhost.example"
    cert = OpenSSL::X509::Certificate.new
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(subject)

    cert.not_before = now = Time.new(2020)
    cert.not_after = now + 5 * 365 * 24 * 60 * 60
    cert.public_key = key.public_key
    cert.serial = 0x0
    cert.version = 2

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = ef.issuer_certificate = cert

    cert.add_extension ef.create_extension('basicConstraints', 'CA:FALSE', true)
    cert.add_extension ef.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')

    sequence = rsa_key_seq(cert.public_key)
    pp sequence if $DEBUG

    cert.add_extension ef.create_extension('subjectKeyIdentifier', 'hash')
    cert.add_extension ef.create_extension('authorityKeyIdentifier', 'keyid:always,issuer:always')

    cert.sign key, OpenSSL::Digest::SHA256.new

    assert_equal 4, cert.extensions.size
    assert_equal 'subjectKeyIdentifier', cert.extensions[2].oid

    assert_equal rsa_key_id(cert.public_key), cert.extensions[2].value
    #assert_equal "D1:FE:F9:FB:F8:AE:1B:C1:60:CB:FA:03:E2:59:6D:D8:73:08:92:13", rsa_key_id(cert.public_key)
    #assert_equal "D1:FE:F9:FB:F8:AE:1B:C1:60:CB:FA:03:E2:59:6D:D8:73:08:92:13", cert.extensions[2].value

    # keyid:...\nDirName:/C=FR/ST=IDF/L=PARIS/O=Company/CN=myhost.example\nserial:00\n
    auth_key_id_value = cert.extensions[3].value
    key_id, dir_name, serial = auth_key_id_value.split("\n")
    # assert_equal 'keyid:' + rsa_key_id(key), key_id
    # assert_equal "DirName:#{subject}", dir_name
    # assert_equal 'serial:00', serial
  end

  def rsa_key_seq(public_key)
    OpenSSL::ASN1::Sequence [ OpenSSL::ASN1::Integer.new(public_key.n), OpenSSL::ASN1::Integer.new(public_key.e) ]
  end

  def rsa_key_id(public_key)
    key_id = OpenSSL::Digest::SHA1.hexdigest(rsa_key_seq(public_key).to_der)
    key_id.scan(/../).join(':').upcase
  end

  def test_subject_alt_name_sign_to_pem
    domain_list = 'test.example.com,test2.example.com,example.com,www.example.com'

    rsa_key = OpenSSL::PKey::RSA.new(2048)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.new [ ["C", 'AU'], ["ST", "NSW"], ["O", 'org'], ["CN", 'www.example.com'] ]
    csr.public_key = rsa_key.public_key

    extensions = OpenSSL::ASN1::Set [ OpenSSL::ASN1::Sequence([ subject_alt_name(domain_list) ]) ]
    csr.add_attribute(OpenSSL::X509::Attribute.new('extReq', extensions))
    csr.add_attribute(OpenSSL::X509::Attribute.new('msExtReq', extensions))

    csr.sign rsa_key, OpenSSL::Digest::SHA256.new

    puts csr.to_text if $DEBUG

    csr = OpenSSL::X509::Request.new pem = csr.to_pem
    assert_equal 2, csr.attributes.length
    ext_set = csr.attributes.first.value ; seq = ext_set.first.value
    assert_equal 'subjectAltName', seq.first.value.first.value
    dns = seq.first.value.last.value
    assert dns =~ /test.example.com.*?test2.example.com.*?example.com.*?www.example.com/
  end

  def test_subject_alt_name_sequence
    tests = [
        {
            :input => "email:foo@bar.com,DNS:a.b.com,email:baz@bar.com",
            :output => "email:foo@bar.com, DNS:a.b.com, email:baz@bar.com",
            :der => "0,\x06\x03U\x1D\x11\x04%0#\x81\vfoo@bar.com\x82\aa.b.com\x81\vbaz@bar.com",
        },
        {
            :input => "DNS:a.b.com, email:foo@bar.com",
            :der => "0\x1f\x06\x03U\x1d\x11\x04\x180\x16\x82\x07a.b.com\x81\x0bfoo@bar.com",
        },
        {
            :input => "URI:https://a.b.com/, DNS:a.b.com",
            :der => "0$\x06\x03U\x1d\x11\x04\x1d0\x1b\x86\x10https://a.b.com/\x82\x07a.b.com",
        },
        {
            :input => "IP:1.2.3.4,IP: fe80::12:345:5678, email:foo@bar.com, dirName: CN=John Doe+CN=Doe\\\\\\, John\\,O=Acme",
            :output => "IP:1.2.3.4, IP:fe80:0:0:0:0:12:345:5678, email:foo@bar.com, DirName:CN=John Doe+CN=Doe\\, John,O=Acme",
            :der => "0f\x06\x03U\x1d\x11\x04_0]\x87\x04\x01\x02\x03\x04\x87\x10\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x03EVx\x81\x0bfoo@bar.com\xa46041#0\x0f\x06\x03U\x04\x03\x0c\x08John Doe0\x10\x06\x03U\x04\x03\x0c\x09Doe, John1\x0d0\x0b\x06\x03U\x04\x0a\x0c\x04Acme"
        },
        {
            :input => "RID:1.3.6.1.3.100.200",
            :der => "0\x12\x06\x03U\x1d\x11\x04\x0b0\x09\x88\x07+\x06\x01\x03d\x81H",
        },
    ]

    extensions = OpenSSL::X509::ExtensionFactory.new
    tests.each { |test|
        ext = extensions.create_extension("subjectAltName", test[:input])
        assert_equal 'subjectAltName', ext.oid
        assert_equal (test[:output] || test[:input]), ext.value
        assert_equal test[:der], ext.to_der
    }
  end

  def test_authority_key_identifier
    cn = [ %w[CN localhost] ]
    # key = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    key = Fixtures.pkey("dsa512") # DSA
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    name = OpenSSL::X509::Name.new(cn)
    cert.subject = name
    cert.issuer = name # self-signed
    cert.not_before = Time.now
    cert.not_after = Time.now + (365*24*60*60)
    cert.public_key = key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new(nil, cert)
    ef.issuer_certificate = cert
    cert.extensions = [
        ef.create_extension("basicConstraints","CA:FALSE"),
        ef.create_extension("subjectKeyIdentifier", "hash"),
        #ef.create_extension("extendedKeyUsage", "serverAuth"),
        ef.create_extension("nsComment", __method__.to_s),
    ]

    ext = ef.create_extension("authorityKeyIdentifier", "keyid")
    cert.add_extension(ext)

    assert_equal 4, cert.extensions.size

    ext = cert.extensions.last
    assert_equal keyid = "keyid:91:0D:0C:A9:43:73:DF:8C:A9:E3:C2:0A:05:E3:CF:BE:A7:38:8D:DD\n", ext.value
    assert !ext.critical?
    assert_equal [ "authorityKeyIdentifier", keyid, false ], ext.to_a

    issuer = "DirName:/CN=localhost\n" + "serial:01\n"
    ext = ef.create_extension("authorityKeyIdentifier", "keyid,issuer")
    assert_equal keyid, ext.value
    assert_equal [ "authorityKeyIdentifier", keyid, false ], ext.to_a

    ext = ef.create_extension("authorityKeyIdentifier", "issuer")
    assert_equal [ "authorityKeyIdentifier", issuer, false ], ext.to_a

    ext = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
    assert_equal keyid + issuer, ext.value
    assert_equal [ "authorityKeyIdentifier", keyid + issuer, false ], ext.to_a

    ext = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer")
    assert_equal keyid, ext.value
    assert_equal [ "authorityKeyIdentifier", keyid, false ], ext.to_a

    # cert.sign(key, OpenSSL::Digest::SHA1.new)
  end

  def subject_alt_name(domains)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.create_extension("subjectAltName", domains.split(',').map { |d| "DNS: #{d}" }.join(','))
  end
  private :subject_alt_name

end
