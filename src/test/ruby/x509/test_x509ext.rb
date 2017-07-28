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

    puts csr.to_text if $VERBOSE

    csr = OpenSSL::X509::Request.new pem = csr.to_pem
    assert_equal 2, csr.attributes.length
    ext_set = csr.attributes.first.value ; seq = ext_set.first.value
    assert_equal 'subjectAltName', seq.first.value.first.value
    dns = seq.first.value.last.value
    assert dns =~ /test.example.com.*?test2.example.com.*?example.com.*?www.example.com/
  end

  def test_subject_alt_name_sign_to_pem_through_cert
    domain_list = 'test.example.com,test2.example.com,example.com,www.example.com'
    rsa_key = OpenSSL::PKey::RSA.new(2048)
    crt = OpenSSL::X509::Certificate.new
    crt.subject = OpenSSL::X509::Name.new [ ["C", 'AU'], ["ST", "NSW"], ["O", 'org'], ["CN", 'www.example.com'] ]
    crt.issuer = crt.subject
    crt.not_before = Time.now
    crt.not_after = Time.now + 1 * 24 * 60 * 60
    crt.serial = 0
    crt.version = 2

    crt.public_key = rsa_key.public_key

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = crt
    ef.issuer_certificate = crt
    crt.add_extension ef.create_extension("subjectAltName", domain_list.split(',').map { |d| "DNS:#{d}" }.join(', '))

    crt.sign rsa_key, OpenSSL::Digest::SHA256.new

    puts crt.to_text if $VERBOSE
    puts crt.to_pem if $VERBOSE

    assert_equal 1,crt.extensions.select{|e| e.oid == 'subjectAltName' }.count

    crt = OpenSSL::X509::Certificate.new pem = crt.to_pem
    assert_equal 1,crt.extensions.select{|e| e.oid == 'subjectAltName' }.count
    assert crt.extensions.find{|e| e.oid == 'subjectAltName' }.value =~ /test.example.com.*?test2.example.com.*?example.com.*?www.example.com/
  end

  def subject_alt_name(domains)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.create_extension("subjectAltName", domains.split(',').map { |d| "DNS:#{d}" }.join(', '))
  end
  private :subject_alt_name

end
