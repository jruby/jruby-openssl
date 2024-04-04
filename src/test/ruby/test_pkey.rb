# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestPKey < TestCase

  KEY = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArTlm5TxJp3WHMNmWIfo/\nWvkyhJCXc1S78Y9B8lSXxXnkRqX8Twxu5EkdUP0TwgD5gp0TGy7UPm/SgWlQOcqX\nqtdOWq/Hk29Ve9z6k6wTmst7NTefmm/7OqkeYmBhfhoECLCKBADM8ctjoqD63R0e\n3bUW2knq6vCS5YMmD76/5UoU647BzB9CjgDzjuTKEbXL5AvcO5wWDgHSp7CA+2t4\nIFQvQMrPso5mvm2hNvD19vI0VjiY21rKgkJQAXSrLgkJg/fTL2wQiz10d2GnYsmx\nDeJCiBMwC+cmRW2eWePqaCPaWJwr92KsIiry+LgyGb3y01SUVV8kQgQXazutHqfu\ncQIDAQAB\n-----END PUBLIC KEY-----\n"

  def test_pkey_read
    pkey = OpenSSL::PKey.read(KEY)
    assert_same OpenSSL::PKey::RSA, pkey.class
    assert_true pkey.public?
    assert_false pkey.private?
    assert_equal OpenSSL::PKey::RSA.new(KEY).n, pkey.n
    assert_equal OpenSSL::PKey::RSA.new(KEY).e, pkey.e
  end

  def test_pkey_read_pkcs8_and_check_with_cert
    pkey = File.expand_path('pkey-pkcs8.pem', File.dirname(__FILE__))
    pkey = OpenSSL::PKey.read(File.read(pkey), nil)

    assert_true pkey.private?
    assert_true pkey.public?
    assert pkey.public_key.to_s

    cert = File.expand_path('pkey-cert.pem', File.dirname(__FILE__))
    cert = OpenSSL::X509::Certificate.new(File.read(cert))

    assert_true cert.check_private_key(pkey)
  end

  def test_to_java
    pkey = OpenSSL::PKey.read(KEY)
    assert_kind_of java.security.PublicKey, pkey.to_java
    assert_kind_of java.security.PublicKey, pkey.to_java(java.security.PublicKey)
    assert_kind_of java.security.PublicKey, pkey.to_java(java.security.interfaces.RSAPublicKey)
    assert_kind_of java.security.PublicKey, pkey.to_java(java.security.Key)
    pub_key = pkey.to_java(java.security.PublicKey)
    if pub_key.is_a? org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
      assert_kind_of java.security.PublicKey, pkey.to_java(org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey)
    end
    assert_raise_kind_of(TypeError) { pkey.to_java(java.security.interfaces.ECPublicKey) }
    # NOTE: won't fail as it's a marker that is neither a PublicKey or PrivateKey (also does not sub-class Key)
    #assert_raise_kind_of(TypeError) { pkey.to_java(java.security.interfaces.ECKey) }
  end if defined?(JRUBY_VERSION)

end
