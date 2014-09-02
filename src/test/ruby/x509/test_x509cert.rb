# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Certificate < TestCase

  if defined? JRUBY_VERSION
    def setup; require 'jopenssl/load' end
  else
    def setup; require 'openssl' end
  end

  def test_new_crl
    cert = OpenSSL::X509::Certificate.new
    empty_name = OpenSSL::X509::Name.new
    assert_equal empty_name, cert.issuer
    assert_equal empty_name, cert.subject
    assert_equal OpenSSL::BN.new(0), cert.serial
    assert_equal nil, cert.not_before
    assert_equal nil, cert.not_after
  end

end