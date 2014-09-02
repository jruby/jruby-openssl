# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Context < TestCase

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
  end

end