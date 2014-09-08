# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Revoked < TestCase

  def setup; require 'openssl' end

  def test_new
    rev = OpenSSL::X509::Revoked.new
    assert_equal 0, rev.serial
    assert_equal nil, rev.time
    assert_equal [], rev.extensions
    if RUBY_VERSION >= '2.0.0' || defined? JRUBY_VERSION
      assert rev.inspect.index('#<OpenSSL::X509::Revoked:') == 0
    end
  end

  def test_serial=
    rev = OpenSSL::X509::Revoked.new
    rev.serial = OpenSSL::BN.new '1234567890'
    assert_equal '1234567890', rev.serial.to_s
    rev.serial = 4242
    assert_equal '4242', rev.serial.to_s
  end

end