# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Revoked < TestCase

  if defined? JRUBY_VERSION
    def setup; require 'jopenssl/load' end
  else
    def setup; require 'openssl' end
  end

  def test_new
    rev = OpenSSL::X509::Revoked.new
    assert_equal 0, rev.serial
    assert_equal nil, rev.time
    assert_equal [], rev.extensions
    if RUBY_VERSION >= '2.0.0' || defined? JRUBY_VERSION
      assert rev.inspect.index('#<OpenSSL::X509::Revoked:') == 0
    end
  end

end