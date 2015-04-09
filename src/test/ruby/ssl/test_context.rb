# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLContext < TestCase
  #include SSLTestHelper

  def test_context_set_ssl_version
    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :"TLSv1_1"
    #assert_equal :TLSv1_1, context.ssl_version

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1_1"

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1.1" if defined? JRUBY_VERSION

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :TLSv1_2

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1.2" if defined? JRUBY_VERSION
  end

end