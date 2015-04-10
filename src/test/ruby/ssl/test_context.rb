# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLContext < TestCase
  #include SSLTestHelper

  def test_methods
    methods = OpenSSL::SSL::SSLContext::METHODS
    assert methods.include?(:'SSLv3')
    assert methods.include?(:'TLSv1_1')
    assert ! methods.include?(:'TLSv1.1')
  end

  def test_context_new
    OpenSSL::SSL::SSLContext.new

    OpenSSL::SSL::SSLContext.new :SSLv3
    assert_raises ArgumentError do
      OpenSSL::SSL::SSLContext.new "TLSv42"
    end
  end

  def test_context_set_ssl_version
    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1"

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :SSLv3

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :"TLSv1_1" unless RUBY_VERSION < '2.0'
    #assert_equal :TLSv1_1, context.ssl_version

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1_1" unless RUBY_VERSION < '2.0'

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1.1" if defined? JRUBY_VERSION

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = :TLSv1_2 unless RUBY_VERSION < '2.0'

    context = OpenSSL::SSL::SSLContext.new
    context.ssl_version = "TLSv1.2" if defined? JRUBY_VERSION

    context = OpenSSL::SSL::SSLContext.new
    assert_raises ArgumentError do
      context.ssl_version = "TLSv42" # ArgumentError: unknown SSL method `TLSv42'
    end
    assert_raises(TypeError) { context.ssl_version = 12 }
  end

end