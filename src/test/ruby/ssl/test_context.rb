# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLContext < TestCase
  #include SSLTestHelper

  def test_methods
    methods = OpenSSL::SSL::SSLContext::METHODS
    assert methods.include?(:SSLv3)
    assert methods.include?(:'TLSv1_1')
    assert ! methods.include?(:'TLSv1.1')

    assert ! methods.include?(:SSLv2)
    assert ! methods.include?(:SSLv2_client)

    assert methods.include?(:'TLSv1_1_client')
    assert methods.include?(:'TLSv1_1_server')

    assert methods.include?(:'TLSv1_2')
    assert methods.include?(:'TLSv1_2_client')
    assert methods.include?(:'TLSv1_2_server')
  end

  def test_context_new
    OpenSSL::SSL::SSLContext.new

    OpenSSL::SSL::SSLContext.new :SSLv3
    assert_raises ArgumentError do
      OpenSSL::SSL::SSLContext.new "TLSv42"
    end
  end

  def test_setup
    ctx = OpenSSL::SSL::SSLContext.new
    assert_equal(ctx.setup, true)
    assert_equal(ctx.setup, nil)

    m = OpenSSL::SSL::SSLContext::METHODS.first

    ex = assert_raise(ArgumentError) do
      OpenSSL::SSL::SSLContext.new("#{m}\0")
    end
    # ex.message =~ /null/
    ex = assert_raise(ArgumentError) do
      OpenSSL::SSL::SSLContext.new("\u{ff33 ff33 ff2c}")
    end
    assert ex.message =~ /\u{ff33 ff33 ff2c}/
  end

  def test_verify_mode
    context = OpenSSL::SSL::SSLContext.new
    assert_nil context.verify_mode
    context = OpenSSL::SSL::SSLContext.new :SSLv3
    assert_nil context.verify_mode

    server_cert = OpenSSL::X509::Certificate.new IO.read( File.join(File.dirname(__FILE__), 'server.crt') )
    server_key = OpenSSL::PKey::RSA.new IO.read( File.join(File.dirname(__FILE__), 'server.key') )

    context = OpenSSL::SSL::SSLContext.new.tap do |context|
      context.cert = server_cert
      context.key  = server_key
    end
    assert_nil context.verify_mode

    client_cert = OpenSSL::X509::Certificate.new IO.read( File.join(File.dirname(__FILE__), 'client.crt') )
    client_key = OpenSSL::PKey::RSA.new IO.read( File.join(File.dirname(__FILE__), 'client.key') )

    context = OpenSSL::SSL::SSLContext.new.tap do |context|
      context.cert = client_cert
      context.key  = client_key
    end
    assert_nil context.verify_mode
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

  def test_context_ciphers
    context = OpenSSL::SSL::SSLContext.new
    context.ciphers = "ALL"

    all_ciphers = context.ciphers.map{|cipher_array| cipher_array[0]}

    expected_ciphers = ["ECDHE-ECDSA-AES256-SHA",
                        "ECDHE-RSA-AES256-SHA",
                        "AES256-SHA",
                        "ECDH-ECDSA-AES256-SHA",
                        "ECDH-RSA-AES256-SHA",
                        "DHE-RSA-AES256-SHA",
                        "DHE-DSS-AES256-SHA",
                        "ECDHE-ECDSA-AES128-SHA256",
                        "ECDHE-RSA-AES128-SHA256",
                        "ECDH-ECDSA-AES128-SHA256",
                        "ECDH-RSA-AES128-SHA256",
                        "ECDHE-ECDSA-AES128-SHA",
                        "ECDHE-RSA-AES128-SHA",
                        "AES128-SHA",
                        "ECDH-ECDSA-AES128-SHA",
                        "ECDH-RSA-AES128-SHA",
                        "DHE-RSA-AES128-SHA",
                        "DHE-DSS-AES128-SHA",
                        "ECDHE-ECDSA-DES-CBC3-SHA",
                        "ECDHE-RSA-DES-CBC3-SHA",
                        "DES-CBC3-SHA",
                        "ECDH-ECDSA-DES-CBC3-SHA",
                        "ECDH-RSA-DES-CBC3-SHA",
                        "EDH-RSA-DES-CBC3-SHA",
                        "EDH-DSS-DES-CBC3-SHA",
                        "AECDH-AES256-SHA",
                        "ADH-AES256-SHA",
                        "AECDH-AES128-SHA",
                        "ADH-AES128-SHA",
                        "AECDH-DES-CBC3-SHA",
                        "ADH-DES-CBC3-SHA"]

    expected_ciphers.each do |cipher|
      assert all_ciphers.include?(cipher), "#{cipher} should have been included"
    end
  end if RUBY_VERSION > '1.9'
end
