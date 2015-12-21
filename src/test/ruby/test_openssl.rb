require File.expand_path('test_helper', File.dirname(__FILE__))

require 'openssl'

class TestOpenSSL < TestCase

  # only test this when the gem is installed - i.e. during integration tests
  def test_gem_version
    assert_equal ENV['BC_VERSION'], Java::OrgBouncycastleJceProvider::BouncyCastleProvider.new.info.sub( /[^0-9.]*/, '' )
    # we have a jruby-openssl gem loaded
    assert Gem.loaded_specs[ 'jruby-openssl' ] != nil
    assert Gem.loaded_specs[ 'jruby-openssl' ].full_gem_path.match( /!/ ) == nil
  end if ENV['BC_VERSION']

  def test_version
    if RUBY_VERSION.index('1.8')
      assert_equal '1.0.0', OpenSSL::VERSION
    else
      assert_equal '1.1.0', OpenSSL::VERSION
    end
    assert OpenSSL::OPENSSL_VERSION.index('OpenSSL')
    if defined? JRUBY_VERSION
      assert_equal 0, OpenSSL::OPENSSL_VERSION.index('JRuby-OpenSSL ')
    end
    assert OpenSSL::OPENSSL_VERSION_NUMBER

    if RUBY_VERSION > '2.0'
      # MRI 2.3 openssl/utils.rb does this (and we shall pass) :
      assert defined?(OpenSSL::OPENSSL_LIBRARY_VERSION)
      assert /\AOpenSSL +0\./ !~ OpenSSL::OPENSSL_LIBRARY_VERSION
      #puts "OpenSSL::OPENSSL_LIBRARY_VERSION = #{OpenSSL::OPENSSL_LIBRARY_VERSION.inspect}"
    end
  end

  def test_debug
    debug = OpenSSL.debug
    assert (OpenSSL.debug == true || OpenSSL.debug == false)
    assert OpenSSL.debug= true
    assert_equal true, OpenSSL.debug
  ensure
    OpenSSL.debug = debug
  end

  def test_stubs
    OpenSSL.deprecated_warning_flag
    OpenSSL.check_func(:func, :header)
    OpenSSL.fips_mode = false
  end

  def test_Digest
    digest = OpenSSL.Digest('MD5')
    assert_equal OpenSSL::Digest::MD5, digest
  end

end # unless defined? OpenSSL::OPENSSL_DUMMY


class TestOpenSSLStub < TestCase

  def test_autoload_consts_error
    assert_raise(LoadError) { OpenSSL::ASN1 }
    assert_raise(LoadError) { OpenSSL::BN }
    assert_raise(LoadError) { OpenSSL::Cipher }
    assert_raise(LoadError) { OpenSSL::Config }
    assert_raise(LoadError) { OpenSSL::Netscape }
    assert_raise(LoadError) { OpenSSL::PKCS7 }
    assert_raise(LoadError) { OpenSSL::PKey }
    assert_raise(LoadError) { OpenSSL::Random }
    assert_raise(LoadError) { OpenSSL::SSL }
    assert_raise(LoadError) { OpenSSL::X509 }
  end

end if defined? OpenSSL::OPENSSL_DUMMY
# This test only makes sense if the gem isn't installed