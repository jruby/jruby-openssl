require File.expand_path('test_helper', File.dirname(__FILE__))

class TestCipher < TestCase

  def test_cipher_new
    OpenSSL::Cipher.new 'AES-256-CBC'
    # NOTE: MRI 1.9.3 raises RuntimeError :
    # RuntimeError: unsupported cipher algorithm (AES)
    # ... maybe we do not need to align that much ?!
    # NOTE: this raises in MRI :
    #assert_raise_cipher_error { OpenSSL::Cipher.new 'AES' }
    assert_raise_cipher_error { OpenSSL::Cipher.new 'AES-XXX' }
    assert_raise_cipher_error { OpenSSL::Cipher.new 'AES-128-XXX' }
    assert_raise_cipher_error { OpenSSL::Cipher.new 'SSS' }
    assert_raise(ArgumentError) { OpenSSL::Cipher.new }
  end

  def test_cipher_extended_support
    # NOTE: since 0.9.6 we allow the underlying JCE cipher algorithms
    # to work - although we won't report support for them in `ciphers`
    OpenSSL::Cipher.new 'PBEWithSHA1AndRC2_40-CBC' # Sun JCE
    #OpenSSL::Cipher.new 'RSA/ECB' # Sun JCE
    OpenSSL::Cipher.new 'RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING' # Sun JCE
    OpenSSL::Cipher.new 'DESedeWrap/CBC/NOPADDING' # Sun JCE
    OpenSSL::Cipher.new 'XTEA/CBC/PKCS7Padding' # BC
    OpenSSL::Cipher.new 'Noekeon/CBC/ZeroBytePadding' # BC
  end

  def test_named_classes
    OpenSSL::Cipher::AES.new '192-ECB'
    #assert_raise_cipher_error { OpenSSL::Cipher::AES.new '128' }
    OpenSSL::Cipher::AES.new 128, 'CBC'

    OpenSSL::Cipher::CAST5.new 'CFB'

    OpenSSL::Cipher::BF.new 'ECB'

    OpenSSL::Cipher::DES.new 'OFB'
    OpenSSL::Cipher::DES.new :EDE3, "CBC"

    assert_raise_cipher_error { OpenSSL::Cipher::DES.new '3X3' }

    OpenSSL::Cipher::RC2.new '64', 'CBC'
    OpenSSL::Cipher::RC2.new 'ECB'

    OpenSSL::Cipher::RC4.new '40'
    #OpenSSL::Cipher::RC4.new 'HMAC' if defined? JRUBY_VERSION
    #OpenSSL::Cipher::RC4.new 'HMAC-MD5'
  end

  def test_AES_classes
    OpenSSL::Cipher::AES128.new
    OpenSSL::Cipher::AES192.new 'CFB'
    OpenSSL::Cipher::AES256.new
    assert_raise_cipher_error { OpenSSL::Cipher::AES256.new 'XXX' }
  end

  def test_instantiate_supported_ciphers
    #puts OpenSSL::Cipher.ciphers.inspect
    #puts OpenSSL::Cipher.ciphers.size

    OpenSSL::Cipher.ciphers.each do |cipher_name|
      OpenSSL::Cipher.new cipher_name
    end
  end

  def assert_raise_cipher_error(&block)
    assert_raise OpenSSL::Cipher::CipherError, &block
  end

end