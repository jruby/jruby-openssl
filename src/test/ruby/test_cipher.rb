require File.expand_path('test_helper', File.dirname(__FILE__))

class TestCipher < TestCase

  def test_cipher_new
    OpenSSL::Cipher.new 'AES-256-CBC'
    # NOTE: MRI 1.9.3 raises RuntimeError :
    # RuntimeError: unsupported cipher algorithm (AES)
    # ... hoping we do not need to align that much ?!
    assert_raise_cipher_error { OpenSSL::Cipher.new 'AES' }
    assert_raise_cipher_error { OpenSSL::Cipher.new 'SSS' }
    assert_raise(ArgumentError) { OpenSSL::Cipher.new }
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
  end

  def test_AES_classes
    OpenSSL::Cipher::AES128.new
    OpenSSL::Cipher::AES192.new 'CFB'
    OpenSSL::Cipher::AES256.new
    assert_raise_cipher_error { OpenSSL::Cipher::AES256.new 'XXX' }
  end

  def test_instantiate_supported_ciphers
    OpenSSL::Cipher.ciphers.each do |cipher_name|
      OpenSSL::Cipher.new cipher_name
    end
    # puts OpenSSL::Cipher.ciphers.size
  end

  def assert_raise_cipher_error(&block)
    assert_raise OpenSSL::Cipher::CipherError, &block
  end

end