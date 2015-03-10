# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestCipher < TestCase

  def setup
    super
    self.class.disable_security_restrictions!
  end

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
  end if defined? JRUBY_VERSION

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

  def test_aes_classes
    # NOTE: ArgumentError: wrong number of arguments (0 for 1) on MRI
    OpenSSL::Cipher::AES128.new if defined? JRUBY_VERSION
    OpenSSL::Cipher::AES192.new 'CFB'
    OpenSSL::Cipher::AES256.new 'ECB'
    assert_raise_cipher_error { OpenSSL::Cipher::AES256.new 'XXX' }
  end

  def test_instantiate_supported_ciphers
    #puts OpenSSL::Cipher.ciphers.inspect
    #puts OpenSSL::Cipher.ciphers.size

    OpenSSL::Cipher.ciphers.each do |cipher_name|
      OpenSSL::Cipher.new cipher_name
    end
  end

  def test_random
    cipher = OpenSSL::Cipher.new 'AES-128-OFB'

    org.jruby.ext.openssl.Cipher.class_eval do
      field_reader :key, :realIV
    end

    assert_equal nil, cipher.to_java.key
    assert_equal nil, cipher.to_java.realIV

    assert_equal 16, cipher.random_key.size
    assert_equal 16, cipher.to_java.key.length
    assert_equal 16, cipher.random_iv.size
    assert_equal 16, cipher.to_java.realIV.length
  end if defined? JRUBY_VERSION

  def test_cipher_init_default_key
    return skip('OpenSSL::Cipher key default not implemented') if defined? JRUBY_VERSION

    out = OpenSSL::Cipher::AES256.new("CBC").update "\1\2\3\4\5\6\7\8"
    assert_equal '', out

    # NOTE on MRI < 1.9.3 : [BUG] Segmentation fault
    return if RUBY_VERSION.index('1.8') == 0 && ! defined? JRUBY_VERSION

    #out = OpenSSL::Cipher::AES128.new("CFB").update "\0\0\0\0\0\0\0\0"
    #assert_equal "f\xE9K\xD4\xEF\x8A,;", out

    # NOTE: quite "crappy" MRI (ECB) behavior :
    out = OpenSSL::Cipher::AES192.new("ECB").update "1234567890"
    assert_equal '', out
    c = OpenSSL::Cipher.new("AES-128-ECB")
    c.encrypt
    assert_equal '', c.update('0')
    assert_equal "B\xF1c\xE2:\xE3\x84fd\xC1s\xDB\x889\x84\x8A", c.update('0' * 15)
    out = c.update '0'
    assert_equal "", out
    c.update('0' * 15)
    assert_equal "G\xDD\x11?\x9D\x99\xAD\xB0\x9F\xB2j\x01L\xD7\xA8\xBD", c.final

    c = OpenSSL::Cipher::AES128.new("ECB")
    assert_equal '', c.update('0')
    assert_equal '', c.update('0' * 15)
    out = c.update '0'
    assert_equal "\x9F\fr\xDB%9\xEC\x11\xF6\xBFt\x9F0\xF0\x8C\x0E", out
  end

  def assert_raise_cipher_error(&block)
    if defined? JRUBY_VERSION # TODO should we fix this?
      assert_raise OpenSSL::Cipher::CipherError, &block
    else
      assert_raise RuntimeError, &block
    end
  end

#  def test_cipher_non_mod_length
#    cipher = OpenSSL::Cipher.new 'AES-128-CFB1'
#    cipher.encrypt
#    length = 50
#    cipher.iv = '0' * length
#    cipher.key = '1' * length
#    bytes = '01234' * 4
#    expected = "L=\x8C\xD1_]\xD6\x8Dk\t\xC3\xF0s\x8D_\x91\x12\x93\x7F\x80" # from MRI
#    assert_equal expected, cipher.update(bytes)
#
#    assert_equal 16, cipher.iv_len
#    assert_equal 16, cipher.key_len
#  end

#  def test_cipher_mod_length
#    cipher = OpenSSL::Cipher.new 'AES-128-CFB1'
#    cipher.encrypt
#    length = 48
#    cipher.iv = '0' * length
#    cipher.key = '1' * length
#    bytes = '123456' * 8
#    expected = "M4\xFE\xFF\xE3\xE7\x11*\xF2E\xA6\x815M\xCFO\xDFp\xB7\x87\xAC\xD0\xB0h" # ... from MRI
#    actual = cipher.update(bytes)
#    assert_equal expected, actual[0...24]
#    assert_equal 48, actual.size
#  end

#  def test_cipher_32_length
#    cipher = OpenSSL::Cipher.new 'AES-128-CFB1'
#    cipher.encrypt
#    length = 32
#    cipher.iv = '0' * length
#    cipher.key = '1' * length
#    bytes = '01234' * 4
#    expected = "L=\x8C\xD1_]\xD6\x8Dk\t\xC3\xF0s\x8D_\x91\x12\x93\x7F\x80" # from MRI
#    assert_equal expected, cipher.update(bytes)
#  end

#  def test_cipher_16_length
#    cipher = OpenSSL::Cipher.new 'AES-128-CFB1'
#    assert_equal cipher, cipher.encrypt
#    length = 16
#    cipher.iv = '0' * length
#    cipher.key = '1' * length
#    bytes = '01234' * 4
#    expected = "L=\x8C\xD1_]\xD6\x8Dk\t\xC3\xF0s\x8D_\x91\x12\x93\x7F\x80" # from MRI
#    assert_equal expected, cipher.update(bytes)
#  end

  def test_encrypt_aes_cfb_4_incompatibility
    cipher = OpenSSL::Cipher.new 'aes-128-cfb'
    assert_equal cipher, cipher.encrypt
    length = 16
    cipher.iv = '0' * length
    cipher.key = '1' * length
    bytes = '0000'
    expected = "f0@\x02" # from MRI
    actual = cipher.update(bytes)
    # NOTE: ugly but this is as far as JCE gets us :
    if defined? JRUBY_VERSION
      #assert_equal expected, actual
      assert_equal expected, cipher.final
    else
      assert_equal expected, actual
      assert_equal "", cipher.final
    end
  end

  def test_encrypt_aes_cfb_16_incompatibility
    cipher = OpenSSL::Cipher.new 'AES-128-CFB'
    assert_equal cipher, cipher.encrypt
    length = 16
    cipher.iv = '0' * length
    cipher.key = '1' * length
    bytes = '0000' * 4
    expected = "f0@\x02\xF6\xA8\xC2\rt\xCC\x83\x8F8e\x19R" # from MRI
    actual = cipher.update(bytes)
    # NOTE: ugly but this is as far as JCE gets us :
    if defined? JRUBY_VERSION
      #assert_equal expected, actual
      assert_equal expected, cipher.final
    else
      assert_equal expected, actual
      assert_equal "", cipher.final
    end
  end

  def test_encrypt_aes_cfb_20_incompatibility
    cipher = OpenSSL::Cipher.new 'AES-128-CFB'
    assert_equal cipher, cipher.encrypt
    length = 16
    cipher.iv = '0' * length
    cipher.key = '1' * length
    bytes = '0000' * 5
    expected = "f0@\x02\xF6\xA8\xC2\rt\xCC\x83\x8F8e\x19RZ\x8D5\xF8" # from MRI
    actual = cipher.update(bytes)
    # NOTE: ugly but this is as far as JCE gets us :
    if defined? JRUBY_VERSION
      assert_equal expected[0...16], actual
      # since on Java the padding is handled internally by the Cipher
      # we get :( "Z\x8D5\xF8\x10S|\xB7_R\xA2\x921\x93\x14]"
      assert_equal expected[16..-1], cipher.final[0...4]
    else
      assert_equal expected, actual
      assert_equal "", cipher.final
    end
  end

end