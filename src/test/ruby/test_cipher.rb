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

  def test_excludes_cfb1_ciphers # due no support in BC for CFB-1
    assert ! OpenSSL::Cipher.ciphers.find { |name| name =~ /CFB1/i }
  end if defined? JRUBY_VERSION

  def test_encrypt_decrypt_des_ede3 # borrowed from OpenSSL suite
    c1 = OpenSSL::Cipher::Cipher.new("DES-EDE3-CBC")
    c2 = OpenSSL::Cipher::DES.new(:EDE3, "CBC")
    key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    iv = "\0\0\0\0\0\0\0\0"
    data = "DATA"

    c1.encrypt.pkcs5_keyivgen(key, iv)
    c2.encrypt.pkcs5_keyivgen(key, iv)
    s1 = c1.update(data) + c1.final
    s2 = c2.update(data) + c2.final
    assert_equal "\xC5q\x99)\x81\xE6\xE7\x06", s1
    assert_equal(s1, s2, "encrypt")

    c1.decrypt.pkcs5_keyivgen(key, iv)
    c2.decrypt.pkcs5_keyivgen(key, iv)
    assert_equal(data, c1.update(s1) + c1.final, "decrypt")
    assert_equal(data, c2.update(s2) + c2.final, "decrypt")
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

  def test_cipher_update_non_mod_length
    cipher = OpenSSL::Cipher.new 'AES-128-CFB1'
    cipher.encrypt
    # length = 50
    cipher.iv = "8\xF2\xEF\xFC7\x97.\xE9\x02)\xED\x18\xA6h\x14\xD2Z0\x97\x8F\x0E\x04`6n\xD8\xB8\xED\x0E\x95\xF3\xBA\xFC\xB3\x16\xF0lC\x97;\xBB\xED\xF1\xEE\xCB\x869\x93k\xB5"
    cipher.key = "\xBB;\x1A\x82\xFB'\xFB\xE4\xFBDP\xD8\x16.\xD1\x0EF.\xFD;\x9B\x8C\xE2\xBC\x18\xAD\x80\xB2\xBB\xF7U\x90y\xD2y\xCA\xE07\xBE\x97\an@\xB9\xE97\xF3\x9DA\xBC"
    bytes = "\xACJ\xF5\xA6m\xE2\xE8W\x0Fy\x93\xEA\xCFA\x03\xCF"
    expected = ",=\xC0\xD2\xEF\xE7(u,e\xD6l\xB4\x8E\x13\x00" # from MRI
    actual = cipher.update(bytes)
    assert_equal expected, actual

    assert_equal 16, cipher.iv_len
    assert_equal 16, cipher.key_len
  end unless jruby? # blocked due #35

  def test_cipher_update_mod_length
    cipher = OpenSSL::Cipher.new 'AES-128-CFB1'
    cipher.encrypt
    # length = 48
    cipher.iv = '1' * 16
    cipher.key = '0' * 16
    bytes = "\xACJ\xF5\xA6m\xE2\xE8W\x0Fy\x93\xEA\xCFA\x03\xCF"
    expected = "\xDD\x88dDj\xB9\xE2\xC9\xC5\x97L\x84V\x18\xE0\x93" # from MRI
    actual = cipher.update(bytes)
    assert_equal expected, actual

    assert_equal 16, cipher.iv_len
    assert_equal 16, cipher.key_len
  end unless jruby? # blocked due #35

  def test_encrypt_aes_cfb_4_incompatibility
    cipher = OpenSSL::Cipher.new 'aes-128-cfb'
    assert_equal cipher, cipher.encrypt
    length = 16
    cipher.iv = '0' * length
    cipher.key = '1' * length
    bytes = '0000'
    expected = "f0@\x02" # from MRI
    actual = cipher.update(bytes)
    if jruby? # NOTE: ugly but this is as far as JCE gets us :
      ##assert_equal expected, actual
      #assert_equal expected, cipher.final
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
    if jruby? # NOTE: ugly but this is as far as JCE gets us :
      ##assert_equal expected, actual
      #assert_equal expected, cipher.final
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
    if jruby? # NOTE: ugly but this is as far as JCE gets us :
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