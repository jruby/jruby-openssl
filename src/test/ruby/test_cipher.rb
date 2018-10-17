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
    OpenSSL::Cipher.new 'RSA/ECB/OAEPWithSHA1AndMGF1Padding' # Sun JCE
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
      next if cipher_name.end_with?('wrap') # e.g. 'id-aes256-wrap'
      OpenSSL::Cipher.new cipher_name
    end
  end

  def test_excludes_cfb1_ciphers # due no support in BC for CFB-1
    assert ! OpenSSL::Cipher.ciphers.find { |name| name =~ /CFB1/i }
  end if defined? JRUBY_VERSION

  def test_encrypt_decrypt_des_ede3_cbc # borrowed from OpenSSL suite
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

  def test_des_key_len
    cipher = OpenSSL::Cipher.new 'des'
    assert_equal  8, cipher.key_len
    cipher = OpenSSL::Cipher.new 'DES3'
    assert_equal 24, cipher.key_len

    cipher = OpenSSL::Cipher.new 'DES-CBC'
    assert_equal  8, cipher.key_len
    cipher = OpenSSL::Cipher.new 'des-ede3'
    assert_equal 24, cipher.key_len

    cipher = OpenSSL::Cipher.new 'des-ede'
    assert_equal 16, cipher.key_len
    cipher = OpenSSL::Cipher.new 'DES-EDE-CFB'
    assert_equal 16, cipher.key_len
  end

  def test_des_iv_len
    cipher = OpenSSL::Cipher.new 'des'
    assert_equal 8, cipher.iv_len
    cipher = OpenSSL::Cipher.new 'DES3'
    assert_equal 8, cipher.iv_len

    cipher = OpenSSL::Cipher.new 'DES-CBC'
    assert_equal 8, cipher.iv_len
    cipher = OpenSSL::Cipher.new 'des-ede3'
    assert_equal 0, cipher.iv_len

    cipher = OpenSSL::Cipher.new 'des-ede'
    assert_equal 0, cipher.iv_len
    cipher = OpenSSL::Cipher.new 'DES-EDE-CFB'
    assert_equal 8, cipher.iv_len
  end

  @@test_encrypt_decrypt_des_variations = nil

  def test_encrypt_decrypt_des_variations
    key = "\0\0\0\0\0\0\0\0" * 3
    iv =  "\0\0\0\0\0\0\0\0"
    data = "JPMNT"

    { # calculated on MRI
      'des' => "b\x00<\xC0\x16\xAF\xDCd",
      'des-cbc' => "b\x00<\xC0\x16\xAF\xDCd",
      #'des-cfb' => "\xE0\x9ER\xCC\xD8",
      #'des-ofb' => "\xE0\x9ER\xCC\xD8",
      'des-ecb' => ".\x1E\xB3\x0E\xE0\xD2\x9DG",

      'des-ede' => "@\x8B\x89}u\xB4\r\xA5",
      'des-ede-cbc' => "\x99\x97\xBE(\xB9+f\xFA",
      #'des-ede-cfb' => "l\x02?\x16\x1A",
      #'des-ede-ofb' => "l\x02?\x16\x1A",
      ##'des-ede-ecb' => RuntimeError: unsupported cipher algorithm (des-ede-ecb)

      'des-ede3' => "\xDC\xD4\xF4\xBDmF\xC26", # actually ECB
      'des-ede3-cbc' => "\x8D\xE6\x17\xD0\x97\rR\x8C",
      #'des-ede3-cfb' => ",\x93^\xAD\x9C",
      #'des-ede3-ofb' => ",\x93^\xAD\x9C",
      ##'des-ede3-ecb' => unsupported cipher algorithm (des-ede3-ecb)
      'des3' => "\x8D\xE6\x17\xD0\x97\rR\x8C"
    }.each do |name, expected|
        c = OpenSSL::Cipher.new name
        c.encrypt
        c.key = key
        c.iv = iv
        c.pkcs5_keyivgen(key, iv)

        assert_equal expected, c.update(data) + c.final, "failed: #{name}"
    end

    cipher = OpenSSL::Cipher::Cipher.new("DES-EDE3")

    cipher.encrypt.pkcs5_keyivgen(key, iv)
    secret = cipher.update(data) + cipher.final
    assert_equal "\xDC\xD4\xF4\xBDmF\xC26", secret

    cipher.decrypt.pkcs5_keyivgen(key, iv)
    assert_equal(data, cipher.update(secret) + cipher.final, "decrypt")

    data = "sa jej lubim alebo moj bicykel"

    cipher.encrypt.pkcs5_keyivgen(key, iv)
    secret = cipher.update(data) + cipher.final
    assert_equal "\xE9;\xDF\xEE/\x1D\xCB\xF9\xD1\xAF\xBC\xF0\x00\xA3\xDBsLxF2\xA4|\x11T\xD7&:\xD8\xF7\xA2\xD1b", secret

    cipher.decrypt.pkcs5_keyivgen(key, iv)
    assert_equal(data, cipher.update(secret) + cipher.final, "decrypt")

    cipher.padding = 0
    data = "hehehehemehehehe"

    cipher.encrypt.pkcs5_keyivgen(key, iv)
    secret = cipher.update(data) + cipher.final
    assert_equal "v\r\xA4\xB3\x02\x18\xB5|A\x13\x87\xF1\xC0A\xC4U", secret

    cipher.decrypt.pkcs5_keyivgen(key, iv)
    assert_equal(data, cipher.update(secret) + cipher.final, "decrypt")

    # assuming Cipher.ciphers not cached - re-run the tests with cache :
    unless @@test_encrypt_decrypt_des_variations
      @@test_encrypt_decrypt_des_variations = true
      OpenSSL::Cipher.ciphers; test_encrypt_decrypt_des_variations
    end
  end

  def test_another_encrypt_des_ede3
    cipher = OpenSSL::Cipher.new('DES-EDE3')
    cipher.encrypt # calculated on MRI :
    cipher.key = "\x1F\xFF&\xA4k\x8F^\xC80\txq'S\x93\xD2\xE3A\xEDT\xDCs\xFD<=G\a\x8F=\x8FhE"
    cipher.iv = "o\x15# \xD1\a\x90\xC7ZO\r[\xE2\x8F\v)# I6;\xE6\xB7h\xD3M\xDA\xA0\xD1\xDCy\xD2"
    assert_equal "\xE1\x8DZ>MEq\xEF\x1A\xAC\xB1ab\x0Ea\x81", (cipher.update('sup3rs33kr3t') + cipher.final)
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

  def test_aes_128_gcm
    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    assert_equal cipher, cipher.encrypt
    cipher.key = '01' * 8
    cipher.iv = '0' * 16

    bytes = '0000' * 4
    expected = "\xAC\xC8\x0E\xEDbX,\xB4\xCD\x02\x06O(p\xF8u" # from MRI
    actual = cipher.update(bytes)
    assert_equal expected, actual
    assert_equal "", cipher.final unless defined? JRUBY_VERSION

    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    assert_equal cipher, cipher.encrypt
    cipher.key = '01' * 8
    cipher.iv = '012345678' * 2

    bytes = '0000' * 4
    expected = "\xF3\xEF\xE6K\xBAJ\xAB=7m'\b\xE0\x06U\x9B" # from MRI
    actual = cipher.update(bytes)
    assert_equal expected, actual
    #assert_equal "", cipher.final unless defined? JRUBY_VERSION

    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    assert_equal cipher, cipher.encrypt
    assert_equal 16, cipher.key_len
    assert_equal 12, cipher.iv_len
    cipher.key = '01' * 8
    cipher.iv = '0' * 12

    bytes = '0000' * 4
    expected = "\xAC\xC8\x0E\xEDbX,\xB4\xCD\x02\x06O(p\xF8u" # from MRI
    actual = cipher.update(bytes)
    assert_equal expected, actual
    #assert_equal "", cipher.final

    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    assert_equal cipher, cipher.encrypt
    assert_equal 32, cipher.key_len
    assert_equal 12, cipher.iv_len
    cipher.key = '01245678' * 4
    cipher.iv = '0123456' * 2

    bytes = '0101' * 8
    expected = "\xA8I0\xF8\xCD?Z\xFD\x8E\"T\xF5\xF2\xC5\xC8\x05\xD4b\x85\xA3}'\xC99]\xC1\x16\x8B\x13\x9E-)" # from MRI
    actual = cipher.update(bytes)
    assert_equal expected, actual
    #assert_equal "", cipher.final
  end

  def test_aes_gcm
    ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm'].each do |algo|
      pt = "You should all use Authenticated Encryption!"
      cipher, key, iv = new_encryptor(algo)

      cipher.auth_data = "aad"
      ct  = cipher.update(pt) + cipher.final
      tag = cipher.auth_tag
      assert_equal(16, tag.size)

      decipher = new_decryptor(algo, key, iv)
      decipher.auth_tag = tag
      decipher.auth_data = "aad"

      assert_equal(pt, decipher.update(ct) + decipher.final)
    end
  end

  def new_encryptor(algo)
    cipher = OpenSSL::Cipher.new(algo)
    cipher.encrypt
    key = cipher.random_key
    iv = cipher.random_iv
    [cipher, key, iv]
  end
  private :new_encryptor

  def new_decryptor(algo, key, iv)
    OpenSSL::Cipher.new(algo).tap do |cipher|
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
    end
  end
  private :new_decryptor

  def test_aes_128_gcm_with_auth_tag
    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    cipher.encrypt
    #assert_equal 16, cipher.key_len
    #assert_equal 12, cipher.iv_len
    cipher.key = '01' * 8
    cipher.iv = '1001' * 3

    plaintext = "Hello World"

    padding = cipher.update("\0\0")
    text = cipher.update(plaintext)

    final = cipher.final; a_tag = cipher.auth_tag

    assert_equal "\xB5\xFD", padding unless defined? JRUBY_VERSION
    assert_equal "\xCCxqd\xDE\x92\x95\xAD0\xB4=", text unless defined? JRUBY_VERSION
    assert_equal "", final unless defined? JRUBY_VERSION

    assert_equal "\xB5\xFD\xCCxqd\xDE\x92\x95\xAD0\xB4=", padding + text + final

    assert_equal "\ay\xBA\x89\xC9\x91\xF8N\xB7\xD6\x17+\x0F\\\xF8N", a_tag

    assert_equal a_tag, cipher.auth_tag
    assert_raise(OpenSSL::Cipher::CipherError) { cipher.update("\0\0") }
    assert_equal a_tag, cipher.auth_tag
    assert_raise(OpenSSL::Cipher::CipherError) { cipher.final }
  end

  def test_encrypt_auth_data_non_gcm
    cipher = OpenSSL::Cipher.new 'aes-128-cfb'
    cipher.encrypt
    #length = 16
    #cipher.iv = '0' * length
    #cipher.key = '1' * length
    assert_raise(OpenSSL::Cipher::CipherError) { cipher.auth_tag }
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

  def test_encrypt_aes_256_cbc_modifies_buffer
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.key = "a" * 32
    cipher.encrypt
    buffer = ''
    actual = cipher.update('bar' * 10, buffer)
    if jruby?
      expected = "\xE6\xD3Y\fc\xEE\xBA\xB2*\x0Fr\xD1\xC2b\x03\xD0"
    else
      expected = "8\xA7\xBE\xB1\xAE\x88j\xCB\xA3\xE9j\x00\xD2W_\x91"
    end
    assert_equal actual, expected
    assert_equal buffer, expected
  end

  def test_encrypt_aes_256_cbc_invalid_buffer
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.key = "a" * 32
    cipher.encrypt
    buffer = Object.new
    assert_raise(TypeError) { cipher.update('bar' * 10, buffer) }
  end

end
