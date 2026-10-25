# coding: US-ASCII
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
    skip_fips_unapproved_ciphers

    # NOTE: since 0.9.6 we allow the underlying JCE cipher algorithms
    # to work - although we won't report support for them in `ciphers`
    if java.security.Security.getProvider('SunJCE')
      OpenSSL::Cipher.new 'PBEWithSHA1AndRC2_40-CBC' # Sun JCE
      #OpenSSL::Cipher.new 'RSA/ECB' # Sun JCE
      OpenSSL::Cipher.new 'RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING' # Sun JCE
      OpenSSL::Cipher.new 'RSA/ECB/OAEPWithSHA1AndMGF1Padding' # Sun JCE
      OpenSSL::Cipher.new 'DESedeWrap/CBC/NOPADDING' # Sun JCE
    end

    OpenSSL::Cipher.new 'XTEA/CBC/PKCS7Padding' # BC
    OpenSSL::Cipher.new 'Noekeon/CBC/ZeroBytePadding' # BC
  end if defined? JRUBY_VERSION

  def test_named_classes
    skip_fips_unapproved_ciphers

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

  def test_excludes_cfb1_ciphers # due no support in BC for 1-bit CFB (CFB16/128/... are supported)
    assert_nil OpenSSL::Cipher.ciphers.find { |name| name =~ /-cfb1$/i }
  end if defined? JRUBY_VERSION

  def test_encrypt_decrypt_des_ede3_cbc # borrowed from OpenSSL suite
    skip_fips_unapproved_ciphers

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

  def test_deprecated_encrypt_password_without_salt_matches_pkcs5_keyivgen
    omit_on_fips 'pkcs5_keyivgen defaults to MD5, which is not FIPS-approved'

    pass = "secret"
    data = "message"

    expected = OpenSSL::Cipher.new("AES-128-CBC")
    expected.encrypt
    expected.pkcs5_keyivgen(pass)
    encrypted = expected.update(data) + expected.final

    cipher = OpenSSL::Cipher.new("AES-128-CBC")
    cipher.encrypt(pass)
    assert_equal encrypted, cipher.update(data) + cipher.final

    cipher = OpenSSL::Cipher.new("AES-128-CBC")
    cipher.decrypt(pass)
    assert_equal data, cipher.update(encrypted) + cipher.final
  end

  def test_des_key_len
    skip_fips_unapproved_ciphers

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
    skip_fips_unapproved_ciphers

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

  def test_aes_ecb_iv_len
    # ECB mode does not use an IV, so iv_len should be 0
    cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    assert_equal 0, cipher.iv_len
    cipher = OpenSSL::Cipher.new 'AES-192-ECB'
    assert_equal 0, cipher.iv_len
    cipher = OpenSSL::Cipher.new 'AES-256-ECB'
    assert_equal 0, cipher.iv_len
  end


  # 128-bit-block non-AES ciphers (Camellia, SEED, CAST6) must report a 16-byte IV
  # (they were reporting 8, which truncated the IV and broke CBC/CFB/OFB)
  def test_non_aes_block_cipher_iv_len_and_roundtrip
    skip_fips_unapproved_ciphers
    {
      'camellia-128-cbc' => 16,
      'camellia-192-cbc' => 16,
      'camellia-256-cbc' => 16,
      'seed-cbc' => 16,
      'cast6-cbc' => 16,
      'cast5-cbc' => 8,
      'bf-cbc' => 8,
      'rc2-cbc' => 8,
      'des-cbc' => 8
    }.each do |algo, iv_len|
      assert_equal iv_len, OpenSSL::Cipher.new(algo).iv_len, "#{algo} iv_len"

      data = "block cipher round-trip test!! .."  # 32 bytes
      enc = OpenSSL::Cipher.new(algo).encrypt; enc.key = "k" * enc.key_len; enc.iv = "v" * iv_len
      ct = enc.update(data) + enc.final
      dec = OpenSSL::Cipher.new(algo).decrypt; dec.key = "k" * dec.key_len; dec.iv = "v" * iv_len
      assert_equal data, dec.update(ct) + dec.final, "#{algo} round-trip"
    end
  end

  # jruby/jruby#5776: reset without key should not raise
  def test_reset_without_key
    c = OpenSSL::Cipher.new("AES-128-CBC")
    c.reset # should not raise
  end

  def test_reset_produces_same_ciphertext
    key = "0123456789abcdef"
    iv = "fedcba9876543210"
    data = "hello world!!!!!"

    c = OpenSSL::Cipher.new("AES-128-CBC")
    c.encrypt; c.key = key; c.iv = iv
    ct1 = c.update(data) + c.final

    c.reset; c.iv = iv
    ct2 = c.update(data) + c.final

    assert_equal ct1, ct2
  end

  # GH-183: cipher.update should flush complete blocks immediately, matching OpenSSL behavior
  def test_update_flushes_complete_blocks_cbc
    key, iv = "0123456789abcdef", "fedcba9876543210"
    [
      [1,  0],  [15, 0],  [16, 16], [17, 16],
      [32, 32], [48, 48], [31, 16], [33, 32],
    ].each do |input_len, expected_output_len|
      c = OpenSSL::Cipher.new("AES-128-CBC")
      c.encrypt; c.key = key; c.iv = iv
      out = c.update("x" * input_len)
      assert_equal expected_output_len, out.length,
        "update(#{input_len}).length should be #{expected_output_len}"
    end
  end

  def test_update_flushes_complete_blocks_ecb
    key = "0123456789abcdef"
    [16, 32, 48].each do |n|
      c = OpenSSL::Cipher.new("AES-128-ECB")
      c.encrypt; c.key = key
      assert_equal n, c.update("x" * n).length,
        "ECB update(#{n}).length should be #{n}"
    end
  end

  def test_update_multi_chunk_accumulation
    key, iv = "0123456789abcdef", "fedcba9876543210"
    c = OpenSSL::Cipher.new("AES-128-CBC")
    c.encrypt; c.key = key; c.iv = iv
    # 5 bytes: no output (partial block)
    assert_equal 0, c.update("x" * 5).length
    # 11 more bytes (total 16): flush one block
    assert_equal 16, c.update("y" * 11).length
    # 3 more bytes: no output (partial block)
    assert_equal 0, c.update("z" * 3).length
    # final: flush padded last block
    assert_equal 16, c.final.length
  end

  def test_update_roundtrip_after_fix
    key, iv = "0123456789abcdef", "fedcba9876543210"
    data = "The quick brown fox jumps over the lazy dog!"
    c = OpenSSL::Cipher.new("AES-128-CBC")
    c.encrypt; c.key = key; c.iv = iv
    ct = c.update(data) + c.final

    d = OpenSSL::Cipher.new("AES-128-CBC")
    d.decrypt; d.key = key; d.iv = iv
    pt = d.update(ct) + d.final
    assert_equal data, pt
  end

  # the manual block-buffering must not touch feedback/counter stream modes
  def test_stream_mode_decrypt_roundtrip
    key = "0123456789abcdef"; iv = "fedcba9876543210"
    # lengths that are not clean block multiples exercised the broken re-chaining
    data = ("The quick brown fox jumps over the lazy dog!!" * 3) # 135 bytes
    %w[AES-128-CTR AES-128-OFB AES-128-CFB AES-128-CFB8].each do |algo|
      enc = OpenSSL::Cipher.new(algo).encrypt; enc.key = key; enc.iv = iv
      ct = enc.update(data) + enc.final

      # single-shot decrypt
      dec = OpenSSL::Cipher.new(algo).decrypt; dec.key = key; dec.iv = iv
      assert_equal data, dec.update(ct) + dec.final, "#{algo} single-shot decrypt"

      # block-by-block decrypt (stresses the per-update path)
      dec2 = OpenSSL::Cipher.new(algo).decrypt; dec2.key = key; dec2.iv = iv
      out = "".b
      (0...ct.bytesize).step(16) { |o| out << dec2.update(ct[o, 16]) }
      out << dec2.final
      assert_equal data, out, "#{algo} chunked decrypt"
    end
  end

  # NIST SP 800-38A known-answer vectors (AES-128) for the feedback/counter stream modes
  def test_aes_stream_modes_nist_kat
    key = ['2b7e151628aed2a6abf7158809cf4f3c'].pack('H*')
    iv  = ['000102030405060708090a0b0c0d0e0f'].pack('H*')
    ctr = ['f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'].pack('H*')
    pt  = ['6bc1bee22e409f96e93d7e117393172a' \
           'ae2d8a571e03ac9c9eb76fac45af8e51' \
           '30c81c46a35ce411e5fbc1191a0a52ef' \
           'f69f2445df4f9b17ad2b417be66c3710'].pack('H*')

    { # algo => [iv, expected ciphertext (NIST SP 800-38A)]
      'aes-128-cfb' => [iv,  '3b3fd92eb72dad20333449f8e83cfb4a' \
                             'c8a64537a0b3a93fcde3cdad9f1ce58b' \
                             '26751f67a3cbb140b1808cf187a4f4df' \
                             'c04b05357c5d1c0eeac4c66f9ff7f2e6'],
      'aes-128-ofb' => [iv,  '3b3fd92eb72dad20333449f8e83cfb4a' \
                             '7789508d16918f03f53c52dac54ed825' \
                             '9740051e9c5fecf64344f7a82260edcc' \
                             '304c6528f659c77866a510d9c1d6ae5e'],
      'aes-128-ctr' => [ctr, '874d6191b620e3261bef6864990db6ce' \
                             '9806f66b7970fdff8617187bb9fffdff' \
                             '5ae4df3edbd5d35e5b4f09020db03eab' \
                             '1e031dda2fbe03d1792170a0f3009cee'],
    }.each do |algo, (ivv, ct_hex)|
      expected_ct = [ct_hex].pack('H*')

      enc = OpenSSL::Cipher.new(algo).encrypt; enc.key = key; enc.iv = ivv
      assert_equal expected_ct, enc.update(pt) + enc.final, "#{algo} encrypt KAT"

      dec = OpenSSL::Cipher.new(algo).decrypt; dec.key = key; dec.iv = ivv
      assert_equal pt, dec.update(expected_ct) + dec.final, "#{algo} decrypt KAT"

      # block-by-block decrypt guards the manual-buffer regression against a fixed vector
      dec2 = OpenSSL::Cipher.new(algo).decrypt; dec2.key = key; dec2.iv = ivv
      out = "".b
      (0...expected_ct.bytesize).step(16) { |o| out << dec2.update(expected_ct[o, 16]) }
      out << dec2.final
      assert_equal pt, out, "#{algo} chunked decrypt KAT"
    end
  end

  # CTR keeps a running counter across updates split on arbitrary boundaries;
  # chunked output must equal a single-shot encrypt
  def test_aes_ctr_streaming_arbitrary_chunks
    iv = ['f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'].pack('H*')
    data = ("Streaming CTR keeps a running counter across updates. " * 5).b # 265 bytes
    %w[aes-128-ctr aes-192-ctr aes-256-ctr].each do |algo|
      key = OpenSSL::Cipher.new(algo).random_key
      one = OpenSSL::Cipher.new(algo).encrypt; one.key = key; one.iv = iv
      expected = one.update(data) + one.final

      c = OpenSSL::Cipher.new(algo).encrypt; c.key = key; c.iv = iv
      out = "".b; off = 0
      [1, 7, 13, 16, 31, 64, 3].cycle do |n|
        break if off >= data.bytesize
        out << c.update(data[off, n]); off += n
      end
      out << c.final
      assert_equal expected, out, "#{algo} arbitrary-chunk streaming"
    end
  end

  def test_other_ctr_ciphers_continue_after_final_on_block_boundary
    skip_fips_unapproved_ciphers

    algos = %w[camellia-128-ctr camellia-192-ctr camellia-256-ctr]
    algos += %w[bf-ctr cast5-ctr des-ctr des-ede3-ctr rc2-ctr twofish-ctr] if defined? JRUBY_VERSION
    algos.each do |algo|
      base = OpenSSL::Cipher.new(algo)
      key = "k" * base.key_len
      iv = "\0".b * base.iv_len
      data = ("0123456789abcdef" * 2).b

      whole = OpenSSL::Cipher.new(algo).encrypt; whole.key = key; whole.iv = iv
      expected = whole.update(data) + whole.final

      split = OpenSSL::Cipher.new(algo).encrypt; split.key = key; split.iv = iv
      first = split.update(data.byteslice(0, base.iv_len)) + split.final
      second = split.update(data.byteslice(base.iv_len, data.bytesize - base.iv_len)) + split.final
      assert_equal expected, first + second, "#{algo} encrypt after final"
    end
  end

  def test_ofb_ciphers_continue_after_final_on_block_boundary
    skip_fips_unapproved_ciphers

    algos = %w[aes-128-ofb aes-192-ofb aes-256-ofb
                camellia-128-ofb camellia-192-ofb camellia-256-ofb]
    algos.each do |algo|
      base = OpenSSL::Cipher.new(algo)
      key = "k" * base.key_len
      iv = "v" * base.iv_len
      data = ("0123456789abcdef" * 2).b

      whole = OpenSSL::Cipher.new(algo).encrypt; whole.key = key; whole.iv = iv
      expected = whole.update(data) + whole.final

      split = OpenSSL::Cipher.new(algo).encrypt; split.key = key; split.iv = iv
      first = split.update(data.byteslice(0, base.iv_len)) + split.final
      second = split.update(data.byteslice(base.iv_len, data.bytesize - base.iv_len)) + split.final
      assert_equal expected, first + second, "#{algo} encrypt after final"

      dec = OpenSSL::Cipher.new(algo).decrypt; dec.key = key; dec.iv = iv
      plain = dec.update(first) + dec.final + dec.update(second) + dec.final
      assert_equal data, plain, "#{algo} decrypt after final"
    end
  end

  def test_aes_ctr_continues_after_final_on_block_boundary
    iv = ['000102030405060708090a0b0c0dfeff'].pack('H*')
    data = ("0123456789abcdef" * 4).b

    %w[aes-128-ctr aes-192-ctr aes-256-ctr].each do |algo|
      key = "k" * OpenSSL::Cipher.new(algo).key_len
      whole = OpenSSL::Cipher.new(algo).encrypt; whole.key = key; whole.iv = iv
      expected = whole.update(data) + whole.final

      enc = OpenSSL::Cipher.new(algo).encrypt; enc.padding = 0; enc.key = key; enc.iv = iv
      encrypted = "".b; offset = 0
      4.times do
        chunk = data.byteslice(offset, 16)
        encrypted << enc.update(chunk)
        assert_equal "", enc.final, "#{algo} encrypt final"
        assert_equal "", enc.final, "#{algo} repeated final"
        offset += chunk.bytesize
      end
      assert_equal expected, encrypted, "#{algo} encrypt after final"

      dec = OpenSSL::Cipher.new(algo).decrypt; dec.padding = 0; dec.key = key; dec.iv = iv
      plain = "".b; offset = 0
      4.times do
        chunk = encrypted.byteslice(offset, 16)
        plain << dec.update(chunk)
        assert_equal "", dec.final, "#{algo} decrypt final"
        offset += chunk.bytesize
      end
      assert_equal data, plain, "#{algo} decrypt after final"

      enc.reset
      enc.iv = iv
      assert_equal expected, enc.update(data) + enc.final, "#{algo} reset with IV after final"
    end
  end

  # NIST SP 800-38A F.5.5/F.5.6 AES-256-CTR known-answer vector
  def test_aes256_ctr_nist_kat
    key = ['603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'].pack('H*')
    iv  = ['f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'].pack('H*')
    pt  = ['6bc1bee22e409f96e93d7e117393172a' \
           'ae2d8a571e03ac9c9eb76fac45af8e51' \
           '30c81c46a35ce411e5fbc1191a0a52ef' \
           'f69f2445df4f9b17ad2b417be66c3710'].pack('H*')
    ct  = ['601ec313775789a5b7a7f504bbf3d228' \
           'f443e3ca4d62b59aca84e990cacaf5c5' \
           '2b0930daa23de94ce87017ba2d84988d' \
           'dfc9c58db67aada613c2dd08457941a6'].pack('H*')

    enc = OpenSSL::Cipher.new('aes-256-ctr').encrypt; enc.key = key; enc.iv = iv
    assert_equal ct, enc.update(pt) + enc.final, "aes-256-ctr encrypt KAT"
    dec = OpenSSL::Cipher.new('aes-256-ctr').decrypt; dec.key = key; dec.iv = iv
    assert_equal pt, dec.update(ct) + dec.final, "aes-256-ctr decrypt KAT"
  end

  # Ensure encrypt-decrypt on the same object still works
  def test_encrypt_then_decrypt_same_object
    key, iv = "0123456789abcdef", "fedcba9876543210"
    data = "hello world!!!!!"  # 16 bytes

    c = OpenSSL::Cipher.new("AES-128-CBC")
    c.encrypt; c.key = key; c.iv = iv
    ct = c.update(data) + c.final

    c.decrypt; c.key = key; c.iv = iv
    pt = c.update(ct) + c.final
    assert_equal data, pt
  end

  # GCM round-trip should not be affected by the buffering change
  def test_gcm_roundtrip_not_affected
    key, iv = "0123456789abcdef", "0123456789ab"
    data = "hello world"
    c = OpenSSL::Cipher.new("AES-128-GCM")
    c.encrypt; c.key = key; c.iv = iv; c.auth_data = "aad"
    ct = c.update(data) + c.final
    tag = c.auth_tag

    d = OpenSSL::Cipher.new("AES-128-GCM")
    d.decrypt; d.key = key; d.iv = iv; d.auth_data = "aad"; d.auth_tag = tag
    pt = d.update(ct) + d.final
    assert_equal data, pt
  end

  # Workaround from rubyzip (hainesr/rubyzip@3567ff4) which added `cipher.final`
  # after block-by-block decryption on JRuby; with our fix this workaround should
  # remain harmless final should return empty on both platforms
  def test_block_decrypt_with_extra_final_workaround
    key, iv = "0123456789abcdef", "fedcba9876543210"
    plaintext = "Hello World?! :)" * 4  # 64 bytes = 4 blocks

    enc = OpenSSL::Cipher.new("AES-128-CBC")
    enc.encrypt; enc.key = key; enc.iv = iv
    ct = enc.update(plaintext) + enc.final

    # Block-by-block decrypt with padding=0 and explicit final (the workaround)
    dec = OpenSSL::Cipher.new("AES-128-CBC")
    dec.decrypt; dec.key = key; dec.iv = iv; dec.padding = 0
    result = ""
    (0...ct.length).step(16) { |i| result << dec.update(ct[i, 16]) }
    result << dec.final  # should be harmless (empty)
    assert_equal plaintext, result[0...plaintext.length]

    # Same without `.final` should also work
    dec2 = OpenSSL::Cipher.new("AES-128-CBC")
    dec2.decrypt; dec2.key = key; dec2.iv = iv; dec2.padding = 0
    result2 = ""
    (0...ct.length).step(16) { |i| result2 << dec2.update(ct[i, 16]) }
    assert_equal plaintext, result2[0...plaintext.length]
  end

  # Uses RFC 3610 Section 8 Test Case 1 (same as CRuby's test_aes_ccm)
  def test_aes_ccm_rfc3610
    key = ["c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"].pack("H*")
    iv =  ["00000003020100a0a1a2a3a4a5"].pack("H*")
    aad = ["0001020304050607"].pack("H*")
    pt =  ["08090a0b0c0d0e0f101112131415161718191a1b1c1d1e"].pack("H*")
    expected_ct =  ["588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"].pack("H*")
    expected_tag = ["17e8d12cfdf926e0"].pack("H*")

    c = OpenSSL::Cipher.new("AES-128-CCM")
    c.encrypt
    c.auth_tag_len = 8
    c.iv_len = 13
    c.key = key
    c.iv = iv
    c.ccm_data_len = pt.length
    c.auth_data = aad
    ct = c.update(pt) + c.final
    assert_equal expected_ct, ct
    assert_equal expected_tag, c.auth_tag(8)

    d = OpenSSL::Cipher.new("AES-128-CCM")
    d.decrypt
    d.auth_tag_len = 8
    d.iv_len = 13
    d.key = key
    d.iv = iv
    d.ccm_data_len = ct.length
    d.auth_tag = expected_tag
    d.auth_data = aad
    assert_equal pt, d.update(ct) + d.final
  end

  def test_aes_ccm_wrong_tag_rejected
    key = ["c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"].pack("H*")
    iv =  ["00000003020100a0a1a2a3a4a5"].pack("H*")
    aad = ["0001020304050607"].pack("H*")
    ct =  ["588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"].pack("H*")
    tag = ["17e8d12cfdf926e0"].pack("H*")

    bad_tag = tag.dup
    bad_tag.setbyte(-1, (bad_tag.getbyte(-1) + 1) & 0xff)

    d = OpenSSL::Cipher.new("AES-128-CCM")
    d.decrypt; d.auth_tag_len = 8; d.iv_len = 13
    d.key = key; d.iv = iv
    d.ccm_data_len = ct.length; d.auth_tag = bad_tag; d.auth_data = aad
    assert_raise(OpenSSL::Cipher::CipherError) { d.update(ct) + d.final }
  end

  def test_aes_ccm_authenticated
    c = OpenSSL::Cipher.new("AES-128-CCM")
    assert_equal true, c.authenticated?
  end

  def test_aes_256_ccm_roundtrip
    key = OpenSSL::Random.random_bytes(32)
    iv = OpenSSL::Random.random_bytes(12)
    data = "AES-256-CCM test data for round-trip"

    c = OpenSSL::Cipher.new("AES-256-CCM")
    c.encrypt; c.key = key; c.iv = iv; c.auth_data = "aad"
    ct = c.update(data) + c.final
    tag = c.auth_tag

    d = OpenSSL::Cipher.new("AES-256-CCM")
    d.decrypt; d.key = key; d.iv = iv; d.auth_tag = tag; d.auth_data = "aad"
    assert_equal data, d.update(ct) + d.final
  end

  # setting a fresh iv re-initializes the context;
  # a GCM cipher is reusable for the next message, generated tag must not linger
  def test_gcm_reusable_after_iv_reset
    key = OpenSSL::Random.random_bytes(16)
    iv1, iv2 = OpenSSL::Random.random_bytes(12), OpenSSL::Random.random_bytes(12)

    reused = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    reused.key = key
    reused.iv = iv1; reused.auth_data = "aad"
    ct1 = reused.update("hello") + reused.final
    tag1 = reused.auth_tag

    reused.iv = iv2; reused.auth_data = "aad"
    ct2 = reused.update("world") + reused.final
    tag2 = reused.auth_tag

    assert_equal [ ct1, tag1 ], gcm_seal(key, iv1, "aad", "hello")
    assert_equal [ ct2, tag2 ], gcm_seal(key, iv2, "aad", "world")
  end

  def test_gcm_reusable_after_encrypt_reinit
    key = OpenSSL::Random.random_bytes(16)
    iv1, iv2 = OpenSSL::Random.random_bytes(12), OpenSSL::Random.random_bytes(12)

    c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    c.key = key; c.iv = iv1; c.auth_data = "aad"
    c.update("hello"); c.final; c.auth_tag

    c.encrypt; c.key = key; c.iv = iv2; c.auth_data = "aad"
    ct = c.update("world") + c.final

    assert_equal [ ct, c.auth_tag ], gcm_seal(key, iv2, "aad", "world")
  end

  # without re-initializing, update after final still raises (MRI behavior)
  def test_gcm_update_after_final_without_reset_raises
    c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    c.key = OpenSSL::Random.random_bytes(16); c.iv = OpenSSL::Random.random_bytes(12)
    c.update("hello"); c.final; c.auth_tag

    assert_raise(OpenSSL::Cipher::CipherError) { c.update("more") }
  end

  def test_gcm_rejects_over_length_iv
    c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    c.key = "0123456789abcdef"
    # default GCM nonce is 12 bytes; 16-byte IV would previously truncate to leading 12
    assert_raise(ArgumentError) { c.iv = "0123456789abcdef" } # 16 bytes
  end

  def test_gcm_exact_length_iv_works
    c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    c.key = "0123456789abcdef"
    assert_nothing_raised { c.iv = "0123456789ab" } # exactly 12 bytes
  end

  # MRI-compatible escape hatch for a non-default nonce length: set iv_len= before iv=
  def test_gcm_custom_nonce_length_via_iv_len
    c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    c.key = "0123456789abcdef"
    c.iv_len = 16
    assert_nothing_raised { c.iv = "0123456789abcdef" } # 16 bytes, now the expected length
  end

  def test_gcm_over_length_ivs_do_not_collapse_to_same_nonce
    key = "0123456789abcdef"
    iv1 = "0123456789ab" + "0001"
    iv2 = "0123456789ab" + "0002"
    [iv1, iv2].each do |iv|
      c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
      c.key = key
      assert_raise(ArgumentError) { c.iv = iv }
    end
  end

  def test_ccm_rejects_over_length_iv_without_iv_len
    c = OpenSSL::Cipher.new("AES-128-CCM").encrypt
    c.key = "0123456789abcdef"
    # default CCM nonce is 12 bytes here; a longer IV without iv_len= must raise (not truncate)
    assert_raise(ArgumentError) { c.iv = ["00000003020100a0a1a2a3a4a5"].pack("H*") } # 13 bytes
  end

  # iv_len= / auth_tag_len= are AEAD-only (match CRuby); non-AEAD ciphers must reject them
  def test_aead_only_setters_reject_non_aead
    c = OpenSSL::Cipher.new("AES-128-CBC").encrypt
    assert_raise(OpenSSL::Cipher::CipherError) { c.iv_len = 16 }
    assert_raise(OpenSSL::Cipher::CipherError) { c.auth_tag_len = 8 }
    assert_raise(OpenSSL::Cipher::CipherError) { c.auth_data = "aad" }

    g = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    assert_nothing_raised { g.iv_len = 16; g.auth_tag_len = 12; g.auth_data = "aad" }
  end

  # key= rejects any length mismatch (OpenSSL >= 2.0); a too-long key must not be silently truncated
  def test_key_rejects_wrong_length
    c = OpenSSL::Cipher.new("AES-256-CBC").encrypt
    assert_raise(ArgumentError) { c.key = "\x01" * 31 }
    assert_nothing_raised      { c.key = "\x01" * 32 }
    assert_raise(ArgumentError) { c.key = "\x01" * 33 }
  end

  # non-AEAD (CBC) over-length IV must raise, not silently truncate (OpenSSL >= 2.0)
  def test_non_aead_rejects_over_length_iv
    enc = OpenSSL::Cipher.new("AES-128-CBC").encrypt
    enc.key = "0123456789abcdef"
    assert_raise(ArgumentError) { enc.iv = "0123456789abcdef" + "EXTRA-IGNORED" } # > 16 bytes
    assert_raise(ArgumentError) { enc.iv = "short" } # < 16 bytes
    assert_nothing_raised      { enc.iv = "0123456789abcdef" } # exactly 16 bytes
  end

  @@test_encrypt_decrypt_des_variations = nil

  def test_encrypt_decrypt_des_variations
    skip_fips_unapproved_ciphers

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
        c.key = key[0, c.key_len] # pkcs5_keyivgen below derives the actual key/iv
        c.iv = iv[0, c.iv_len] # empty for ECB variants
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
    skip_fips_unapproved_ciphers

    cipher = OpenSSL::Cipher.new('DES-EDE3')
    cipher.encrypt # calculated on MRI (key/iv truncated to the cipher's lengths) :
    cipher.key = "\x1F\xFF&\xA4k\x8F^\xC80\txq'S\x93\xD2\xE3A\xEDT\xDCs\xFD<=G\a\x8F=\x8FhE"[0, cipher.key_len]
    cipher.iv = "o\x15# \xD1\a\x90\xC7ZO\r[\xE2\x8F\v)# I6;\xE6\xB7h\xD3M\xDA\xA0\xD1\xDCy\xD2"[0, cipher.iv_len]
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

  def skip_fips_unapproved_ciphers
    omit_on_fips 'cipher is not FIPS-approved'
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
    assert_equal 16, cipher.key_len
    assert_equal 12, cipher.iv_len
    cipher.key = '01' * 8
    cipher.iv = '0' * 12 # default 96-bit GCM nonce

    bytes = '0000' * 4
    expected = "\xAC\xC8\x0E\xEDbX,\xB4\xCD\x02\x06O(p\xF8u" # from MRI
    actual = cipher.update(bytes)
    if fips?
      assert_equal "", actual
      assert_equal expected, cipher.final
    else
      assert_equal expected, actual
    end
    assert_equal "", cipher.final unless defined? JRUBY_VERSION

    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    assert_equal cipher, cipher.encrypt
    assert_equal 32, cipher.key_len
    assert_equal 12, cipher.iv_len
    cipher.key = '01245678' * 4
    cipher.iv = '0' * 12 # default 96-bit GCM nonce

    bytes = '0101' * 8
    expected = ["3bb2feeb20c6db802ac5d61c55067d6908d1a96223d41dd7dd6b4535c6a19ac6"].pack("H*") # from MRI/OpenSSL
    actual = cipher.update(bytes)
    if fips?
      assert_equal "", actual
      assert_equal expected, cipher.final
    else
      assert_equal expected, actual
    end
  end

  # GCM with a non-default (non-96-bit) nonce length must be declared via iv_len= first; a longer IV
  # passed straight to iv= is now rejected instead of silently truncated to the leading nonce bytes
  # (which would reuse them and match MRI's ciphertext for the *shorter* nonce -- a nonce-reuse trap).
  # omitted on FIPS where the provider's GCM nonce-length policy differs.
  def test_aes_gcm_non_default_nonce_length
    omit_on_fips 'FIPS provider restricts GCM nonce length'

    [[16, '0' * 16,        "c0c2b5559e4a66c314bfa831c577e219"],
     [18, '012345678' * 2, "852e210c357f5716ec54ccaec5385059"]].each do |iv_len, iv, hex|
      cipher = OpenSSL::Cipher.new('aes-128-gcm').encrypt
      cipher.key = '01' * 8
      cipher.iv_len = iv_len
      cipher.iv = iv
      assert_equal [hex].pack("H*"), cipher.update('0000' * 4) # from MRI/OpenSSL
    end

    cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
    cipher.key = '01245678' * 4
    cipher.iv_len = 14
    cipher.iv = '0123456' * 2
    expected = ["a6f70ea1a025a121e14d800f1355b5c7c96633f38e2a314cf11cbff9615ffc0f"].pack("H*") # from MRI/OpenSSL
    assert_equal expected, cipher.update('0101' * 8)
  end

  def test_aes_gcm_custom
    ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm'].each do |algo|
      pt = "You should all use Authenticated Encryption!"
      cipher, key, iv = new_random_encryptor(algo)

      cipher.auth_data = "aad"
      ct  = cipher.update(pt) + cipher.final
      tag = cipher.auth_tag
      assert_equal(16, tag.size)

      decipher = new_decryptor(algo, key: key, iv: iv)
      decipher.auth_tag = tag
      decipher.auth_data = "aad"

      assert_equal(pt, decipher.update(ct) + decipher.final)
    end
  end

  def test_authenticated
    cipher = OpenSSL::Cipher.new('aes-128-gcm')
    assert_predicate(cipher, :authenticated?)
    cipher = OpenSSL::Cipher.new('aes-128-cbc')
    assert_not_predicate(cipher, :authenticated?)
  end

  # AEAD authenticity: GCM decryption must reject a forged tag, tampered ciphertext, or tampered AAD.
  def test_gcm_rejects_forged_tag_and_tampered_input
    key = '0123456789abcdef'; iv = '0123456789ab'; aad = 'header'; pt = 'authenticated secret msg'

    enc = OpenSSL::Cipher.new('aes-128-gcm').encrypt
    enc.key = key; enc.iv = iv; enc.auth_data = aad
    ct = enc.update(pt) + enc.final
    tag = enc.auth_tag

    # baseline: an untampered decrypt succeeds
    good = OpenSSL::Cipher.new('aes-128-gcm').decrypt
    good.key = key; good.iv = iv; good.auth_data = aad; good.auth_tag = tag
    assert_equal pt, good.update(ct) + good.final

    # forged tag (flip one bit)
    forged = tag.dup; forged.setbyte(-1, forged.getbyte(-1) ^ 0x01)
    d1 = OpenSSL::Cipher.new('aes-128-gcm').decrypt
    d1.key = key; d1.iv = iv; d1.auth_data = aad; d1.auth_tag = forged
    assert_raise(OpenSSL::Cipher::CipherError) { d1.update(ct) + d1.final }

    # tampered ciphertext
    bad_ct = ct.dup; bad_ct.setbyte(0, bad_ct.getbyte(0) ^ 0x01)
    d2 = OpenSSL::Cipher.new('aes-128-gcm').decrypt
    d2.key = key; d2.iv = iv; d2.auth_data = aad; d2.auth_tag = tag
    assert_raise(OpenSSL::Cipher::CipherError) { d2.update(bad_ct) + d2.final }

    # tampered AAD
    d3 = OpenSSL::Cipher.new('aes-128-gcm').decrypt
    d3.key = key; d3.iv = iv; d3.auth_data = 'HEADER'; d3.auth_tag = tag
    assert_raise(OpenSSL::Cipher::CipherError) { d3.update(ct) + d3.final }
  end

  def new_random_encryptor(algo)
    cipher = OpenSSL::Cipher.new(algo)
    cipher.encrypt
    key = cipher.random_key
    iv = cipher.random_iv
    [cipher, key, iv]
  end
  private :new_random_encryptor

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
    if fips?
      assert_equal expected, actual
      assert_equal "", cipher.final
    elsif jruby? # NOTE: ugly but this is as far as JCE gets us :
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
    cipher.encrypt
    cipher.key = "a" * 32
    buffer = ''
    actual = cipher.update('bar' * 10, buffer)
    expected = "\xE6\xD3Y\fc\xEE\xBA\xB2*\x0Fr\xD1\xC2b\x03\xD0"
    assert_equal actual, expected
    assert_equal buffer, expected
  end

  def test_encrypt_aes_256_cbc_invalid_buffer
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.key = "a" * 32
    buffer = Object.new
    assert_raise(TypeError) { cipher.update('bar' * 10, buffer) }
  end

  def test_aes_gcm
    # GCM spec Appendix B Test Case 4
    key = ["feffe9928665731c6d6a8f9467308308"].pack("H*")
    iv =  ["cafebabefacedbaddecaf888"].pack("H*")
    aad = ["feedfacedeadbeeffeedfacedeadbeef" \
           "abaddad2"].pack("H*")
    pt =  ["d9313225f88406e5a55909c5aff5269a" \
           "86a7a9531534f7da2e4c303d8a318a72" \
           "1c3c0c95956809532fcf0e2449a6b525" \
           "b16aedf5aa0de657ba637b39"].pack("H*")
    ct =  ["42831ec2217774244b7221b784d0d49c" \
           "e3aa212f2c02a4e035c17e2329aca12e" \
           "21d514b25466931c7d8f6a5aac84aa05" \
           "1ba30b396a0aac973d58e091"].pack("H*")
    tag = ["5bc94fbc3221a5db94fae95ae7121a47"].pack("H*")

    cipher = new_encryptor("aes-128-gcm", key: key, iv: iv, auth_data: aad)
    # TODO JOpenSSL should raise
    # assert_raise(OpenSSL::Cipher::CipherError, 'unable to set authentication tag length: failed to get parameter') do
    #   cipher.auth_tag_len = 16
    # end
    assert_equal ct, cipher.update(pt) << cipher.final
    assert_equal tag, cipher.auth_tag
    cipher = new_decryptor("aes-128-gcm", key: key, iv: iv, auth_tag: tag, auth_data: aad)
    # TODO JOpenSSL should raise
    # assert_raise(OpenSSL::Cipher::CipherError, 'unable to set authentication tag length: failed to get parameter') do
    #   cipher.auth_tag_len = 16
    # end
    assert_equal pt, cipher.update(ct) << cipher.final

    # truncated tag is accepted
    cipher = new_encryptor("aes-128-gcm", key: key, iv: iv, auth_data: aad)
    assert_equal ct, cipher.update(pt) << cipher.final
    assert_equal tag[0, 8], cipher.auth_tag(8)
    assert_equal tag, cipher.auth_tag

    # NOTE: MRI seems to just ignore the invalid tag?!
    # cipher = new_decryptor("aes-128-gcm", key: key, iv: iv, auth_tag: tag[0, 8], auth_data: aad)
    # assert_equal pt, cipher.update(ct) << cipher.final

    # wrong tag is rejected
    tag2 = tag.dup
    tag2.setbyte(-1, (tag2.getbyte(-1) + 1) & 0xff)
    cipher = new_decryptor("aes-128-gcm", key: key, iv: iv, auth_tag: tag2, auth_data: aad)
    cipher.update(ct)
    assert_raise(OpenSSL::Cipher::CipherError) { cipher.final }

    # wrong aad is rejected
    aad2 = aad[0..-2] << aad[-1].succ
    cipher = new_decryptor("aes-128-gcm", key: key, iv: iv, auth_tag: tag, auth_data: aad2)
    cipher.update(ct)
    assert_raise(OpenSSL::Cipher::CipherError) { cipher.final }

    # wrong ciphertext is rejected
    ct2 = ct[0..-2] << ct[-1].succ
    cipher = new_decryptor("aes-128-gcm", key: key, iv: iv, auth_tag: tag, auth_data: aad)
    cipher.update(ct2)
    assert_raise(OpenSSL::Cipher::CipherError) { cipher.final }
  end

  private

  def new_encryptor(algo, **kwargs)
    OpenSSL::Cipher.new(algo).tap do |cipher|
      cipher.encrypt
      kwargs.each {|k, v| cipher.send(:"#{k}=", v) }
    end
  end

  # encrypt with a throw-away cipher, to compare against a re-used one
  def gcm_seal(key, iv, aad, data)
    c = OpenSSL::Cipher.new("AES-128-GCM").encrypt
    c.key = key; c.iv = iv; c.auth_data = aad
    [ c.update(data) + c.final, c.auth_tag ]
  end

  def new_decryptor(algo, **kwargs)
    OpenSSL::Cipher.new(algo).tap do |cipher|
      cipher.decrypt
      kwargs.each {|k, v| cipher.send(:"#{k}=", v) }
    end
  end

end
