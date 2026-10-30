require File.expand_path('test_helper', File.dirname(__FILE__))

class TestHMAC < TestCase

  def setup
    super

    # SHA256 is FIPS-approved, and the key is >= 112 bits, so this setup works under FIPS too
    @digest_name = 'SHA256'
    @digest = OpenSSL::Digest.const_get(@digest_name)
    @key = 'K' * 14
    @data = "DATA"
    @h1 = OpenSSL::HMAC.new(@key, @digest.new)
    @h2 = OpenSSL::HMAC.new(@key, @digest_name)
  end

  def test_to_s
    @h1.update(''); @h1.update('1234567890')
    assert_equal(@h1.hexdigest, @h1.to_s)
    assert_equal(@h2.hexdigest, @h2.to_s)
  end

  def test_reset
    data = 'He is my neighbor Nursultan Tuliagby. He is pain in my assholes.'
    @h1.update('4'); @h1.update('2')
    @h1.reset
    @h1.update(data)
    @h2.update(data)
    assert_equal(@h2.digest, @h1.digest)
  end

  def test_correct_digest
    omit_on_fips 'hardcoded MD5 test vectors; HMAC-MD5 is not FIPS-approved'

    h2 = OpenSSL::HMAC.new('KEY', 'MD5')
    assert_equal('c17c7b655b11574fea8d676a1fdc0ca8', h2.hexdigest) # calculated on MRI
    h2.update('DATA')
    assert_equal('9e50596c0fa1197f8587443a942d8afc', h2.hexdigest) # calculated on MRI
    h2.reset
    h2.update("\xFF") # invalid utf-8 char
    assert_equal('0770623462e782b51bb0689a8ba4f3f1', h2.hexdigest) # calcualted on MRI
  end

  def test_hexdigest_with_empty_key
    omit_on_fips 'hardcoded MD5 test vector; HMAC-MD5 is not FIPS-approved'

    result = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('md5'), "", "foo")
    assert_equal "4acb10ca3965a14a080297db0921950c", result
  end

  def test_update_string_coercion
    h1 = OpenSSL::HMAC.new("KEY", "SHA256")
    h2 = OpenSSL::HMAC.new("KEY", "SHA256")

    str_like = Object.new
    def str_like.to_str
      "DATA"
    end

    h1.update(str_like)
    h2.update("DATA")
    assert_equal h2.digest, h1.digest

    assert_raise(TypeError) { h1.update(1) }
  rescue OpenSSL::HMACError => e
    skip 'FIPS approved-only mode rejects SHA-256/HMAC' if fips? && e.message.include?('approved mode')
    raise e
  end

  def test_unsupported_digest
    err = assert_raise(OpenSSL::Digest::DigestError) do
      OpenSSL::HMAC.new('key', 'BOGUS')
    end
    assert_match(/unsupported.*BOGUS/i, err.message)
  end

  def test_digest_restrictions
    omit_on_non_fips

    fips_key = 'x' * 14 # FIPS requires HMAC key >= 112 bits (14 bytes)

    # HMAC-MD5 is not FIPS-approved: BCFIPS does not register it under approved-only mode
    assert_raise(OpenSSL::Digest::DigestError) { OpenSSL::HMAC.new(fips_key, 'MD5') }
    # SHA256 is FIPS-approved and should work with a long-enough key
    assert_nothing_raised { OpenSSL::HMAC.new(fips_key, 'SHA256') }

    # a key under 112 bits is rejected in approved mode, even with an approved digest
    assert_raise(OpenSSL::HMACError) { OpenSSL::HMAC.new('xyz', 'SHA256') }
  end

  def test_uninitialized_copy
    uninit = OpenSSL::HMAC.allocate
    assert_instance_of OpenSSL::HMAC, uninit.dup
    assert_instance_of OpenSSL::HMAC, uninit.clone

    h = OpenSSL::HMAC.new('key', 'SHA256')
    h.send(:initialize_copy, uninit)
    assert_raise(OpenSSL::HMACError) { h.digest }
  end

  def test_uninitialized_methods
    uninit = OpenSSL::HMAC.allocate
    assert_raise(OpenSSL::HMACError) { uninit.digest }
    assert_raise(OpenSSL::HMACError) { uninit.hexdigest }
    assert_raise(OpenSSL::HMACError) { uninit.inspect }
    assert_raise(OpenSSL::HMACError) { uninit.to_s }
    assert_raise(OpenSSL::HMACError) { uninit << "data" }
    assert_raise(OpenSSL::HMACError) { uninit.update("data") }
    assert_raise(OpenSSL::HMACError) { uninit.reset } if defined?(JRUBY_VERSION)
  end
end
