# frozen_string_literal: true
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestPKeyDH < TestCase

  def test_new_empty
    # DH.new without args creates empty params (no key)
    dh = OpenSSL::PKey::DH.new
    assert_nil dh.p
    assert_nil dh.g
    assert_nil dh.priv_key
    assert_nil dh.pub_key
  end

  def test_new_from_pem
    pem = <<~EOF
    -----BEGIN DH PARAMETERS-----
    MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
    +8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
    87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
    YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
    7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
    ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
    -----END DH PARAMETERS-----
    EOF

    dh = OpenSSL::PKey::DH.new(pem)
    assert_kind_of OpenSSL::BN, dh.p
    assert_kind_of OpenSSL::BN, dh.g
    assert_equal 2, dh.g.to_i
    assert_nil dh.pub_key
    assert_nil dh.priv_key
  end

  def test_new_from_der
    dh_params = Fixtures.pkey_dh("dh2048_ffdhe2048")

    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(dh_params.p),
      OpenSSL::ASN1::Integer(dh_params.g)
    ])
    dh = OpenSSL::PKey::DH.new(asn1.to_der)
    assert_equal dh_params.p, dh.p
    assert_equal dh_params.g, dh.g
  end

  # OpenSSL::PKey.read used to reject DH parameters
  def test_pkey_read_parameters
    dh_params = Fixtures.pkey_dh("dh2048_ffdhe2048")

    [dh_params.to_pem, dh_params.to_der].each do |input|
      dh = OpenSSL::PKey.read(input)
      assert_kind_of OpenSSL::PKey::DH, dh
      assert_equal dh_params.p, dh.p
      assert_equal dh_params.g, dh.g
      assert_nil dh.pub_key
      assert_nil dh.priv_key
    end
  end

  # a DH key (rather than bare parameters) is a plain PKCS#8 / SubjectPublicKeyInfo
  def test_pkey_read_key
    key = OpenSSL::PKey.generate_key(Fixtures.pkey_dh('dh2048_ffdhe2048'))

    priv = OpenSSL::PKey.read(key.private_to_pem)
    assert_kind_of OpenSSL::PKey::DH, priv
    assert_equal key.priv_key, priv.priv_key
    assert_equal key.pub_key, priv.pub_key # not stored in PKCS#8, gets derived
    assert_equal key.p, priv.p

    pub = OpenSSL::PKey.read(key.public_to_pem)
    assert_kind_of OpenSSL::PKey::DH, pub
    assert_nil pub.priv_key
    assert_equal key.pub_key, pub.pub_key

    assert_equal key.priv_key, OpenSSL::PKey::DH.new(key.private_to_pem).priv_key
    assert_equal key.pub_key, OpenSSL::PKey::DH.new(key.public_to_pem).pub_key
  end

  # DH parameters are a SEQUENCE of INTEGERs, which an RSA (9) or DSA (6)
  # private key also starts with - those must never be taken for DH parameters
  def test_pkey_read_der_private_key_is_not_dh
    %w[rsa2048 dsa2048].each do |name|
      der = Fixtures.pkey(name).to_der
      begin
        parsed = OpenSSL::PKey.read(der)
      rescue OpenSSL::PKey::PKeyError
        next # DER private keys are not supported yet - but must not parse as DH
      end
      assert !parsed.is_a?(OpenSSL::PKey::DH), "#{name} DER parsed as DH: #{parsed.inspect}"
    end
  end

  def test_params
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    assert_kind_of OpenSSL::BN, dh.p
    assert_equal dh.p, dh.params["p"]
    assert_kind_of OpenSSL::BN, dh.g
    assert_equal dh.g, dh.params["g"]
    assert_nil dh.pub_key
    assert_nil dh.priv_key
  end

  def test_params_with_key
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!

    assert_kind_of OpenSSL::BN, dh.pub_key
    assert_equal dh.pub_key, dh.params["pub_key"]
    assert_kind_of OpenSSL::BN, dh.priv_key
    assert_equal dh.priv_key, dh.params["priv_key"]
  end

  def test_generate_key
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    assert_no_key(dh)

    dh.generate_key!
    assert_key(dh)

    # Generate another key with the same params
    dh2 = OpenSSL::PKey::DH.new(dh.to_der)
    dh2.generate_key!
    assert_not_equal dh.pub_key, dh2.pub_key
    assert_equal dh.compute_key(dh2.pub_key), dh2.compute_key(dh.pub_key)
  end

  def test_to_der
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    der = dh.to_der
    assert_kind_of String, der

    # Should be parseable
    dh2 = OpenSSL::PKey::DH.new(der)
    assert_equal dh.p, dh2.p
    assert_equal dh.g, dh2.g
  end

  def test_to_pem
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    pem = dh.to_pem
    assert_kind_of String, pem
    assert_match(/-----BEGIN DH PARAMETERS-----/, pem)
    assert_match(/-----END DH PARAMETERS-----/, pem)

    # Should be parseable
    dh2 = OpenSSL::PKey::DH.new(pem)
    assert_equal dh.p, dh2.p
    assert_equal dh.g, dh2.g
  end

  def test_export
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    # export is an alias for to_pem
    assert_equal dh.to_pem, dh.export
  end

  def test_to_text
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    text = dh.to_text
    assert_kind_of String, text
    assert_match(/DH Parameters/, text)
    # Should contain the prime (p) value
    assert_match(/prime/i, text)
    # Should contain the generator (g) value
    assert_match(/generator/i, text)
  end

  def test_to_text_with_key
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!

    text = dh.to_text
    assert_kind_of String, text
    assert_match(/DH Parameters/, text)
    # With a generated key, should show public and private key info
    assert_match(/pub/i, text)
    assert_match(/priv/i, text)
  end

  def test_public_to_der
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!

    der = dh.public_to_der
    assert_kind_of String, der
    # Should be a valid DER encoding (starts with SEQUENCE tag 0x30)
    assert_equal 0x30, der.getbyte(0)
  end

  def test_public_to_pem
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!

    pem = dh.public_to_pem
    assert_kind_of String, pem
    assert_match(/-----BEGIN PUBLIC KEY-----/, pem)
    assert_match(/-----END PUBLIC KEY-----/, pem)
  end

  def test_private_to_der
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!

    der = dh.private_to_der
    assert_kind_of String, der
    # Should be a valid DER encoding (starts with SEQUENCE tag 0x30)
    assert_equal 0x30, der.getbyte(0)
  end

  def test_private_to_pem
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!

    pem = dh.private_to_pem
    assert_kind_of String, pem
    assert_match(/-----BEGIN PRIVATE KEY-----/, pem)
    assert_match(/-----END PRIVATE KEY-----/, pem)
  end

  def test_derive_key
    dh1 = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh1.generate_key!
    dh2 = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh2.generate_key!

    # derive produces the same shared secret from both sides
    secret1 = dh1.derive(dh2)
    secret2 = dh2.derive(dh1)
    assert_equal secret1, secret2

    # Verify against math: g^(a*b) mod p == (g^a mod p)^b mod p
    z = dh1.g.mod_exp(dh1.priv_key, dh1.p).mod_exp(dh2.priv_key, dh1.p).to_s(2)
    assert_equal z, secret1

    # derive and compute_key produce the same result
    assert_equal secret1, dh1.compute_key(dh2.pub_key)
    assert_equal secret2, dh2.compute_key(dh1.pub_key)

    # Raises when self has no private key (params only)
    params = Fixtures.pkey_dh("dh2048_ffdhe2048")
    assert_raise(OpenSSL::PKey::PKeyError) { params.derive(dh1) }

    # Raises when peer has no public key (params only)
    assert_raise(OpenSSL::PKey::PKeyError) { dh1.derive(params) }
  end

  def test_compute_key
    dh1 = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh1.generate_key!
    dh2 = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh2.generate_key!

    shared1 = dh1.compute_key(dh2.pub_key)
    shared2 = dh2.compute_key(dh1.pub_key)
    assert_equal shared1, shared2

    # Verify against math: should match BN binary representation (no leading zero)
    z = dh1.g.mod_exp(dh1.priv_key, dh1.p).mod_exp(dh2.priv_key, dh1.p).to_s(2)
    assert_equal z, shared1
  end

  def test_reject_invalid_peer_public_values
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!
    invalid_values = [0, 1, dh.p - 1, dh.p]

    invalid_values.each do |value|
      pub_key = OpenSSL::BN.new(value)
      assert_raise(OpenSSL::PKey::PKeyError) { dh.compute_key(pub_key) }

      peer = dh.dup
      peer.pub_key = pub_key
      assert_raise(OpenSSL::PKey::PKeyError) { dh.derive(peer) }
    end

    other_params = dh.dup
    other_params.p = dh.p + 2
    assert_raise(OpenSSL::PKey::PKeyError) { dh.derive(other_params) }
  end

  def test_dup
    # Parameters only
    dh1 = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh2 = dh1.dup
    assert_equal dh1.to_der, dh2.to_der
    assert_not_nil dh1.p
    assert_not_nil dh1.g
    assert_equal [dh1.p, dh1.g], [dh2.p, dh2.g]
    assert_nil dh1.pub_key
    assert_nil dh1.priv_key
    assert_equal [dh1.pub_key, dh1.priv_key], [dh2.pub_key, dh2.priv_key]

    # With a key pair
    dh3 = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh3.generate_key!
    dh4 = dh3.dup
    assert_not_nil dh3.pub_key
    assert_not_nil dh3.priv_key
    assert_equal [dh3.pub_key, dh3.priv_key], [dh4.pub_key, dh4.priv_key]
  end

  def test_marshal
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    deserialized = Marshal.load(Marshal.dump(dh))
    assert_equal dh.to_der, deserialized.to_der
  end

  def test_public_private_predicates_params_only
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    # With only parameters, neither public nor private
    assert_equal false, dh.public?
    assert_equal false, dh.private?
  end

  def test_public_private_predicates_with_key
    dh = Fixtures.pkey_dh("dh2048_ffdhe2048")
    dh.generate_key!
    # With generated key, both are true
    assert_equal true, dh.public?
    assert_equal true, dh.private?
  end

  # GH-366: net-ssh generates its kex key this way
  def test_generate_key_from_params
    params = Fixtures.pkey_dh("dh2048_ffdhe2048")

    dh = OpenSSL::PKey.generate_key(params)

    assert_instance_of OpenSSL::PKey::DH, dh
    assert_key dh
    assert_equal params.p, dh.p
    assert_equal params.g, dh.g
    assert_no_key params # generating must not modify the parameters
  end

  def test_generate_key_from_params_is_not_reused
    params = Fixtures.pkey_dh("dh2048_ffdhe2048")

    dh1 = OpenSSL::PKey.generate_key(params)
    dh2 = OpenSSL::PKey.generate_key(params)

    assert_not_equal dh1.priv_key, dh2.priv_key
    assert_equal dh1.compute_key(dh2.pub_key), dh2.compute_key(dh1.pub_key)
  end

  # a key with a private part is still only used as a parameter template
  def test_generate_key_from_key_ignores_its_key
    key = OpenSSL::PKey.generate_key(Fixtures.pkey_dh("dh2048_ffdhe2048"))
    assert_key key

    dh = OpenSSL::PKey.generate_key(key)

    assert_equal key.p, dh.p
    assert_not_equal key.priv_key, dh.priv_key
  end

  def test_new_from_to_der_object
    dh = Fixtures.pkey_dh('dh2048')

    obj = Object.new
    pem = dh.to_pem
    obj.define_singleton_method(:to_der) { pem }
    dh2 = OpenSSL::PKey::DH.new(obj)
    assert_equal dh.p, dh2.p
    assert_equal dh.g, dh2.g
  end

  private

  def assert_no_key(dh)
    assert_equal false, dh.public?
    assert_equal false, dh.private?
    assert_nil dh.pub_key
    assert_nil dh.priv_key
  end

  def assert_key(dh)
    assert dh.public?
    assert dh.private?
    assert_kind_of OpenSSL::BN, dh.pub_key
    assert_kind_of OpenSSL::BN, dh.priv_key
  end
end
