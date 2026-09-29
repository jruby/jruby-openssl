# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestPKCS12 < TestCase

  DEFAULT_PBE_PKEYS = "AES-256-CBC"
  DEFAULT_PBE_CERTS = "AES-256-CBC"

  # BC-FIPS requires PBKDF2 passwords of at least 112 bits (SP 800-132),
  # C OpenSSL does not enforce a password length - divergence
  PASSWORD = "a-sufficiently-long-secret"
  WRONG_PASSWORD = "wrong-but-sufficiently-long"

  def setup
    super

    @key = OpenSSL::PKey::RSA.new(2048)
    @cert = issue_cert
  end

  def test_create_and_parse_with_password
    p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert)
    assert p12.to_der.bytesize > 0

    parsed = OpenSSL::PKCS12.new(p12.to_der, PASSWORD)
    assert_instance_of OpenSSL::PKey::RSA, parsed.key
    assert_equal @cert.subject.to_s, parsed.certificate.subject.to_s
  end

  def test_create_honors_iteration_counts
    p12 = OpenSSL::PKCS12.create(
      PASSWORD, "myalias", @key, @cert, nil, nil, nil, 1234, 2345
    )
    pbkdf2 = find_algorithms(p12.to_der, "1.2.840.113549.1.5.12")

    if fips?
      assert_equal [1234, 1234, 2345], pbkdf2.map { |algorithm| algorithm.value[1].value[1].value.to_i }.sort

      pbmac1 = find_algorithms(p12.to_der, "1.2.840.113549.1.5.14").first
      mac_kdf = pbmac1.value[1].value.first
      assert_equal 2345, mac_kdf.value[1].value[1].value.to_i
    else
      assert_equal [1234, 1234], pbkdf2.map { |algorithm| algorithm.value[1].value[1].value.to_i }.sort
    end
  end

  def test_create_honors_aes_pbe_options
    {
      "AES-128-CBC" => "2.16.840.1.101.3.4.1.2",
      "AES-192-CBC" => "2.16.840.1.101.3.4.1.22",
      "AES-256-CBC" => "2.16.840.1.101.3.4.1.42"
    }.each do |cipher, oid|
      p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert, nil, cipher, cipher)
      assert_equal 2, find_algorithms(p12.to_der, oid).size, cipher
    end
  end

  def test_find_algorithms_skips_invalid_asn1_octet_strings
    der = OpenSSL::ASN1::OctetString.new("\x0c\x01\xff".b).to_der

    assert_equal [], find_algorithms(der, "1.2.3")
  end

  def test_create_honors_legacy_pbe_options
    omit_on_fips 'legacy PKCS12 PBE is not approved'

    {
      "PBE-SHA1-3DES" => "1.2.840.113549.1.12.1.3",
      "PBE-SHA1-RC2-40" => "1.2.840.113549.1.12.1.6"
    }.each do |pbe, oid|
      p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert, nil, pbe, pbe)
      assert_equal 2, find_algorithms(p12.to_der, oid).size, pbe
    end
  end

  def test_create_rejects_tampered_content
    p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert)
    tampered = p12.to_der.dup
    tampered.setbyte(600, tampered.getbyte(600) ^ 0xFF)
    assert_raise(OpenSSL::PKCS12::PKCS12Error) do
      OpenSSL::PKCS12.new(tampered, PASSWORD)
    end
  end

  # BC's PBKDF2 rejects empty passwords, OpenSSL allows them (divergence)
  def test_create_with_empty_password_raises
    assert_raise(OpenSSL::PKCS12::PKCS12Error, SecurityError) do
      OpenSSL::PKCS12.create("", "myalias", @key, @cert)
    end
  end

  def test_create_with_nil_password_raises
    assert_raise(OpenSSL::PKCS12::PKCS12Error, SecurityError) do
      OpenSSL::PKCS12.create(nil, "myalias", @key, @cert)
    end
  end

  def test_parse_with_wrong_password_raises
    p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert)
    assert_raise(OpenSSL::PKCS12::PKCS12Error) do
      OpenSSL::PKCS12.new(p12.to_der, WRONG_PASSWORD)
    end
  end

  def test_create_and_parse_with_ca_certs
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(cn: "CA", key: ca_key)
    leaf_cert = issue_cert(cn: "leaf", issuer: ca_cert, issuer_key: ca_key)

    p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, leaf_cert, [ca_cert])
    parsed = OpenSSL::PKCS12.new(p12.to_der, PASSWORD)
    assert_equal leaf_cert.subject.to_s, parsed.certificate.subject.to_s
    assert_equal 1, parsed.ca_certs.size
    assert_equal ca_cert.subject.to_s, parsed.ca_certs.first.subject.to_s
  end

  def test_parse_returns_only_selected_key_chain
    unrelated_cert = issue_cert(cn: "unrelated", key: OpenSSL::PKey::RSA.new(2048))

    p12 = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert, [unrelated_cert])
    parsed = OpenSSL::PKCS12.new(p12.to_der, PASSWORD)

    assert_equal @cert.subject.to_s, parsed.certificate.subject.to_s
    assert_equal [], Array(parsed.ca_certs)
  end

  def test_create_accepts_mri_optional_pbe_args
    p12 = OpenSSL::PKCS12.create(
      PASSWORD, "myalias", @key, @cert, nil, DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS
    )

    assert_equal @cert, p12.certificate
    assert_equal @key.to_der, p12.key.to_der
    assert_nil p12.ca_certs

    parsed = OpenSSL::PKCS12.new(p12.to_der, PASSWORD)
    assert_equal @key.to_der, parsed.key.to_der
    assert_equal @cert.subject.to_s, parsed.certificate.subject.to_s
    assert_equal [], Array(parsed.ca_certs)
  end

  def test_create_rejects_unknown_pbe_algorithm
    assert_raise(ArgumentError) do
      OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert, [], "foo")
    end
  end

  def test_create_checks_key_iteration_type
    OpenSSL::PKCS12.create(
      PASSWORD, "myalias", @key, @cert, [], DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS, 2048
    )

    assert_raise(TypeError) do
      OpenSSL::PKCS12.create(
        PASSWORD, "myalias", @key, @cert, [], DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS, "omg"
      )
    end
  end

  def test_create_checks_mac_iteration_type
    OpenSSL::PKCS12.create(
      PASSWORD, "myalias", @key, @cert, [], DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS, nil, 2048
    )

    assert_raise(TypeError) do
      OpenSSL::PKCS12.create(
        PASSWORD, "myalias", @key, @cert, [], DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS, nil, "omg"
      )
    end
  end

  def test_create_checks_keytype
    OpenSSL::PKCS12.create(
      PASSWORD, "myalias", @key, @cert, [], DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS,
      nil, nil, OpenSSL::PKCS12::KEY_SIG
    )

    assert_raise(ArgumentError) do
      OpenSSL::PKCS12.create(
        PASSWORD, "myalias", @key, @cert, [], DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS, nil, nil, 2048
      )
    end
  end

  def test_dup_preserves_der
    p12 = OpenSSL::PKCS12.create(
      PASSWORD, "myalias", @key, @cert, nil, DEFAULT_PBE_PKEYS, DEFAULT_PBE_CERTS
    )

    assert_equal p12.to_der, p12.dup.to_der
  end


  # OpenSSL writes a PBMAC1 (RFC 9579) MAC instead of the PKCS12KDF one under FIPS
  # created with: openssl pkcs12 -export -macsaltlen 16 (password below)
  PBMAC1_P12 = <<~EOF.unpack1("m")
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
  EOF

  PBMAC1_PASSWORD = "a-sufficiently-long-secret"

  def test_new_with_pbmac1_mac
    p12 = OpenSSL::PKCS12.new(PBMAC1_P12, PBMAC1_PASSWORD)
    assert_instance_of OpenSSL::PKey::RSA, p12.key
    assert_equal "/CN=pbmac1-fixture", p12.certificate.subject.to_s
    assert_equal [], Array(p12.ca_certs)
  end

  def test_new_with_pbmac1_mac_rejects_wrong_password
    assert_raise(OpenSSL::PKCS12::PKCS12Error) do
      OpenSSL::PKCS12.new(PBMAC1_P12, "wrong-but-long-enough-password")
    end
  end

  def test_new_rejects_tampered_content
    tampered = PBMAC1_P12.dup
    tampered.setbyte(600, tampered.getbyte(600) ^ 0xFF)
    assert_raise(OpenSSL::PKCS12::PKCS12Error) do
      OpenSSL::PKCS12.new(tampered, PBMAC1_PASSWORD)
    end
  end

  # PBMAC1 param validation - C OpenSSL (p12_mutl.c) rejects a keyDerivationFunc that
  # is not id-PBKDF2 and a PBKDF2 keyLength that is missing or > EVP_MAX_MD_SIZE (64)
  def test_rejects_malformed_pbmac1
    skip 'PBMAC1 is only emitted in FIPS mode' unless fips?

    der = OpenSSL::PKCS12.create(PASSWORD, "myalias", @key, @cert).to_der

    not_pbkdf2 = mutate_pbmac1(der) do |kdf, _pbkdf2|
      kdf.value[0] = OpenSSL::ASN1::ObjectId.new("1.2.840.113549.1.5.13")
    end
    assert_raise(OpenSSL::PKCS12::PKCS12Error) { OpenSSL::PKCS12.new(not_pbkdf2, PASSWORD) }

    no_key_len = mutate_pbmac1(der) { |kdf, pbkdf2|
      kdf.value[1] = OpenSSL::ASN1::Sequence([ pbkdf2.value[0], pbkdf2.value[1], pbkdf2.value[3] ]) }
    assert_raise(OpenSSL::PKCS12::PKCS12Error) { OpenSSL::PKCS12.new(no_key_len, PASSWORD) }

    oversized_key_len = mutate_pbmac1(der) { |kdf, pbkdf2|
      kdf.value[1] = OpenSSL::ASN1::Sequence([ pbkdf2.value[0], pbkdf2.value[1],
        OpenSSL::ASN1::Integer.new(127), pbkdf2.value[3] ]) }
    assert_raise(OpenSSL::PKCS12::PKCS12Error) { OpenSSL::PKCS12.new(oversized_key_len, PASSWORD) }
  end

  def test_new_with_no_keys
    omit_on_fips 'fixture uses legacy PKCS12 PBE-SHA1-3DES'
    str = <<~EOF.unpack1("m")
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
AA==
    EOF
    p12 = OpenSSL::PKCS12.new(str, "abc123")

    assert_nil p12.key
    assert_nil p12.certificate
    assert_equal 1, p12.ca_certs.size
    assert_instance_of OpenSSL::X509::Certificate, p12.ca_certs.first
  end

  def test_new_with_no_certs
    omit_on_fips 'fixture uses legacy PKCS12 PBE-SHA1-3DES'
    str = <<~EOF.unpack1("m")
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
BC8fv38mue8LZVcbHQQIUNrWKEnskCoCAggA
    EOF
    p12 = OpenSSL::PKCS12.new(str, "abc123")

    assert_instance_of OpenSSL::PKey::RSA, p12.key
    assert_nil p12.certificate
    assert_equal [], Array(p12.ca_certs)
  end

  private

  # PKCS12 nests the safe bags inside OCTET STRINGs, so walk them recursively;
  # ciphertext blobs are not valid ASN.1 and are skipped
  def find_algorithms(der, oid)
    algorithms = []
    visit = lambda do |node|
      if node.is_a?(OpenSSL::ASN1::Sequence) && node.value.first.is_a?(OpenSSL::ASN1::ObjectId)
        algorithms << node if node.value.first.oid == oid
      end
      if node.value.is_a?(Array)
        node.value.each { |child| visit.call(child) }
      elsif node.is_a?(OpenSSL::ASN1::OctetString)
        begin
          visit.call(OpenSSL::ASN1.decode(node.value))
        rescue OpenSSL::ASN1::ASN1Error, ArgumentError
        end
      end
    end
    visit.call(OpenSSL::ASN1.decode(der))
    algorithms
  end

  # reach into the PBMAC1 macData params and yield [keyDerivationFunc, PBKDF2-params]
  # returns re-encoded DER after the block mutates them
  def mutate_pbmac1(der)
    root = OpenSSL::ASN1.decode(der)
    mac_alg = root.value[2].value[0].value[0]
    kdf = mac_alg.value[1].value[0]
    yield kdf, kdf.value[1]
    root.to_der
  end

  def issue_cert(cn: "test", key: nil, issuer: nil, issuer_key: nil)
    key ||= @key
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.public_key = key.public_key
    cert.sign(issuer_key || key, OpenSSL::Digest::SHA256.new)
    cert
  end

end
