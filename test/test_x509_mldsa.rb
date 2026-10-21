require_relative 'test_helper'

class TestX509MLDSA < TestCase
  ALGORITHMS = %w[ML-DSA-44 ML-DSA-65 ML-DSA-87].freeze
  CA_EXTENSIONS = [
    ['basicConstraints', 'CA:TRUE', true],
    ['keyUsage', 'keyCertSign,cRLSign', true]
  ].freeze

  def test_certificate_public_key_and_roundtrip
    ALGORITHMS.each do |algorithm|
      key = generate_key(algorithm)
      other = generate_key(algorithm)
      public_key = OpenSSL::PKey.read(key.public_to_der)
      cert = issue_cert(distinguished_name(algorithm), public_key, 1, [], nil, key, digest: nil)

      [cert, OpenSSL::X509::Certificate.new(cert.to_der),
       OpenSSL::X509::Certificate.new(cert.to_pem)].each do |copy|
        assert_equal algorithm, copy.signature_algorithm
        assert_equal "id-ml-dsa-#{algorithm.split('-').last}", copy.public_key.oid
        assert_equal key.public_to_der, copy.public_key.public_to_der
        assert_equal false, copy.public_key.private?
        assert_equal true, copy.check_private_key(key)
        assert_equal false, copy.check_private_key(other)
        assert_equal true, copy.verify(copy.public_key)
        assert_equal false, copy.verify(other)
        assert_equal cert.to_der, copy.to_der
      end
    end
  end

  def test_request_sign_verify_and_roundtrip
    ALGORITHMS.each do |algorithm|
      key = generate_key(algorithm)
      other = generate_key(algorithm)
      request = OpenSSL::X509::Request.new
      request.version = 0
      request.subject = distinguished_name(algorithm)
      request.public_key = OpenSSL::PKey.read(key.public_to_der)
      assert_same request, request.sign(key, nil)

      [request, OpenSSL::X509::Request.new(request.to_der),
       OpenSSL::X509::Request.new(request.to_pem)].each do |copy|
        assert_equal algorithm, copy.signature_algorithm
        assert_equal "id-ml-dsa-#{algorithm.split('-').last}", copy.public_key.oid
        assert_equal key.public_to_der, copy.public_key.public_to_der
        assert_equal false, copy.public_key.private?
        assert_equal true, copy.verify(copy.public_key)
        assert_equal false, copy.verify(other)
        assert_equal request.to_der, copy.to_der
      end

      request.subject = distinguished_name('modified')
      assert_equal false, request.verify(key)
    end
  end

  def test_crl_sign_verify_and_roundtrip
    ALGORITHMS.each do |algorithm|
      key = generate_key(algorithm)
      other = generate_key(algorithm)
      ca = issue_cert(distinguished_name(algorithm), key, 1, CA_EXTENSIONS, nil, nil, digest: nil)
      now = Time.now
      crl = issue_crl([[2, now - 60, 1]], 1, now - 60, now + 3600, [], ca, key, nil)

      [crl, OpenSSL::X509::CRL.new(crl.to_der),
       OpenSSL::X509::CRL.new(crl.to_pem)].each do |copy|
        assert_equal algorithm, copy.signature_algorithm
        assert_equal true, copy.verify(ca.public_key)
        assert_equal false, copy.verify(other)
        assert_equal 2, copy.revoked.first.serial.to_i
        assert_equal crl.to_der, copy.to_der
      end
    end
  end

  def test_mixed_classical_and_mldsa_chains
    rsa = Fixtures.pkey('rsa2048')
    ALGORITHMS.each do |algorithm|
      key = generate_key(algorithm)
      [[rsa, key, rsa], [key, rsa, key]].each do |root_key, issuer_key, leaf_key|
        root_digest = root_key.equal?(rsa) ? 'SHA256' : nil
        issuer_digest = issuer_key.equal?(rsa) ? 'SHA256' : nil
        root = issue_cert(distinguished_name('root'), root_key, 1, CA_EXTENSIONS,
                          nil, nil, digest: root_digest)
        issuer = issue_cert(distinguished_name('intermediate'), issuer_key, 2, CA_EXTENSIONS,
                            root, root_key, digest: root_digest)
        leaf = issue_cert(distinguished_name('leaf'), leaf_key, 3,
                          [['keyUsage', 'digitalSignature', true]],
                          issuer, issuer_key, digest: issuer_digest)
        store = OpenSSL::X509::Store.new
        store.add_cert(OpenSSL::X509::Certificate.new(root.to_der))
        assert_equal true, store.verify(OpenSSL::X509::Certificate.new(leaf.to_pem),
                                        [OpenSSL::X509::Certificate.new(issuer.to_der)]), store.error_string
        assert_equal true, issuer.verify(root.public_key)
        assert_equal true, leaf.verify(issuer.public_key)
      end
    end
  end

  def test_signing_rejects_digests
    ALGORITHMS.each do |algorithm|
      key = generate_key(algorithm)
      cert = issue_cert(distinguished_name(algorithm), key, 1, [], nil, nil, digest: nil)
      request = OpenSSL::X509::Request.new
      request.version = 0
      request.subject = distinguished_name(algorithm)
      request.public_key = OpenSSL::PKey.read(key.public_to_der)
      crl = issue_crl([], 1, Time.now - 60, Time.now + 3600, [], cert, key, nil)

      ['SHA256', OpenSSL::Digest::SHA512.new].each do |digest|
        assert_raise(OpenSSL::X509::CertificateError) { cert.sign(key, digest) }
        assert_raise(OpenSSL::X509::RequestError) { request.sign(key, digest) }
        assert_raise(OpenSSL::X509::CRLError) { crl.sign(key, digest) }
      end
    end
  end

  private

  def generate_key(algorithm)
    OpenSSL::PKey.generate_key(algorithm)
  rescue OpenSSL::PKey::PKeyError => error
    raise unless fips? && error.message.include?('unsupported algorithm')
    skip("#{algorithm} unavailable from the FIPS provider: #{error.message}")
  end

  def distinguished_name(common_name)
    OpenSSL::X509::Name.new([['CN', common_name]])
  end
end
