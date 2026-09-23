# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestTimestamp < TestCase
  def setup
    super
    now = Time.at(Time.now.to_i)
    ca_name = OpenSSL::X509::Name.parse('/CN=Timestamp CA')
    @ca_key = Fixtures.pkey('rsa2048')
    @ca_cert = issue_cert(ca_name, @ca_key, 1,
      [['basicConstraints', 'CA:TRUE', true], ['keyUsage', 'keyCertSign,cRLSign', true]],
      nil, nil, not_before: now - 60, not_after: now + 3600)

    tsa_name = OpenSSL::X509::Name.parse('/CN=Timestamp TSA')
    @tsa_key = Fixtures.pkey('custom/rsa-2048-private.pem')
    @tsa_cert = issue_cert(tsa_name, @tsa_key, 2,
      [['keyUsage', 'digitalSignature', true], ['extendedKeyUsage', 'timeStamping', true]],
      @ca_cert, @ca_key, not_before: now - 60, not_after: now + 3600)
  end

  def test_request_round_trip
    request = OpenSSL::Timestamp::Request.new
    assert_equal 1, request.version
    assert_equal true, request.cert_requested?
    assert_equal 'NULL', request.algorithm
    assert_equal '', request.message_imprint

    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'
    request.nonce = 42
    der = request.to_der

    parsed = OpenSSL::Timestamp::Request.new(der)
    assert_equal 'SHA256', parsed.algorithm
    assert_equal request.message_imprint, parsed.message_imprint
    assert_equal '1.2.3.4.5', parsed.policy_id
    assert_equal 42, parsed.nonce
    assert_equal der, parsed.to_der
    assert_match(/SHA256/i, parsed.to_text)
  end

  def test_request_mandatory_fields
    request = OpenSSL::Timestamp::Request.new
    assert_raise(OpenSSL::Timestamp::TimestampError) { request.to_der }
    request.algorithm = 'SHA256'
    assert_raise(OpenSSL::Timestamp::TimestampError) { request.to_der }
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    assert_nothing_raised { request.to_der }
  end

  def test_factory_and_response_round_trip
    request = OpenSSL::Timestamp::Request.new
    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'
    request.nonce = 42

    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = Time.at(Time.now.to_i)
    factory.serial_number = 7
    factory.allowed_digests = ['SHA256']
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_equal OpenSSL::Timestamp::Response::GRANTED, response.status
    assert_nil response.failure_info
    assert_equal '1.2.3.4.5', response.token_info.policy_id
    assert_equal 'SHA256', response.token_info.algorithm
    assert_equal request.message_imprint, response.token_info.message_imprint
    assert_equal 7, response.token_info.serial_number
    assert_equal 42, response.token_info.nonce
    assert_equal @tsa_cert.to_der, response.tsa_certificate.to_der

    parsed = OpenSSL::Timestamp::Response.new(response.to_der)
    assert_equal response.to_der, parsed.to_der
    assert_equal OpenSSL::Timestamp::Response::GRANTED, parsed.status
    assert_equal @tsa_cert.to_der, parsed.tsa_certificate.to_der
    assert_match(/1\.2\.3\.4\.5/, parsed.to_text)
    assert_match(/1\.2\.3\.4\.5/, parsed.token_info.to_text)
  end

  def test_response_failure_info
    request = OpenSSL::Timestamp::Request.new
    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'
    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = Time.now
    factory.serial_number = 1
    factory.allowed_digests = ['SHA384']
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)
    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
    assert_equal :BAD_ALG, response.failure_info
    assert_nil response.token
    assert_nil response.token_info
  end

  def test_factory_rejects_non_timestamp_certificate
    request = OpenSSL::Timestamp::Request.new
    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'

    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = Time.now
    factory.serial_number = 1
    factory.allowed_digests = ['SHA256']
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      factory.create_timestamp(@tsa_key, @ca_cert, request)
    end
  end

  def test_response_verify
    request = OpenSSL::Timestamp::Request.new
    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'

    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = Time.now
    factory.serial_number = 1
    factory.allowed_digests = ['SHA256']
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)

    store = OpenSSL::X509::Store.new
    store.add_cert(@ca_cert)
    assert_same response, response.verify(request, store)
  end

  def test_factory_without_certificate_request
    request = OpenSSL::Timestamp::Request.new
    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'
    request.cert_requested = false

    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = Time.now
    factory.serial_number = 1
    factory.allowed_digests = ['SHA256']
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_equal OpenSSL::Timestamp::Response::GRANTED, response.status
    assert_nil response.tsa_certificate
    assert_nil response.token.certificates
    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store) }
    assert_same response, response.verify(request, trusted_store, [@tsa_cert])
  end

  def test_response_verify_embedded_intermediate
    intermediate, tsa = intermediate_chain
    request = timestamp_request
    factory = timestamp_factory
    factory.additional_certs = [intermediate]
    response = factory.create_timestamp(@tsa_key, tsa, request)

    assert_same response, response.verify(request, trusted_store)
  end

  def test_response_verify_supplied_intermediate
    intermediate, tsa = intermediate_chain
    request = timestamp_request
    response = timestamp_factory.create_timestamp(@tsa_key, tsa, request)

    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store) }
    assert_same response, response.verify(request, trusted_store, [intermediate])
  end

  def test_response_verify_supplied_signer_and_intermediate
    intermediate, tsa = intermediate_chain
    request = timestamp_request
    request.cert_requested = false
    response = timestamp_factory.create_timestamp(@tsa_key, tsa, request)

    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store, [tsa]) }
    assert_same response, response.verify(request, trusted_store, [tsa, intermediate])
  end

  def test_response_verify_untrusted_chain
    request = timestamp_request
    factory = timestamp_factory
    factory.additional_certs = [@ca_cert]
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_raise(OpenSSL::Timestamp::TimestampError) do
      response.verify(request, OpenSSL::X509::Store.new)
    end
  end

  def test_response_verify_wrong_imprint
    request = timestamp_request
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'other data')

    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store) }
  end

  def test_response_verify_wrong_digest
    request = timestamp_request
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)
    request.algorithm = 'SHA384'
    request.message_imprint = OpenSSL::Digest.digest('SHA384', 'data')

    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store) }
  end

  def test_response_verify_wrong_nonce
    request = timestamp_request
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)
    request.nonce = 43

    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store) }
  end

  def test_response_verify_wrong_policy
    request = timestamp_request
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)
    request.policy_id = '1.2.3.4.6'

    assert_raise(OpenSSL::Timestamp::TimestampError) { response.verify(request, trusted_store) }
  end

  def test_response_verify_tampered_signature
    request = timestamp_request
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)
    asn1 = OpenSSL::ASN1.decode(response.to_der)
    signed_data = asn1.value[1].value[1].value[0]
    signer_info = signed_data.value.last.value.first
    signature = signer_info.value.find { |value| value.is_a?(OpenSSL::ASN1::OctetString) }
    signature.value.setbyte(0, signature.value.getbyte(0) ^ 1)
    tampered = OpenSSL::Timestamp::Response.new(asn1.to_der)

    assert_raise(OpenSSL::Timestamp::TimestampError) { tampered.verify(request, trusted_store) }
  end

  def test_malformed_der
    [OpenSSL::Timestamp::Request, OpenSSL::Timestamp::Response, OpenSSL::Timestamp::TokenInfo].each do |type|
      ['', 'invalid', OpenSSL::ASN1::Sequence.new([]).to_der].each do |der|
        assert_raise(OpenSSL::Timestamp::TimestampError) { type.new(der) }
      end
    end
  end

  def test_factory_invalid_request_version
    request = timestamp_request
    request.version = 2
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
    assert_equal :BAD_REQUEST, response.failure_info
    assert_nil response.token
  end

  def test_factory_invalid_imprint_length
    request = timestamp_request
    request.message_imprint = 'too short'
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
    assert_equal :BAD_DATA_FORMAT, response.failure_info
    assert_nil response.token
  end

  def test_factory_rejects_mismatched_key
    response = timestamp_factory.create_timestamp(@ca_key, @tsa_cert, timestamp_request)

    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
    assert_nil response.token
  end

  def test_factory_nil_allowed_digests
    factory = timestamp_factory
    factory.allowed_digests = nil
    response = factory.create_timestamp(@tsa_key, @tsa_cert, timestamp_request)

    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
    assert_equal :BAD_ALG, response.failure_info
    assert_nil response.token
  end

  def test_response_token_pkcs7
    factory = timestamp_factory
    factory.additional_certs = [@ca_cert]
    response = factory.create_timestamp(@tsa_key, @tsa_cert, timestamp_request)
    token = response.token

    assert_kind_of OpenSSL::PKCS7, token
    assert_equal :signed, token.type
    assert_equal [@ca_cert.to_der, @tsa_cert.to_der].sort, token.certificates.map(&:to_der).sort
    parsed = OpenSSL::PKCS7.new(token.to_der)
    assert_equal token.to_der, parsed.to_der
    assert_equal :signed, parsed.type
  end

  def test_token_info_round_trip
    request = timestamp_request
    factory = timestamp_factory
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)
    info = OpenSSL::Timestamp::TokenInfo.new(response.token_info.to_der)

    assert_equal response.token_info.to_der, info.to_der
    assert_equal 1, info.version
    assert_equal request.policy_id, info.policy_id
    assert_equal request.algorithm, info.algorithm
    assert_equal request.message_imprint, info.message_imprint
    assert_equal request.nonce, info.nonce
    assert_equal factory.serial_number, info.serial_number
    assert_equal factory.gen_time, info.gen_time
    assert_equal false, info.ordering
  end

  def test_request_assignment_errors
    request = timestamp_request
    [:algorithm, :policy_id, :message_imprint, :nonce, :version].each do |attribute|
      assert_raise(TypeError) { request.public_send("#{attribute}=", nil) }
    end
    [:algorithm, :policy_id].each do |attribute|
      assert_raise(OpenSSL::ASN1::ASN1Error) { request.public_send("#{attribute}=", 'invalid') }
    end
    assert_raise(TypeError) { request.algorithm = 4 }
    assert_raise(TypeError) { request.nonce = '123' }
    assert_raise(OpenSSL::Timestamp::TimestampError) { request.version = -1 }
    request.cert_requested = nil
    assert_equal false, request.cert_requested?
  end

  def test_sha1_imprint_with_sha256_signature
    request = timestamp_request
    request.algorithm = 'SHA1'
    request.message_imprint = OpenSSL::Digest.digest('SHA1', 'data')
    factory = timestamp_factory
    factory.allowed_digests = ['SHA1']
    response = factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_equal OpenSSL::Timestamp::Response::GRANTED, response.status
    assert_equal 'SHA1', response.token_info.algorithm
    signed_data = OpenSSL::ASN1.decode(response.token.to_der).value[1].value[0]
    signer_info = signed_data.value.last.value.first
    assert_equal '2.16.840.1.101.3.4.2.1', signer_info.value[2].value[0].oid
    assert_same response, response.verify(request, trusted_store)
  end

  def test_factory_rejects_request_extensions
    request = timestamp_request
    extension = OpenSSL::X509::Extension.new('1.2.3.4.9', 'unsupported')
    asn1 = OpenSSL::ASN1.decode(request.to_der)
    asn1.value << OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1.decode(extension.to_der)], 0, :CONTEXT_SPECIFIC)
    request = OpenSSL::Timestamp::Request.new(asn1.to_der)
    response = timestamp_factory.create_timestamp(@tsa_key, @tsa_cert, request)

    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
    assert_equal :UNACCEPTED_EXTENSION, response.failure_info
    assert_nil response.token
  end

  def test_factory_rejects_invalid_certificate_purpose
    [
      [['keyUsage', 'keyEncipherment', true], ['extendedKeyUsage', 'timeStamping', true]],
      [['keyUsage', 'digitalSignature,keyEncipherment', true], ['extendedKeyUsage', 'timeStamping', true]],
      [['extendedKeyUsage', 'timeStamping', false]],
      [['extendedKeyUsage', 'timeStamping,serverAuth', true]]
    ].each do |extensions|
      cert = issue_cert(@tsa_cert.subject, @tsa_key, 5, extensions, @ca_cert, @ca_key)
      assert_raise(OpenSSL::Timestamp::TimestampError) do
        timestamp_factory.create_timestamp(@tsa_key, cert, timestamp_request)
      end
    end
  end

  def test_factory_accepts_certificate_purpose
    [
      [['keyUsage', 'nonRepudiation', true], ['extendedKeyUsage', 'timeStamping', true]],
      [['extendedKeyUsage', 'timeStamping', true]]
    ].each do |extensions|
      cert = issue_cert(@tsa_cert.subject, @tsa_key, 5, extensions, @ca_cert, @ca_key)
      request = timestamp_request
      response = timestamp_factory.create_timestamp(@tsa_key, cert, request)
      assert_equal OpenSSL::Timestamp::Response::GRANTED, response.status
      assert_same response, response.verify(request, trusted_store)
    end
  end

  def test_response_status_text
    text = ['first status message', 'second status message']
    status = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(2),
      OpenSSL::ASN1::Sequence.new(text.map { |value| OpenSSL::ASN1::UTF8String.new(value) })
    ])
    response = OpenSSL::Timestamp::Response.new(OpenSSL::ASN1::Sequence.new([status]).to_der)

    assert_equal text, response.status_text
    assert_equal OpenSSL::Timestamp::Response::REJECTION, response.status
  end

  private

  def timestamp_request
    request = OpenSSL::Timestamp::Request.new
    request.algorithm = 'SHA256'
    request.message_imprint = OpenSSL::Digest.digest('SHA256', 'data')
    request.policy_id = '1.2.3.4.5'
    request.nonce = 42
    request
  end

  def timestamp_factory
    factory = OpenSSL::Timestamp::Factory.new
    factory.gen_time = Time.at(Time.now.to_i)
    factory.serial_number = 7
    factory.allowed_digests = ['SHA256']
    factory
  end

  def trusted_store
    store = OpenSSL::X509::Store.new
    store.add_cert(@ca_cert)
    store
  end

  def intermediate_chain
    intermediate = issue_cert(OpenSSL::X509::Name.parse('/CN=Timestamp Intermediate'), @ca_key, 3,
      [['basicConstraints', 'CA:TRUE', true], ['keyUsage', 'keyCertSign,cRLSign', true]],
      @ca_cert, @ca_key)
    tsa = issue_cert(OpenSSL::X509::Name.parse('/CN=Intermediate Timestamp TSA'), @tsa_key, 4,
      [['keyUsage', 'digitalSignature', true], ['extendedKeyUsage', 'timeStamping', true]],
      intermediate, @ca_key)
    [intermediate, tsa]
  end
end
