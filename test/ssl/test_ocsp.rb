# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestOCSP < TestCase
  include SSLTestHelper

  def setup
    super
    # @ca_cert
    #   |
    # @cert
    #   |----------|
    # @cert2   @ocsp_cert
    now = Time.now

    ca_subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA")
    @ca_key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1
    ca_exts = [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "cRLSign,keyCertSign", true],
    ]
    @ca_cert = issue_cert(ca_subj, @ca_key, 1, ca_exts, nil, nil, not_before: now, not_after: now + 1800, digest: sha1_or_approved)

    cert_subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA2")
    @cert_key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1
    cert_exts = [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "cRLSign,keyCertSign", true],
    ]
    @cert = issue_cert(cert_subj, @cert_key, 5, cert_exts, @ca_cert, @ca_key, not_before: now, not_after: now + 1800, digest: sha1_or_approved)

    cert2_subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCert")
    @cert2_key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1
    cert2_exts = []
    @cert2 = issue_cert(cert2_subj, @cert2_key, 10, cert2_exts, @cert, @cert_key, not_before: now, not_after: now + 1800, digest: sha1_or_approved)

    ocsp_subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCAOCSP")
    @ocsp_key = OpenSSL::PKey::RSA.new TEST_KEY_RSA2
    ocsp_exts = [
      ["extendedKeyUsage", "OCSPSigning", true],
    ]
    @ocsp_cert = issue_cert(ocsp_subj, @ocsp_key, 100, ocsp_exts, @cert, @cert_key, not_before: now, not_after: now + 1800, digest: sha1_or_approved)
  end

  def test_new_certificate_id
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    assert_kind_of OpenSSL::OCSP::CertificateId, cid
    assert_equal @cert.serial, cid.serial
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    assert_kind_of OpenSSL::OCSP::CertificateId, cid
    assert_equal @cert.serial, cid.serial
  end

  def test_certificate_id_issuer_name_hash
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    assert_equal OpenSSL::Digest::SHA1.hexdigest(@cert.issuer.to_der), cid.issuer_name_hash
    assert_equal "d91f736ac4dc3242f0fb9b77a3149bd83c5c43d0", cid.issuer_name_hash
  end

  def test_certificate_id_issuer_key_hash
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    assert_equal OpenSSL::Digest::SHA1.hexdigest(OpenSSL::ASN1.decode(@ca_cert.to_der).value[0].value[6].value[1].value), cid.issuer_key_hash
    assert_equal "6eef4d0b438009bda21dd7f38a92472bc9bbfb3b", cid.issuer_key_hash
  end

  def test_certificate_id_hash_algorithm
    cid_sha1 = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    cid_sha256 = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    cid_sha384 = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA384.new)
    cid_sha512 = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA512.new)
    assert_equal "sha1", cid_sha1.hash_algorithm
    assert_equal "sha256", cid_sha256.hash_algorithm
    assert_equal "sha384", cid_sha384.hash_algorithm
    assert_equal "sha512", cid_sha512.hash_algorithm
  end

  def test_certificate_id_sha2_der
    {
      OpenSSL::Digest::SHA224.new => "SHA224",
      OpenSSL::Digest::SHA384.new => "SHA384",
      OpenSSL::Digest::SHA512.new => "SHA512",
    }.each do |digest, oid_name|
      cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, digest)
      asn1 = OpenSSL::ASN1.decode(cid.to_der)
      assert_equal OpenSSL::ASN1.ObjectId(oid_name).to_der, asn1.value[0].value[0].to_der
    end
  end

  def test_certificate_id_der
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    der = cid.to_der
    asn1 = OpenSSL::ASN1.decode(der)
    # hash algorithm defaults to SHA-1
    assert_equal OpenSSL::ASN1.ObjectId("SHA1").to_der, asn1.value[0].value[0].to_der
    assert_equal [cid.issuer_name_hash].pack("H*"), asn1.value[1].value
    assert_equal [cid.issuer_key_hash].pack("H*"), asn1.value[2].value
    assert_equal @cert.serial, asn1.value[3].value
    assert_equal der, OpenSSL::OCSP::CertificateId.new(der).to_der
  end

  def test_certificate_id_dup
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    other = cid.dup.to_der
    assert_equal cid.to_der, other
  end

  def test_request_der
    request = OpenSSL::OCSP::Request.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    request.add_certid(cid)
    request.sign(@cert, @cert_key, [@ca_cert], 0, OpenSSL::Digest::SHA256.new)
    asn1 = OpenSSL::ASN1.decode(request.to_der)
    # TODO: ASN1#to_der seems to be missing some data...
    # assert_equal cid.to_der, asn1.value[0].value.find { |a| a.tag_class == :UNIVERSAL }.value[0].value[0].to_der
    assert_equal OpenSSL::ASN1.ObjectId("sha256WithRSAEncryption").to_der, asn1.value[1].value[0].value[0].value[0].to_der
    # assert_equal @cert.to_der, asn1.value[1].value[0].value[2].value[0].value[0].to_der
    # assert_equal @ca_cert.to_der, asn1.value[1].value[0].value[2].value[0].value[1].to_der
    # assert_equal asn1.to_der, OpenSSL::OCSP::Request.new(asn1.to_der).to_der
  end

  def test_request_sign_verify
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    store = OpenSSL::X509::Store.new.add_cert(@ca_cert)

    # with signer cert
    req = OpenSSL::OCSP::Request.new.add_certid(cid)
    req.sign(@cert, @cert_key, [], 0, OpenSSL::Digest::SHA256.new)
    assert_equal true, req.verify([], store)

    unless fips?
      # without signer cert
      req = OpenSSL::OCSP::Request.new.add_certid(cid)
      req.sign(@cert, @cert_key, nil, 0, OpenSSL::Digest::SHA256.new)
      assert_equal false, req.verify([@cert2], store)
      assert_equal false, req.verify([], store) # no signer
      assert_equal false, req.verify([], store, OpenSSL::OCSP::NOVERIFY)

      assert_equal true, req.verify([@cert], store, OpenSSL::OCSP::NOINTERN)
      ret = req.verify([@cert], store)

    if ret || OpenSSL::OPENSSL_VERSION =~ /OpenSSL/ && OpenSSL::OPENSSL_VERSION_NUMBER >= 0x10002000
      assert_equal true, ret
    else
      # RT2560; OCSP_request_verify() does not find signer cert from 'certs' when
      # OCSP_NOINTERN is not specified.
      # fixed by OpenSSL 1.0.1j, 1.0.2 and LibreSSL 2.4.2
      pend "RT2560: ocsp_req_find_signer"
      end
    end
  end

  def test_request_nonce
    req0 = OpenSSL::OCSP::Request.new
    req1 = OpenSSL::OCSP::Request.new.add_nonce("NONCE")
    req2 = OpenSSL::OCSP::Request.new.add_nonce("ABCDE")
    bres = OpenSSL::OCSP::BasicResponse.new
    assert_equal 2, req0.check_nonce(bres)
    bres.copy_nonce(req1)
    assert_equal 3, req0.check_nonce(bres)
    assert_equal 1, req1.check_nonce(bres)
    bres.add_nonce("NONCE")
    assert_equal 1, req1.check_nonce(bres)
    assert_equal 0, req2.check_nonce(bres)
  end

  def test_request_is_signed
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    req = OpenSSL::OCSP::Request.new.add_certid(cid)

    assert_equal false, req.signed?
    assert_equal false, OpenSSL::OCSP::Request.new(req.to_der).signed?

    req.sign(@cert, @cert_key, [], 0, OpenSSL::Digest::SHA256.new)
    assert_equal true, req.signed?
    assert_equal true, OpenSSL::OCSP::Request.new(req.to_der).signed?
  end

  def test_request_dup
    request = OpenSSL::OCSP::Request.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    request.add_certid(cid)
    assert_equal request.to_der, request.dup.to_der
  end

  def test_basic_response_der
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, 0, nil, -300, 500, [])
    bres.add_nonce("NONCE")
    bres.sign(@ocsp_cert, @ocsp_key, [@ca_cert], 0, OpenSSL::Digest::SHA256.new)
    der = bres.to_der
    asn1 = OpenSSL::ASN1.decode(der)
    assert_equal OpenSSL::ASN1.Sequence([@ocsp_cert, @ca_cert]).to_der, asn1.value[3].value[0].to_der
    assert_equal der, OpenSSL::OCSP::BasicResponse.new(der).to_der
  # rescue TypeError
  #   if /GENERALIZEDTIME/ =~ $!.message
  #     pend "OCSP_basic_sign() is broken"
  #   else
  #     raise
  #   end
  end

  def test_basic_response_sign_verify
    omit_on_fips 'OCSP BasicResponse#sign defaults to SHA-1'
    store = OpenSSL::X509::Store.new.add_cert(@ca_cert)

    # signed by CA
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, -400, -300, 500, [])
    bres.sign(@ca_cert, @ca_key, nil, 0, OpenSSL::Digest::SHA256.new)
    assert_equal false, bres.verify([], store) # signer not found
    assert_equal true, bres.verify([@ca_cert], store)
    bres.sign(@ca_cert, @ca_key, [], 0, OpenSSL::Digest::SHA256.new)
    assert_equal true, bres.verify([], store)
    assert_equal true, bres.verify([@ca_cert], store, OpenSSL::OCSP::NOSIGS | OpenSSL::OCSP::NOVERIFY)

    # signed by OCSP signer
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert2, @cert)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, -400, -300, 500, [])
    bres.sign(@ocsp_cert, @ocsp_key, [@cert])
    assert_equal true, bres.verify([], store)
    assert_equal false, bres.verify([], store, OpenSSL::OCSP::NOCHAIN)
    # OpenSSL had a bug on this; test that our workaround works
    bres.sign(@ocsp_cert, @ocsp_key, [], 0, OpenSSL::Digest::SHA256.new)
    assert_equal true, bres.verify([@cert], store)
  end

  def test_basic_response_rejects_invalid_signature
    store = OpenSSL::X509::Store.new.add_cert(@ca_cert)
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, -400, -300, 500, [])
    bres.sign(@ca_cert, @ca_key, nil, 0, OpenSSL::Digest::SHA256.new)
    assert_equal true, bres.verify([@ca_cert], store)

    der = OpenSSL::ASN1.decode(bres.to_der)
    signature = der.value[2]
    signature.value = signature.value.dup
    signature.value.setbyte(0, signature.value.getbyte(0) ^ 1)

    tampered = OpenSSL::OCSP::BasicResponse.new(der.to_der)
    assert_equal false, tampered.verify([@ca_cert], store)
  end

  def test_basic_response_nochecks_requires_valid_chain
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, -400, -300, 500, [])
    bres.sign(@ca_cert, @ca_key, nil, 0, OpenSSL::Digest::SHA256.new)

    assert_equal false, bres.verify([@ca_cert], OpenSSL::X509::Store.new, OpenSSL::OCSP::NOCHECKS)
    assert_equal true, bres.verify([@ca_cert], OpenSSL::X509::Store.new.add_cert(@ca_cert), OpenSSL::OCSP::NOCHECKS)
  end

  def test_basic_response_noexplicit
    store = OpenSSL::X509::Store.new.add_cert(@ca_cert)

    valid = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA256.new)
    valid.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, -400, -300, 500, [])
    valid.sign(@ca_cert, @ca_key, nil, 0, OpenSSL::Digest::SHA256.new)
    assert_equal true, valid.verify([@ca_cert], store, OpenSSL::OCSP::NOEXPLICIT)

    mismatched = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert2, @cert, OpenSSL::Digest::SHA256.new)
    mismatched.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, -400, -300, 500, [])
    mismatched.sign(@ca_cert, @ca_key, nil, 0, OpenSSL::Digest::SHA256.new)
    assert_equal false, mismatched.verify([@ca_cert], store, OpenSSL::OCSP::NOEXPLICIT)
    assert_equal false, mismatched.verify([@ca_cert], store, OpenSSL::OCSP::NOEXPLICIT | OpenSSL::OCSP::NOCHAIN)
  end

  def test_basic_response_dup
    omit_on_fips 'OCSP BasicResponse#sign defaults to SHA-1'
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, 0, nil, -300, 500, [])
    bres.sign(@ocsp_cert, @ocsp_key, [@ca_cert], 0)
    assert_equal bres.to_der, bres.dup.to_der
  end

  def test_basic_response_response_operations
    bres = OpenSSL::OCSP::BasicResponse.new
    now = Time.at(Time.now.to_i) # OCSP times are whole-second (ASN.1 GeneralizedTime)
    cid1 = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    cid2 = OpenSSL::OCSP::CertificateId.new(@ocsp_cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    cid3 = OpenSSL::OCSP::CertificateId.new(@ca_cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    bres.add_status(cid1, OpenSSL::OCSP::V_CERTSTATUS_REVOKED, OpenSSL::OCSP::REVOKED_STATUS_UNSPECIFIED, now - 400, -300, nil, nil)
    bres.add_status(cid2, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, nil, -300, 500, [])
    now_after = Time.at(Time.now.to_i)

    assert_equal 2, bres.responses.size
    single = bres.responses.first
    assert_equal cid1.to_der, single.certid.to_der
    assert_equal OpenSSL::OCSP::V_CERTSTATUS_REVOKED, single.cert_status
    assert_equal OpenSSL::OCSP::REVOKED_STATUS_UNSPECIFIED, single.revocation_reason
    assert_equal now - 400, single.revocation_time
    # this_update was set from a relative -300 offset applied to Time.now inside add_status
    # a tight assert_in_delta is flaky on (slow) CI when a second boundary is crossed between capturing `now` and add_status
    assert_operator single.this_update, :>=, now - 301
    assert_operator single.this_update, :<=, now_after - 299
    assert_equal nil, single.next_update
    assert_equal [], single.extensions

    assert_equal cid2.to_der, bres.find_response(cid2).certid.to_der
    assert_equal nil, bres.find_response(cid3)
  end

  def test_single_response_der
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, nil, -300, 500, nil)
    single = bres.responses[0]
    der = single.to_der
    asn1 = OpenSSL::ASN1.decode(der)
    assert_equal :CONTEXT_SPECIFIC, asn1.value[1].tag_class
    assert_equal 0, asn1.value[1].tag # good
    assert_equal der, OpenSSL::OCSP::SingleResponse.new(der).to_der
  end

  def test_single_response_check_validity
    bres = OpenSSL::OCSP::BasicResponse.new
    cid1 = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    cid2 = OpenSSL::OCSP::CertificateId.new(@ocsp_cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    bres.add_status(cid1, OpenSSL::OCSP::V_CERTSTATUS_REVOKED, OpenSSL::OCSP::REVOKED_STATUS_UNSPECIFIED, -400, -300, -50, [])
    bres.add_status(cid2, OpenSSL::OCSP::V_CERTSTATUS_REVOKED, OpenSSL::OCSP::REVOKED_STATUS_UNSPECIFIED, -400, -300, nil, [])
    bres.add_status(cid2, OpenSSL::OCSP::V_CERTSTATUS_GOOD, nil, nil, Time.now + 100, nil, nil)

    if bres.responses[2].check_validity # thisUpdate is in future; must fail
      # LibreSSL bug; skip for now
      #pend "OCSP_check_validity() is broken"
    end

    single1 = bres.responses[0]
    assert_equal false, single1.check_validity
    assert_equal false, single1.check_validity(30)
    assert_equal true, single1.check_validity(60)
    single2 = bres.responses[1]
    assert_equal true, single2.check_validity
    assert_equal true, single2.check_validity(0, 500)
    assert_equal false, single2.check_validity(0, 200)
  end

  def test_response
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, 0, nil, -300, 500, [])
    bres.sign(@ocsp_cert, @ocsp_key, [], 0, OpenSSL::Digest::SHA256.new)
    res = OpenSSL::OCSP::Response.create(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, bres)

    assert_equal bres.to_der, res.basic.to_der
    assert_equal OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, res.status
  end

  def test_response_der
    bres = OpenSSL::OCSP::BasicResponse.new
    cid = OpenSSL::OCSP::CertificateId.new(@cert, @ca_cert, OpenSSL::Digest::SHA1.new)
    bres.add_status(cid, OpenSSL::OCSP::V_CERTSTATUS_GOOD, 0, nil, -300, 500, [])
    bres.sign(@ocsp_cert, @ocsp_key, [@ca_cert], 0, OpenSSL::Digest::SHA256.new)
    res = OpenSSL::OCSP::Response.create(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, bres)
    der = res.to_der
    asn1 = OpenSSL::ASN1.decode(der)
    assert_equal OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, asn1.value[0].value
    assert_equal OpenSSL::ASN1.ObjectId("basicOCSPResponse").to_der, asn1.value[1].value[0].value[0].to_der
    assert_equal bres.to_der, asn1.value[1].value[0].value[1].value
    assert_equal der, OpenSSL::OCSP::Response.new(der).to_der
  end

  def test_response_dup
    bres = OpenSSL::OCSP::BasicResponse.new
    bres.sign(@ocsp_cert, @ocsp_key, [@ca_cert], 0, OpenSSL::Digest::SHA256.new)
    res = OpenSSL::OCSP::Response.create(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, bres)
    assert_equal res.to_der, res.dup.to_der
  end
end
