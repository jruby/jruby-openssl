# coding: US-ASCII
require File.expand_path('../pkcs7_helper', File.dirname(__FILE__))

module PKCS7Test
  class TestPKCS7 < TestCase
    def test_is_signed
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      assert p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_encrypted
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert !p7.signed?
      assert p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_enveloped
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert !p7.signed?
      assert !p7.encrypted?
      assert p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_signed_and_enveloped
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped
      assert !p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_is_data
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert !p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert p7.data?
      assert !p7.digest?
    end

    def test_is_digest
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      assert !p7.signed?
      assert !p7.encrypted?
      assert !p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert p7.digest?
    end

    def test_set_detached
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed

      sign = Signed.new
      p7.sign = sign

      test_p7 = PKCS7.new
      test_p7.type = ASN1Registry::NID_pkcs7_data
      test_p7.data = OctetString.new("foo".to_java_bytes)
      sign.contents = test_p7

      p7.detached = 2
      assert_equal 1, p7.get_detached
      assert_equal nil, test_p7.get_data
    end

    def test_set_not_detached
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed

      sign = Signed.new
      p7.sign = sign

      test_p7 = PKCS7.new
      test_p7.type = ASN1Registry::NID_pkcs7_data
      data = OctetString.new("foo".to_java_bytes)
      test_p7.data = data
      sign.contents = test_p7

      p7.detached = 0
      assert_equal 0, p7.get_detached
      assert_equal data, test_p7.get_data
    end

    def test_is_detached
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed

      sign = Signed.new
      p7.sign = sign

      test_p7 = PKCS7.new
      test_p7.type = ASN1Registry::NID_pkcs7_data
      data = OctetString.new("foo".to_java_bytes)
      test_p7.data = data
      sign.contents = test_p7

      p7.detached = 1
      assert p7.detached?
    end

    def test_is_detached_with_wrong_type
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data

      assert !p7.detached?
    end

    def _test_encrypt_generates_enveloped_pkcs7_object
      p7 = PKCS7.encrypt([], "".to_java_bytes, nil, 0)
      assert !p7.signed?
      assert !p7.encrypted?
      assert p7.enveloped?
      assert !p7.signed_and_enveloped?
      assert !p7.data?
      assert !p7.digest?
    end

    def test_set_type_throws_exception_on_wrong_argument
      assert_raise_pkcs7_exception do
        # 42 is a value that is not one of the valid NID's for type
        PKCS7.new.type = 42
      end
    end

    def test_set_type_signed
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed

      assert p7.signed?
      assert_equal 1, p7.get_sign.version

      assert_nil p7.get_data
      assert_nil p7.get_enveloped
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    OctetString = org.bouncycastle.asn1.DEROctetString

    def test_set_type_data
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data

      assert p7.data?
      assert_equal OctetString.new("".to_java_bytes), p7.get_data

      assert_nil p7.get_sign
      assert_nil p7.get_enveloped
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_signed_and_enveloped
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped

      assert p7.signed_and_enveloped?
      assert_equal 1, p7.get_signed_and_enveloped.version
      assert_equal ASN1Registry::NID_pkcs7_data, p7.get_signed_and_enveloped.enc_data.content_type

      assert_nil p7.get_sign
      assert_nil p7.get_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_enveloped
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped

      assert p7.enveloped?
      assert_equal 0, p7.get_enveloped.version
      assert_equal ASN1Registry::NID_pkcs7_data, p7.get_enveloped.enc_data.content_type

      assert_nil p7.get_sign
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_digest
      assert_nil p7.get_encrypted
      assert_nil p7.get_other
    end

    def test_set_type_encrypted
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted

      assert p7.encrypted?
      assert_equal 0, p7.get_encrypted.version
      assert_equal ASN1Registry::NID_pkcs7_data, p7.get_encrypted.enc_data.content_type

      assert_nil p7.get_sign
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_digest
      assert_nil p7.get_enveloped
      assert_nil p7.get_other
    end

    def test_set_type_digest
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest

      assert p7.digest?
      assert_equal 0, p7.get_digest.version

      assert_nil p7.get_sign
      assert_nil p7.get_signed_and_enveloped
      assert_nil p7.get_data
      assert_nil p7.get_encrypted
      assert_nil p7.get_enveloped
      assert_nil p7.get_other
    end

    def test_set_cipher_on_non_enveloped_object
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest

      assert_raise_pkcs7_exception do
        p7.cipher = nil
      end

      p7.type = ASN1Registry::NID_pkcs7_encrypted

      assert_raise_pkcs7_exception do
        p7.cipher = nil
      end

      p7.type = ASN1Registry::NID_pkcs7_data

      assert_raise_pkcs7_exception do
        p7.cipher = nil
      end

      p7.type = ASN1Registry::NID_pkcs7_signed

      assert_raise_pkcs7_exception do
        p7.cipher = nil
      end
    end

    def test_set_cipher_on_enveloped_object
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped

      c = javax.crypto.Cipher.getInstance("RSA")
      cipher = CipherSpec.new(c, "RSA", 128)

      p7.cipher = cipher

      assert_equal cipher, p7.get_enveloped.enc_data.cipher
    end


    def test_set_cipher_on_signed_and_enveloped_object
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped

      c = javax.crypto.Cipher.getInstance("RSA")
      cipher = CipherSpec.new(c, "RSA", 128)

      p7.cipher = cipher

      assert_equal cipher, p7.get_signed_and_enveloped.enc_data.cipher
    end

    def test_add_recipient_info_to_something_that_cant_have_recipients
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      assert_raise_pkcs7_exception do
        p7.add_recipient(X509Cert)
      end

      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_raise_pkcs7_exception do
        p7.add_recipient(X509Cert)
      end

      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_raise_pkcs7_exception do
        p7.add_recipient(X509Cert)
      end

      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      assert_raise_pkcs7_exception do
        p7.add_recipient(X509Cert)
      end
    end

    def test_add_recipient_info_to_enveloped_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped

      ri = p7.add_recipient(X509Cert)

      assert_equal 1, p7.get_enveloped.recipient_info.size
      assert_equal ri, p7.get_enveloped.recipient_info.iterator.next
    end


    def test_add_recipient_info_to_signed_and_enveloped_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped

      ri = p7.add_recipient(X509Cert)

      assert_equal 1, p7.get_signed_and_enveloped.recipient_info.size
      assert_equal ri, p7.get_signed_and_enveloped.recipient_info.iterator.next
    end

    def test_add_signer_to_something_that_cant_have_signers
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert_raise_pkcs7_exception do
        p7.add_signer(SignerInfoWithPkey.new(nil, nil, nil, nil, nil, nil, nil))
      end

      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_raise_pkcs7_exception do
        p7.add_signer(SignerInfoWithPkey.new(nil, nil, nil, nil, nil, nil, nil))
      end

      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_raise_pkcs7_exception do
        p7.add_signer(SignerInfoWithPkey.new(nil, nil, nil, nil, nil, nil, nil))
      end

      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      assert_raise_pkcs7_exception do
        p7.add_signer(SignerInfoWithPkey.new(nil, nil, nil, nil, nil, nil, nil))
      end
    end

    def test_add_signer_to_signed_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed

      si = SignerInfoWithPkey.new(nil, nil, nil, nil, nil, nil, nil)
      p7.add_signer(si)

      assert_equal 1, p7.get_sign.signer_info.size
      assert_equal si, p7.get_sign.signer_info.iterator.next
    end


    def test_add_signer_to_signed_and_enveloped_should_add_that_to_stack
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped

      si = SignerInfoWithPkey.new(nil, nil, nil, nil, nil, nil, nil)
      p7.add_signer(si)

      assert_equal 1, p7.get_signed_and_enveloped.signer_info.size
      assert_equal si, p7.get_signed_and_enveloped.signer_info.iterator.next
    end

    BIG_ONE = BigInteger::ONE.to_java

    def create_signer_info_with_algo(algo)
      md5 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(4))
      SignerInfoWithPkey.new(
          ASN1Integer.new(BIG_ONE),
          IssuerAndSerialNumber.new(X500Name.new("C=SE"), BIG_ONE),
          algo,
          DERSet.new,
          md5,
          DEROctetString.new([].to_java(:byte)),
          DERSet.new
      )
    end

    def test_add_signer_to_signed_with_new_algo_should_add_that_algo_to_the_algo_list
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed

      # YES, these numbers are correct. Don't change them. They are OpenSSL internal NIDs
      md5 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(4))
      md4 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(5))

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_sign.md_algs.iterator.next
      assert_equal 1, p7.get_sign.md_algs.size

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_sign.md_algs.iterator.next
      assert_equal 1, p7.get_sign.md_algs.size

      si = create_signer_info_with_algo(md4)
      p7.add_signer(si)

      assert_equal 2, p7.get_sign.md_algs.size
      assert p7.get_sign.md_algs.contains(md4)
      assert p7.get_sign.md_algs.contains(md5)
    end


    def test_add_signer_to_signed_and_enveloped_with_new_algo_should_add_that_algo_to_the_algo_list
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped

      # YES, these numbers are correct. Don't change them. They are OpenSSL internal NIDs
      md5 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(4))
      md4 = AlgorithmIdentifier.new(ASN1Registry.nid2obj(5))

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_signed_and_enveloped.md_algs.iterator.next
      assert_equal 1, p7.get_signed_and_enveloped.md_algs.size

      si = create_signer_info_with_algo(md5)
      p7.add_signer(si)

      assert_equal md5, p7.get_signed_and_enveloped.md_algs.iterator.next
      assert_equal 1, p7.get_signed_and_enveloped.md_algs.size

      si = create_signer_info_with_algo(md4)
      p7.add_signer(si)

      assert_equal 2, p7.get_signed_and_enveloped.md_algs.size
      assert p7.get_signed_and_enveloped.md_algs.contains(md4)
      assert p7.get_signed_and_enveloped.md_algs.contains(md5)
    end

    def test_set_content_on_data_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_raise_pkcs7_exception do
        p7.setContent(PKCS7.new)
      end
    end

    def test_set_content_on_enveloped_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert_raise_pkcs7_exception do
        p7.setContent(PKCS7.new)
      end
    end

    def test_set_content_on_signed_and_enveloped_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped
      assert_raise_pkcs7_exception do
        p7.setContent(PKCS7.new)
      end
    end

    def test_set_content_on_encrypted_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_raise_pkcs7_exception do
        p7.setContent(PKCS7.new)
      end
    end

    def test_set_content_on_signed_sets_the_content
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      p7new = PKCS7.new
      p7.setContent(p7new)

      assert_equal p7new, p7.get_sign.contents
    end

    def test_set_content_on_digest_sets_the_content
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      p7new = PKCS7.new
      p7.setContent(p7new)

      assert_equal p7new, p7.get_digest.contents
    end

    def test_get_signer_info_on_digest_returns_null
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      assert_nil p7.signer_info
    end

    def test_get_signer_info_on_data_returns_null
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_nil p7.signer_info
    end

    def test_get_signer_info_on_encrypted_returns_null
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_nil p7.signer_info
    end

    def test_get_signer_info_on_enveloped_returns_null
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert_nil p7.signer_info
    end

    def test_get_signer_info_on_signed_returns_signer_info
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      assert_equal p7.get_sign.signer_info.object_id, p7.signer_info.object_id
    end

    def test_get_signer_info_on_signed_and_enveloped_returns_signer_info
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped
      assert_equal p7.get_signed_and_enveloped.signer_info.object_id, p7.signer_info.object_id
    end

    def test_content_new_on_data_raises_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_raise_pkcs7_exception do
        p7.content_new(ASN1Registry::NID_pkcs7_data)
      end
    end

    def test_content_new_on_encrypted_raises_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_raise_pkcs7_exception do
        p7.content_new(ASN1Registry::NID_pkcs7_data)
      end
    end

    def test_content_new_on_enveloped_raises_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert_raise_pkcs7_exception do
        p7.content_new(ASN1Registry::NID_pkcs7_data)
      end
    end

    def test_content_new_on_signed_and_enveloped_raises_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped
      assert_raise_pkcs7_exception do
        p7.content_new(ASN1Registry::NID_pkcs7_data)
      end
    end

    def test_content_new_on_digest_creates_new_content
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      p7.content_new(ASN1Registry::NID_pkcs7_signedAndEnveloped)
      assert p7.get_digest.contents.signed_and_enveloped?

      p7.content_new(ASN1Registry::NID_pkcs7_encrypted)
      assert p7.get_digest.contents.encrypted?
    end

    def test_content_new_on_signed_creates_new_content
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      p7.content_new(ASN1Registry::NID_pkcs7_signedAndEnveloped)
      assert p7.get_sign.contents.signed_and_enveloped?

      p7.content_new(ASN1Registry::NID_pkcs7_encrypted)
      assert p7.get_sign.contents.encrypted?
    end


    def test_add_certificate_on_data_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_raise_pkcs7_exception do
        p7.add_certificate(X509Cert)
      end
    end

    def test_add_certificate_on_enveloped_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert_raise_pkcs7_exception do
        p7.add_certificate(X509Cert)
      end
    end

    def test_add_certificate_on_encrypted_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_raise_pkcs7_exception do
        p7.add_certificate(X509Cert)
      end
    end

    def test_add_certificate_on_digest_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      assert_raise_pkcs7_exception do
        p7.add_certificate(X509Cert)
      end
    end

    def test_add_certificate_on_signed_adds_the_certificate
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      p7.add_certificate(X509Cert)
      assert_equal 1, p7.get_sign.cert.size
      assert_equal X509Cert, p7.get_sign.cert.iterator.next
    end

    def test_add_certificate_on_signed_and_enveloped_adds_the_certificate
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped
      p7.add_certificate(X509Cert)
      assert_equal 1, p7.get_signed_and_enveloped.cert.size
      assert_equal X509Cert, p7.get_signed_and_enveloped.cert.get(0)
    end

    def test_add_crl_on_data_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_data
      assert_raise_pkcs7_exception do
        p7.add_crl(X509CRL)
      end
    end

    def test_add_crl_on_enveloped_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_enveloped
      assert_raise_pkcs7_exception do
        p7.add_crl(X509CRL)
      end
    end

    def test_add_crl_on_encrypted_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_encrypted
      assert_raise_pkcs7_exception do
        p7.add_crl(X509CRL)
      end
    end

    def test_add_crl_on_digest_throws_exception
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_digest
      assert_raise_pkcs7_exception do
        p7.add_crl(X509CRL)
      end
    end

    def test_add_crl_on_signed_adds_the_crl
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signed
      p7.add_crl(X509CRL)
      assert_equal 1, p7.get_sign.crl.size
      assert_equal X509CRL, p7.get_sign.crl.iterator.next
    end

    def test_add_crl_on_signed_and_enveloped_adds_the_crl
      p7 = PKCS7.new
      p7.type = ASN1Registry::NID_pkcs7_signedAndEnveloped
      p7.add_crl(X509CRL)
      assert_equal 1, p7.get_signed_and_enveloped.crl.size
      assert_equal X509CRL, p7.get_signed_and_enveloped.crl.get(0)
    end

    EXISTING_PKCS7_DEF = "0\202\002 \006\t*\206H\206\367\r\001\a\003\240\202\002\0210\202\002\r\002\001\0001\202\001\2700\201\331\002\001\0000B0=1\0230\021\006\n\t\222&\211\223\362,d\001\031\026\003org1\0310\027\006\n\t\222&\211\223\362,d\001\031\026\truby-lang1\v0\t\006\003U\004\003\f\002CA\002\001\0020\r\006\t*\206H\206\367\r\001\001\001\005\000\004\201\200\213kF\330\030\362\237\363$\311\351\207\271+_\310sr\344\233N\200\233)\272\226\343\003\224OOf\372 \r\301{\206\367\241\270\006\240\254\3179F\232\231Q\232\225\347\373\233\032\375\360\035o\371\275p\306\v5Z)\263\037\302|\307\300\327\a\375\023G'Ax\313\346\261\254\227K\026\364\242\337\367\362rk\276\023\217m\326\343F\366I1\263\nLuNf\234\203\261\300\030\232Q\277\231\f0\030\001\332\021\0030\201\331\002\001\0000B0=1\0230\021\006\n\t\222&\211\223\362,d\001\031\026\003org1\0310\027\006\n\t\222&\211\223\362,d\001\031\026\truby-lang1\v0\t\006\003U\004\003\f\002CA\002\001\0030\r\006\t*\206H\206\367\r\001\001\001\005\000\004\201\200\215\223\3428\2440]\0278\016\230,\315\023Tg\325`\376~\353\304\020\243N{\326H\003\005\361q\224OI\310\2324-\341?\355&r\215\233\361\245jF\255R\271\203D\304v\325\265\243\321$\bSh\031i\eS\240\227\362\221\364\232\035\202\f?x\031\223D\004ZHD\355'g\243\037\236mJ\323\210\347\274m\324-\351\332\353#A\273\002\"h\aM\202\347\236\265\aI$@\240bt=<\212\2370L\006\t*\206H\206\367\r\001\a\0010\035\006\t`\206H\001e\003\004\001\002\004\020L?\325\372\\\360\366\372\237|W\333nnI\255\200 \253\234\252\263\006\335\037\320\350{s\352r\337\304\305\216\223k\003\376f\027_\201\035#*\002yM\334"

    EXISTING_PKCS7_1 = PKCS7::from_asn1(ASN1InputStream.new(EXISTING_PKCS7_DEF.to_java_bytes).read_object)

    def test_encrypt_integration_test
      certs = [X509Cert]
      c = Cipher.get_instance("AES", BCP.new)
      cipher = CipherSpec.new(c, "AES-128-CBC", 128)
      data = "aaaaa\nbbbbb\nccccc\n".to_java_bytes
      PKCS7::encrypt(certs, data, cipher, PKCS7::BINARY)
    end

    EXISTING_PKCS7_PEM = <<PKCS7STR
-----BEGIN PKCS7-----
MIICIAYJKoZIhvcNAQcDoIICETCCAg0CAQAxggG4MIHZAgEAMEIwPTETMBEGCgmS
JomT8ixkARkWA29yZzEZMBcGCgmSJomT8ixkARkWCXJ1YnktbGFuZzELMAkGA1UE
AwwCQ0ECAQIwDQYJKoZIhvcNAQEBBQAEgYCPGMV4KS/8amYA2xeIjj9qLseJf7dl
BtSDp+YAU3y1JnW7XufBCKxYw7eCuhWWA/mrxijr+wdsFDvSalM6nPX2P2NiVMWP
a7mzErZ4WrzkKIuGczYPYPJetwBYuhik3ya4ygYygoYssVRAITOSsEKpfqHAPmI+
AUJkqmCdGpQu9TCB2QIBADBCMD0xEzARBgoJkiaJk/IsZAEZFgNvcmcxGTAXBgoJ
kiaJk/IsZAEZFglydWJ5LWxhbmcxCzAJBgNVBAMMAkNBAgEDMA0GCSqGSIb3DQEB
AQUABIGAPaBX0KM3S+2jcrQrncu1jrvm1PUXlUvMfFIG2oBfPkMhiqCBvkOct1Ve
ws1hxvGtsqyjAUn02Yx1+gQJhTN4JZZHNqkfi0TwN32nlwLxclKcrbF9bvtMiVHx
V3LrSygblxxJsBf8reoV4yTJRa3w98bEoDhjUwjfy5xTml2cAn4wTAYJKoZIhvcN
AQcBMB0GCWCGSAFlAwQBAgQQath+2gUo4ntkKl8FO1LLhoAg58j0Jn/OfWG3rNRH
kTtUQfnBFk/UGbTZgExHILaGz8Y=
-----END PKCS7-----
PKCS7STR

    PKCS7_PEM_CONTENTS = "\347\310\364&\177\316}a\267\254\324G\221;TA\371\301\026O\324\031\264\331\200LG \266\206\317\306"

    PKCS7_PEM_FIRST_KEY = "\217\030\305x)/\374jf\000\333\027\210\216?j.\307\211\177\267e\006\324\203\247\346\000S|\265&u\273^\347\301\b\254X\303\267\202\272\025\226\003\371\253\306(\353\373\al\024;\322jS:\234\365\366?cbT\305\217k\271\263\022\266xZ\274\344(\213\206s6\017`\362^\267\000X\272\030\244\337&\270\312\0062\202\206,\261T@!3\222\260B\251~\241\300>b>\001Bd\252`\235\032\224.\365"

    PKCS7_PEM_SECOND_KEY = "=\240W\320\2437K\355\243r\264+\235\313\265\216\273\346\324\365\027\225K\314|R\006\332\200_>C!\212\240\201\276C\234\267U^\302\315a\306\361\255\262\254\243\001I\364\331\214u\372\004\t\2053x%\226G6\251\037\213D\3607}\247\227\002\361rR\234\255\261}n\373L\211Q\361Wr\353K(\e\227\034I\260\027\374\255\352\025\343$\311E\255\360\367\306\304\2408cS\b\337\313\234S\232]\234\002~"

    def test_pem_read_pkcs7_bio
      bio = BIO::mem_buf(EXISTING_PKCS7_PEM.to_java_bytes)
      p7 = PKCS7.read_pem(bio)

      assert_equal ASN1Registry::NID_pkcs7_enveloped, p7.type
      env = p7.get_enveloped
      assert_equal 0, env.version
      enc_data = env.enc_data
      assert_equal ASN1Registry::NID_pkcs7_data, enc_data.content_type
      assert_equal ASN1Registry::NID_aes_128_cbc, ASN1Registry::oid2nid(alg_oid(enc_data.algorithm))
      assert_equal PKCS7_PEM_CONTENTS, String.from_java_bytes(enc_data.enc_data.octets)

      ris = env.recipient_info
      assert_equal 2, ris.size

      first = second = nil
      tmp = ris.iterator.next

      if tmp.issuer_and_serial.certificate_serial_number.value == 2
        first = tmp
        iter = ris.iterator
        iter.next
        second = iter.next
      else
        second = tmp
        iter = ris.iterator
        iter.next
        first = iter.next
      end

      assert_equal 0, first.version
      assert_equal 0, second.version

      assert_equal "DC=org,DC=ruby-lang,CN=CA", first.issuer_and_serial.name.to_s
      assert_equal "DC=org,DC=ruby-lang,CN=CA", second.issuer_and_serial.name.to_s

      assert_equal ASN1Registry::NID_rsaEncryption, ASN1Registry::oid2nid(alg_oid(first.key_enc_algor))
      assert_equal ASN1Registry::NID_rsaEncryption, ASN1Registry::oid2nid(alg_oid(second.key_enc_algor))

      assert_equal PKCS7_PEM_FIRST_KEY, String.from_java_bytes(first.enc_key.octets)
      assert_equal PKCS7_PEM_SECOND_KEY, String.from_java_bytes(second.enc_key.octets)
    end

    private

    def alg_oid(alg); return alg.getAlgorithm end

    def assert_raise_pkcs7_exception
      begin
        yield
        fail 'expected PKCS7Exception to be raised but did not'
      rescue PKCS7Exception => e
        assert e
      end
    end

    public

    def test_enveloped
      @rsa1024 = OpenSSL::PKey.read <<-_PEM_
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDLwsSw1ECnPtT+PkOgHhcGA71nwC2/nL85VBGnRqDxOqjVh7Cx
aKPERYHsk4BPCkE3brtThPWc9kjHEQQ7uf9Y1rbCz0layNqHyywQEVLFmp1cpIt/
Q3geLv8ZD9pihowKJDyMDiN6ArYUmZczvW4976MU3+l54E6lF/JfFEU5hwIDAQAB
AoGBAKSl/MQarye1yOysqX6P8fDFQt68VvtXkNmlSiKOGuzyho0M+UVSFcs6k1L0
maDE25AMZUiGzuWHyaU55d7RXDgeskDMakD1v6ZejYtxJkSXbETOTLDwUWTn618T
gnb17tU1jktUtU67xK/08i/XodlgnQhs6VoHTuCh3Hu77O6RAkEA7+gxqBuZR572
74/akiW/SuXm0SXPEviyO1MuSRwtI87B02D0qgV8D1UHRm4AhMnJ8MCs1809kMQE
JiQUCrp9mQJBANlt2ngBO14us6NnhuAseFDTBzCHXwUUu1YKHpMMmxpnGqaldGgX
sOZB3lgJsT9VlGf3YGYdkLTNVbogQKlKpB8CQQDiSwkb4vyQfDe8/NpU5Not0fII
8jsDUCb+opWUTMmfbxWRR3FBNu8wnym/m19N4fFj8LqYzHX4KY0oVPu6qvJxAkEA
wa5snNekFcqONLIE4G5cosrIrb74sqL8GbGb+KuTAprzj5z1K8Bm0UW9lTjVDjDi
qRYgZfZSL+x1P/54+xTFSwJAY1FxA/N3QPCXCjPh5YqFxAMQs2VVYTfg+t0MEcJD
dPMQD5JX6g5HKnHFg2mZtoXQrWmJSn7p8GJK8yNTopEErA==
-----END RSA PRIVATE KEY-----
      _PEM_
      @rsa2048 = OpenSSL::PKey.read <<-_PEM_
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuV9ht9J7k4NBs38jOXvvTKY9gW8nLICSno5EETR1cuF7i4pN
s9I1QJGAFAX0BEO4KbzXmuOvfCpD3CU+Slp1enenfzq/t/e/1IRW0wkJUJUFQign
4CtrkJL+P07yx18UjyPlBXb81ApEmAB5mrJVSrWmqbjs07JbuS4QQGGXLc+Su96D
kYKmSNVjBiLxVVSpyZfAY3hD37d60uG+X8xdW5v68JkRFIhdGlb6JL8fllf/A/bl
NwdJOhVr9mESHhwGjwfSeTDPfd8ZLE027E5lyAVX9KZYcU00mOX+fdxOSnGqS/8J
DRh0EPHDL15RcJjV2J6vZjPb0rOYGDoMcH+94wIDAQABAoIBAAzsamqfYQAqwXTb
I0CJtGg6msUgU7HVkOM+9d3hM2L791oGHV6xBAdpXW2H8LgvZHJ8eOeSghR8+dgq
PIqAffo4x1Oma+FOg3A0fb0evyiACyrOk+EcBdbBeLo/LcvahBtqnDfiUMQTpy6V
seSoFCwuN91TSCeGIsDpRjbG1vxZgtx+uI+oH5+ytqJOmfCksRDCkMglGkzyfcl0
Xc5CUhIJ0my53xijEUQl19rtWdMnNnnkdbG8PT3LZlOta5Do86BElzUYka0C6dUc
VsBDQ0Nup0P6rEQgy7tephHoRlUGTYamsajGJaAo1F3IQVIrRSuagi7+YpSpCqsW
wORqorkCgYEA7RdX6MDVrbw7LePnhyuaqTiMK+055/R1TqhB1JvvxJ1CXk2rDL6G
0TLHQ7oGofd5LYiemg4ZVtWdJe43BPZlVgT6lvL/iGo8JnrncB9Da6L7nrq/+Rvj
XGjf1qODCK+LmreZWEsaLPURIoR/Ewwxb9J2zd0CaMjeTwafJo1CZvcCgYEAyCgb
aqoWvUecX8VvARfuA593Lsi50t4MEArnOXXcd1RnXoZWhbx5rgO8/ATKfXr0BK/n
h2GF9PfKzHFm/4V6e82OL7gu/kLy2u9bXN74vOvWFL5NOrOKPM7Kg+9I131kNYOw
Ivnr/VtHE5s0dY7JChYWE1F3vArrOw3T00a4CXUCgYEA0SqY+dS2LvIzW4cHCe9k
IQqsT0yYm5TFsUEr4sA3xcPfe4cV8sZb9k/QEGYb1+SWWZ+AHPV3UW5fl8kTbSNb
v4ng8i8rVVQ0ANbJO9e5CUrepein2MPL0AkOATR8M7t7dGGpvYV0cFk8ZrFx0oId
U0PgYDotF/iueBWlbsOM430CgYEAqYI95dFyPI5/AiSkY5queeb8+mQH62sdcCCr
vd/w/CZA/K5sbAo4SoTj8dLk4evU6HtIa0DOP63y071eaxvRpTNqLUOgmLh+D6gS
Cc7TfLuFrD+WDBatBd5jZ+SoHccVrLR/4L8jeodo5FPW05A+9gnKXEXsTxY4LOUC
9bS4e1kCgYAqVXZh63JsMwoaxCYmQ66eJojKa47VNrOeIZDZvd2BPVf30glBOT41
gBoDG3WMPZoQj9pb7uMcrnvs4APj2FIhMU8U15LcPAj59cD6S6rWnAxO8NFK7HQG
4Jxg3JNNf8ErQoCHb1B3oVdXJkmbJkARoDpBKmTCgKtP8ADYLmVPQw==
-----END RSA PRIVATE KEY-----
      _PEM_
      ca = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")
      ee1 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE1")
      ee2 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE2")

      ca_exts = [
          ["basicConstraints","CA:TRUE",true],
          ["keyUsage","keyCertSign, cRLSign",true],
          ["subjectKeyIdentifier","hash",false],
          ["authorityKeyIdentifier","keyid:always",false],
      ]
      @ca_cert = issue_cert(ca, @rsa2048, 1, ca_exts, nil, nil)
      ee_exts = [
          ["keyUsage","Non Repudiation, Digital Signature, Key Encipherment",true],
          ["authorityKeyIdentifier","keyid:always",false],
          ["extendedKeyUsage","clientAuth, emailProtection, codeSigning",false],
      ]
      @ee1_cert = issue_cert(ee1, @rsa1024, 2, ee_exts, @ca_cert, @rsa2048)
      @ee2_cert = issue_cert(ee2, @rsa1024, 3, ee_exts, @ca_cert, @rsa2048)

      #

      certs = [@ee1_cert, @ee2_cert]
      cipher = OpenSSL::Cipher::AES.new("128-CBC")
      data = "aaaaa\nbbbbb\nccccc\n"

      tmp = OpenSSL::PKCS7.encrypt(certs, data, cipher, OpenSSL::PKCS7::BINARY)
      p7 = OpenSSL::PKCS7.new(tmp.to_der)
      recip = p7.recipients
      assert_equal(:enveloped, p7.type)
      assert_equal(2, recip.size)

      assert_equal(@ca_cert.subject.to_s, recip[0].issuer.to_s)
      assert_equal(2, recip[0].serial)
      assert_equal(data, p7.decrypt(@rsa1024, @ee1_cert))

      assert_equal(@ca_cert.subject.to_s, recip[1].issuer.to_s)
      assert_equal(3, recip[1].serial)
      assert_equal(data, p7.decrypt(@rsa1024, @ee2_cert))
      assert_equal(data, p7.decrypt(@rsa1024))
    end

  end
end

