# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestASN1 < TestCase

  def test_decode_x509_certificate
    subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA")
    key = Fixtures.pkey("rsa1024")
    now = Time.at(Time.now.to_i) # suppress usec
    s = 0xdeadbeafdeadbeafdeadbeafdeadbeaf
    exts = [
      ["basicConstraints","CA:TRUE,pathlen:1",true],
      ["keyUsage","keyCertSign, cRLSign",true],
      ["subjectKeyIdentifier","hash",false],
    ]
    dgst = OpenSSL::Digest.new('SHA256')
    cert = issue_cert(subj, key, s, exts, nil, nil, digest: dgst, not_before: now, not_after: now+3600)


    asn1 = OpenSSL::ASN1.decode(cert)
    assert_equal(OpenSSL::ASN1::Sequence, asn1.class)
    assert_equal(3, asn1.value.size)
    tbs_cert, sig_alg, sig_val = *asn1.value

    assert_equal(OpenSSL::ASN1::Sequence, tbs_cert.class)
    assert_equal(8, tbs_cert.value.size)

    version = tbs_cert.value[0]
    assert_equal(:CONTEXT_SPECIFIC, version.tag_class)
    assert_equal(0, version.tag)
    assert_equal(1, version.value.size)
    assert_equal(OpenSSL::ASN1::Integer, version.value[0].class)
    assert_equal(2, version.value[0].value)

    serial = tbs_cert.value[1]
    assert_equal(OpenSSL::ASN1::Integer, serial.class)
    assert_equal(0xdeadbeafdeadbeafdeadbeafdeadbeaf, serial.value)

    sig = tbs_cert.value[2]
    assert_equal(OpenSSL::ASN1::Sequence, sig.class)
    assert_equal(2, sig.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, sig.value[0].class)
    assert_equal("1.2.840.113549.1.1.11", sig.value[0].oid)
    assert_equal(OpenSSL::ASN1::Null, sig.value[1].class)

    dn = tbs_cert.value[3] # issuer
    assert_equal(subj.hash, OpenSSL::X509::Name.new(dn).hash)
    assert_equal(OpenSSL::ASN1::Sequence, dn.class)
    assert_equal(3, dn.value.size)
    assert_equal(OpenSSL::ASN1::Set, dn.value[0].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[1].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[2].class)
    assert_equal(1, dn.value[0].value.size)
    assert_equal(1, dn.value[1].value.size)
    assert_equal(1, dn.value[2].value.size)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[0].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[1].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[2].value[0].class)
    assert_equal(2, dn.value[0].value[0].value.size)
    assert_equal(2, dn.value[1].value[0].value.size)
    assert_equal(2, dn.value[2].value[0].value.size)
    oid, value = *dn.value[0].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("org", value.value)
    oid, value = *dn.value[1].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("ruby-lang", value.value)
    oid, value = *dn.value[2].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("2.5.4.3", oid.oid)
    assert_equal(OpenSSL::ASN1::UTF8String, value.class)
    assert_equal("TestCA", value.value)

    validity = tbs_cert.value[4]
    assert_equal(OpenSSL::ASN1::Sequence, validity.class)
    assert_equal(2, validity.value.size)
    assert_equal(OpenSSL::ASN1::UTCTime, validity.value[0].class)
    assert_equal(now, validity.value[0].value)
    assert_equal(OpenSSL::ASN1::UTCTime, validity.value[1].class)
    assert_equal(now+3600, validity.value[1].value)

    dn = tbs_cert.value[5] # subject
    assert_equal(subj.hash, OpenSSL::X509::Name.new(dn).hash)
    assert_equal(OpenSSL::ASN1::Sequence, dn.class)
    assert_equal(3, dn.value.size)
    assert_equal(OpenSSL::ASN1::Set, dn.value[0].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[1].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[2].class)
    assert_equal(1, dn.value[0].value.size)
    assert_equal(1, dn.value[1].value.size)
    assert_equal(1, dn.value[2].value.size)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[0].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[1].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[2].value[0].class)
    assert_equal(2, dn.value[0].value[0].value.size)
    assert_equal(2, dn.value[1].value[0].value.size)
    assert_equal(2, dn.value[2].value[0].value.size)
    oid, value = *dn.value[0].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("org", value.value)
    oid, value = *dn.value[1].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("ruby-lang", value.value)
    oid, value = *dn.value[2].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("2.5.4.3", oid.oid)
    assert_equal(OpenSSL::ASN1::UTF8String, value.class)
    assert_equal("TestCA", value.value)

    pkey = tbs_cert.value[6]
    assert_equal(OpenSSL::ASN1::Sequence, pkey.class)
    assert_equal(2, pkey.value.size)
    assert_equal(OpenSSL::ASN1::Sequence, pkey.value[0].class)
    assert_equal(2, pkey.value[0].value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, pkey.value[0].value[0].class)
    assert_equal("1.2.840.113549.1.1.1", pkey.value[0].value[0].oid)
    assert_equal(OpenSSL::ASN1::BitString, pkey.value[1].class)
    assert_equal(0, pkey.value[1].unused_bits)
    spkey = OpenSSL::ASN1.decode(pkey.value[1].value)
    assert_equal(OpenSSL::ASN1::Sequence, spkey.class)
    assert_equal(2, spkey.value.size)
    assert_equal(OpenSSL::ASN1::Integer, spkey.value[0].class)
    assert_equal(cert.public_key.n, spkey.value[0].value)
    assert_equal(OpenSSL::ASN1::Integer, spkey.value[1].class)
    assert_equal(cert.public_key.e, spkey.value[1].value)

    extensions = tbs_cert.value[7]
    assert_equal(:CONTEXT_SPECIFIC, extensions.tag_class)
    assert_equal(3, extensions.tag)
    assert_equal(1, extensions.value.size)
    assert_equal(OpenSSL::ASN1::Sequence, extensions.value[0].class)
    assert_equal(3, extensions.value[0].value.size)

    ext = extensions.value[0].value[0]  # basicConstraints
    assert_equal(OpenSSL::ASN1::Sequence, ext.class)
    assert_equal(3, ext.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.19",  ext.value[0].oid)
    assert_equal(OpenSSL::ASN1::Boolean, ext.value[1].class)
    assert_equal(true, ext.value[1].value)
    assert_equal(OpenSSL::ASN1::OctetString, ext.value[2].class)
    extv = OpenSSL::ASN1.decode(ext.value[2].value)
    assert_equal(OpenSSL::ASN1::Sequence, extv.class)
    assert_equal(2, extv.value.size)
    assert_equal(OpenSSL::ASN1::Boolean, extv.value[0].class)
    assert_equal(true, extv.value[0].value)
    assert_equal(OpenSSL::ASN1::Integer, extv.value[1].class)
    assert_equal(1, extv.value[1].value)

    ext = extensions.value[0].value[1]  # keyUsage
    assert_equal(OpenSSL::ASN1::Sequence, ext.class)
    assert_equal(3, ext.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.15",  ext.value[0].oid)
    assert_equal(OpenSSL::ASN1::Boolean, ext.value[1].class)
    assert_equal(true, ext.value[1].value)
    assert_equal(OpenSSL::ASN1::OctetString, ext.value[2].class)
    extv = OpenSSL::ASN1.decode(ext.value[2].value)
    assert_equal(OpenSSL::ASN1::BitString, extv.class)
    str = +"\000"; str[0] = 0b00000110.chr
    assert_equal(str, extv.value)

    ext = extensions.value[0].value[2]  # subjectKeyIdentifier
    assert_equal(OpenSSL::ASN1::Sequence, ext.class)
    assert_equal(2, ext.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.14",  ext.value[0].oid)
    assert_equal(OpenSSL::ASN1::OctetString, ext.value[1].class)
    extv = OpenSSL::ASN1.decode(ext.value[1].value)
    assert_equal(OpenSSL::ASN1::OctetString, extv.class)
    sha1 = OpenSSL::Digest.new('SHA1')
    sha1.update(pkey.value[1].value)
    assert_equal(sha1.digest, extv.value)

    assert_equal(OpenSSL::ASN1::Sequence, sig_alg.class)
    assert_equal(2, sig_alg.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, pkey.value[0].value[0].class)
    assert_equal("1.2.840.113549.1.1.1", pkey.value[0].value[0].oid)
    assert_equal(OpenSSL::ASN1::Null, pkey.value[0].value[1].class)

    assert_equal(OpenSSL::ASN1::BitString, sig_val.class)
    cululated_sig = key.sign(OpenSSL::Digest.new('SHA256'), tbs_cert.to_der)
    # TODO: Import Issue
    # Fails from import with:
    # <"\x9E\x19\xE3oI\xC0\x85n$\xF4\xCE\n" +
    # "\x87\xA6\xFCu\x1AQbti\xB1\xE0o\xD5\x18?}\xFAEq\xC8\xEF\x17K\xCA|d\xDEu;%\xFB\xA1\xD4\x14\x04\x837\x90E\xAC.p=\x14\xA7\x8B\xAE\xC4\xBE-\x99\xBAx\xB8\x9B+\x87\x80\e\xA1\x17{\fV\xA0\xCF\xA60b\xDFc\x06\x81\xFB\xD3:\x01\x17\x8F\xC5[\xE0m\xAB,\xD3D\xBE\xA0\xA5\x8C\x1E\xCB\x18!\xBF&\x17\xA6\xCF\x8A\xDD\xF1\xB4\x1C\x89\xD8t\xAEz\x95\xC6\xE4\x9E\xA3\xA4">
    # expected but was
    # <",\xF4.\x1CH\xD5y\xFE\x05~\xB2\x05\xB7\xCB{2VwdZ\xD7\r^\x87AF\x16\x1A\xC8+U\xA1\xCA'\x1Ca\xCE}\xD2H<g\x9D\b\xB3\rz\x81f\x8Eu\x16+G\x84\xF8\xDB\xDF\xC8YV\xE3Fa\x14\x16\b\x86\xF7\xB7w\xCB9\xA67\x11\x91MJ\n" +
    # "\x83M{3\x1D|\xBCK\xF8\xFA\ei\xAC\xFD\xF7q\xE6\xC5\xD8\xDC.$\x99\x94\xE9\xC4rl\xE5D\x82\x17\x03\x81\x96)\e\xE0\xCE\x02\x13y\xBD\xB5\x843V\x8A">
    #assert_equal(cululated_sig, sig_val.value)
  end

  def test_encode_boolean
    encode_decode_test1(OpenSSL::ASN1::Boolean, [true, false])
  end

  def test_end_of_content
    # TODO: Import Issue
    # raises OpenSSL::ASN1::ASN1Error: unexpected end-of-contents marker
    #encode_decode_test B(%w{ 00 00 }), OpenSSL::ASN1::EndOfContent.new
    assert_raise(OpenSSL::ASN1::ASN1Error) {
      OpenSSL::ASN1.decode(B(%w{ 00 01 00 }))
    }
  end

  def test_encode_integer
    ai = OpenSSL::ASN1::Integer.new( i = 42 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value

    ai = OpenSSL::ASN1::Integer.new( i = 0 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value

    ai = OpenSSL::ASN1::Integer.new( i = -1 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value

    ai = OpenSSL::ASN1::Integer.new( i = 2**4242 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value
  end

  def test_enumerated
    encode_decode_test B(%w{ 0A 01 00 }), OpenSSL::ASN1::Enumerated.new(0)
    encode_decode_test B(%w{ 0A 01 48 }), OpenSSL::ASN1::Enumerated.new(72)
    encode_decode_test B(%w{ 0A 02 00 80 }), OpenSSL::ASN1::Enumerated.new(128)
    encode_decode_test B(%w{ 0A 09 01 00 00 00 00 00 00 00 00 }), OpenSSL::ASN1::Enumerated.new(2 ** 64)
  end

  def test_encode_nested_sequence_to_der
    data_sequence = ::OpenSSL::ASN1::Sequence([::OpenSSL::ASN1::Integer(0)])
    asn1 = ::OpenSSL::ASN1::Sequence(data_sequence)
    assert_equal "0\x03\x02\x01\x00", asn1.to_der
  end

  def test_encode_nested_set_to_der
    data_set = ::OpenSSL::ASN1::Set([::OpenSSL::ASN1::Integer(0)])
    asn1 = ::OpenSSL::ASN1::Set(data_set)
    assert_equal "1\x03\x02\x01\x00", asn1.to_der
  end

  def test_null
    encode_decode_test B(%w{ 05 00 }), OpenSSL::ASN1::Null.new(nil)
    assert_raise(OpenSSL::ASN1::ASN1Error) {
      OpenSSL::ASN1.decode(B(%w{ 05 01 00 }))
    }
  end

  def test_encode_asn1_data
    ai = OpenSSL::ASN1::ASN1Data.new(i = "bla", 0, :APPLICATION)
    ai2 = OpenSSL::ASN1.decode(ai.to_der)
    assert_equal :APPLICATION, ai2.tag_class
    assert_equal 0, ai2.tag
    assert_equal i, ai2.value

    ai = OpenSSL::ASN1::ASN1Data.new(i = "bla", 4, :UNIVERSAL)
    ai2 = OpenSSL::ASN1.decode(ai.to_der)
    assert_equal :UNIVERSAL, ai2.tag_class
    assert_equal 4, ai2.tag
    assert_equal i, ai2.value

    ai = OpenSSL::ASN1::ASN1Data.new(i = ["bla"], 0, :APPLICATION)
    ai2 = OpenSSL::ASN1.decode(ai.to_der)
    assert_equal :APPLICATION, ai2.tag_class
    assert_equal 0, ai2.tag
    assert_equal "bla", ai2.value

    ai = OpenSSL::ASN1::ASN1Data.new(i = ["bla", "bla"], 0, :APPLICATION)
    ai2 = OpenSSL::ASN1.decode(ai.to_der)
    assert_equal :APPLICATION, ai2.tag_class
    assert_equal 0, ai2.tag
    assert_equal "blabla", ai2.value

    assert_raise(ArgumentError) { OpenSSL::ASN1::ASN1Data.new(1).to_der }
    assert_raise("no implicit conversion of Integer into String") { OpenSSL::ASN1::ASN1Data.new(1, 0, :APPLICATION).to_der }
    assert_raise("no implicit conversion of Integer into String") { OpenSSL::ASN1::ASN1Data.new(1, 0, :CONTEXT_SPECIFIC).to_der }
  end

  def test_encode_nil
    #Primitives raise TypeError, Constructives NoMethodError

    assert_raise(TypeError) { OpenSSL::ASN1::Integer.new(nil).to_der }
    assert_raise(TypeError) { OpenSSL::ASN1::Boolean.new(nil).to_der }
  end

  def test_encode_data_integer
    data = OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Integer.new(90)], 1, :CONTEXT_SPECIFIC)
    der = data.to_der
    assert_equal "\xA1\x03\x02\x01Z", der

    dec = OpenSSL::ASN1.decode(der)
    # #<OpenSSL::ASN1::ASN1Data:0x000077be141e1e60
    #  @indefinite_length=false,
    #  @tag=1,
    #  @tag_class=:CONTEXT_SPECIFIC,
    #  @value=[#<OpenSSL::ASN1::Integer:0x000077be141e1e88 @indefinite_length=false, @tag=2, @tag_class=:UNIVERSAL, @tagging=nil, @value=#<OpenSSL::BN 1>>]>
    assert_equal OpenSSL::ASN1::ASN1Data, dec.class
    assert_equal :CONTEXT_SPECIFIC, dec.tag_class
    assert_equal 1, dec.tag

    assert_equal Array, dec.value.class
    assert_equal 1, dec.value.size
    int = dec.value[0]
    assert_equal OpenSSL::ASN1::Integer, int.class
    assert_equal 2, int.tag
    assert_equal :UNIVERSAL, int.tag_class
    assert_equal OpenSSL::BN.new(90), int.value
  end

  def test_object_identifier
    encode_decode_test B(%w{ 06 01 00 }), OpenSSL::ASN1::ObjectId.new("0.0".b)
    encode_decode_test B(%w{ 06 01 28 }), OpenSSL::ASN1::ObjectId.new("1.0".b)
    encode_decode_test B(%w{ 06 03 88 37 03 }), OpenSSL::ASN1::ObjectId.new("2.999.3".b)
    encode_decode_test B(%w{ 06 05 2A 22 83 BB 55 }), OpenSSL::ASN1::ObjectId.new("1.2.34.56789".b)
    obj = encode_decode_test B(%w{ 06 09 60 86 48 01 65 03 04 02 01 }), OpenSSL::ASN1::ObjectId.new("sha256")
    assert_equal "2.16.840.1.101.3.4.2.1", obj.oid
    assert_equal "SHA256", obj.sn
    assert_equal "sha256", obj.ln
    # TODO: Import Issue
    # Fails with: <OpenSSL::ASN1::ASN1Error> expected but was <RuntimeError(<(TypeError) string  not an OID>)
    #assert_raise(OpenSSL::ASN1::ASN1Error) {
    #  OpenSSL::ASN1.decode(B(%w{ 06 00 }))
    #}
    #assert_raise(OpenSSL::ASN1::ASN1Error) {
    #  OpenSSL::ASN1.decode(B(%w{ 06 01 80 }))
    #}
    # <OpenSSL::ASN1::ASN1Error> expected but was <TypeError(<string 3.0 not an OID>)
    #assert_raise(OpenSSL::ASN1::ASN1Error) { OpenSSL::ASN1::ObjectId.new("3.0".b).to_der }
    # <OpenSSL::ASN1::ASN1Error> exception was expected but none was thrown.
    #assert_raise(OpenSSL::ASN1::ASN1Error) { OpenSSL::ASN1::ObjectId.new("0.40".b).to_der }

    oid = (0...100).to_a.join(".").b
    obj = OpenSSL::ASN1::ObjectId.new(oid)
    assert_equal oid, obj.oid

    aki = [
      OpenSSL::ASN1::ObjectId.new("authorityKeyIdentifier"),
      OpenSSL::ASN1::ObjectId.new("X509v3 Authority Key Identifier"),
      OpenSSL::ASN1::ObjectId.new("2.5.29.35")
    ]

    ski = [
      OpenSSL::ASN1::ObjectId.new("subjectKeyIdentifier"),
      OpenSSL::ASN1::ObjectId.new("X509v3 Subject Key Identifier"),
      OpenSSL::ASN1::ObjectId.new("2.5.29.14")
    ]

    aki.each do |a|
      # TODO: Import Issue
      # None of these are equivalent to each other
      #aki.each do |b|
      #  assert a == b
      #end

      ski.each do |b|
        refute a == b
      end
    end

    # TODO: Import Issue
    # <TypeError> exception was expected but none was thrown.
    #assert_raise(TypeError) {
    #  OpenSSL::ASN1::ObjectId.new("authorityKeyIdentifier") == nil
    #}

    oid = OpenSSL::ASN1::ObjectId.new("2.5.29.14")
    assert_equal true, oid == OpenSSL::ASN1::ObjectId.new("2.5.29.14")
    assert_equal false, oid == OpenSSL::ASN1::ObjectId.new("2.5.29.35")
  end

  def test_instantiate
    # nothing shall raise :
    OpenSSL::ASN1::Null.new(nil)
    OpenSSL::ASN1::EndOfContent.new
    OpenSSL::ASN1::OctetString.new('')
  end

  def test_constants
    universal_tag_name = ["EOC", "BOOLEAN", "INTEGER", "BIT_STRING", "OCTET_STRING",
      "NULL", "OBJECT", "OBJECT_DESCRIPTOR", "EXTERNAL", "REAL", "ENUMERATED",
      "EMBEDDED_PDV", "UTF8STRING", "RELATIVE_OID", nil, nil, "SEQUENCE", "SET",
      "NUMERICSTRING", "PRINTABLESTRING", "T61STRING", "VIDEOTEXSTRING", "IA5STRING",
      "UTCTIME", "GENERALIZEDTIME", "GRAPHICSTRING", "ISO64STRING", "GENERALSTRING",
      "UNIVERSALSTRING", "CHARACTER_STRING", "BMPSTRING"]
    assert_equal universal_tag_name, OpenSSL::ASN1::UNIVERSAL_TAG_NAME
  end

  def _test_parse_infinite_length_sequence; require 'pp' # borrowed from Krypt
    raw = [%w{30 80 04 01 01 02 01 01 00 00}.join("")].pack("H*")
    pp asn1 = OpenSSL::ASN1.decode(raw)

    assert_universal(OpenSSL::ASN1::SEQUENCE, asn1, true)
    seq = asn1.value
    assert_equal(3, seq.size)
    octet = seq[0]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, octet)
    assert_equal("\1", octet.value)
    integer = seq[1]
    assert_universal(OpenSSL::ASN1::INTEGER, integer)
    assert_equal(1, integer.value)
    eoc = seq[2]
    assert_universal(0, eoc)
    assert_equal('', eoc.value) # assert_nil(eoc.value)
    assert_equal(raw, asn1.to_der)
  end

  def test_simple_to_der
    assert_equal "0\x00", OpenSSL::ASN1::Sequence.new(nil).to_der
    assert_equal "1\x00", OpenSSL::ASN1::Set.new(nil).to_der
  end

  def test_sequence
    encode_decode_test B(%w{ 30 00 }), OpenSSL::ASN1::Sequence.new([])
    encode_decode_test B(%w{ 30 07 05 00 30 00 04 01 00 }), OpenSSL::ASN1::Sequence.new([
     OpenSSL::ASN1::Null.new(nil),
     OpenSSL::ASN1::Sequence.new([]),
     OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))
    ])

    expected = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))])
    expected.indefinite_length = true
    encode_decode_test B(%w{ 30 80 04 01 00 00 00 }), expected

    # OpenSSL::ASN1::EndOfContent can only be at the end
    obj = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::EndOfContent.new,
      OpenSSL::ASN1::OctetString.new(B(%w{ 00 })),
      OpenSSL::ASN1::EndOfContent.new,
    ])
    obj.indefinite_length = true
    # TODO: Import Issue
    # <OpenSSL::ASN1::ASN1Error> exception was expected but none was thrown.
    #assert_raise(OpenSSL::ASN1::ASN1Error) { obj.to_der }

    # The last EOC in value is ignored if indefinite length form is used
    expected = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::OctetString.new(B(%w{ 00 })),
      OpenSSL::ASN1::EndOfContent.new
    ])
    expected.indefinite_length = true
    encode_test B(%w{ 30 80 04 01 00 00 00 }), expected
  end

  def test_set
    encode_decode_test B(%w{ 31 00 }), OpenSSL::ASN1::Set.new([])
    # TODO: Import Issue
    # <"1\a\x05\x000\x00\x04\x01\x00"> expected but was <"1\a\x04\x01\x00\x05\x000\x00">
    #encode_decode_test B(%w{ 31 07 05 00 30 00 04 01 00 }), OpenSSL::ASN1::Set.new([
    #  OpenSSL::ASN1::Null.new(nil),
    #  OpenSSL::ASN1::Sequence.new([]),
    #  OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))
    #])
    expected = OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))])
    expected.indefinite_length = true
    encode_decode_test B(%w{ 31 80 04 01 00 00 00 }), expected
  end

  def test_utctime
    encode_decode_test B(%w{ 17 0D }) + "160908234339Z".b,
      OpenSSL::ASN1::UTCTime.new(Time.utc(2016, 9, 8, 23, 43, 39))
    begin
      # possible range of UTCTime is 1969-2068 currently
      encode_decode_test B(%w{ 17 0D }) + "690908234339Z".b,
        OpenSSL::ASN1::UTCTime.new(Time.utc(1969, 9, 8, 23, 43, 39))
    rescue OpenSSL::ASN1::ASN1Error
      pend "No negative time_t support?"
    end
    # not implemented
    # decode_test B(%w{ 17 11 }) + "500908234339+0930".b,
    #   OpenSSL::ASN1::UTCTime.new(Time.new(1950, 9, 8, 23, 43, 39, "+09:30"))
    # decode_test B(%w{ 17 0F }) + "5009082343-0930".b,
    #   OpenSSL::ASN1::UTCTime.new(Time.new(1950, 9, 8, 23, 43, 0, "-09:30"))
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 17 0C }) + "500908234339".b)
    # }
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 17 0D }) + "500908234339Y".b)
    # }
  end

  def test_generalizedtime
    encode_decode_test B(%w{ 18 0F }) + "20161208193429Z".b,
      OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 29))
    encode_decode_test B(%w{ 18 0F }) + "99990908234339Z".b,
      OpenSSL::ASN1::GeneralizedTime.new(Time.utc(9999, 9, 8, 23, 43, 39))
    # not implemented
    # decode_test B(%w{ 18 13 }) + "20161208193439+0930".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 39, "+09:30"))
    # decode_test B(%w{ 18 11 }) + "201612081934-0930".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 0, "-09:30"))
    # decode_test B(%w{ 18 11 }) + "201612081934-09".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 0, "-09:00"))
    # decode_test B(%w{ 18 0D }) + "2016120819.5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 30, 0))
    # decode_test B(%w{ 18 0D }) + "2016120819,5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 30, 0))
    # decode_test B(%w{ 18 0F }) + "201612081934.5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 30))
    # decode_test B(%w{ 18 11 }) + "20161208193439.5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 39.5))
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 18 0D }) + "201612081934Y".b)
    # }
  end

  def test_basic_asn1data
    # TODO: Import Issue
    # Java::JavaLang::ClassCastException:
    # class org.jruby.RubyString cannot be cast to class org.jruby.ext.openssl.ASN1$ASN1Data
    #  org.jruby.ext.openssl.ASN1$ASN1Data.toASN1TaggedObject(ASN1.java:1408)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.toASN1(ASN1.java:1383)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.toDER(ASN1.java:1424)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.to_der(ASN1.java:1414)
    #encode_test B(%w{ 00 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 0, :UNIVERSAL)
    #encode_test B(%w{ 01 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :UNIVERSAL)
    #encode_decode_test B(%w{ 41 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :APPLICATION)
    #encode_decode_test B(%w{ 81 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :CONTEXT_SPECIFIC)
    #encode_decode_test B(%w{ C1 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :PRIVATE)
    # TODO: Import Issue
    # OpenSSL::ASN1::ASN1Error: tag number for :UNIVERSAL too large
    #  org/jruby/RubyClass.java:942:in `new'
    #encode_decode_test B(%w{ 1F 20 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 32, :UNIVERSAL)
    #encode_decode_test B(%w{ 1F C0 20 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 8224, :UNIVERSAL)
    # TODO: Import Issue (same as start of this test)
    # Java::JavaLang::ClassCastException:
    # class org.jruby.RubyString cannot be cast to class org.jruby.ext.openssl.ASN1$ASN1Data
    #  org.jruby.ext.openssl.ASN1$ASN1Data.toASN1TaggedObject(ASN1.java:1408)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.toASN1(ASN1.java:1383)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.toDER(ASN1.java:1424)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.to_der(ASN1.java:1414)
    #encode_decode_test B(%w{ 41 02 AB CD }), OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 1, :APPLICATION)
    #encode_decode_test B(%w{ 41 81 80 } + %w{ AB CD } * 64), OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD } * 64), 1, :APPLICATION)
    #encode_decode_test B(%w{ 41 82 01 00 } + %w{ AB CD } * 128), OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD } * 128), 1, :APPLICATION)
    #encode_decode_test B(%w{ 61 00 }), OpenSSL::ASN1::ASN1Data.new([], 1, :APPLICATION)
    #obj = OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 2, :PRIVATE)], 1, :APPLICATION)
    #obj.indefinite_length = true
    #encode_decode_test B(%w{ 61 80 C2 02 AB CD 00 00 }), obj
    #obj = OpenSSL::ASN1::ASN1Data.new([
    #  OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 2, :PRIVATE),
    #  OpenSSL::ASN1::EndOfContent.new
    #], 1, :APPLICATION)
    #obj.indefinite_length = true
    #encode_test B(%w{ 61 80 C2 02 AB CD 00 00 }), obj
    #obj = OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 1, :UNIVERSAL)
    #obj.indefinite_length = true
    # TODO: Import Issue
    # <OpenSSL::ASN1::ASN1Error> expected but was <#<Java::JavaLang::ClassCastException: class org.jruby.RubyString cannot be cast to class org.jruby.ext.openssl.ASN1$ASN1Data
    #assert_raise(OpenSSL::ASN1::ASN1Error) { obj.to_der }
  end

  def test_basic_primitive
    # TODO: Import Issue
    # Java::JavaLang::NullPointerException:
    #  org.jruby.ext.openssl.ASN1$Primitive.toDER(ASN1.java:1610)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.to_der(ASN1.java:1414)
    #  org.jruby.ext.openssl.ASN1$Primitive.to_der(ASN1.java:1522)
    #encode_test B(%w{ 00 00 }), OpenSSL::ASN1::Primitive.new(B(%w{}), 0)
    # TODO: Import Issue
    # <"\x01\x00"> expected but was <"\x01\x01\xFF">
    #encode_test B(%w{ 01 00 }), OpenSSL::ASN1::Primitive.new(B(%w{}), 1, nil, :UNIVERSAL)
    # <"\x81\x00"> expected but was <"\x01\x01\xFF">
    #encode_test B(%w{ 81 00 }), OpenSSL::ASN1::Primitive.new(B(%w{}), 1, nil, :CONTEXT_SPECIFIC)
    # <"\x01\x02\xAB\xCD"> expected but was <"\x01\x01\xFF">
    #encode_test B(%w{ 01 02 AB CD }), OpenSSL::ASN1::Primitive.new(B(%w{ AB CD }), 1)
    # <TypeError> exception was expected but none was thrown.
    #assert_raise(TypeError) { OpenSSL::ASN1::Primitive.new([], 1).to_der }

    prim = OpenSSL::ASN1::Integer.new(50)
    assert_equal false, prim.indefinite_length
    assert_not_respond_to prim, :indefinite_length=
  end

  #
  # MRI seems to have some different tests for similar things (constructive
  # vs constructed) There may be some duplicated test cases within these but
  # for completeness' sake I'm going to include all of MRI's tests below
  #

  def test_basic_constructed
    #octet_string = OpenSSL::ASN1::OctetString.new(B(%w{ AB CD }))
    # TODO: Import Issue
    # OpenSSL::ASN1::ASN1Error: Constructive shall only be used with indefinite length
    #encode_test B(%w{ 20 00 }), OpenSSL::ASN1::Constructive.new([], 0)
    #encode_test B(%w{ 21 00 }), OpenSSL::ASN1::Constructive.new([], 1, nil, :UNIVERSAL)
    #encode_test B(%w{ A1 00 }), OpenSSL::ASN1::Constructive.new([], 1, nil, :CONTEXT_SPECIFIC)
    #encode_test B(%w{ 21 04 04 02 AB CD }), OpenSSL::ASN1::Constructive.new([octet_string], 1)
    # Java::JavaLang::UnsupportedOperationException:
    # #<OpenSSL::ASN1::Constructive:0x4fc256ec @tag=1, @value=[#<OpenSSL::ASN1::OctetString:0x7fc56d61
    #   @tag=4, @value="\xAB\xCD", @tag_class=:UNIVERSAL, @tagging=nil, @indefinite_length=false>],
    #   @tag_class=:CONTEXT_SPECIFIC, @tagging=:EXPLICIT, @indefinite_length=true>
    #   org.jruby.ext.openssl.ASN1$Constructive.toDER(ASN1.java:1881)
    #   org.jruby.ext.openssl.ASN1$ASN1Data.to_der(ASN1.java:1414)
    #   org.jruby.ext.openssl.ASN1$Constructive.to_der(ASN1.java:1858)
    #obj = OpenSSL::ASN1::Constructive.new([octet_string], 1)
    #obj.indefinite_length = true
    #encode_decode_test B(%w{ 21 80 04 02 AB CD 00 00 }), obj
    # (see above) Java::JavaLang::UnsupportedOperationException
    #obj = OpenSSL::ASN1::Constructive.new([octet_string, OpenSSL::ASN1::EndOfContent.new], 1)
    #obj.indefinite_length = true
    #encode_test B(%w{ 21 80 04 02 AB CD 00 00 }), obj
  end

  def test_constructive
    oct = OpenSSL::ASN1::OctetString.new("")
    assert_equal "\x04\x00", oct.to_der

    eoc = OpenSSL::ASN1::EndOfContent.new
    int = OpenSSL::ASN1::Integer.new 1

    set = OpenSSL::ASN1::Set.new([int, eoc])
    set.infinite_length = true
    expected = "1\x80\x02\x01\x01\x00\x00"
    actual = set.to_der

    #puts "set expected: #{expected.to_java_bytes.inspect}"
    #puts "set  actual: #{actual.to_java_bytes.inspect}"

    assert_equal expected, actual

    inner = OpenSSL::ASN1::Sequence.new([int, eoc])
    inner.infinite_length = true
    expected = "0\x80\x02\x01\x01\x00\x00"
    actual = inner.to_der

    #puts "seq expected: #{expected.to_java_bytes.inspect}"
    #puts "seq   actual: #{actual.to_java_bytes.inspect}"

    assert_equal expected, actual

    outer = OpenSSL::ASN1::Sequence.new([inner, eoc])
    outer.infinite_length = true
    assert_equal "0\x800\x80\x02\x01\x01\x00\x00\x00\x00", outer.to_der
  end

  def test_prim_explicit_tagging
    oct_str = OpenSSL::ASN1::OctetString.new("a", 0, :EXPLICIT)
    encode_test B(%w{ A0 03 04 01 61 }), oct_str
    oct_str2 = OpenSSL::ASN1::OctetString.new("a", 1, :EXPLICIT, :APPLICATION)
    encode_test B(%w{ 61 03 04 01 61 }), oct_str2

    decoded = OpenSSL::ASN1.decode(oct_str2.to_der)
    assert_equal :APPLICATION, decoded.tag_class
    assert_equal 1, decoded.tag
    assert_equal 1, decoded.value.size
    inner = decoded.value[0]
    assert_equal OpenSSL::ASN1::OctetString, inner.class
    assert_equal B(%w{ 61 }), inner.value
  end

  def test_prim_implicit_tagging
    int = OpenSSL::ASN1::Integer.new(1, 0, :IMPLICIT)
    encode_test B(%w{ 80 01 01 }), int
    int2 = OpenSSL::ASN1::Integer.new(1, 1, :IMPLICIT, :APPLICATION)
    encode_test B(%w{ 41 01 01 }), int2
    #decoded = OpenSSL::ASN1.decode(int2.to_der)
    # <:APPLICATION> expected but was <:UNIVERSAL>
    #assert_equal :APPLICATION, decoded.tag_class
    # <1> expected but was <2>
    #assert_equal 1, decoded.tag
    # <"\x01"> expected but was <#<OpenSSL::BN 1>>
    #assert_equal B(%w{ 01 }), decoded.value

    # Special behavior: Encoding universal types with non-default 'tag'
    # attribute and nil tagging method.
    #int3 = OpenSSL::ASN1::Integer.new(1, 1)
    # <"\x01\x01\x01"> expected but was <"\x02\x01\x01">
    #encode_test B(%w{ 01 01 01 }), int3
  end

  def test_cons_explicit_tagging
    #content = [ OpenSSL::ASN1::PrintableString.new('abc') ]
    #seq = OpenSSL::ASN1::Sequence.new(content, 2, :EXPLICIT)
    # TODO: Import Issue
    # RuntimeError: No message available
    #encode_test B(%w{ A2 07 30 05 13 03 61 62 63 }), seq
    #seq2 = OpenSSL::ASN1::Sequence.new(content, 3, :EXPLICIT, :APPLICATION)
    # RuntimeError: No message available
    #encode_test B(%w{ 63 07 30 05 13 03 61 62 63 }), seq2

    #content3 = [ OpenSSL::ASN1::PrintableString.new('abc'),
    #             OpenSSL::ASN1::EndOfContent.new() ]
    #seq3 = OpenSSL::ASN1::Sequence.new(content3, 2, :EXPLICIT)
    #seq3.indefinite_length = true
    # RuntimeError: No message available
    #encode_test B(%w{ A2 80 30 80 13 03 61 62 63 00 00 00 00 }), seq3
  end

  def test_cons_implicit_tagging
    #content = [ OpenSSL::ASN1::Null.new(nil) ]
    #seq = OpenSSL::ASN1::Sequence.new(content, 1, :IMPLICIT)
    # TODO: Import Issue
    # <"\xA1\x02\x05\x00"> expected but was <"0\x02\x05\x00">
    #encode_test B(%w{ A1 02 05 00 }), seq
    #seq2 = OpenSSL::ASN1::Sequence.new(content, 1, :IMPLICIT, :APPLICATION)
    # <"a\x02\x05\x00"> expected but was <"0\x02\x05\x00">
    #encode_test B(%w{ 61 02 05 00 }), seq2

    #content3 = [ OpenSSL::ASN1::Null.new(nil),
    #             OpenSSL::ASN1::EndOfContent.new() ]
    #seq3 = OpenSSL::ASN1::Sequence.new(content3, 1, :IMPLICIT)
    #seq3.indefinite_length = true
    # <"\xA1\x80\x05\x00\x00\x00"> expected but was <"0\x80\x05\x00\x00\x00">
    #encode_test B(%w{ A1 80 05 00 00 00 }), seq3

    # Special behavior: Encoding universal types with non-default 'tag'
    # attribute and nil tagging method.
    #seq4 = OpenSSL::ASN1::Sequence.new([], 1)
    # <"!\x00"> expected but was <"0\x00">
    #encode_test B(%w{ 21 00 }), seq4
  end

  def test_octet_string_constructed_tagging
    #octets = [ OpenSSL::ASN1::OctetString.new('aaa') ]
    #cons = OpenSSL::ASN1::Constructive.new(octets, 0, :IMPLICIT)
    # TODO: Import Issues
    # OpenSSL::ASN1::ASN1Error: Constructive shall only be used with indefinite length
    #encode_test B(%w{ A0 05 04 03 61 61 61 }), cons

    #octets = [ OpenSSL::ASN1::OctetString.new('aaa'),
    #           OpenSSL::ASN1::EndOfContent.new() ]
    #cons = OpenSSL::ASN1::Constructive.new(octets, 0, :IMPLICIT)
    #cons.indefinite_length = true
    # Java::JavaLang::UnsupportedOperationException:
    # #<OpenSSL::ASN1::Constructive:0x4a86be01 @tag=0,
    # @value=[#<OpenSSL::ASN1::OctetString:0x53b907d9 @tag=4, @value="aaa",
    # @tag_class=:UNIVERSAL, @tagging=nil, @indefinite_length=false>,
    # #<OpenSSL::ASN1::EndOfContent:0x2c3b0cc8 @tag=0, @value="",
    # @tag_class=:UNIVERSAL>], @tag_class=:CONTEXT_SPECIFIC, @tagging=:IMPLICIT, @indefinite_length=true>
    #encode_test B(%w{ A0 80 04 03 61 61 61 00 00 }), cons
  end

  def test_recursive_octet_string_indefinite_length
    #octets_sub1 = [ OpenSSL::ASN1::OctetString.new("\x01"),
    #                OpenSSL::ASN1::EndOfContent.new() ]
    #octets_sub2 = [ OpenSSL::ASN1::OctetString.new("\x02"),
    #                OpenSSL::ASN1::EndOfContent.new() ]
    #container1 = OpenSSL::ASN1::Constructive.new(octets_sub1, OpenSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    #container1.indefinite_length = true
    #container2 = OpenSSL::ASN1::Constructive.new(octets_sub2, OpenSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    #container2.indefinite_length = true
    #octets3 = OpenSSL::ASN1::OctetString.new("\x03")

    #octets = [ container1, container2, octets3,
    #           OpenSSL::ASN1::EndOfContent.new() ]
    #cons = OpenSSL::ASN1::Constructive.new(octets, OpenSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    #cons.indefinite_length = true
    #raw = B(%w{ 24 80 24 80 04 01 01 00 00 24 80 04 01 02 00 00 04 01 03 00 00 })
    # TODO: Implict Issue
    # Java::JavaLang::UnsupportedOperationException
    #  org.jruby.ext.openssl.ASN1$Constructive$InternalEncodable.toASN1Primitive(ASN1.java:1961)
    #  org.jruby.ext.openssl.ASN1$Constructive.octetStringToDER(ASN1.java:1904)
    #  org.jruby.ext.openssl.ASN1$Constructive.toDER(ASN1.java:1873)
    #  org.jruby.ext.openssl.ASN1$ASN1Data.to_der(ASN1.java:1414)
    #assert_equal(raw, cons.to_der)
    # <"$\x80$\x80\x04\x01\x01\x00\x00$\x80\x04\x01\x02\x00\x00\x04\x01\x03\x00\x00"> expected but was <"$\x80\x04\x03\x01\x02\x03\x00\x00">
    #assert_equal(raw, OpenSSL::ASN1.decode(raw).to_der)
  end

  def test_recursive_octet_string_parse
    raw = B(%w{ 24 80 24 80 04 01 01 00 00 24 80 04 01 02 00 00 04 01 03 00 00 })
    asn1 = OpenSSL::ASN1.decode(raw)
    assert_equal(OpenSSL::ASN1::Constructive, asn1.class)
    # TODO: Import Issue
    # <false> expected but was <true>
    #assert_universal(OpenSSL::ASN1::OCTET_STRING, asn1)
    assert_equal(true, asn1.indefinite_length)
    # <3> expected but was <2>
    #assert_equal(3, asn1.value.size)
    nested1 = asn1.value[0]
    # <OpenSSL::ASN1::Constructive> expected but was <OpenSSL::ASN1::OctetString>
    #assert_equal(OpenSSL::ASN1::Constructive, nested1.class)
    assert_universal(OpenSSL::ASN1::OCTET_STRING, nested1)
    # <true> expected but was <false>
    #assert_equal(true, nested1.indefinite_length)
    # <1> expected but was <3>
    #assert_equal(1, nested1.value.size)
    #oct1 = nested1.value[0]
    #   NoMethodError: undefined method `tag' for "\x01":String
    #     Did you mean?  tap
    #     src/test/ruby/test_asn1.rb:1286:in `assert_universal'
    #assert_universal(OpenSSL::ASN1::OCTET_STRING, oct1)
    # NoMethodError: undefined method `indefinite_length' for "\x01":String
    #assert_equal(false, oct1.indefinite_length)
    #nested2 = asn1.value[1]
    # <OpenSSL::ASN1::Constructive> expected but was <OpenSSL::ASN1::EndOfContent>
    #assert_equal(OpenSSL::ASN1::Constructive, nested2.class)
    # <4> expected but was <0>
    #assert_universal(OpenSSL::ASN1::OCTET_STRING, nested2)
    # <true> expected but was <nil>
    #assert_equal(true, nested2.indefinite_length)
    # <1> expected but was <0>
    #assert_equal(1, nested2.value.size)
    #oct2 = nested2.value[0]
    # NoMethodError: undefined method `tag' for nil:NilClass
    #assert_universal(OpenSSL::ASN1::OCTET_STRING, oct2)
    # NoMethodError: undefined method `indefinite_length' for nil:NilClass
    #assert_equal(false, oct2.indefinite_length)
    #oct3 = asn1.value[2]
    # NoMethodError: undefined method `tag' for nil:NilClass
    #assert_universal(OpenSSL::ASN1::OCTET_STRING, oct3)
    # NoMethodError: undefined method `indefinite_length' for nil:NilClass
    #assert_equal(false, oct3.indefinite_length)
  end

  def test_decode_constructed_overread
    #test = %w{ 31 06 31 02 30 02 05 00 }
    ##                          ^ <- invalid
    #raw = [test.join].pack("H*")
    #ret = []
    # <OpenSSL::ASN1::ASN1Error> exception was expected but none was thrown.
    #assert_raise(OpenSSL::ASN1::ASN1Error) {
    #  OpenSSL::ASN1.traverse(raw) { |x| ret << x }
    #}
    # <2> expected but was <0>
    #assert_equal 2, ret.size
    # NoMethodError: undefined method `[]' for nil:NilClass
    #assert_equal 17, ret[0][6]
    #assert_equal 17, ret[1][6]

    #test = %w{ 31 80 30 03 00 00 }
    ##                    ^ <- invalid
    #raw = [test.join].pack("H*")
    #ret = []
    # <OpenSSL::ASN1::ASN1Error> exception was expected but none was thrown.
    #assert_raise(OpenSSL::ASN1::ASN1Error) {
    #  OpenSSL::ASN1.traverse(raw) { |x| ret << x }
    #}
    #assert_equal 1, ret.size
    #assert_equal 17, ret[0][6]
  end

  def test_constructive_nesting
    seq = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('DC'),
        OpenSSL::ASN1::IA5String.new('the-borg')
    ])

    expected = "0\x16\x06\n\t\x92&\x89\x93\xF2,d\x01\x19\x16\bthe-borg"
    assert_equal expected, seq.to_der

    set = OpenSSL::ASN1::Set.new([
        OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new('CN'),
            OpenSSL::ASN1::UTF8String('Queen_42')
        ])
    ])
    expected = "1\x110\x0F\x06\x03U\x04\x03\f\bQueen_42"
    assert_equal expected, set.to_der

    name = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Set.new([
            OpenSSL::ASN1::Sequence.new([
                OpenSSL::ASN1::ObjectId.new('DC'),
                OpenSSL::ASN1::IA5String.new('org')
            ]),
            OpenSSL::ASN1::Set.new([
                OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ObjectId.new('DC'),
                    OpenSSL::ASN1::IA5String.new('the-borg')
                ]),
                OpenSSL::ASN1::Set.new([
                    OpenSSL::ASN1::Sequence.new([
                        OpenSSL::ASN1::ObjectId.new('CN'),
                        OpenSSL::ASN1::UTF8String('Queen_42')
                    ])
                ])
            ])
        ])
    ])

    name = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Set.new([
            OpenSSL::ASN1::Sequence.new([
                OpenSSL::ASN1::ObjectId.new('DC'),
                OpenSSL::ASN1::IA5String.new('org')
            ]),
            OpenSSL::ASN1::Set.new([
                OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ObjectId.new('DC'),
                    OpenSSL::ASN1::IA5String.new('the-borg')
                ]),
                OpenSSL::ASN1::Set.new([
                    OpenSSL::ASN1::Sequence.new([
                        OpenSSL::ASN1::ObjectId.new('CN'),
                        OpenSSL::ASN1::UTF8String('Queen_42')
                    ])
                ])
            ])
        ])
    ])

    expected = "0B1@0\x11\x06\n\t\x92&\x89\x93\xF2,d\x01\x19\x16\x03org1+0\x16\x06\n\t\x92&\x89\x93\xF2,d\x01\x19\x16\bthe-borg1\x110\x0F\x06\x03U\x04\x03\f\bQueen_42"
    assert_equal expected, name.to_der
  end

  def test_sequence_convert_to_array
    data_sequence = ::OpenSSL::ASN1::Sequence([::OpenSSL::ASN1::Integer(0)])
    asn1 = ::OpenSSL::ASN1::Sequence(data_sequence)
    assert_equal "0\x03\x02\x01\x00" , asn1.to_der

    assert_raise(TypeError) { ::OpenSSL::ASN1::Sequence(::OpenSSL::ASN1::Integer(0)).to_der }
  end

  def test_raw_constructive
    eoc = OpenSSL::ASN1::EndOfContent.new
    #puts "eoc: #{eoc.inspect}"
    oct = OpenSSL::ASN1::OctetString.new("")
    #puts "oct: #{oct.inspect}"

    c = OpenSSL::ASN1::Constructive.new([oct, eoc], OpenSSL::ASN1::OCTET_STRING)
    assert_equal 4, c.tag
    c.infinite_length = true
    #puts "'empty' constructive octet: #{c.inspect} \n#{c.to_der.inspect}"
    assert_equal "$\x80\x04\x00\x00\x00", c.to_der

    partial1 = OpenSSL::ASN1::OctetString.new("\x01")
    partial2 = OpenSSL::ASN1::OctetString.new("\x02")
    inf_octets = OpenSSL::ASN1::Constructive.new( [ partial1,
                                                    partial2,
                                                    OpenSSL::ASN1::EndOfContent.new ],
                                                  tag = OpenSSL::ASN1::OCTET_STRING,
                                                  nil,
                                                  :UNIVERSAL )
    assert_equal false, inf_octets.infinite_length
    # The real value of inf_octets is "\x01\x02", i.e. the concatenation of partial1 and partial2
    inf_octets.infinite_length = true
    assert_equal true, inf_octets.infinite_length

    assert_equal tag, inf_octets.tag

    inf_octets.infinite_length = false
    #assert_raise(OpenSSL::ASN1::ASN1Error) { inf_octets.to_der }

    inf_octets.infinite_length = true
    der = inf_octets.to_der
    #puts 'expected: ' + "$\x80\x04\x01\x01\x04\x01\x02\x00\x00".to_java_bytes.inspect
    #puts '  actual: ' + der.to_java_bytes.inspect
    assert_equal "$\x80\x04\x01\x01\x04\x01\x02\x00\x00", der
  end

  def test_constructive_decode
    der = "$\x80\x04\x01\x01\x04\x01\x02\x00\x00"
    asn1 = OpenSSL::ASN1.decode(der)

    assert asn1.instance_of?(OpenSSL::ASN1::Constructive), "expected Constructive got: #{asn1.class}"
    assert_equal 4, asn1.tag
    assert_equal :UNIVERSAL, asn1.tag_class
    assert_equal true, asn1.infinite_length

    first = asn1.value[0]
    assert first.instance_of?(OpenSSL::ASN1::OctetString), "expected OctetString got: #{first.class}"
    # NOTE: probably won't pass (without writing a custom "parser") :
    #assert_equal "\x01", asn1.value[0].value
    #assert_equal "\x02", asn1.value[1].value
    #assert_equal "", asn1.value[2].value
    last = asn1.value.last
    assert last.instance_of?(OpenSSL::ASN1::EndOfContent), "expected EndOfContent got: #{last.class}"
  end

  TEST_KEY_RSA1024 = <<-_end_of_pem_
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
  _end_of_pem_

  def test_decode
    subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA")
    key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1024
    now = Time.at(Time.now.to_i) # suppress usec
    s = 0xdeadbeafdeadbeafdeadbeafdeadbeaf
    exts = [
      ["basicConstraints","CA:TRUE,pathlen:1",true],
      ["keyUsage","keyCertSign, cRLSign",true],
      ["subjectKeyIdentifier","hash",false],
    ]
    dgst = OpenSSL::Digest::SHA1.new
    cert = issue_cert(subj, key, s, exts, nil, nil, not_before: now, not_after: now + 3600, digest: dgst)

    asn1 = OpenSSL::ASN1.decode(cert)
    assert_equal(OpenSSL::ASN1::Sequence, asn1.class)
    assert_equal(3, asn1.value.size)
    tbs_cert, sig_alg, sig_val = *asn1.value

    assert_equal(OpenSSL::ASN1::Sequence, tbs_cert.class)
    assert_equal(8, tbs_cert.value.size)

    version = tbs_cert.value[0]
    assert_equal(:CONTEXT_SPECIFIC, version.tag_class)
    assert_equal(0, version.tag)
    assert_equal(1, version.value.size)
    assert_equal(OpenSSL::ASN1::Integer, version.value[0].class)
    assert_equal(2, version.value[0].value)

    serial = tbs_cert.value[1]
    assert_equal(OpenSSL::ASN1::Integer, serial.class)
    assert_equal(0xdeadbeafdeadbeafdeadbeafdeadbeaf, serial.value)

    sig = tbs_cert.value[2]
    assert_equal(OpenSSL::ASN1::Sequence, sig.class)
    assert_equal(2, sig.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, sig.value[0].class)
    assert_equal("1.2.840.113549.1.1.5", sig.value[0].oid)
    assert_equal(OpenSSL::ASN1::Null, sig.value[1].class)

    dn = tbs_cert.value[3] # issuer

    assert_equal(subj.hash, OpenSSL::X509::Name.new(dn).hash)

    assert_equal(OpenSSL::ASN1::Sequence, dn.class)

    assert_equal(3, dn.value.size)
    assert_equal(OpenSSL::ASN1::Set, dn.value[0].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[1].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[2].class)
    assert_equal(1, dn.value[0].value.size)
    assert_equal(1, dn.value[1].value.size)
    assert_equal(1, dn.value[2].value.size)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[0].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[1].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[2].value[0].class)
    assert_equal(2, dn.value[0].value[0].value.size)
    assert_equal(2, dn.value[1].value[0].value.size)
    assert_equal(2, dn.value[2].value[0].value.size)
    oid, value = *dn.value[0].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("org", value.value)
    oid, value = *dn.value[1].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("ruby-lang", value.value)
    oid, value = *dn.value[2].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("2.5.4.3", oid.oid)
    assert_equal(OpenSSL::ASN1::UTF8String, value.class)
    assert_equal("TestCA", value.value)

    validity = tbs_cert.value[4]
    assert_equal(OpenSSL::ASN1::Sequence, validity.class)
    assert_equal(2, validity.value.size)
    assert_equal(OpenSSL::ASN1::UTCTime, validity.value[0].class)
    assert_equal(now, validity.value[0].value)
    assert_equal(OpenSSL::ASN1::UTCTime, validity.value[1].class)
    assert_equal(now+3600, validity.value[1].value)

    dn = tbs_cert.value[5] # subject

    assert_equal(subj, OpenSSL::X509::Name.new(dn))
    assert_equal(subj.hash, OpenSSL::X509::Name.new(dn).hash)

    assert_equal(OpenSSL::ASN1::Sequence, dn.class)
    assert_equal(3, dn.value.size)
    assert_equal(OpenSSL::ASN1::Set, dn.value[0].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[1].class)
    assert_equal(OpenSSL::ASN1::Set, dn.value[2].class)
    assert_equal(1, dn.value[0].value.size)
    assert_equal(1, dn.value[1].value.size)
    assert_equal(1, dn.value[2].value.size)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[0].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[1].value[0].class)
    assert_equal(OpenSSL::ASN1::Sequence, dn.value[2].value[0].class)
    assert_equal(2, dn.value[0].value[0].value.size)
    assert_equal(2, dn.value[1].value[0].value.size)
    assert_equal(2, dn.value[2].value[0].value.size)
    oid, value = *dn.value[0].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("org", value.value)
    oid, value = *dn.value[1].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("0.9.2342.19200300.100.1.25", oid.oid)
    assert_equal(OpenSSL::ASN1::IA5String, value.class)
    assert_equal("ruby-lang", value.value)
    oid, value = *dn.value[2].value[0].value
    assert_equal(OpenSSL::ASN1::ObjectId, oid.class)
    assert_equal("2.5.4.3", oid.oid)
    assert_equal(OpenSSL::ASN1::UTF8String, value.class)
    assert_equal("TestCA", value.value)

    pkey = tbs_cert.value[6]
    assert_equal(OpenSSL::ASN1::Sequence, pkey.class)
    assert_equal(2, pkey.value.size)
    assert_equal(OpenSSL::ASN1::Sequence, pkey.value[0].class)
    assert_equal(2, pkey.value[0].value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, pkey.value[0].value[0].class)
    assert_equal("1.2.840.113549.1.1.1", pkey.value[0].value[0].oid)
    assert_equal(OpenSSL::ASN1::BitString, pkey.value[1].class)
    assert_equal(0, pkey.value[1].unused_bits)
    spkey = OpenSSL::ASN1.decode(pkey.value[1].value)
    assert_equal(OpenSSL::ASN1::Sequence, spkey.class)
    assert_equal(2, spkey.value.size)
    assert_equal(OpenSSL::ASN1::Integer, spkey.value[0].class)
    assert_equal(143085709396403084580358323862163416700436550432664688288860593156058579474547937626086626045206357324274536445865308750491138538454154232826011964045825759324933943290377903384882276841880081931690695505836279972214003660451338124170055999155993192881685495391496854691199517389593073052473319331505702779271, spkey.value[0].value)
    assert_equal(OpenSSL::ASN1::Integer, spkey.value[1].class)
    assert_equal(65537, spkey.value[1].value)

    extensions = tbs_cert.value[7]
    assert_equal(:CONTEXT_SPECIFIC, extensions.tag_class)
    assert_equal(3, extensions.tag)
    assert_equal(1, extensions.value.size)
    assert_equal(OpenSSL::ASN1::Sequence, extensions.value[0].class)
    assert_equal(3, extensions.value[0].value.size)

    ext = extensions.value[0].value[0]  # basicConstraints

    assert_equal(OpenSSL::ASN1::Sequence, ext.class)
    assert_equal(3, ext.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.19",  ext.value[0].oid)
    assert_equal(OpenSSL::ASN1::Boolean, ext.value[1].class)
    assert_equal(true, ext.value[1].value)
    assert_equal(OpenSSL::ASN1::OctetString, ext.value[2].class)

    assert_equal "0\x06\x01\x01\xFF\x02\x01\x01", ext.value[2].value
    extv = OpenSSL::ASN1.decode(ext.value[2].value)

    assert_equal(OpenSSL::ASN1::Sequence, extv.class)
    assert_equal(2, extv.value.size)
    assert_equal(OpenSSL::ASN1::Boolean, extv.value[0].class)
    assert_equal(true, extv.value[0].value)
    assert_equal(OpenSSL::ASN1::Integer, extv.value[1].class)
    assert_equal(1, extv.value[1].value)

    ext = extensions.value[0].value[1]  # keyUsage

    assert_equal(OpenSSL::ASN1::Sequence, ext.class)
    assert_equal(3, ext.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.15",  ext.value[0].oid)
    assert_equal(OpenSSL::ASN1::Boolean, ext.value[1].class)
    assert_equal(true, ext.value[1].value)
    assert_equal(OpenSSL::ASN1::OctetString, ext.value[2].class)
    extv = OpenSSL::ASN1.decode(ext.value[2].value)
    assert_equal(OpenSSL::ASN1::BitString, extv.class)
    str = "\000"; str[0] = 0b00000110.chr
    assert_equal(str, extv.value)

    ext = extensions.value[0].value[2]  # subjectKeyIdentifier

    assert_equal(OpenSSL::ASN1::Sequence, ext.class)
    assert_equal(2, ext.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, ext.value[0].class)
    assert_equal("2.5.29.14",  ext.value[0].oid)
    assert_equal(OpenSSL::ASN1::OctetString, ext.value[1].class)

    assert OpenSSL::X509::Certificate.new( cert.to_der ).verify key

    octet_value = ext.value[1].value

    assert_equal "\x04\x14\xD1\xFE\xF9\xFB\xF8\xAE\e\xC1`\xCB\xFA\x03\xE2Ym\xD8s\b\x92\x13", octet_value

    extv = OpenSSL::ASN1.decode(octet_value)
    assert_equal(OpenSSL::ASN1::OctetString, extv.class)
    sha1 = OpenSSL::Digest::SHA1.new
    sha1.update(pkey.value[1].value)
    assert_equal(sha1.digest, extv.value)

    assert_equal(OpenSSL::ASN1::Sequence, sig_alg.class)
    assert_equal(2, sig_alg.value.size)
    assert_equal(OpenSSL::ASN1::ObjectId, pkey.value[0].value[0].class)
    assert_equal("1.2.840.113549.1.1.1", pkey.value[0].value[0].oid)
    assert_equal(OpenSSL::ASN1::Null, pkey.value[0].value[1].class)

    assert_equal(OpenSSL::ASN1::BitString, sig_val.class)

    cert_der = cert.to_der
    assert_equal 593, cert_der.size

    assert OpenSSL::X509::Certificate.new( cert_der ).verify key
    # running the same in MRI also fails
    calulated_sig = key.sign(OpenSSL::Digest::SHA1.new, cert_der)
    #assert_equal calulated_sig, sig_val.value
  end

  # This is from the upstream MRI tests
  def test_bitstring
    encode_decode_test B(%w{ 03 01 00 }), OpenSSL::ASN1::BitString.new(B(%w{}))
    encode_decode_test B(%w{ 03 02 00 01 }), OpenSSL::ASN1::BitString.new(B(%w{ 01 }))

    obj = OpenSSL::ASN1::BitString.new(B(%w{ F0 }))
    obj.unused_bits = 4
    encode_decode_test B(%w{ 03 02 04 F0 }), obj
    assert_raise(OpenSSL::ASN1::ASN1Error) {
      OpenSSL::ASN1.decode(B(%w{ 03 00 }))
    }
    assert_raise(OpenSSL::ASN1::ASN1Error) {
      OpenSSL::ASN1.decode(B(%w{ 03 03 08 FF 00 }))
    }

    assert_raise(OpenSSL::ASN1::ASN1Error) {
      obj = OpenSSL::ASN1::BitString.new(B(%w{ FF FF }))
      obj.unused_bits = 8
      obj.to_der
    }
  end

  def test_bit_string_unused_length
    asn = "\x00\x04".b
    asn.prepend "\x03#{asn.bytesize.chr}"
    bs = OpenSSL::ASN1.decode(asn)
    assert_equal asn, bs.to_der

    bs.unused_bits = 6
    assert_equal "\x03\x02\x06\x00", bs.to_der
  end

  def test_bit_string_infinite_length
    begin
      content = [ OpenSSL::ASN1::BitString.new("\x01"), OpenSSL::ASN1::EndOfContent.new() ]
      cons = OpenSSL::ASN1::Constructive.new content, OpenSSL::ASN1::BIT_STRING, nil, :UNIVERSAL
      cons.infinite_length = true
      expected = %w{ 23 80 03 02 00 01 00 00 }
      raw = [expected.join('')].pack('H*')
      assert_equal raw, cons.to_der
      # TODO for now we can not decode our own sh*t :
      #assert_equal raw, OpenSSL::ASN1.decode(raw).to_der
    end
  end

  def test_string_basic
    test = -> (tag, klass) {
      encode_decode_test tag.chr + B(%w{ 00 }), klass.new(B(%w{}))
      encode_decode_test tag.chr + B(%w{ 02 00 01 }), klass.new(B(%w{ 00 01 }))
    }
    test.(4, OpenSSL::ASN1::OctetString)
    test.(12, OpenSSL::ASN1::UTF8String)
    test.(18, OpenSSL::ASN1::NumericString)
    test.(19, OpenSSL::ASN1::PrintableString)
    test.(20, OpenSSL::ASN1::T61String)
    test.(21, OpenSSL::ASN1::VideotexString)
    test.(22, OpenSSL::ASN1::IA5String)
    test.(25, OpenSSL::ASN1::GraphicString)
    test.(26, OpenSSL::ASN1::ISO64String)
    test.(27, OpenSSL::ASN1::GeneralString)
    test.(28, OpenSSL::ASN1::UniversalString)
    test.(30, OpenSSL::ASN1::BMPString)
  end

  def test_constructive_each
    data = [OpenSSL::ASN1::Integer.new(0), OpenSSL::ASN1::Integer.new(1)]
    seq = OpenSSL::ASN1::Sequence.new data

    assert_equal data, seq.entries
  end

  def test_decode_all
    expected = %w{ 02 01 01 02 01 02 02 01 03 }
    raw = [expected.join('')].pack('H*')
    ary = OpenSSL::ASN1.decode_all(raw)
    assert_equal(3, ary.size)
    ary.each_with_index do |asn1, i|
      assert_universal(OpenSSL::ASN1::INTEGER, asn1)
      assert_equal(i + 1, asn1.value)
    end
  end

  def test_decode_application_specific
    raw = "0\x18\x02\x01\x01`\x13\x02\x01\x03\x04\to=Telstra\x80\x03ess"
    asn1 = OpenSSL::ASN1.decode(raw)
    pp asn1 if false

    assert_equal OpenSSL::ASN1::Sequence, asn1.class
    assert_equal 2, asn1.value.size
    assert_equal OpenSSL::ASN1::Integer, asn1.value[0].class
    assert_equal 1,  asn1.value[0].value
    assert_equal OpenSSL::ASN1::ASN1Data, asn1.value[1].class
    assert_equal :APPLICATION,  asn1.value[1].tag_class

    asn1_data = asn1.value[1]
    assert_equal 3, asn1_data.value.size
    assert_equal OpenSSL::ASN1::Integer, asn1_data.value[0].class
    assert_equal 3, asn1_data.value[0].value
    assert_equal OpenSSL::BN, asn1_data.value[0].value.class
    assert_equal OpenSSL::ASN1::OctetString, asn1_data.value[1].class
    assert_equal 'o=Telstra', asn1_data.value[1].value
    assert_equal OpenSSL::ASN1::ASN1Data, asn1_data.value[2].class
    assert_equal :CONTEXT_SPECIFIC,  asn1_data.value[2].tag_class
#    assert_equal 'ess', asn1_data.value[2].value

#    assert_equal raw, asn1.to_der
  end


  def test_encode_der_integer_wrapped
    asn1 = OpenSSL::ASN1::Sequence([ OpenSSL::ASN1::Integer(42), OpenSSL::ASN1::Integer(84) ])

    der = "0\x06\x02\x01*\x02\x01T"
    assert_equal der, asn1.to_der

    asn1 = OpenSSL::ASN1::Sequence([ OpenSSL::ASN1::Integer(OpenSSL::BN.new(42)), OpenSSL::ASN1::Integer(OpenSSL::BN.new(84)) ])

    der = "0\x06\x02\x01*\x02\x01T"
    assert_equal der, asn1.to_der

    i = OpenSSL::ASN1::Integer(OpenSSL::BN.new('1234567890'))
    assert_equal 1234567890, i.value.to_i

    i = OpenSSL::ASN1::Integer('12345678901234567890')
    assert_equal 12345678901234567890, i.value.to_i
  end

  private

  def B(ary)
    [ary.join].pack("H*")
  end

  def assert_asn1_equal(a, b)
    assert_equal a.class, b.class
    assert_equal a.tag, b.tag
    assert_equal a.tag_class, b.tag_class
    assert_equal a.indefinite_length, b.indefinite_length
    assert_equal a.unused_bits, b.unused_bits if a.respond_to?(:unused_bits)
    case a.value
    when Array
      a.value.each_with_index { |ai, i|
        assert_asn1_equal ai, b.value[i]
      }
    else
      if OpenSSL::ASN1::ObjectId === a
        assert_equal a.oid, b.oid
      else
        assert_equal a.value, b.value
      end
    end
    assert_equal a.to_der, b.to_der
  end

  def encode_test(der, obj)
    assert_equal der, obj.to_der
  end

  def decode_test(der, obj)
    decoded = OpenSSL::ASN1.decode(der)
    assert_asn1_equal obj, decoded
    decoded
  end

  def encode_decode_test(der, obj)
    encode_test(der, obj)
    decode_test(der, obj)
  end

  def assert_universal(tag, asn1, inf_len=false)
    assert_equal(tag, asn1.tag)
    assert_equal(:UNIVERSAL, asn1.tag_class)
    assert_equal(inf_len, asn1.infinite_length)
  end

  def encode_decode_test1(type, values)
    values.each do |v|
      assert_equal(v, OpenSSL::ASN1.decode(type.new(v).to_der).value)
    end
  end

end
