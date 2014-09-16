require File.expand_path('test_helper', File.dirname(__FILE__))

class TestASN1 < TestCase

  def test_encode_boolean
    encode_decode_test(OpenSSL::ASN1::Boolean, [true, false])
  end

  def test_encode_integer
    ai = OpenSSL::ASN1::Integer.new( i = 42 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value

    ai = OpenSSL::ASN1::Integer.new( i = 0 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value

    ai = OpenSSL::ASN1::Integer.new( i = -1 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value

    ai = OpenSSL::ASN1::Integer.new( i = 2**12345 )
    assert_equal i, OpenSSL::ASN1.decode(ai.to_der).value
  end

  def test_encode_nil
    #Primitives raise TypeError, Constructives NoMethodError

    assert_raise(TypeError) { OpenSSL::ASN1::Integer.new(nil).to_der }
    assert_raise(TypeError) { OpenSSL::ASN1::Boolean.new(nil).to_der }

    assert_raise(NoMethodError) { OpenSSL::ASN1::Set.new(nil).to_der }
    assert_raise(NoMethodError) { OpenSSL::ASN1::Sequence.new(nil).to_der }
  end

  def test_instantiate
    # nothing shall raise :
    OpenSSL::ASN1::Null.new(nil)
    OpenSSL::ASN1::EndOfContent.new()
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

  def test_constructive
    partial1 = OpenSSL::ASN1::OctetString.new("\x01")
    partial2 = OpenSSL::ASN1::OctetString.new("\x02")
    inf_octets = OpenSSL::ASN1::Constructive.new( [ partial1,
                                                    partial2,
                                                    OpenSSL::ASN1::EndOfContent.new ],
                                                  OpenSSL::ASN1::OCTET_STRING,
                                                  nil,
                                                  :UNIVERSAL )
    assert_equal false, inf_octets.infinite_length
    # The real value of inf_octets is "\x01\x02", i.e. the concatenation
    # of partial1 and partial2
    inf_octets.infinite_length = true
    assert_equal true, inf_octets.infinite_length
  end

  private

  def encode_decode_test(type, values)
    values.each do |v|
      assert_equal(v, OpenSSL::ASN1.decode(type.new(v).to_der).value)
    end
  end

end