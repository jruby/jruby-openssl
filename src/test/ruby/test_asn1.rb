# coding: US-ASCII
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

    ai = OpenSSL::ASN1::Integer.new( i = 2**4242 )
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

  require 'pp'

  def _test_parse_infinite_length_sequence # borrowed from Krypt
    raw = [%w{30 80 04 01 01 02 01 01 00 00}.join("")].pack("H*")
    asn1 = OpenSSL::ASN1.decode(raw)
    pp asn1

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
    # The real value of inf_octets is "\x01\x02", i.e. the concatenation
    # of partial1 and partial2
    inf_octets.infinite_length = true
    assert_equal true, inf_octets.infinite_length

    assert_equal tag, inf_octets.tag

    inf_octets.infinite_length = false
    assert_raise(OpenSSL::ASN1::ASN1Error) { inf_octets.to_der }

    inf_octets.infinite_length = true
    der = inf_octets.to_der
    #puts 'expected: ' + "$\x80\x04\x01\x01\x04\x01\x02\x00\x00".to_java_bytes.inspect
    #puts '  actual: ' + der.to_java_bytes.inspect
    assert_equal "$\x80\x04\x01\x01\x04\x01\x02\x00\x00", der
  end

  def _test_constructive_decode # TODO NOT IMPLEMENTED
    der = "$\x80\x04\x01\x01\x04\x01\x02\x00\x00"
    asn1 = OpenSSL::ASN1.decode(der)
    #assert asn1.instance_of? OpenSSL::ASN1::Constructive
    assert_equal 4, asn1.tag
    assert_equal :UNIVERSAL, asn1.tag_class
    assert_equal true, asn1.infinite_length

    assert_equal "\x01", asn1.value[0].value
    assert_equal "\x02", asn1.value[1].value
    assert_equal "", asn1.value[2].value
  end

  private

  def assert_universal(tag, asn1, inf_len=false)
    assert_equal(tag, asn1.tag)
    assert_equal(:UNIVERSAL, asn1.tag_class)
    assert_equal(inf_len, asn1.infinite_length)
  end

  def encode_decode_test(type, values)
    values.each do |v|
      assert_equal(v, OpenSSL::ASN1.decode(type.new(v).to_der).value)
    end
  end

end
