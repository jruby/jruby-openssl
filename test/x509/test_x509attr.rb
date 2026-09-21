require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Attribute < TestCase

  # oid: challengePassword, values: Set[UTF8String<"abc123">]
  CHALLENGE_PASSWORD_DER = "\x30\x15\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x07\x31\x08" \
    "\x0c\x06\x61\x62\x63\x31\x32\x33".b

  def test_from_der
    attr = OpenSSL::X509::Attribute.new(CHALLENGE_PASSWORD_DER)
    assert_equal CHALLENGE_PASSWORD_DER, attr.to_der
    assert_equal "challengePassword", attr.oid
    assert_equal "abc123", attr.value.value[0].value
  end

  def test_from_to_der_object
    obj = Object.new
    der = CHALLENGE_PASSWORD_DER
    obj.define_singleton_method(:to_der) { der }

    attr = OpenSSL::X509::Attribute.new(obj)
    assert_equal "challengePassword", attr.oid
    assert_equal "abc123", attr.value.value[0].value
  end

  def test_new_with_oid_and_value
    val = OpenSSL::ASN1::Set.new([
      OpenSSL::ASN1::UTF8String.new("abc123")
    ])
    attr = OpenSSL::X509::Attribute.new("challengePassword", val)
    assert_equal "challengePassword", attr.oid
    assert_equal val.to_der, attr.value.to_der
  end

  def test_new_with_non_set_value
    error = assert_raise(OpenSSL::X509::AttributeError) do
      OpenSSL::X509::Attribute.new("challengePassword", OpenSSL::ASN1::EndOfContent.new)
    end

    assert_equal "attribute value must be ASN1::Set: nested asn1 error", error.message
  end

  def test_dup
    attr = OpenSSL::X509::Attribute.new(CHALLENGE_PASSWORD_DER)
    assert_equal attr.to_der, attr.dup.to_der
  end

  def test_eq
    attr1 = OpenSSL::X509::Attribute.new(CHALLENGE_PASSWORD_DER)
    attr2 = OpenSSL::X509::Attribute.new(CHALLENGE_PASSWORD_DER)
    assert_equal attr1, attr2
  end

end
