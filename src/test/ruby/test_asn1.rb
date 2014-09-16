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

  private

  def encode_decode_test(type, values)
    values.each do |v|
      assert_equal(v, OpenSSL::ASN1.decode(type.new(v).to_der).value)
    end
  end

end