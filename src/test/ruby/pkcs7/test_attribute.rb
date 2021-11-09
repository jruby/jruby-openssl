require File.expand_path('../test_helper', File.dirname(__FILE__))

module PKCS7Test
  class TestAttribute < TestCase

    def test_attributes
      val = org.bouncycastle.asn1.DEROctetString.new("foo".to_java_bytes)
      val2 = org.bouncycastle.asn1.DEROctetString.new("bar".to_java_bytes)
      attr = org.jruby.ext.openssl.impl.Attribute.create(123, 444, val)
      assert_raise NoMethodError do
        attr.type = 12
      end
      assert_raise NoMethodError do
        attr.value = val2
      end

      assert_equal 123, attr.type
      assert_equal val, attr.set.get(0)

      attr2 = org.jruby.ext.openssl.impl.Attribute.create(123, 444, val)

      assert_equal attr, attr2

      assert_not_equal org.jruby.ext.openssl.impl.Attribute.create(124, 444, val), attr
      assert_not_equal org.jruby.ext.openssl.impl.Attribute.create(123, 444, val2), attr
    end

  end
end
