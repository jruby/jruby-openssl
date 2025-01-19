require File.expand_path('test_helper', File.dirname(__FILE__))

class TestBN < TestCase

  def setup
    super
    @e1 = OpenSSL::BN.new(999.to_s(16), 16) # OpenSSL::BN.new(str, 16) must be most stable
    @e2 = OpenSSL::BN.new("-" + 999.to_s(16), 16)
    @e3 = OpenSSL::BN.new((2**107-1).to_s(16), 16)
    @e4 = OpenSSL::BN.new("-" + (2**107-1).to_s(16), 16)
  end

  def test_to_int
    assert_equal(999, @e1.to_i)
    assert_equal(-999, @e2.to_i)
    assert_equal(2**107-1, @e3.to_i)
    assert_equal(-(2**107-1), @e4.to_i)

    assert_equal(999, @e1.to_int)
  end

  def test_coerce
    assert_equal(["", "-999"], @e2.coerce(""))
    assert_equal([1000, -999], @e2.coerce(1000))
    assert_raise(TypeError) { @e2.coerce(Class.new.new) }
  end

  def test_zero_p
    assert_equal(true, 0.to_bn.zero?)
    assert_equal(false, 1.to_bn.zero?)
  end

  def test_one_p
    assert_equal(true, 1.to_bn.one?)
    assert_equal(false, 2.to_bn.one?)
  end

  def test_odd_p
    assert_equal(true, 1.to_bn.odd?)
    assert_equal(false, 2.to_bn.odd?)
  end

  def test_negative_p
    assert_equal(false, 0.to_bn.negative?)
    assert_equal(false, @e1.negative?)
    assert_equal(true, @e2.negative?)
  end

  def test_abs
    assert_equal(@e1, @e2.abs)
    assert_equal(@e3, @e4.abs)
    assert_not_equal(@e2, @e2.abs)
    assert_not_equal(@e4, @e4.abs)
    assert_equal(false, @e2.abs.negative?)
    assert_equal(false, @e4.abs.negative?)
    assert_equal(true, (-@e1.abs).negative?)
    assert_equal(true, (-@e2.abs).negative?)
    assert_equal(true, (-@e3.abs).negative?)
    assert_equal(true, (-@e4.abs).negative?)
  end

  def test_unary_plus_minus
    assert_equal(999, +@e1)
    assert_equal(-999, +@e2)
    assert_equal(-999, -@e1)
    assert_equal(+999, -@e2)

    # These methods create new BN instances due to BN mutability
    # Ensure that the instance isn't the same
    e1_plus = +@e1
    e1_minus = -@e1
    assert_equal(false, @e1.equal?(e1_plus))
    assert_equal(true, @e1 == e1_plus)
    assert_equal(false, @e1.equal?(e1_minus))
  end

  def test_mod
    assert_equal(1, 1.to_bn % 2)
    assert_equal(0, 2.to_bn % 1)
    #assert_equal(-2, -2.to_bn % 7)
  end


  def test_new
    bn = OpenSSL::BN.new('0') unless defined? JRUBY_VERSION
    assert_equal ( bn || OpenSSL::BN.new(0) ).to_s, '0'
  end

  def test_to_s
    bn = OpenSSL::BN.new('10')
    assert_equal bn.to_s(10), '10'
    assert_equal bn.to_s(16), '0A'

    bn = OpenSSL::BN.new('100')
    assert_equal bn.to_s(16), '64'
    assert_equal bn.to_s, '100'

    if defined? JRUBY_VERSION
      bn = OpenSSL::BN.new(-4242)
      assert_equal bn.to_s, '-4242'
    end
  end

  def test_comparable
    assert OpenSSL::BN.include? Comparable
  end

  def test_cmp
    bn1 = OpenSSL::BN.new('1')
    bn2 = OpenSSL::BN.new('1')
    bn3 = OpenSSL::BN.new('2')
    assert_equal(false, bn1 == nil)
    assert_equal(true,  bn1 != nil)
    assert_equal(true, bn1 == bn2)
    assert_equal(false, bn1 == bn3)
    assert_equal(true, bn1.eql?(bn2))
    assert_equal(false, bn1.eql?(bn3))
    assert_equal(bn1.hash, bn2.hash)
    assert_not_equal(bn3.hash, bn1.hash)
  end if RUBY_VERSION >= '2.3'

  def test_to_bn
    bn = OpenSSL::BN.new('4224')
    assert_equal bn, 4224.to_bn
    assert_equal OpenSSL::BN, 1.to_bn.class

    bn = OpenSSL::BN.new('-1234567890')
    assert_equal bn, ( -1234567890 ).to_bn

    bn = OpenSSL::BN.new('1234567890123456789012345678901234567890')
    assert_equal bn, 1234567890123456789012345678901234567890.to_bn

    e1 = OpenSSL::BN.new(999.to_s(16), 16)
    e2 = OpenSSL::BN.new((2**107-1).to_s(16), 16)
    assert_equal(e1, 999.to_bn)
    assert_equal(e2, (2**107-1).to_bn)
  end

  def test_comparison
    e1 = OpenSSL::BN.new(999.to_s(16), 16)
    e3 = OpenSSL::BN.new((2**107-1).to_s(16), 16)
    assert_equal(false, e1 == nil)
    assert_equal(false, e1 == -999)
    assert_equal(true, e1 == 999)
    assert_equal(true, e1 == 999.to_bn)
    assert_equal(false, e1.eql?(nil))
    assert_equal(false, e1.eql?(999))
    assert_equal(true, e1.eql?(999.to_bn))
    assert_equal(e1.hash, 999.to_bn.hash)
    assert_not_equal(e1.hash, e3.hash)
    assert_equal(0, e1.cmp(999))
    assert_equal(1, e1.cmp(-999))
    assert_equal(0, e1.ucmp(999))
    assert_equal(0, e1.ucmp(-999))
    assert_instance_of(String, e1.hash.to_s)
  end

  def test_to_java
    assert_equal java.lang.Integer.new(42), OpenSSL::BN.new('42').to_java(:int)
    assert_equal java.math.BigInteger.valueOf(24), val = OpenSSL::BN.new('24').to_java
    assert_equal java.math.BigInteger, val.class
    assert_equal java.math.BigInteger.valueOf(24), val = OpenSSL::BN.new('24').to_java(java.lang.Number)
  end if defined? JRUBY_VERSION

  def test_new_str
    e1 = OpenSSL::BN.new(999.to_s(16), 16) # OpenSSL::BN.new(str, 16) must be most stable
    e2 = OpenSSL::BN.new((2**107-1).to_s(16), 16)
    assert_equal(e1, OpenSSL::BN.new("999"))
    assert_equal(e2, OpenSSL::BN.new((2**107-1).to_s))
    assert_equal(e1, OpenSSL::BN.new("999", 10))
    assert_equal(e2, OpenSSL::BN.new((2**107-1).to_s, 10))
    assert_equal(e1, OpenSSL::BN.new("\x03\xE7", 2))
    assert_equal(e2, OpenSSL::BN.new("\a\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 2))
    assert_equal(e1, OpenSSL::BN.new("\x00\x00\x00\x02\x03\xE7", 0))
    assert_equal(e2, OpenSSL::BN.new("\x00\x00\x00\x0E\a\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 0))
  end

  def test_new_bn
    e1 = OpenSSL::BN.new(999.to_s(16), 16)
    e2 = OpenSSL::BN.new((2**107-1).to_s(16), 16)
    assert_equal(e1, OpenSSL::BN.new(e1))
    assert_equal(e2, OpenSSL::BN.new(e2))
  end

  def test_new_integer
    assert_equal(999.to_bn, OpenSSL::BN.new(999))
    assert_equal((2 ** 107 - 1).to_bn, OpenSSL::BN.new(2 ** 107 - 1))
    assert_equal(-999.to_bn, OpenSSL::BN.new(-999))
    assert_equal((-(2 ** 107 - 1)).to_bn, OpenSSL::BN.new(-(2 ** 107 - 1)))
  end

  def test_prime_p
    assert_equal(true, OpenSSL::BN.new((2 ** 107 - 1).to_s(16), 16).prime?)
    assert_equal(true, OpenSSL::BN.new((2 ** 127 - 1).to_s(16), 16).prime?(1))
  end

end