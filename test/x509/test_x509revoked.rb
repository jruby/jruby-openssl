# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Revoked < TestCase

  def setup; require 'openssl' end

  def test_new
    rev = OpenSSL::X509::Revoked.new
    assert_equal 0, rev.serial
    assert_equal nil, rev.time
    assert_equal [], rev.extensions
    assert_raises(TypeError) { rev.time = nil }
    assert_raises(TypeError) { rev.serial = nil }
    assert_raises(TypeError) { rev.serial = '1' }
    rev.time = 1.5
    assert_equal 1, rev.time.to_i
    assert_raises(ArgumentError) { rev.time = 'x' }

    rev.time = Time.new(2024, 3, 5, 12, 34, 56.789, '+05:30')
    assert_equal 1_709_622_296, rev.time.to_i
    assert rev.time.utc?
    assert_equal 0, rev.time.nsec

    assert_raises(TypeError) { rev.extensions = nil }
    assert_raises(TypeError) { rev.add_extension(nil) }
    if RUBY_VERSION >= '2.0.0' || defined? JRUBY_VERSION
      assert rev.inspect.index('#<OpenSSL::X509::Revoked:') == 0
    end
  end

  def test_serial=
    rev = OpenSSL::X509::Revoked.new
    rev.serial = OpenSSL::BN.new '1234567890'
    assert_equal '1234567890', rev.serial.to_s
    rev.serial = 4242
    assert_equal '4242', rev.serial.to_s
  end

  def test_to_der
    rev = OpenSSL::X509::Revoked.new
    rev.serial = 42
    rev.time = Time.at(1)

    entries = OpenSSL::ASN1.decode(rev.to_der).value
    assert_equal 42, entries[0].value.to_i
    assert_equal Time.at(1).utc, entries[1].value

    other = OpenSSL::X509::Revoked.new
    other.serial = 42
    other.time = Time.at(1)
    assert_equal rev, other
  end

end
