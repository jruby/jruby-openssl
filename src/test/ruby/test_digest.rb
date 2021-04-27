# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestDigest < TestCase

  def test_digest_classes
    OpenSSL::Digest::SHA.new.block_length
    OpenSSL::Digest::SHA1.new.block_length
    OpenSSL::Digest::SHA224.new.block_length # BC
    OpenSSL::Digest::SHA256.new.block_length
    OpenSSL::Digest::SHA384.new.block_length
    OpenSSL::Digest::SHA512.new.block_length

    OpenSSL::Digest::MD2.new.block_length
    OpenSSL::Digest::MD4.new.block_length # BC
    OpenSSL::Digest::MD5.new.block_length
    # NOTE: MDC2 not supported
    #OpenSSL::Digest::MDC2.new

    OpenSSL::Digest::RIPEMD160.new.block_length # BC

    OpenSSL::Digest::DSS.new.block_length
    OpenSSL::Digest::DSS1.new.block_length
  end

  def test_digest_extension
    # BC supports these - we shall allow any supported algorithms to work
    OpenSSL::Digest.new('RipeMD256').digest
    OpenSSL::Digest.new('SHA224').digest
    OpenSSL::Digest.new('SHA-384').digest
    #OpenSSL::Digest.new('SHA3').digest
    OpenSSL::Digest.new('Whirlpool').digest
  end if defined? JRUBY_VERSION

  def test_digest_helpers
    md5 = "\x1EJ\e\x03\xD1\xB6\xCD\x8A\x17J\x82ov\xE0\t\xF4"
    assert_equal md5, OpenSSL::Digest.digest('MD5', '0000000000000000')
    sha = "b02132081808b493c61e86626ee6c2e29326a662"
    assert_equal sha, OpenSSL::Digest.hexdigest('SHA1', '0000000000000000')
  end

  def setup
    require 'openssl'
    @d1 = OpenSSL::Digest::Digest::new("MD5")
    @d2 = OpenSSL::Digest::MD5.new

    require 'digest/md5'
    @md = Digest::MD5.new
    @data = "DATA"
  end

  def teardown
    @d1 = @d2 = @md = nil
  end

  def test_digest
    assert_equal(@md.digest, @d1.digest)
    assert_equal(@md.hexdigest, @d1.hexdigest)
    @d1 << @data
    @d2 << @data
    @md << @data
    assert_equal(@md.digest, @d1.digest)
    assert_equal(@md.hexdigest, @d1.hexdigest)
    assert_equal(@d1.digest, @d2.digest)
    assert_equal(@d1.hexdigest, @d2.hexdigest)
    assert_equal(@md.digest, OpenSSL::Digest::MD5.digest(@data))
    assert_equal(@md.hexdigest, OpenSSL::Digest::MD5.hexdigest(@data))
  end

  def test_eql
    assert(@d1 == @d2, "==")
    d = @d1.clone
    assert(d == @d1, "clone")
  end

  def test_info
    assert_equal("MD5", @d1.name, "name")
    assert_equal("MD5", @d2.name, "name")
    assert_equal(16, @d1.size, "size")
  end

  def test_dup
    @d1.update(@data)
    assert_equal(@d1.name, @d1.dup.name, "dup")
    assert_equal(@d1.name, @d1.clone.name, "clone")
    assert_equal(@d1.digest, @d1.clone.digest, "clone .digest")
  end

  def test_reset
    @d1.update(@data)
    dig1 = @d1.digest
    @d1.reset
    @d1.update(@data)
    dig2 = @d1.digest
    assert_equal(dig1, dig2, "reset")
  end

  def encode16(str)
    str.unpack("H*").first
  end

  def test_098_features
    sha224_a = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
    sha256_a = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    sha384_a = "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    sha512_a = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"

    assert_equal(sha224_a, OpenSSL::Digest::SHA224.hexdigest("a"))
    assert_equal(sha256_a, OpenSSL::Digest::SHA256.hexdigest("a"))
    assert_equal(sha384_a, OpenSSL::Digest::SHA384.hexdigest("a"))
    assert_equal(sha512_a, OpenSSL::Digest::SHA512.hexdigest("a"))

    assert_equal(sha224_a, encode16(OpenSSL::Digest::SHA224.digest("a")))
    assert_equal(sha256_a, encode16(OpenSSL::Digest::SHA256.digest("a")))
    assert_equal(sha384_a, encode16(OpenSSL::Digest::SHA384.digest("a")))
    assert_equal(sha512_a, encode16(OpenSSL::Digest::SHA512.digest("a")))
  end

  def test_net_ssh_like_loading
    require 'openssl'
    require 'openssl/digest'
    # shout not raise TypeError: superclass mismatch for class Digest
    assert OpenSSL::Digest.is_a?(Class)
    assert OpenSSL::Digest("MD5")
  end

end