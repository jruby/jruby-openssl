# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestRandom < TestCase

  def test_api
    assert_equal 24, OpenSSL::Random.random_bytes(24).size
    assert_equal 1024, OpenSSL::Random.random_bytes(1024).size

    OpenSSL::Random.seed OpenSSL::Random.random_bytes(24)
    assert_equal 42, OpenSSL::Random.random_bytes(42).size

    assert_equal true, OpenSSL::Random.status?

    assert_equal 24, OpenSSL::Random.pseudo_bytes(24).size
    assert_equal 1024, OpenSSL::Random.pseudo_bytes(1024).size
  end

  def test_stubs
    OpenSSL::Random.random_add('42', :entropy)
    OpenSSL::Random.egd('hello.rb')
    OpenSSL::Random.egd_bytes('hello.rb', 42)
  end

end