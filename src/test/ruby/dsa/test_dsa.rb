# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestDsa < TestCase

  def setup
    super
    self.class.disable_security_restrictions!
    require 'base64'
  end

  def test_dsa_param_accessors
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::DSA.new(File.read(key_file))

    [:priv_key, :pub_key, :p, :q, :g].each do |param|
      dsa = OpenSSL::PKey::DSA.new
      assert_nil(dsa.send(param))
      value = key.send(param)
      dsa.send("#{param}=", value)
      assert_equal(value, dsa.send(param), param)
    end
  end

  def test_dsa_from_params_private_first
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::DSA.new(File.read(key_file))

    dsa = OpenSSL::PKey::DSA.new
    dsa.priv_key, dsa.p, dsa.q, dsa.g = key.priv_key, key.p, key.q, key.g
    assert(dsa.private?)
    assert(!dsa.public?)
    [:priv_key, :p, :q, :g].each do |param|
      assert_equal(key.send(param), dsa.send(param), param)
    end

    dsa.pub_key = key.pub_key
    assert(dsa.private?)
    assert(dsa.public?)
    [:priv_key, :pub_key, :p, :q, :g].each do |param|
      assert_equal(key.send(param), dsa.send(param), param)
    end
  end

  def test_dsa_from_params_public_first
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::DSA.new(File.read(key_file))

    dsa = OpenSSL::PKey::DSA.new
    dsa.pub_key, dsa.p, dsa.q, dsa.g = key.pub_key, key.p, key.q, key.g
    assert(!dsa.private?)
    assert(dsa.public?)
    [:pub_key, :p, :q, :g].each do |param|
      assert_equal(key.send(param), dsa.send(param), param)
    end

    dsa.priv_key = key.priv_key
    assert(dsa.private?)
    assert(dsa.public?)
    [:priv_key, :pub_key, :p, :q, :g].each do |param|
      assert_equal(key.send(param), dsa.send(param), param)
    end
  end
end
