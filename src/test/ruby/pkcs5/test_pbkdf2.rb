require File.expand_path('../test_helper', File.dirname(__FILE__))

module Jopenssl
  class TestPKCS5 < TestCase

    def test_pbkdf2_hmac_sha1
      pass = 'secret'
      salt = 'sugar0'
      iter = 42
      keylen = 24
      expected = "\a\xB6I\xE1)\xD8\xA6\x84\xC8D\b\xB2h(]\xBA\x87\xDE\e\xFC\x7F\e\xC3\x06"
      expected.force_encoding('ASCII-8BIT') if ''.respond_to?(:force_encoding)
      assert_equal expected, OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass, salt, iter, keylen)
    end

  end
end