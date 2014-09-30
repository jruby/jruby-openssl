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

    def test_pbkdf2_hmac
      pass = 'SecreT2'
      salt = '0123456789001234567890'

      digest = OpenSSL::Digest::MD5.new
      expected = "\xC10D2\x8F\xEA}\xF7ag\xB5\xC8Ad\xFBN9Ff\x9D}\xA6\a\x86\x8F\xC4&HI\x85\x89<cGl\x02W\xF9\xD8\xF9\x1C\xAB\xFF\xA3\xC9C>U"
      expected.force_encoding('ASCII-8BIT') if ''.respond_to?(:force_encoding)
      assert_equal expected, OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, 120, 48, digest)
      assert_equal expected, OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, 120, 48, digest)

      digest = OpenSSL::Digest::SHA256.new
      expected = "}\xF4\xE3\xBF\xA7u\xB3[l\xE0(\x84\x96W\xFA\x00h\xA1l#\xB8\xC0Ptirz\v\xBA\x0Es\n<\xF8\xB5(\x85\xDA\xFE\x02y\x14\xB5A`\x8F\xA3\x03\x95\xA7G\xB4pU\xB6pf=Q\x1Fz\x12u\x83"
      expected.force_encoding('ASCII-8BIT') if ''.respond_to?(:force_encoding)
      assert_equal expected, OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, 100, 64, digest)

      expected = "\x03\x1C\x86\xC7N?\xC3\xBC\xF30W\xEC\x9B\x89I\x8D\xE6|\xA1Y\xEF\bt\xB4\x17\xA9\x87\xCB\xEA\x7F\x92\xDB\x88N@\xCB\x17\xDF\xC4\x8F\xE48L\x1Dy<\xD8\x9B\x8Cx\x85\x93\n\xA3`\xE9]\x90\xA2\x10I[\xE9\x84"
      expected.force_encoding('ASCII-8BIT') if ''.respond_to?(:force_encoding)
      assert_equal expected, OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, 100, 64, 'SHA512')
    end

  end
end