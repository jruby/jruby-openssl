# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestOaep < TestCase

  def setup
    super
    self.class.disable_security_restrictions!
    require 'base64'
  end

  def test_oaep_decrypt
    key = File::read(File.join(File.dirname(__FILE__), 'encrypted.key'))
    base64_cipher_text = "s+ydnGyGfJlH6FPB21tYeAeeMKcqLuybw7lxArZIEGRjMNSn2LHNzUEwX/H6FQan5lKQPZxxU1tBuFP6sP27ektEIXgoIQm+PdxilJnNPVoDA9Wff93MMa9JG3VMsc0kbUNMmJf6SQcJ+IB3OyBPZfPrz6wbkwM2zVm9Y/oqFWM="

    # create cleaned up key object
    key = OpenSSL::PKey::RSA.new(key)

    cipher_text = Base64.decode64(base64_cipher_text)
    # assert_nothing_raised {
    key.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    # }
  end
end
