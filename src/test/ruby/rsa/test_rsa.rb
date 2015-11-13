# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestRsa < TestCase

  def setup
    super
    self.class.disable_security_restrictions!
    require 'base64'
  end

  def test_rsa_private_decrypt
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    base64_cipher = "oj1VB1Lnh6j5Ahoq4dllIXkStZHaT9RvizB0x+yIUDtzi6grSh9vXoCchb+U\nkyLOcMmIXopv1Oe7h2te+XS63AG0EAfUhKTFVDYkm7VmcXue25MPr+P+0w+7\nWjZci4VRBLq3T2qZa3IJhQPsNAtEE1DYXnEjNe0jcFa2bu8TPNscoogo5aAw\nQGT+3cKe7A053czG47Sip7aIo+4NlJHE9kFMOTLaWi3fvv/M9/VKo3Bmm/88\n8Ai09LncNTpq787CRHw/wfjuPlQJOiLt+i7AZHBl6x0jK9bqkhPK5YwP0vmc\nuL52QLzgPxj9E78crg47iJDOgNwU/ux1/VuKnlQ9PQ==\n"

    key = OpenSSL::PKey::RSA.new(File.read(key_file))
    decrypted = key.private_decrypt(Base64.decode64(base64_cipher))

    assert_equal('Test string for RSA', decrypted)
  end

  def test_rsa_public_decrypt
    pub_key_file = File.join(File.dirname(__FILE__), 'public_key.pub')
    base64_cipher = "ZBiJ0yHAcEJWDPI38R4M7ccpDK+Ek6Apl/CyPJOSwiY/GvlJ3J3VjRYwRVvE\nox173agDckKY9/gaT4otgfk0OuQRaIaPF51uFWbSPZhOBWD+gLrDAlAfhMg6\nascRrUYydEYzOHjXZ8SMhWg8bmsajABd36SoTcpa7FVm4WXGm/OG65htPYQ+\n1XjChiw3NvVJqFWf5Khpl12+/4s9k5GPjziFCAPgmfxGYDp0KnsqqHIg6s7P\nvR6zFcS9uReNcns4POecI/oeZHqvS/0TZ/q5eZJzFGMSflPJMxrCCnImGbiC\nNRchZyK2kTuTAWzz8d5Ml72/75mCJyimrAtv66XaEQ==\n"

    pub_key = OpenSSL::PKey::RSA.new(File.read(pub_key_file))
    decrypted = pub_key.public_decrypt(Base64.decode64(base64_cipher))

    assert_equal('Test public decrypt string', decrypted)
  end

  def test_rsa_private_encrypt
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::RSA.new(File.read(key_file))

    # Assert nothing raised {
    key.private_encrypt("Test string")
    # }
  end

  def test_rsa_public_encrypt
    pub_key_file = File.join(File.dirname(__FILE__), 'public_key.pub')
    pub_key = OpenSSL::PKey::RSA.new(File.read(pub_key_file))

    # Assert nothing raised {
    pub_key.public_encrypt("Test string")
    # }
  end

end
