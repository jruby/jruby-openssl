# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestRSA < TestCase

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

  def test_rsa_param_accessors
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::RSA.new(File.read(key_file))

    [:e, :n, :d, :p, :q, :iqmp, :dmp1, :dmq1].each do |param|
      rsa = OpenSSL::PKey::RSA.new
      assert_nil(rsa.send(param))
      value = key.send(param)
      rsa.send("#{param}=", value)
      assert_equal(value, rsa.send(param), param)
    end
  end

  def test_rsa_from_params_public_first
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::RSA.new(File.read(key_file))

    rsa = OpenSSL::PKey::RSA.new
    rsa.e, rsa.n = key.e, key.n
    assert_nothing_raised { rsa.public_encrypt('Test string') }
    [:e, :n].each {|param| assert_equal(key.send(param), rsa.send(param)) }

    rsa.d, rsa.p, rsa.q, rsa.iqmp, rsa.dmp1, rsa.dmq1 = key.d, key.p, key.q, key.iqmp, key.dmp1, key.dmq1
    assert_nothing_raised { rsa.private_encrypt('Test string') }
    [:e, :n, :d, :p, :q, :iqmp, :dmp1, :dmq1].each do |param|
      assert_equal(key.send(param), rsa.send(param), param)
    end
  end

  def test_rsa_from_params_private_first
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')
    key = OpenSSL::PKey::RSA.new(File.read(key_file))

    rsa = OpenSSL::PKey::RSA.new
    rsa.d, rsa.p, rsa.q, rsa.iqmp, rsa.dmp1, rsa.dmq1 = key.d, key.p, key.q, key.iqmp, key.dmp1, key.dmq1
    rsa.e, rsa.n = key.e, key.n
    assert_nothing_raised { rsa.public_encrypt('Test string') }
    assert_nothing_raised { rsa.private_encrypt('Test string') }
    [:e, :n, :d, :p, :q, :iqmp, :dmp1, :dmq1].each do |param|
      assert_equal(key.send(param), rsa.send(param), param)
    end
  end

  def test_read_private_key
    cert = File.join(File.dirname(__FILE__), 'private_key.pem')
    assert key = OpenSSL::PKey.read(File.read(cert))
    assert key.is_a?(OpenSSL::PKey::RSA)
  end

  def test_read_private_key_with_password
    cert = File.join(File.dirname(__FILE__), 'private_key_with_pass.pem')
    pass = "secure-password!42"
    assert key = OpenSSL::PKey.read(File.read(cert), pass)
    assert key.is_a?(OpenSSL::PKey::RSA)
  end

  def test_RSAPrivateKey_encrypted
    rsa1024 = Fixtures.pkey("rsa1024")
    # key = abcdef
    pem = <<-EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,733F5302505B34701FC41F5C0746E4C0

zgJniZZQfvv8TFx3LzV6zhAQVayvQVZlAYqFq2yWbbxzF7C+IBhKQle9IhUQ9j/y
/jkvol550LS8vZ7TX5WxyDLe12cdqzEvpR6jf3NbxiNysOCxwG4ErhaZGP+krcoB
ObuL0nvls/+3myy5reKEyy22+0GvTDjaChfr+FwJjXMG+IBCLscYdgZC1LQL6oAn
9xY5DH3W7BW4wR5ttxvtN32TkfVQh8xi3jrLrduUh+hV8DTiAiLIhv0Vykwhep2p
WZA+7qbrYaYM8GLLgLrb6LfBoxeNxAEKiTpl1quFkm+Hk1dKq0EhVnxHf92x0zVF
jRGZxAMNcrlCoE4f5XK45epVZSZvihdo1k73GPbp84aZ5P/xlO4OwZ3i4uCQXynl
jE9c+I+4rRWKyPz9gkkqo0+teJL8ifeKt/3ab6FcdA0aArynqmsKJMktxmNu83We
YVGEHZPeOlyOQqPvZqWsLnXQUfg54OkbuV4/4mWSIzxFXdFy/AekSeJugpswMXqn
oNck4qySNyfnlyelppXyWWwDfVus9CVAGZmJQaJExHMT/rQFRVchlmY0Ddr5O264
gcjv90o1NBOc2fNcqjivuoX7ROqys4K/YdNQ1HhQ7usJghADNOtuLI8ZqMh9akXD
Eqp6Ne97wq1NiJj0nt3SJlzTnOyTjzrTe0Y+atPkVKp7SsjkATMI9JdhXwGhWd7a
qFVl0owZiDasgEhyG2K5L6r+yaJLYkPVXZYC/wtWC3NEchnDWZGQcXzB4xROCQkD
OlWNYDkPiZioeFkA3/fTMvG4moB2Pp9Q4GU5fJ6k43Ccu1up8dX/LumZb4ecg5/x
-----END RSA PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::RSA.new(pem, "abcdef")
    assert_same_rsa rsa1024, key
    key = OpenSSL::PKey::RSA.new(pem) { "abcdef" }
    assert_same_rsa rsa1024, key
    assert_predicate key, :private?

    ##
    der = "0\x82\x02^\x02\x01\x00\x02\x81\x81\x00\xCB\xC2\xC4\xB0\xD4@\xA7>\xD4\xFE>C\xA0\x1E\x17\x06\x03\xBDg\xC0-\xBF\x9C\xBF9T\x11\xA7F\xA0\xF1:\xA8\xD5\x87\xB0\xB1h\xA3\xC4E\x81\xEC\x93\x80O\nA7n\xBBS\x84\xF5\x9C\xF6H\xC7\x11\x04;\xB9\xFFX\xD6\xB6\xC2\xCFIZ\xC8\xDA\x87\xCB,\x10\x11R\xC5\x9A\x9D\\\xA4\x8B\x7FCx\x1E.\xFF\x19\x0F\xDAb\x86\x8C\n$<\x8C\x0E#z\x02\xB6\x14\x99\x973\xBDn=\xEF\xA3\x14\xDF\xE9y\xE0N\xA5\x17\xF2_\x14E9\x87\x02\x03\x01\x00\x01\x02\x81\x81\x00\xA4\xA5\xFC\xC4\x1A\xAF'\xB5\xC8\xEC\xAC\xA9~\x8F\xF1\xF0\xC5B\xDE\xBCV\xFBW\x90\xD9\xA5J\"\x8E\x1A\xEC\xF2\x86\x8D\f\xF9ER\x15\xCB:\x93R\xF4\x99\xA0\xC4\xDB\x90\feH\x86\xCE\xE5\x87\xC9\xA59\xE5\xDE\xD1\\8\x1E\xB2@\xCCj@\xF5\xBF\xA6^\x8D\x8Bq&D\x97lD\xCEL\xB0\xF0Qd\xE7\xEB_\x13\x82v\xF5\xEE\xD55\x8EKT\xB5N\xBB\xC4\xAF\xF4\xF2/\xD7\xA1\xD9`\x9D\bl\xE9Z\aN\xE0\xA1\xDC{\xBB\xEC\xEE\x91\x02A\x00\xEF\xE81\xA8\e\x99G\x9E\xF6\xEF\x8F\xDA\x92%\xBFJ\xE5\xE6\xD1%\xCF\x12\xF8\xB2;S.I\x1C-#\xCE\xC1\xD3`\xF4\xAA\x05|\x0FU\aFn\x00\x84\xC9\xC9\xF0\xC0\xAC\xD7\xCD=\x90\xC4\x04&$\x14\n\xBA}\x99\x02A\x00\xD9m\xDAx\x01;^.\xB3\xA3g\x86\xE0,xP\xD3\a0\x87_\x05\x14\xBBV\n\x1E\x93\f\x9B\x1Ag\x1A\xA6\xA5th\x17\xB0\xE6A\xDEX\t\xB1?U\x94g\xF7`f\x1D\x90\xB4\xCDU\xBA @\xA9J\xA4\x1F\x02A\x00\xE2K\t\e\xE2\xFC\x90|7\xBC\xFC\xDAT\xE4\xDA-\xD1\xF2\b\xF2;\x03P&\xFE\xA2\x95\x94L\xC9\x9Fo\x15\x91GqA6\xEF0\x9F)\xBF\x9B_M\xE1\xF1c\xF0\xBA\x98\xCCu\xF8)\x8D(T\xFB\xBA\xAA\xF2q\x02A\x00\xC1\xAEl\x9C\xD7\xA4\x15\xCA\x8E4\xB2\x04\xE0n\\\xA2\xCA\xC8\xAD\xBE\xF8\xB2\xA2\xFC\x19\xB1\x9B\xF8\xAB\x93\x02\x9A\xF3\x8F\x9C\xF5+\xC0f\xD1E\xBD\x958\xD5\x0E0\xE2\xA9\x16 e\xF6R/\xECu?\xFEx\xFB\x14\xC5K\x02@cQq\x03\xF3w@\xF0\x97\n3\xE1\xE5\x8A\x85\xC4\x03\x10\xB3eUa7\xE0\xFA\xDD\f\x11\xC2Ct\xF3\x10\x0F\x92W\xEA\x0EG*q\xC5\x83i\x99\xB6\x85\xD0\xADi\x89J~\xE9\xF0bJ\xF3#S\xA2\x91\x04\xAC"
    pp OpenSSL::ASN1.decode(key.to_der) if $DEBUG
    assert_equal der, key.to_der

    cipher = OpenSSL::Cipher.new("aes-128-cbc")
    exported = rsa1024.to_pem(cipher, "abcdef\0\1")
    assert_same_rsa rsa1024, OpenSSL::PKey::RSA.new(exported, "abcdef\0\1")
    assert_raise(OpenSSL::PKey::RSAError) {
      OpenSSL::PKey::RSA.new(exported, "abcdef")
    }
  end

  def test_RSAPublicKey
    rsa1024 = Fixtures.pkey("rsa1024")

    asn1 = OpenSSL::ASN1::Sequence([ OpenSSL::ASN1::Integer(rsa1024.n), OpenSSL::ASN1::Integer(rsa1024.e) ])

    key = OpenSSL::PKey::RSA.new(asn1.to_der)
    assert_not_predicate key, :private?
    n = 143085709396403084580358323862163416700436550432664688288860593156058579474547937626086626045206357324274536445865308750491138538454154232826011964045825759324933943290377903384882276841880081931690695505836279972214003660451338124170055999155993192881685495391496854691199517389593073052473319331505702779271
    assert_equal n, key.n
    assert_same_rsa dup_public(rsa1024), key

    ##
    der = "0\x81\x9F0\r\x06\t*\x86H\x86\xF7\r\x01\x01\x01\x05\x00\x03\x81\x8D\x000\x81\x89\x02\x81\x81\x00\xCB\xC2\xC4\xB0\xD4@\xA7>\xD4\xFE>C\xA0\x1E\x17\x06\x03\xBDg\xC0-\xBF\x9C\xBF9T\x11\xA7F\xA0\xF1:\xA8\xD5\x87\xB0\xB1h\xA3\xC4E\x81\xEC\x93\x80O\nA7n\xBBS\x84\xF5\x9C\xF6H\xC7\x11\x04;\xB9\xFFX\xD6\xB6\xC2\xCFIZ\xC8\xDA\x87\xCB,\x10\x11R\xC5\x9A\x9D\\\xA4\x8B\x7FCx\x1E.\xFF\x19\x0F\xDAb\x86\x8C\n$<\x8C\x0E#z\x02\xB6\x14\x99\x973\xBDn=\xEF\xA3\x14\xDF\xE9y\xE0N\xA5\x17\xF2_\x14E9\x87\x02\x03\x01\x00\x01"
    pp OpenSSL::ASN1.decode(key.to_der) if $DEBUG
    assert_equal der, key.to_der

    pem = <<-EOF
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMvCxLDUQKc+1P4+Q6AeFwYDvWfALb+cvzlUEadGoPE6qNWHsLFoo8RF
geyTgE8KQTduu1OE9Zz2SMcRBDu5/1jWtsLPSVrI2ofLLBARUsWanVyki39DeB4u
/xkP2mKGjAokPIwOI3oCthSZlzO9bj3voxTf6XngTqUX8l8URTmHAgMBAAE=
-----END RSA PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::RSA.new(pem)
    assert_not_predicate key, :private?
    assert_same_rsa dup_public(rsa1024), key

    ##
    assert_equal der, key.to_der

    expected = "b48c0b2bbd35b906c5af4e46ed7355e4aaeadc99"
    assert_equal expected, OpenSSL::Digest::SHA1.hexdigest(key.to_der)
  end if !defined?(JRUBY_VERSION) || JRUBY_VERSION > '9.1' # set_key only since Ruby 2.3

  private

  def assert_same_rsa(expected, key)
    check_component(expected, key, [:n, :e, :d, :p, :q, :dmp1, :dmq1, :iqmp])
  end

  def check_component(base, test, keys)
    keys.each { |comp| assert_equal base.send(comp), test.send(comp) }
  end

  def dup_public(key)
    case key
    when OpenSSL::PKey::RSA
      rsa = OpenSSL::PKey::RSA.new
      rsa.set_key(key.n, key.e, nil)
      rsa
    else
      raise "unknown key type: #{key.class}"
    end
  end

end
