# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestDSA < TestCase

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

  def test_dsa_sys_sign_verify
    dsa = OpenSSL::PKey::DSA.new(1024)
    doc = 'Sign ME!'
    digest = OpenSSL::Digest::SHA1.digest(doc)
    sig = dsa.syssign(digest)
    puts sig.inspect if $VERBOSE
    assert dsa.sysverify(digest, sig).eql?(true)
  end

  def test_DSAPrivateKey
    # OpenSSL DSAPrivateKey format; similar to RSAPrivateKey
    dsa512 = Fixtures.pkey("dsa512")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(0),
      OpenSSL::ASN1::Integer(dsa512.p),
      OpenSSL::ASN1::Integer(dsa512.q),
      OpenSSL::ASN1::Integer(dsa512.g),
      OpenSSL::ASN1::Integer(dsa512.pub_key),
      OpenSSL::ASN1::Integer(dsa512.priv_key)
    ])
    key = OpenSSL::PKey::DSA.new(asn1.to_der)
    assert_predicate key, :private?
    assert_same_dsa dsa512, key

    pem = <<-EOF
-----BEGIN DSA PRIVATE KEY-----
MIH4AgEAAkEA5lB4GvEwjrsMlGDqGsxrbqeFRh6o9OWt6FgTYiEEHaOYhkIxv0Ok
RZPDNwOG997mDjBnvDJ1i56OmS3MbTnovwIVAJgub/aDrSDB4DZGH7UyarcaGy6D
AkB9HdFw/3td8K4l1FZHv7TCZeJ3ZLb7dF3TWoGUP003RCqoji3/lHdKoVdTQNuR
S/m6DlCwhjRjiQ/lBRgCLCcaAkEAjN891JBjzpMj4bWgsACmMggFf57DS0Ti+5++
Q1VB8qkJN7rA7/2HrCR3gTsWNb1YhAsnFsoeRscC+LxXoXi9OAIUBG98h4tilg6S
55jreJD3Se3slps=
-----END DSA PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::DSA.new(pem)
    assert_same_dsa dsa512, key

    assert_equal asn1.to_der, dsa512.to_der
    assert_equal pem, dsa512.export
  end

  def test_DSAPrivateKey_encrypted
    # key = abcdef
    dsa512 = Fixtures.pkey("dsa512")
    pem = <<-EOF
-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,F8BB7BFC7EAB9118AC2E3DA16C8DB1D9

D2sIzsM9MLXBtlF4RW42u2GB9gX3HQ3prtVIjWPLaKBYoToRUiv8WKsjptfZuLSB
74ZPdMS7VITM+W1HIxo/tjS80348Cwc9ou8H/E6WGat8ZUk/igLOUEII+coQS6qw
QpuLMcCIavevX0gjdjEIkojBB81TYDofA1Bp1z1zDI/2Zhw822xapI79ZF7Rmywt
OSyWzFaGipgDpdFsGzvT6//z0jMr0AuJVcZ0VJ5lyPGQZAeVBlbYEI4T72cC5Cz7
XvLiaUtum6/sASD2PQqdDNpgx/WA6Vs1Po2kIUQIM5TIwyJI0GdykZcYm6xIK/ta
Wgx6c8K+qBAIVrilw3EWxw==
-----END DSA PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::DSA.new(pem, "abcdef")
    assert_same_dsa dsa512, key
    key = OpenSSL::PKey::DSA.new(pem) { "abcdef" }
    assert_same_dsa dsa512, key

    cipher = OpenSSL::Cipher.new("aes-128-cbc")
    exported = dsa512.to_pem(cipher, "abcdef\0\1")
    assert_same_dsa dsa512, OpenSSL::PKey::DSA.new(exported, "abcdef\0\1")
    assert_raise(OpenSSL::PKey::DSAError) {
      OpenSSL::PKey::DSA.new(exported, "abcdef")
    }
  end

  def test_PUBKEY
    dsa512 = Fixtures.pkey("dsa512")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("DSA"),
        OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(dsa512.p),
          OpenSSL::ASN1::Integer(dsa512.q),
          OpenSSL::ASN1::Integer(dsa512.g)
        ])
      ]),
      OpenSSL::ASN1::BitString(OpenSSL::ASN1::Integer(dsa512.pub_key).to_der)
    ])
    key = OpenSSL::PKey::DSA.new(asn1.to_der)
    assert_not_predicate key, :private?
    assert_same_dsa dup_public(dsa512), key

    ##
    der = "0\x81\xF10\x81\xA8\x06\a*\x86H\xCE8\x04\x010\x81\x9C\x02A\x00\xE6Px\x1A\xF10\x8E\xBB\f\x94`\xEA\x1A\xCCkn\xA7\x85F\x1E\xA8\xF4\xE5\xAD\xE8X\x13b!\x04\x1D\xA3\x98\x86B1\xBFC\xA4E\x93\xC37\x03\x86\xF7\xDE\xE6\x0E0g\xBC2u\x8B\x9E\x8E\x99-\xCCm9\xE8\xBF\x02\x15\x00\x98.o\xF6\x83\xAD \xC1\xE06F\x1F\xB52j\xB7\x1A\e.\x83\x02@}\x1D\xD1p\xFF{]\xF0\xAE%\xD4VG\xBF\xB4\xC2e\xE2wd\xB6\xFBt]\xD3Z\x81\x94?M7D*\xA8\x8E-\xFF\x94wJ\xA1WS@\xDB\x91K\xF9\xBA\x0EP\xB0\x864c\x89\x0F\xE5\x05\x18\x02,'\x1A\x03D\x00\x02A\x00\x8C\xDF=\xD4\x90c\xCE\x93#\xE1\xB5\xA0\xB0\x00\xA62\b\x05\x7F\x9E\xC3KD\xE2\xFB\x9F\xBECUA\xF2\xA9\t7\xBA\xC0\xEF\xFD\x87\xAC$w\x81;\x165\xBDX\x84\v'\x16\xCA\x1EF\xC7\x02\xF8\xBCW\xA1x\xBD8"
    pp OpenSSL::ASN1.decode(key.to_der) if $DEBUG
    assert_equal der, key.to_der

    pem = <<-EOF
-----BEGIN PUBLIC KEY-----
MIHxMIGoBgcqhkjOOAQBMIGcAkEA5lB4GvEwjrsMlGDqGsxrbqeFRh6o9OWt6FgT
YiEEHaOYhkIxv0OkRZPDNwOG997mDjBnvDJ1i56OmS3MbTnovwIVAJgub/aDrSDB
4DZGH7UyarcaGy6DAkB9HdFw/3td8K4l1FZHv7TCZeJ3ZLb7dF3TWoGUP003RCqo
ji3/lHdKoVdTQNuRS/m6DlCwhjRjiQ/lBRgCLCcaA0QAAkEAjN891JBjzpMj4bWg
sACmMggFf57DS0Ti+5++Q1VB8qkJN7rA7/2HrCR3gTsWNb1YhAsnFsoeRscC+LxX
oXi9OA==
-----END PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::DSA.new(pem)
    assert_same_dsa dup_public(dsa512), key

    ##
    assert_equal der, key.to_der

    dup_der = dup_public(dsa512).to_der
    # pp OpenSSL::ASN1.decode(dup_der)
    assert_equal asn1.to_der.size, dup_der.size
    assert_equal asn1.to_der.encoding, dup_der.encoding
    # TODO smt slightly weird with to_der:
    #assert_equal asn1.to_der, dup_der
    assert_equal asn1.value[1].value, OpenSSL::ASN1.decode(dup_der).value[1].value
    assert_equal asn1.value[0].value[0].value, OpenSSL::ASN1.decode(dup_der).value[0].value[0].value
    assert_equal asn1.value[0].value[1].value[0].value, OpenSSL::ASN1.decode(dup_der).value[0].value[1].value[0].value
    assert_equal asn1.value[0].value[1].value[1].value, OpenSSL::ASN1.decode(dup_der).value[0].value[1].value[1].value
    assert_equal asn1.value[0].value[1].value[2].value, OpenSSL::ASN1.decode(dup_der).value[0].value[1].value[2].value

    assert_equal pem, dup_public(dsa512).export
  end if !defined?(JRUBY_VERSION) || JRUBY_VERSION > '9.1' # set_pqg only since Ruby 2.3

  def test_read_DSAPublicKey_pem
    # NOTE: where is the standard? PKey::DSA.new can read only PEM
    p = 12260055936871293565827712385212529106400444521449663325576634579961635627321079536132296996623400607469624537382977152381984332395192110731059176842635699
    q = 979494906553787301107832405790107343409973851677
    g = 3731695366899846297271147240305742456317979984190506040697507048095553842519347835107669437969086119948785140453492839427038591924536131566350847469993845
    y = 10505239074982761504240823422422813362721498896040719759460296306305851824586095328615844661273887569281276387605297130014564808567159023649684010036304695
    pem = <<-EOF
-----BEGIN DSA PUBLIC KEY-----
MIHfAkEAyJSJ+g+P/knVcgDwwTzC7Pwg/pWs2EMd/r+lYlXhNfzg0biuXRul8VR4
VUC/phySExY0PdcqItkR/xYAYNMbNwJBAOoV57X0FxKO/PrNa/MkoWzkCKV/hzhE
p0zbFdsicw+hIjJ7S6Sd/FlDlo89HQZ2FuvWJ6wGLM1j00r39+F2qbMCFQCrkhIX
SG+is37hz1IaBeEudjB2HQJAR0AloavBvtsng8obsjLb7EKnB+pSeHr/BdIQ3VH7
fWLOqqkzFeRrYMDzUpl36XktY6Yq8EJYlW9pCMmBVNy/dQ==
-----END DSA PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::DSA.new(pem)
    assert(key.public?)
    assert(!key.private?)
    assert_equal(p, key.p)
    assert_equal(q, key.q)
    assert_equal(g, key.g)
    assert_equal(y, key.pub_key)
    assert_equal(nil, key.priv_key)
  end

  private

  def assert_same_dsa(expected, key)
    check_component(expected, key, [:p, :q, :g, :pub_key, :priv_key])
  end

  def check_component(base, test, keys)
    keys.each { |comp| assert_equal base.send(comp), test.send(comp) }
  end

  def dup_public(key)
    case key
    when OpenSSL::PKey::DSA
      dsa = OpenSSL::PKey::DSA.new
      dsa.set_pqg(key.p, key.q, key.g)
      dsa.set_key(key.pub_key, nil)
      dsa
    else
      raise "unknown key type: #{key.class}"
    end
  end

end
