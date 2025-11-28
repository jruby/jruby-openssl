# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))
require 'base64'

class TestEC < TestCase

  def test_ec_key
    builtin_curves = OpenSSL::PKey::EC.builtin_curves
    assert_not_empty builtin_curves

    builtin_curves.each do |curve_name, comment|
      # Oakley curves and X25519 are not suitable for signing and causes
      # FIPS-selftest failure on some environment, so skip for now.
      next if ["Oakley", "X25519"].any? { |n| curve_name.start_with?(n) }

      key = OpenSSL::PKey::EC.generate(curve_name)
      assert_predicate key, :private?
      assert_predicate key, :public?
      assert_nothing_raised { key.check_key }
    end

    key1 = OpenSSL::PKey::EC.generate("prime256v1")

    # PKey is immutable in OpenSSL >= 3.0; constructing an empty EC object is deprecated
    #if !openssl?(3, 0, 0)
      key2 = OpenSSL::PKey::EC.new
      key2.group = key1.group
      key2.private_key = key1.private_key
      key2.public_key = key1.public_key
      assert_equal key1.to_der, key2.to_der
    #end

    key3 = OpenSSL::PKey::EC.new(key1)
    assert_equal key1.to_der, key3.to_der

    key4 = OpenSSL::PKey::EC.new(key1.to_der)
    assert_equal key1.to_der, key4.to_der

    key5 = key1.dup
    assert_equal key1.to_der, key5.to_der

    # PKey is immutable in OpenSSL >= 3.0; EC object should not be modified
    #if !openssl?(3, 0, 0)
      key_tmp = OpenSSL::PKey::EC.generate("prime256v1")
      key5.private_key = key_tmp.private_key
      key5.public_key = key_tmp.public_key
      assert_not_equal key1.to_der, key5.to_der
    #end
  end

  def test_generate
    assert_raise(OpenSSL::PKey::ECError) { OpenSSL::PKey::EC.generate("non-existent") }
    g = OpenSSL::PKey::EC::Group.new("prime256v1")
    ec = OpenSSL::PKey::EC.generate(g)
    assert_equal(true, ec.private?)
    ec = OpenSSL::PKey::EC.generate("prime256v1")
    assert_equal(true, ec.private?)
  end

  def test_generate_key
    ec = OpenSSL::PKey::EC.new("prime256v1")
    assert_equal false, ec.private?
    ec.generate_key!
    assert_equal true, ec.private?
  end #if !openssl?(3, 0, 0)

  def test_PUBKEY
    p256 = Fixtures.pkey("p256")
    p256pub = OpenSSL::PKey::EC.new(p256.public_to_der)

    public_to_der = "0Y0\x13\x06\a*\x86H\xCE=\x02\x01\x06\b*\x86H\xCE=\x03\x01\a\x03B\x00\x04\x16\td\xD9\xCF\xA8UB\nC\xAE\x1Edo[\x84\xB3OX\x1E\xE5I\x9F\xC0\xAC\xAE5xl\xB9\xC0\f\xD4\xFFA\xB9\xD5{m\t\xE0T\x97\xE3\x1A\x85\x9Bg\xF5\xF3\xB5$\xA7E\xE2\xA2fK\x7F]^zD6"
    assert_equal public_to_der, p256.public_to_der

    # MRI:
    uncompressed_public_key = "\x04\x16\td\xD9\xCF\xA8UB\nC\xAE\x1Edo[\x84\xB3OX\x1E\xE5I\x9F\xC0\xAC\xAE5xl\xB9\xC0\f\xD4\xFFA\xB9\xD5{m\t\xE0T\x97\xE3\x1A\x85\x9Bg\xF5\xF3\xB5$\xA7E\xE2\xA2fK\x7F]^zD6"
    assert_equal uncompressed_public_key, p256.public_key.to_octet_string(:uncompressed)

    asn1 = OpenSSL::ASN1::Sequence([
                                     OpenSSL::ASN1::Sequence([
                                                               OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                                                               OpenSSL::ASN1::ObjectId("prime256v1")
                                                             ]),
                                     OpenSSL::ASN1::BitString(
                                       p256.public_key.to_octet_string(:uncompressed)
                                     )
                                   ])
    assert_equal public_to_der, asn1.to_der

    to_der = "0w\x02\x01\x01\x04 \x80\xF8\xF4P\xEAq\xFDN\xD5\xE3\xBC\xB1\xA4\xE0\e\xBD\x14mt0\xF4Z\xB0\xB1\xE9b\x8A\xDD\x9AZ\x11\xF5\xA0\n\x06\b*\x86H\xCE=\x03\x01\a\xA1D\x03B\x00\x04\x16\td\xD9\xCF\xA8UB\nC\xAE\x1Edo[\x84\xB3OX\x1E\xE5I\x9F\xC0\xAC\xAE5xl\xB9\xC0\f\xD4\xFFA\xB9\xD5{m\t\xE0T\x97\xE3\x1A\x85\x9Bg\xF5\xF3\xB5$\xA7E\xE2\xA2fK\x7F]^zD6"
    #pp OpenSSL::ASN1.decode(to_der)
    # #<OpenSSL::ASN1::Sequence:0x000072229cabc698
    # @indefinite_length=false,
    #   @tag=16,
    #   @tag_class=:UNIVERSAL,
    #   @tagging=nil,
    #   @value=
    #     [#<OpenSSL::ASN1::Integer:0x000072229cabc8c8 @indefinite_length=false, @tag=2, @tag_class=:UNIVERSAL, @tagging=nil, @value=#<OpenSSL::BN 1>>,
    #       #<OpenSSL::ASN1::OctetString:0x000072229cabc828 @indefinite_length=false, @tag=4, @tag_class=:UNIVERSAL, @tagging=nil, @value="\x80\xF8\xF4P\xEAq\xFDN\xD5\xE3\xBC\xB1\xA4\xE0\e\xBD\x14mt0\xF4Z\xB0\xB1\xE9b\x8A\xDD\x9AZ\x11\xF5">,
    #       #<OpenSSL::ASN1::ASN1Data:0x000072229cabc760
    #       @indefinite_length=false,
    #       @tag=0,
    #       @tag_class=:CONTEXT_SPECIFIC,
    #       @value=[#<OpenSSL::ASN1::ObjectId:0x000072229cabc7b0 @indefinite_length=false, @tag=6, @tag_class=:UNIVERSAL, @tagging=nil, @value="prime256v1">]>,
    #         #<OpenSSL::ASN1::ASN1Data:0x000072229cabc6c0
    #         @indefinite_length=false,
    #         @tag=1,
    #         @tag_class=:CONTEXT_SPECIFIC,
    #         @value=
    #           [#<OpenSSL::ASN1::BitString:0x000072229cabc6e8
    #             @indefinite_length=false,
    #             @tag=3,
    #             @tag_class=:UNIVERSAL,
    #             @tagging=nil,
    #             @unused_bits=0,
    #             @value="\x04\x16\td\xD9\xCF\xA8UB\n" + "C\xAE\x1Edo[\x84\xB3OX\x1E\xE5I\x9F\xC0\xAC\xAE5xl\xB9\xC0\f\xD4\xFFA\xB9\xD5{m\t\xE0T\x97\xE3\x1A\x85\x9Bg\xF5\xF3\xB5$\xA7E\xE2\xA2fK\x7F]^zD6">]>]>

    assert_equal to_der, p256.to_der

    key = OpenSSL::PKey::EC.new(asn1.to_der)
    assert_not_predicate key, :private?
    assert_same_ec p256pub, key

    pem = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFglk2c+oVUIKQ64eZG9bhLNPWB7l
    SZ/ArK41eGy5wAzU/0G51XttCeBUl+MahZtn9fO1JKdF4qJmS39dXnpENg==
    -----END PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::EC.new(pem)
    assert_same_ec p256pub, key

    assert_equal asn1.to_der, key.to_der
    assert_equal pem, key.export

    assert_equal asn1.to_der, p256.public_to_der
    assert_equal asn1.to_der, key.public_to_der
    assert_equal pem, p256.public_to_pem
    assert_equal pem, key.public_to_pem
  end

  def test_oid
    key = OpenSSL::PKey::EC.new
    assert_equal 'id-ecPublicKey', key.oid
  end

  def test_read_pem
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')

    key = OpenSSL::PKey::EC.new(File.read(key_file))
    assert_equal '3799522885287541632525744605009198', key.private_key.to_s

    if defined? JRUBY_VERSION
      #puts key.to_java.getPublicKey.to_s
      #x = key.to_java.getPublicKey.getW.getAffineX
      #y = key.to_java.getPublicKey.getW.getAffineY
      #puts 'X: ' + x.to_s
      #puts 'Y: ' + y.to_s
    end

    #puts exp = '120833863706476653138797887024101356894168914780792837123086246530098'
    #puts key.public_key.to_bn.to_s(16)

    assert_equal '120833863706476653138797887024101356894168914780792837123086246530098', key.public_key.to_bn.to_s
    assert_equal 'secp112r1', key.group.curve_name
    group = key.group
    # TODO seems to not match under JRuby+BC ?!
    #assert_equal "\x00\xF5\v\x02\x8EMinghuaQu)\x04rx?\xB1", group.seed
    assert_equal '1', group.cofactor.to_s
    assert_equal '112', group.degree.to_s
    assert_equal '4451685225093714776491891542548933', group.order.to_s

    #pem = key.to_pem
    #puts pem
    #assert_equal(pem, OpenSSL::PKey::EC.new(pem).to_pem)

    # to_text
    text = key.to_text
    assert_include text, "Private-Key: (112 bit)\n"
    assert_include text, "bb:54:b8:93:a9:51:3c:09:a6:37:f7:2c:95:2e\n"
    assert_include text, "ASN1 OID: secp112r1\n"
  end

  def test_read_pem2
    key_file = File.join(File.dirname(__FILE__), 'private_key2.pem')

    key = OpenSSL::PKey::EC.new(File.read(key_file))
    assert_equal '476154198002596104803238069251020502662523042506824360051479804577598604971468345833166876271341274102391714812706759347009731580016190266434110134398790', key.private_key.to_s
    assert_equal '724664761298071194184067291718596276558181552214511004334530978676843312147340497441492810597004957502007504373782147802415558443578478808342286909152917608996652942169120263280723117356614533448503051685400082877326382909445989024396491709450773515529281107708539356521507912663674257568110287055756424062220', key.public_key.to_bn.to_s
    assert_equal 'brainpoolP512t1', key.group.curve_name
    group = key.group
    assert_equal nil, group.seed
    assert_equal '1', group.cofactor.to_s
    assert_equal '512', group.degree.to_s
    assert_equal '8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169', group.order.to_s

    #signature = key.dsa_sign_asn1('foo')
    #puts signature.inspect
  end

  def test_read_pkcs8_with_ec
    key_file = File.join(File.dirname(__FILE__), 'private_key_pkcs8.pem')

    key = OpenSSL::PKey::read(File.read(key_file))
    assert_equal OpenSSL::PKey::EC, key.class
    assert_equal '37273549501637553234010607973347901861080883009977847480473501706546896416762', key.private_key.to_s

    assert_equal OpenSSL::PKey::EC::Point, key.public_key.class
    public_key = '59992919564038617581477192805085606797983518604284049179473294859597640027055772972320536875319417493705914919226919250526441868144324498122209513139102397'
    assert_equal public_key, key.public_key.to_bn.to_s
  end

  def test_point
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    client_public_key_bn = OpenSSL::BN.new('58089019511196532477248433747314139754458690644712400444716868601190212265537817278966641566813745621284958192417192818318052462970895792919572995957754854')

    binary = "\x04U\x1D6|\xA9\x14\eC\x13\x99b\x96\x9B\x94f\x8F\xB0o\xE2\xD3\xBC%\x8E\xE0Xn\xF2|R\x99b\xBD\xBFB\x8FS\xCF\x13\x7F\x8C\x03N\x96\x9D&\xB2\xE1\xBDQ\b\xCE\x94!s\x06.\xC5?\x96\xC7q\xDA\x8B\xE6"
    point = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)
    assert_equal binary, point.to_bn.to_s(2)
    assert_equal binary, point.to_octet_string(:uncompressed)

    point2 = OpenSSL::PKey::EC::Point.new(group, point.to_octet_string(:uncompressed))
    assert_equal binary, point2.to_bn.to_s(2)

    compressed = "\x02U\x1D6|\xA9\x14\eC\x13\x99b\x96\x9B\x94f\x8F\xB0o\xE2\xD3\xBC%\x8E\xE0Xn\xF2|R\x99b\xBD"
    assert_equal compressed, point.to_octet_string(:compressed)

    # TODO: not yet implemented
    # hybrid = "\x06U\x1D6|\xA9\x14\eC\x13\x99b\x96\x9B\x94f\x8F\xB0o\xE2\xD3\xBC%\x8E\xE0Xn\xF2|R\x99b\xBD\xBFB\x8FS\xCF\x13\x7F\x8C\x03N\x96\x9D&\xB2\xE1\xBDQ\b\xCE\x94!s\x06.\xC5?\x96\xC7q\xDA\x8B\xE6"
    # assert_equal hybrid, point.to_octet_string(:hybrid)
  end

  def test_point_error
    assert_raise(ArgumentError) { OpenSSL::PKey::EC::Point.new }
    assert_raise(TypeError) { OpenSSL::PKey::EC::Point.new(nil) }
    assert_raise(TypeError) { OpenSSL::PKey::EC::Point.new(nil, '') }
    assert_raise(TypeError) { OpenSSL::PKey::EC::Point.new(100, '') }
  end

  def test_random_point
    group = OpenSSL::PKey::EC::Group.new("prime256v1")
    key = OpenSSL::PKey::EC.generate(group)
    point = key.public_key

    point2 = OpenSSL::PKey::EC::Point.new(group, point.to_bn)
    assert_equal point, point2
    assert_equal point.to_bn, point2.to_bn
    assert_equal point.to_octet_string(:uncompressed), point2.to_octet_string(:uncompressed)

    point3 = OpenSSL::PKey::EC::Point.new(group, point.to_octet_string(:uncompressed))
    assert_equal point, point3
    assert_equal point.to_bn, point3.to_bn
    assert_equal point.to_octet_string(:uncompressed), point3.to_octet_string(:uncompressed)
  end

  def test_encrypt
    p256dh = "BNFege3oh74znsDbVkGf5CRAtLVUHlo5NTU9-inepE_HpUBWUq3FP_dJR-WDORPvKL7fM_AKyfYch-nKY7kDOe0="
    group_name = 'prime256v1'

    server = OpenSSL::PKey::EC.new(group_name)
    # assert server.group.nil? # TODO MRI has a "null" group

    server.private_key = OpenSSL::BN.new('107411000028178101972699773683980269641478018566010848092863514011724406285076')
    # '62303413620263991527470772975506242387142677576794087805856701493545918209262092657150628139966331940997693252502978347289754390001755240229834360187731879'

    group = OpenSSL::PKey::EC::Group.new(group_name)
    client_public_key_bn = OpenSSL::BN.new(Base64.urlsafe_decode64(p256dh), 2)
    # puts client_public_key_bn
    client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)

    expected = "\xC1\xF9\xF3\xA2-n\xD1z\xBB\xE0\xDA\xDF\xB6\xFF\x8A\xAAR\"\xA7\b\xED\x0E\x83\xAA\x03s\xB0\xECtN\xF4\xC3"
    assert_equal expected, server.dh_compute_key(client_public_key)
  end

  def test_encrypt_integration # inspired by WebPush
    require File.expand_path('ece.rb', File.dirname(__FILE__)) unless defined? ECE
    require File.expand_path('hkdf.rb', File.dirname(__FILE__)) unless defined? HKDF

    p256dh = Base64.urlsafe_encode64 generate_ecdh_key
    auth = Base64.urlsafe_encode64 Random.new.bytes(16)

    payload = Encryption.encrypt("Hello World", p256dh, auth)

    encrypted = payload.fetch(:ciphertext)

    decrypted_data = ECE.decrypt(encrypted,
      :key => payload.fetch(:shared_secret),
      :salt => payload.fetch(:salt),
      :server_public_key => payload.fetch(:server_public_key_bn),
      :user_public_key => Base64.urlsafe_decode64(p256dh),
      :auth => Base64.urlsafe_decode64(auth))

    assert_equal "Hello World", decrypted_data
  end if RUBY_VERSION > '1.9'

  def generate_ecdh_key(group = 'prime256v1')
    curve = OpenSSL::PKey::EC.new(group)
    curve.generate_key
    str = curve.public_key.to_bn.to_s(2)
    puts "curve.public_key.to_bn.to_s(2): #{str.inspect}" if $VERBOSE
    str
  end
  private :generate_ecdh_key

  module Encryption # EC + (symmetric) AES GCM AAED encryption
    extend self

    def encrypt(message, p256dh, auth)

      group_name = "prime256v1"
      salt = Random.new.bytes(16)

      server = OpenSSL::PKey::EC.new(group_name)
      server.generate_key
      server_public_key_bn = server.public_key.to_bn

      group = OpenSSL::PKey::EC::Group.new(group_name)
      client_public_key_bn = OpenSSL::BN.new(Base64.urlsafe_decode64(p256dh), 2)

      #puts client_public_key_bn.to_s if $VERBOSE

      client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)

      shared_secret = server.dh_compute_key(client_public_key)

      client_auth_token = Base64.urlsafe_decode64(auth)

      prk = HKDF.new(shared_secret, :salt => client_auth_token, :algorithm => 'SHA256', :info => "Content-Encoding: auth\0").next_bytes(32)

      context = create_context(client_public_key_bn, server_public_key_bn)

      content_encryption_key_info = create_info('aesgcm', context)
      content_encryption_key = HKDF.new(prk, :salt => salt, :info => content_encryption_key_info).next_bytes(16)

      nonce_info = create_info('nonce', context)
      nonce = HKDF.new(prk, :salt => salt, :info => nonce_info).next_bytes(12)

      ciphertext = encrypt_payload(message, content_encryption_key, nonce)

      {
        :ciphertext => ciphertext, :salt => salt, :shared_secret => shared_secret,
        :server_public_key_bn => convert16bit(server_public_key_bn)
      }
    end

    private

    def create_context(client_public_key, server_public_key)
      c = convert16bit(client_public_key)
      s = convert16bit(server_public_key)
      context = "\0"
      context += [c.bytesize].pack("n*")
      context += c
      context += [s.bytesize].pack("n*")
      context += s
      context
    end

    def encrypt_payload(plaintext, content_encryption_key, nonce)
      cipher = OpenSSL::Cipher.new('aes-128-gcm')
      cipher.encrypt
      cipher.key = content_encryption_key
      cipher.iv = nonce
      padding = cipher.update("\0\0")
      text = cipher.update(plaintext)

      e_text = padding + text + cipher.final
      e_tag = cipher.auth_tag

      e_text + e_tag
    end

    def create_info(type, context)
      info = "Content-Encoding: "
      info += type; info += "\0"; info += "P-256"; info += context
      info
    end

    def convert16bit(key)
      [key.to_s(16)].pack("H*")
    end

  end

  def setup
    super

    @groups = []; @keys = []

    OpenSSL::PKey::EC.builtin_curves.each do |curve, comment|
      next if curve.start_with?("Oakley") # Oakley curves are not suitable for ECDSA

      @groups << group = OpenSSL::PKey::EC::Group.new(curve)
      @keys << OpenSSL::PKey::EC.generate(group)
    end
  end

  def compare_keys(k1, k2)
    assert_equal(k1.to_pem, k2.to_pem)
  end

  def test_builtin_curves
    assert(!OpenSSL::PKey::EC.builtin_curves.empty?)
  end

  def test_curve_names
    @groups.each_with_index do |group, idx|
      key = @keys[idx]
      assert_equal(group.curve_name, key.group.curve_name)
    end
  end

  def test_check_key
    for key in @keys
      assert_equal(key.check_key, true)
      assert_equal(key.private_key?, true)
      assert_equal(key.public_key?, true)
    end
  end

  def test_sign_verify
    p256 = Fixtures.pkey("p256")
    data = "Sign me!"
    signature = p256.sign("SHA1", data)
    assert_equal true, p256.verify("SHA1", signature, data)

    signature0 = (<<~'end;').unpack("m")[0]
      MEQCIEOTY/hD7eI8a0qlzxkIt8LLZ8uwiaSfVbjX2dPAvN11AiAQdCYx56Fq
      QdBp1B4sxJoA8jvODMMklMyBKVmudboA6A==
    end;
    assert_equal true, p256.verify("SHA256", signature0, data)
    signature1 = signature0.succ
    assert_equal false, p256.verify("SHA256", signature1, data)
  end

  def test_group_encoding
    for group in @groups
      for meth in [:to_der, :to_pem]
        txt = group.send(meth)
        gr = OpenSSL::PKey::EC::Group.new(txt)

        assert_equal(txt, gr.send(meth))

        assert_equal(group.generator.to_bn, gr.generator.to_bn)
        assert_equal(group.cofactor, gr.cofactor)
        assert_equal(group.order, gr.order)
        assert_equal(group.seed, gr.seed)
        assert_equal(group.degree, gr.degree)
      end
    end
  end if false # NOT-IMPLEMENTED

  def test_key_encoding
    for key in @keys
      group = key.group

      for meth in [:to_der, :to_pem]
        txt = key.send(meth)

        puts " #{key} #{key.group.curve_name} #{meth.inspect}"

        assert_equal(txt, OpenSSL::PKey::EC.new(txt).send(meth))
      end

      bn = key.public_key.to_bn
      assert_equal(bn, OpenSSL::PKey::EC::Point.new(group, bn).to_bn)
    end
  end if false # NOT-IMPLEMENTED

  def test_set_keys
    for key in @keys
      k = OpenSSL::PKey::EC.new
      k.group = key.group
      k.private_key = key.private_key
      k.public_key = key.public_key

      compare_keys(key, k)
    end
  end if false # NOT-IMPLEMENTED TODO

  def test_dsa_sign_verify_all
    data1 = 'hashed-value'
    for key in @keys
      next if key.group.curve_name == 'SM2'

      sig = key.dsa_sign_asn1(data1)
      assert_equal(true, key.dsa_verify_asn1(data1, sig))
      assert_equal(false, key.dsa_verify_asn1(data1 + 'X', sig))
    end
  end

  def test_sign_verify_raw
    key = Fixtures.pkey("p256")
    data1 = "foo"
    data2 = "bar"

    malformed_sig = "*" * 30

    # Sign by #dsa_sign_asn1
    sig = key.dsa_sign_asn1(data1)

    assert_equal true, key.dsa_verify_asn1(data1, sig)
    assert_equal false, key.dsa_verify_asn1(data2, sig)
    assert_raise(OpenSSL::PKey::ECError) { key.dsa_verify_asn1(data1, malformed_sig) }
  end

  def test_new_from_der
    priv_key_hex = '05768F097A19FFE5022D4A862CDBAE22019695D1C2F88FD41607417AD45E2F55'
    pub_key_hex = '04B827833DC1BC38CE0BBE36E0357B1D08AB0BFA05DBD211F0FC677FF9913FAF0EB3A3CC562EEAE8D841B112DBFDAD494E10CFBD4964DC2D175D06F17ACC5771CF'
    do_test_from_sequence('prime256v1', pub_key_hex, priv_key_hex)
    do_test_from_sequence('prime256v1', pub_key_hex, nil)

    priv_key_hex = 'D4E775192298037DAD55150AE76C8585CE4AD628897F5F9F02762C416F1D4A33'
    pub_key_hex = '0456D3DD1587DE605D167AB037FF9856B58705970BA3AE49E68CDFA8A5D580EC506E1D6F1AEFE5621EF458322F68C59D461FC5D3633881D82BD8E4AF7924306979'
    do_test_from_sequence('prime256v1', pub_key_hex, priv_key_hex)
    do_test_from_sequence('prime256v1', pub_key_hex, nil)

    priv_key_hex = '9174C3E24DBA2AADE34D4885371B0AEA89D44CFEC70348C9FF5EB3207550F18A'
    pub_key_hex = '048344CA3520410CFD1D77FEA79AF543A2769545D6D143A12E86AC8F65D9280049FDC88A883D748C6229D9210AD0984DD4ED8F7742ECC0588409446FF6BC8830AA'
    do_test_from_sequence('prime256v1', pub_key_hex, priv_key_hex)
    do_test_from_sequence('prime256v1', pub_key_hex, nil)
  end

  def do_test_from_sequence(curve, pub_key_hex, priv_key_hex)
    group = OpenSSL::PKey::EC::Group.new(curve)
    d = OpenSSL::BN.new(priv_key_hex, 16) if priv_key_hex # private_key
    point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(pub_key_hex, 16)) # public_key (x, y)

    sequence = if priv_key_hex
                 # https://datatracker.ietf.org/doc/html/rfc5915.html
                 # ECPrivateKey ::= SEQUENCE {
                 #   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                 #   privateKey     OCTET STRING,
                 #   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                 #   publicKey  [1] BIT STRING OPTIONAL
                 # }

                 OpenSSL::ASN1::Sequence([
                                           OpenSSL::ASN1::Integer(1),
                                           OpenSSL::ASN1::OctetString(d.to_s(2)),
                                           OpenSSL::ASN1::ObjectId(curve, 0, :EXPLICIT),
                                           OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed), 1, :EXPLICIT)
                                         ])
               else
                 OpenSSL::ASN1::Sequence([
                                           OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId(curve)]),
                                           OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
                                         ])
               end

    key = OpenSSL::PKey::EC.new(sequence.to_der)
    assert_equal group.curve_name, key.group.curve_name
    assert_equal group, key.group
    assert_equal point, key.public_key
    assert_equal d, key.private_key if d
  end
  private :do_test_from_sequence

  def test_new_from_der_jwt_style
    jwk_x = "g0TKNSBBDP0dd_6nmvVDonaVRdbRQ6EuhqyPZdkoAEk"
    jwk_y = "_ciKiD10jGIp2SEK0JhN1O2Pd0LswFiECURv9ryIMKo"
    do_test_from_sequence_with_packed_point('prime256v1', jwk_x, jwk_y)

    jwk_x = "ts5_Jv5_QkWPVkaC_Y7rGZ2gdeJSkDR3I96M2CuVNtU"
    jwk_y = "fCLLRp7lX_Q8g60IRhT8sNONGTjNmoTWUny8FPe91Gs"
    do_test_from_sequence_with_packed_point('prime256v1', jwk_x, jwk_y)

    jwk_x = "iIv_aqVNBfTBr3C7u8E3kYrWbYXjHnH9jLzbBkl1PqA"
    jwk_y = "sXueAB7o9QmrmDQGGy7hqN0bx5gOxYDJyLQAMDNMRBw"
    jwk_d = "-KgbRgiVEztCTgxSZmScegXkBVNokqZlCodlpakFtFc"
    do_test_from_sequence_with_packed_point('prime256v1', jwk_x, jwk_y, jwk_d)
    do_test_from_sequence_with_packed_point('prime256v1', jwk_x, jwk_y)

    jwk_x = "mAObq2aOmjkZwS5ruLmZITbXKTepItbnyrMm1VWGeeg"
    jwk_y = "EtQDulK7N-v_0mdbFQe-bNCyc-ey1sPRa1l--_7vAiA"
    do_test_from_sequence_with_packed_point('prime256v1', jwk_x, jwk_y) # GH-318
  end

  def do_test_from_sequence_with_packed_point(curve, jwk_x, jwk_y, jwk_d = nil)
    group = OpenSSL::PKey::EC::Group.new(curve)
    d = OpenSSL::BN.new(decode_octets(jwk_d), 2) if jwk_d

    x_octets = decode_octets(jwk_x)
    y_octets = decode_octets(jwk_y)

    point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new([0x04, x_octets, y_octets].pack('Ca*a*'), 2))

    sequence = if jwk_d
                 # https://datatracker.ietf.org/doc/html/rfc5915.html
                 # ECPrivateKey ::= SEQUENCE {
                 #   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                 #   privateKey     OCTET STRING,
                 #   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                 #   publicKey  [1] BIT STRING OPTIONAL
                 # }

                 OpenSSL::ASN1::Sequence([
                                           OpenSSL::ASN1::Integer(1),
                                           OpenSSL::ASN1::OctetString(OpenSSL::BN.new(decode_octets(jwk_d), 2).to_s(2)),
                                           OpenSSL::ASN1::ObjectId(curve, 0, :EXPLICIT),
                                           OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed), 1, :EXPLICIT)
                                         ])
               else
                 OpenSSL::ASN1::Sequence([
                                           OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId(curve)]),
                                           OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
                                         ])
               end

    key = OpenSSL::PKey::EC.new(sequence.to_der)
    assert_equal group.curve_name, key.group.curve_name
    assert_equal group, key.group
    assert_equal point, key.public_key
    assert_equal d, key.private_key if d
  end
  private :do_test_from_sequence

  def decode_octets(base64_encoded_coordinate); require 'base64'
    bytes = ::Base64.urlsafe_decode64(base64_encoded_coordinate)
    assert_false bytes.bytesize.odd?
    bytes
  end
  private :decode_octets

#  def test_dh_compute_key
#    for key in @keys
#      k = OpenSSL::PKey::EC.new(key.group)
#      k.generate_key
#
#      puba = key.public_key
#      pubb = k.public_key
#      a = key.dh_compute_key(pubb)
#      b = k.dh_compute_key(puba)
#      assert_equal(a, b)
#    end
#  end

  private

  def B(ary)
    [Array(ary).join].pack("H*")
  end

  def assert_same_ec(expected, key)
    check_component(expected, key, [:group, :public_key, :private_key])
  end

  def check_component(base, test, keys)
    keys.each { |comp|
      assert_equal base.send(comp), test.send(comp)
    }
  end
end
