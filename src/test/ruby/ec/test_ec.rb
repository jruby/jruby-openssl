# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestEC < TestCase

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

  def test_point
    group = OpenSSL::PKey::EC::Group.new('prime256v1')
    client_public_key_bn = OpenSSL::BN.new('58089019511196532477248433747314139754458690644712400444716868601190212265537817278966641566813745621284958192417192818318052462970895792919572995957754854')

    binary = "\x04U\x1D6|\xA9\x14\eC\x13\x99b\x96\x9B\x94f\x8F\xB0o\xE2\xD3\xBC%\x8E\xE0Xn\xF2|R\x99b\xBD\xBFB\x8FS\xCF\x13\x7F\x8C\x03N\x96\x9D&\xB2\xE1\xBDQ\b\xCE\x94!s\x06.\xC5?\x96\xC7q\xDA\x8B\xE6"
    client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)
    assert_equal binary, client_public_key.to_bn.to_s(2)
  end

  require File.expand_path('base64.rb', File.dirname(__FILE__))

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
    self.class.disable_security_restrictions!

    # @data1 = 'foo'; @data2 = 'bar' * 1000 # data too long for DSA sig

    @groups = []; @keys = []

    OpenSSL::PKey::EC.builtin_curves.each do |curve, comment|
      next if curve.start_with?("Oakley") # Oakley curves are not suitable for ECDSA
      group = OpenSSL::PKey::EC::Group.new(curve)

      key = OpenSSL::PKey::EC.new(group)
      key.generate_key

      @groups << group; @keys << key
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
    key_file = File.join(File.dirname(__FILE__), 'private_key.pem')

    key = OpenSSL::PKey::EC.new(File.read(key_file))
    data = 'abcd'
    digest = OpenSSL::Digest::SHA256.new
    sig = key.sign(digest, data)
    assert_true key.verify(digest, sig, data)

    key.sign(OpenSSL::Digest::SHA1.new, data)
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

  def test_dsa_sign_verify
    data1 = 'foo'
    for key in @keys
      sig = key.dsa_sign_asn1(data1)
      assert(key.dsa_verify_asn1(data1, sig))
    end
  end if false # NOT-IMPLEMENTED

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

end