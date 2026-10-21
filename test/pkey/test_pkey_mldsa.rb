require File.expand_path('../test_helper', File.dirname(__FILE__))
require 'base64'

class TestPKeyMLDSA < TestCase
  PARAMETERS = [44, 65, 87].freeze
  FIXTURES = File.expand_path('../fixtures/mldsa', File.dirname(__FILE__))

  def setup
    super
    if fips?
      begin
        OpenSSL::PKey.generate_key('ML-DSA-44')
      rescue OpenSSL::PKey::PKeyError => error
        skip("ML-DSA unavailable from the FIPS provider: #{error.message}")
      end
    end
  end

  def test_generate_and_sign
    PARAMETERS.each do |parameter|
      algorithm = "ML-DSA-#{parameter}"
      key = OpenSSL::PKey.generate_key(algorithm)
      assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.generate_key(algorithm, 'seed' => 'ignored') }
      assert_equal key.oid, OpenSSL::PKey.generate_key(algorithm, {}).oid
      public_key = OpenSSL::PKey.read(key.public_to_der)
      other = OpenSSL::PKey.generate_key(algorithm)
      assert_instance_of OpenSSL::PKey::PKey, key
      assert_equal "id-ml-dsa-#{parameter}", key.oid
      assert_match(/type_name=#{algorithm}/, key.inspect)
      assert_equal true, key.private?
      assert_equal true, key.public?
      assert_equal false, public_key.private?
      exported = OpenSSL::ASN1.decode(key.private_to_der)
      expanded = OpenSSL::ASN1.decode(exported.value[2].value)
      assert_instance_of OpenSSL::ASN1::OctetString, expanded
      assert_equal(parameter == 44 ? 2560 : parameter == 65 ? 4032 : 4896, expanded.value.bytesize)

      ['', fixture('binary.bin'), 'prefix-message-suffix'[7, 7]].each do |message|
        signature = key.sign(nil, message)
        assert_equal true, public_key.verify(nil, signature, message)
        assert_equal false, public_key.verify(nil, signature, message + "\0")
        assert_equal false, other.verify(nil, signature, message)
        ['', signature[0, signature.bytesize - 1], signature + "\0",
         "\xff".b * signature.bytesize].each do |bad_signature|
          assert_equal false, public_key.verify(nil, bad_signature, message)
        end
      end
      assert_raise(ArgumentError) { public_key.sign(nil, 'message') }
      ['SHA256', OpenSSL::Digest::SHA512.new].each do |digest|
        assert_raise(OpenSSL::PKey::PKeyError) { key.sign(digest, 'message') }
        assert_raise(OpenSSL::PKey::PKeyError) { public_key.verify(digest, '', 'message') }
      end
      assert_raise(OpenSSL::PKey::PKeyError) { key.derive(public_key) }
      assert_raise(OpenSSL::PKey::PKeyError) { public_key.private_to_der }
      assert_raise(OpenSSL::PKey::PKeyError) { key.private_to_pem(OpenSSL::Cipher.new('aes-256-cbc'), 'password') }
    end
  end

  %w[seed seed-priv expanded].each do |encoding|
    define_method("test_independent_openssl_#{encoding.tr('-', '_')}_keys_and_signatures") do
      PARAMETERS.each do |parameter|
        public_key = OpenSSL::PKey.read(fixture("ml-dsa-#{parameter}-public.pem"))
        pem = fixture("ml-dsa-#{parameter}-#{encoding}.pem")
        [pem, pem_der(pem)].each do |input|
          key = OpenSSL::PKey.read(input)
          assert_equal public_key.public_to_der, key.public_to_der
          assert_equal true, key.private?
          assert_equal "id-ml-dsa-#{parameter}", key.oid
          %w[empty binary].each do |message|
            data = fixture("#{message}.bin")
            signature = fixture("ml-dsa-#{parameter}-#{message}.sig")
            assert_equal true, key.verify(nil, signature, data)
            assert_equal true, public_key.verify(nil, key.sign(nil, data), data)
          end
          [key.private_to_der, key.private_to_pem].each do |export|
            assert_equal public_key.public_to_der, OpenSSL::PKey.read(export).public_to_der
          end
        end
        [public_key.public_to_der, public_key.public_to_pem].each do |export|
          assert_equal public_key.public_to_der, OpenSSL::PKey.read(export).public_to_der
        end
        spki = OpenSSL::ASN1.decode(public_key.public_to_der)
        assert_equal "2.16.840.1.101.3.4.3.#{parameter == 44 ? 17 : parameter == 65 ? 18 : 19}", spki.value[0].value[0].oid
        assert_equal "id-ml-dsa-#{parameter}", spki.value[0].value[0].sn
        assert_equal "ML-DSA-#{parameter}", spki.value[0].value[0].ln
      end
    end
  end

  def test_encrypted_pkcs8_import
    PARAMETERS.each do |parameter|
      pem = fixture("ml-dsa-#{parameter}-encrypted.pem")
      expected = OpenSSL::PKey.read(fixture("ml-dsa-#{parameter}-public.pem"))
      [pem, pem_der(pem)].each do |input|
        key = OpenSSL::PKey.read(input, 'mldsa-test-password')
        assert_equal expected.public_to_der, key.public_to_der
        assert_equal true, expected.verify(nil, key.sign(nil, ''), '')
        assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(input, 'wrong-password') }
        assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(input) }
      end
    end
  end

  def test_malformed_keys
    ['', 'not a key', "\x30\x03\x02\x01\x00".b].each do |input|
      assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(input) }
    end
    PARAMETERS.each do |parameter|
      public_der = pem_der(fixture("ml-dsa-#{parameter}-public.pem"))
      [:short, :long].each do |variant|
        spki = OpenSSL::ASN1.decode(public_der)
        bytes = spki.value[1].value
        spki.value[1].value = variant == :short ? bytes[0, bytes.bytesize - 1] : bytes + "\0"
        assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(spki.to_der) }
      end
      %w[seed expanded public].each do |encoding|
        der = pem_der(fixture("ml-dsa-#{parameter}-#{encoding}.pem"))
        assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(der[0, der.bytesize - 1]) }
      end
    end
  end

  def test_invalid_private_key_components
    PARAMETERS.each do |parameter|
      original = pem_der(fixture("ml-dsa-#{parameter}-seed-priv.pem"))
      [31, 33].each do |length|
        info = OpenSSL::ASN1.decode(original)
        both = OpenSSL::ASN1.decode(info.value[2].value)
        both.value[0].value = "\0" * length
        info.value[2].value = both.to_der
        assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(info.to_der) }
      end
      [:short, :long, :inconsistent].each do |variant|
        info = OpenSSL::ASN1.decode(original)
        both = OpenSSL::ASN1.decode(info.value[2].value)
        expanded = both.value[1].value
        both.value[1].value = case variant
                             when :short then expanded[0, expanded.bytesize - 1]
                             when :long then expanded + "\0"
                             else "\0" * expanded.bytesize
                             end
        info.value[2].value = both.to_der
        assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(info.to_der) }
      end
      info = OpenSSL::ASN1.decode(pem_der(fixture("ml-dsa-#{parameter}-seed.pem")))
      seed = OpenSSL::ASN1.decode(info.value[2].value)
      seed.tag = 1
      info.value[2].value = seed.to_der
      assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(info.to_der) }

      # These malformed standard encodings have the length of a legacy bare key.
      info.value[2].value = OpenSSL::ASN1::OctetString.new("\0" * 30, 0, :IMPLICIT, :CONTEXT_SPECIFIC).to_der
      assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(info.to_der) }
      info = OpenSSL::ASN1.decode(pem_der(fixture("ml-dsa-#{parameter}-expanded.pem")))
      expanded = OpenSSL::ASN1.decode(info.value[2].value)
      expanded.value = expanded.value[0, expanded.value.bytesize - 4]
      info.value[2].value = expanded.to_der
      assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(info.to_der) }

      info = OpenSSL::ASN1.decode(original)
      info.value[0].value = 1
      public_key = OpenSSL::ASN1.decode(pem_der(fixture("ml-dsa-#{parameter}-public.pem"))).value[1].value
      info.value << OpenSSL::ASN1::BitString.new(public_key, 1, :IMPLICIT, :CONTEXT_SPECIFIC)
      assert_equal public_key, OpenSSL::ASN1.decode(OpenSSL::PKey.read(info.to_der).public_to_der).value[1].value
      info.value.last.value = "\0" * public_key.bytesize
      assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(info.to_der) }
    end
  end

  private

  def fixture(name)
    File.binread(File.join(FIXTURES, name))
  end

  def pem_der(pem)
    Base64.decode64(pem.lines.reject { |line| line.start_with?('-----') }.join)
  end
end
