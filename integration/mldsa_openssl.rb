require_relative '../test/test_helper'
require 'open3'
require 'tmpdir'

class TestMLDSAOpenSSL < TestCase
  def test_native_openssl_accepts_jruby_keys_and_signatures
    version = openssl('version')
    number = version[/\AOpenSSL (\d+\.\d+\.\d+)/, 1]
    assert(number && Gem::Version.new(number) >= Gem::Version.new('3.5.0'),
           "OpenSSL 3.5 or later is required; found #{version.strip}")
    message = File.expand_path('../test/fixtures/mldsa/binary.bin', File.dirname(__FILE__))

    Dir.mktmpdir('mldsa-openssl') do |directory|
      private_path = File.join(directory, 'private.der')
      public_path = File.join(directory, 'public.der')
      signature_path = File.join(directory, 'signature.bin')
      [44, 65, 87].each do |parameter|
        key = OpenSSL::PKey.generate_key("ML-DSA-#{parameter}")
        File.binwrite(private_path, key.private_to_der)
        File.binwrite(public_path, key.public_to_der)
        File.binwrite(signature_path, key.sign(nil, File.binread(message)))

        assert_equal key.public_to_der,
                     openssl('pkey', '-inform', 'DER', '-in', private_path, '-pubout', '-outform', 'DER')
        assert_equal key.public_to_der,
                     openssl('pkey', '-pubin', '-inform', 'DER', '-in', public_path, '-pubout', '-outform', 'DER')
        openssl('pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', public_path,
                '-in', message, '-sigfile', signature_path)
      end
    end
  end

  private

  def openssl(*arguments)
    output, error, status = Open3.capture3('openssl', *arguments, binmode: true)
    assert status.success?, "openssl #{arguments.join(' ')} failed: #{error}#{output}"
    output
  rescue Errno::ENOENT
    flunk 'OpenSSL 3.5 or later must be installed and available on PATH'
  end
end
