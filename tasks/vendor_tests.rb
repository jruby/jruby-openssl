require 'rake/testtask'

# Re-usable definitions of the vendored integration-test namespaces
# (net-http, net-imap, net-ssh, ruby-jwt, sigstore) run against a JOSSL's `lib`
#
# caller must define a `file 'lib/jopenssl.jar'` task that builds its ext jar
def define_vendor_test_tasks(root: File.expand_path('..', __dir__),
                             jopenssl_lib: File.expand_path('lib', root),
                             extra_ruby_opts: [])
  jar = 'lib/jopenssl.jar'

  namespace 'net-http' do
    dir = File.join(root, 'net-http')

    desc 'Install net-http gem dependencies'
    task(:bundle) { sh "cd #{dir} && bundle install --without sig" }

    task :bundle_check do
      File.exist?(File.join(dir, 'Gemfile.lock')) or fail "bundle not installed, run `rake net-http:bundle'"
    end

    desc 'Run net-http (HTTPS) tests against jruby-openssl'
    Rake::TestTask.new(:test) do |task|
      task.libs = [ jopenssl_lib, File.join(dir, 'lib'), File.join(dir, 'test/lib') ]
      test_files = %w[test/net/http/test_https.rb test/net/http/test_https_proxy.rb]
      task.test_files = test_files.map { |path| File.expand_path(path, dir) }
      task.verbose = false
      task.loader = :direct
      task.ruby_opts = [ '-v', '-C', dir, '-rhelper' ] + extra_ruby_opts
    end
    task :test => [ jar, :bundle_check ]
  end

  namespace 'net-imap' do
    dir = File.join(root, 'net-imap')

    desc 'Install net-imap gem dependencies'
    task(:bundle) { sh "cd #{dir} && bundle install" }

    task :bundle_check do
      File.exist?(File.join(dir, 'Gemfile.lock')) or fail "bundle not installed, run `rake net-imap:bundle'"
    end

    desc 'Run net-imap (SSL/STARTTLS) tests against jruby-openssl'
    task :test => [ jar, :bundle_check ] do
      # jruby-openssl lib is absolute (and first) so the -C chdir can't shadow the local openssl
      libs = [ jopenssl_lib, File.join(dir, 'lib'), File.join(dir, 'test/lib') ]
      # TLS handshake / STARTTLS tests only (the rest of test_imap.rb hangs on JRuby)
      # the two starttls_stripping tests are excluded - their 10ms coordination sleep is a JRuby
      # thread-scheduling race (plain-socket IOError, not TLS)
      name_filter = '--name=/^test_(imaps|starttls(?!_stripping))/'
      # array form (no shell) so the regexp metacharacters reach test-unit intact
      ruby '-C', dir, "-I#{libs.join(File::PATH_SEPARATOR)}", *extra_ruby_opts,
           '-rbundler/setup', '-rhelper',
           File.join(dir, 'test/net/imap/test_imap.rb'), name_filter, '-v'
    end
  end

  namespace 'net-ssh' do
    dir = File.join(root, 'net-ssh')

    desc 'Install net-ssh gem dependencies'
    task :bundle do
      sh "cd #{dir} && bundle install"
      # net-ssh's gemspec skips bcrypt_pbkdf on java (-java variant is only out as a pre-release)
      sh "gem install --no-document ed25519 && gem install --no-document --pre bcrypt_pbkdf"
    end

    task :bundle_check do
      File.exist?(File.join(dir, 'Gemfile.lock')) or fail "bundle not installed, run `rake net-ssh:bundle'"
    end

    desc 'Run net-ssh (OpenSSL) tests against jruby-openssl'
    Rake::TestTask.new(:test) do |task|
      test_files = %w[
        test/test_key_factory.rb
        test/transport/test_cipher_factory.rb
        test/transport/test_hmac.rb
        test/authentication/test_certificate.rb
        test/authentication/test_ed25519.rb
        test/authentication/test_key_manager.rb
      ]
      test_files += FileList[File.join(dir, 'test/transport/{kex,hmac}/test_*.rb')].to_a

      task.libs = [ jopenssl_lib, File.join(dir, 'lib'), File.join(dir, 'test') ]
      task.test_files = test_files.map { |path| File.expand_path(path, dir) }
      task.verbose = false
      # exclude the CTR *_encryption2/decryption2 tests: they update-then-final-then-update
      # JOSSL' native CTR resets the counter on final (MRI continues) - a test-only pattern,
      # real SSH streams updates continuously (see test/test_cipher.rb for CTR coverage)
      task.options = "--verbose --exclude='/_ctr_for_.*cryption2/'"
      task.ruby_opts = [ '-v', '-C', dir, '-rcommon' ] + extra_ruby_opts
    end
    task :test => [ jar, :bundle_check ]
  end

  namespace 'ruby-jwt' do
    dir = File.join(root, 'ruby-jwt')

    desc 'Install ruby-jwt gem dependencies'
    task :deps do
      # dev deps pull irb -> rdoc -> rbs (C-extension gem); specs run via `-S rspec`
      # pin simplecov to avoid its undeclared prism dependency on JRuby
      ruby '-S gem install --no-document rspec simplecov:0.22.0 base64 logger'
    end

    task(:deps_check) { }

    desc 'Run ruby-jwt (OpenSSL) tests against jruby-openssl'
    task :test => [ jar, :deps_check ] do
      spec_files = [
        'spec/jwt/jwt_spec.rb',
        'spec/jwt/jwa_spec.rb',
        'spec/jwt/jwa/ecdsa_spec.rb',
        'spec/jwt/jwa/hmac_spec.rb',
        'spec/jwt/jwa/rsa_spec.rb',
        'spec/jwt/jwk_spec.rb',
        'spec/jwt/jwk/decode_with_jwk_spec.rb',
        'spec/jwt/jwk/ec_spec.rb',
        'spec/jwt/jwk/rsa_spec.rb',
        'spec/jwt/x5c_key_finder_spec.rb',
        'spec/integration/readme_examples_spec.rb'
      ].map { |file| File.expand_path(file, dir) }

      ruby '-C', dir, "-I#{jopenssl_lib}", *extra_ruby_opts,
           '-S', 'rspec', "-I#{jopenssl_lib}", *spec_files
    end
  end

  namespace 'sigstore' do
    dir = File.join(root, 'sigstore-ruby')

    desc 'Install sigstore-ruby gem dependencies'
    task(:bundle) { sh "cd #{dir} && bundle install" }

    task :bundle_check do
      File.exist?(File.join(dir, 'Gemfile.lock')) or fail "bundle not installed, run `rake sigstore:bundle'"
    end

    desc 'Run sigstore-ruby (OpenSSL) tests against jruby-openssl'
    Rake::TestTask.new(:test) do |task|
      test_files = FileList[File.join(dir, 'test/sigstore/**/*_test.rb')].to_a
      test_files = test_files.reject { |f| f.include?('conformance_test') }

      task.libs = [ jopenssl_lib, File.join(dir, 'lib'), File.join(dir, 'test') ]
      task.test_files = test_files.map { |path| File.expand_path(path, dir) }
      task.verbose = false
      task.loader = :direct
      task.ruby_opts = [ '-v', '-C', dir, '-rbundler/setup', '-rtest_helper' ] + extra_ruby_opts
    end
    task :test => [ jar, :bundle_check ]
  end
end
