require 'rubygems' unless defined? Gem

require 'java' if defined? JRUBY_VERSION

if bc_version = ENV['BC_VERSION'] # && respond_to?(:require_jar)
  require 'jar-dependencies'
  require_jar 'org.bouncycastle', 'bcpkix-jdk15on', bc_version
  require_jar 'org.bouncycastle', 'bcprov-jdk15on', bc_version
  Jars.freeze_loading if defined? Jars.freeze_loading

  puts Java::OrgBouncycastleJceProvider::BouncyCastleProvider.new.info if $VERBOSE
else
  base_dir = File.expand_path('../../..', File.dirname(__FILE__))

  jar = File.join(base_dir, 'lib/jopenssl.jar')
  raise "jopenssl.jar jar not found" unless jar; $CLASSPATH << jar

  jar = Dir[File.join(base_dir, 'lib/org/bouncycastle/**/bcprov-*.jar')].first
  raise "bcprov jar not found" unless jar; $CLASSPATH << jar
  jar = Dir[File.join(base_dir, 'lib/org/bouncycastle/**/bcpkix-*.jar')].first
  raise "bcpkix jar not found" unless jar; $CLASSPATH << jar
end if defined? JRUBY_VERSION

# NOTE: RUnit maven plugin (<= 1.0.5) does not handle test-unit well !
#begin
#  gem 'test-unit'
#rescue LoadError
#  puts "gem 'test-unit' not available, will load built-in 'test/unit'"
#end
begin
  gem 'minitest'
  require 'minitest/autorun'
  # NOTE: deal with maven plugin 1.0.10 setting output (gone on minitest 5) :
  if Minitest.const_defined?(:Unit) && ! defined?(Minitest::Unit.output)
      Minitest::Unit.module_eval do
        @@report_path = nil
        def self.report_path; @@report_path end
        def self.output=(report_path) # called by the runit-maven-plugin
          Minitest.extensions << 'output' # add a plugin (MiniT calls #plugin_output_init)
          @@report_path = report_path
        end
      end
      Minitest.module_eval do
        def self.plugin_output_init(options)
          summary = self.reporter.reporters.find { |rr| rr.is_a?(Minitest::SummaryReporter) }
          if summary && Minitest::Unit.report_path
            summary = summary.dup
            summary.io = Minitest::Unit.report_path
            self.reporter.reporters << summary
          end
        end
      end
  end
rescue LoadError
end

if defined? Minitest::Test
  TestCase = Minitest::Test
else
  require 'test/unit'
  TestCase = Test::Unit::TestCase
end

TestCase.class_eval do

  def setup; require 'openssl' end

  alias assert_raise assert_raises unless method_defined?(:assert_raise)

  unless method_defined?(:skip)
    if method_defined?(:omit)
      alias skip omit
    else
      def skip(msg = nil)
        warn "Skipped: #{caller[0]} #{msg}"
      end
    end
  end

  unless method_defined?(:assert_not_equal)
    def assert_not_equal(expected, actual)
      assert expected != actual, "expected: #{expected} to not equal: #{actual} but did"
    end
  end

  unless method_defined?(:assert_nothing_raised)
    def assert_nothing_raised
      begin
        yield
      rescue => e
        assert false, "unexpected error raised: #{e.inspect}"
      end
    end
  end

  unless method_defined?(:assert_not_same)
    def assert_not_same(expected, actual)
      assert ! expected.equal?(actual), "expected: #{expected} to be same as: #{actual} but did"
    end
  end

  def self.disable_security_restrictions!; end # do nothing on MRI

  @@security_restrictions = nil

  def self.disable_security_restrictions!
    jce_security_class = java.lang.Class.for_name('javax.crypto.JceSecurity')
    restricted_field = jce_security_class.getDeclaredField('isRestricted')
    restricted_field.accessible = true
    @@security_restrictions = restricted_field.getBoolean(nil)
    return false unless @@security_restrictions

    if java.lang.reflect.Modifier.isFinal restricted_field.modifiers
      field_class = java.lang.Class.for_name('java.lang.reflect.Field')
      # NOTE: this no longer works since 8u111 as it's using unsafe :
      # Can not set static final boolean field javax.crypto.JceSecurity.isRestricted to (boolean)false
      #   sun.reflect.UnsafeFieldAccessorImpl.throwFinalFieldIllegalAccessException(sun/reflect/UnsafeFieldAccessorImpl.java:76)
      #   sun.reflect.UnsafeFieldAccessorImpl.throwFinalFieldIllegalAccessException(sun/reflect/UnsafeFieldAccessorImpl.java:84)
      #   sun.reflect.UnsafeQualifiedStaticBooleanFieldAccessorImpl.setBoolean(sun/reflect/UnsafeQualifiedStaticBooleanFieldAccessorImpl.java:93)
      #   java.lang.reflect.Field.setBoolean(java/lang/reflect/Field.java:801)
      mods_field = field_class.getDeclaredField('modifiers')
      mods_field.accessible = true

      # restricted_field = jce_security_class.getDeclaredField('isRestricted')
      # restricted_field.accessible = true
      mods_field.setInt restricted_field, (~java.lang.reflect.Modifier::FINAL & restricted_field.modifiers)
    end
    restricted_field.setBoolean nil, false; return true
  rescue Java::JavaLang::ClassNotFoundException => e
    warn "failed to disable JCE security restrictions: #{e.inspect}"; nil
  rescue Java::JavaLang::NoSuchFieldException => e # Java 6
    warn "failed to disable JCE security restrictions: #{e.inspect}"; nil
  rescue Java::JavaLang::IllegalAccessException => e
    warn "failed to disable JCE security restrictions: #{e.inspect}"; nil
  rescue NameError => e
    warn "failed to disable JCE security restrictions: #{e.inspect}"; nil
  end if defined? JRUBY_VERSION

  def self.security_restrictions?
    disable_security_restrictions! if @@security_restrictions.nil?
    @@security_restrictions
  end

  def self.java6?; java_version.last.to_i == 6 end
  def self.java7?; java_version.last.to_i == 7 end
  def self.java8?; java_version.last.to_i == 8 end

  def self.java_version
    return [] unless defined? JRUBY_VERSION
    ENV_JAVA[ 'java.specification.version' ].split('.')
  end

  def self.jruby?; !! defined?(JRUBY_VERSION) end
  def jruby?; self.class.jruby? end

  private

  def issue_cert(dn, key, serial, not_before, not_after, extensions,
                 issuer, issuer_key, digest)
    cert = OpenSSL::X509::Certificate.new
    issuer = cert unless issuer
    issuer_key = key unless issuer_key
    cert.version = 2
    cert.serial = serial
    cert.subject = dn
    cert.issuer = issuer.subject
    cert.public_key = key.public_key
    cert.not_before = not_before
    cert.not_after = not_after
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer
    extensions.each do |oid, value, critical|
      cert.add_extension ef.create_extension(oid, value, critical)
    end
    cert.sign(issuer_key, digest)
    cert
  end

  def issue_crl(revoke_info, serial, lastup, nextup, extensions,
                issuer, issuer_key, digest)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = lastup
    crl.next_update = nextup
    revoke_info.each{|rserial, time, reason_code|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = rserial
      revoked.time = time
      enum = OpenSSL::ASN1::Enumerated(reason_code)
      ext = OpenSSL::X509::Extension.new("CRLReason", enum)
      revoked.add_extension(ext)
      crl.add_revoked(revoked)
    }
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = issuer
    ef.crl = crl
    crlnum = OpenSSL::ASN1::Integer(serial)
    crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
    extensions.each do |oid, value, critical|
      crl.add_extension ef.create_extension(oid, value, critical)
    end
    crl.sign(issuer_key, digest)
    crl
  end

end

begin
  gem 'mocha'
rescue LoadError => e
  warn "#{e} to run all tests please `gem install mocha'"
else
  begin
    if defined? MiniTest
      require 'mocha/mini_test'
    else
      require 'mocha/test_unit'
    end
  rescue LoadError => e
    warn "current mocha version might not work (try `gem install mocha'): #{e}"
  end
end

if defined? JRUBY_VERSION # make sure our OpenSSL lib gets used not JRuby's
  unless ENV['BC_VERSION']
    $LOAD_PATH.unshift(File.expand_path('../../../lib', File.dirname(__FILE__)))
  end
end

if ENV['OPENSSL_TEST_SUITE'].to_s == 'true'

  require 'jopenssl/load' if defined? JRUBY_VERSION

  base = File.expand_path('../ossl', File.dirname(__FILE__))
  if ( sub = RUBY_VERSION[0, 3] ) == '2.0'
    sub = '1.9'
  end
  puts "loading (MRI) OpenSSL suite from: #{File.join(base, sub)}"
  Dir.glob("#{File.join(base, sub)}/**/test_*.rb").each do |test|
    require test
  end
end
