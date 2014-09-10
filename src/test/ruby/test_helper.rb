require 'rubygems' unless defined? Gem

require 'java' if defined? JRUBY_VERSION

if bc_version = ENV['BC_VERSION'] # && respond_to?(:require_jar)
  require 'jar-dependencies'
  require_jar 'org.bouncycastle', 'bcpkix-jdk15on', bc_version
  require_jar 'org.bouncycastle', 'bcprov-jdk15on', bc_version
  Jars.freeze_loading if defined? Jars.freeze_loading

  puts Java::OrgBouncycastleJceProvider::BouncyCastleProvider.new.info
else
  $CLASSPATH << 'pkg/classes'
  jar = Dir['lib/org/bouncycastle/**/bcprov-*.jar'].first
  raise "bcprov jar not found" unless jar; $CLASSPATH << jar
  jar = Dir['lib/org/bouncycastle/**/bcpkix-*.jar'].first
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

end

begin
  gem 'mocha'
rescue LoadError => e
  warn "#{e} to run all tests please `gem install mocha'"
else
  if defined? MiniTest
    require 'mocha/mini_test'
  else
    require 'mocha/test_unit'
  end
end

if defined? JRUBY_VERSION # make sure our OpenSSL lib gets used not JRuby's
  unless ENV['BC_VERSION']
    $LOAD_PATH.unshift(File.expand_path('../../../lib', File.dirname(__FILE__)))
  end
end