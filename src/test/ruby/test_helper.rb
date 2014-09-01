require 'rubygems'

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
require 'test/unit'

begin
  gem 'mocha'
rescue LoadError => e
  warn "#{e.inspect} to run all tests please `gem install mocha'"
end

begin
  if defined? MiniTest
    require 'mocha/mini_test'
  else
    require 'mocha/test_unit'
  end
rescue LoadError
end