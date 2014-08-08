require 'rubygems'

require 'java'

if ENV['BC_VERSION'] # && respond_to?(:require_jar)
  require 'jar-dependencies'
  require_jar( 'org.bouncycastle', 'bcpkix-jdk15on', ENV[ 'BC_VERSION' ] )
  require_jar( 'org.bouncycastle', 'bcprov-jdk15on', ENV[ 'BC_VERSION' ] )
  Jars.freeze_loading
else
  $CLASSPATH << 'pkg/classes'
  jar = Dir['lib/org/bouncycastle/**/bcprov-*.jar'].first
  raise "bcprov jar not found" unless jar; $CLASSPATH << jar
  jar = Dir['lib/org/bouncycastle/**/bcpkix-*.jar'].first
  raise "bcpkix jar not found" unless jar; $CLASSPATH << jar
end

begin
  gem 'test-unit'
rescue LoadError
  puts "gem 'test-unit' not available, will use built-in Test::Unit"
end
require 'test/unit'

begin
  gem 'mocha'
rescue LoadError => e
  warn "WARN: #{e} to run all tests please `gem install mocha'"
end

begin
  if defined? MiniTest
    require "mocha/mini_test"
  else
    require "mocha/test_unit"
  end
rescue LoadError
end