warn 'Loading jruby-openssl in a non-JRuby interpreter' unless defined? JRUBY_VERSION

require 'java'
require 'jopenssl/version'

version = Jopenssl::Version::BOUNCY_CASTLE_VERSION
bc_jars = nil
begin
  # if we have jar-dependencies we let it track the jars
  require_jar( 'org.bouncycastle', 'bcpkix-jdk15on', version )
  require_jar( 'org.bouncycastle', 'bcprov-jdk15on', version )
  bc_jars = true
rescue LoadError
end if (defined?(Jars) && ( ! Jars.skip? ) rescue nil)
unless bc_jars
  begin
    # try regular require first
    require "bcpkix-jdk15on-#{version}.jar"
    require "bcprov-jdk15on-#{version}.jar"
  rescue LoadError
    # load from here
    load "org/bouncycastle/bcpkix-jdk15on/#{version}/bcpkix-jdk15on-#{version}.jar"
    load "org/bouncycastle/bcprov-jdk15on/#{version}/bcprov-jdk15on-#{version}.jar"
  end
end

require 'jruby'
require 'jopenssl.jar'
org.jruby.ext.openssl.OpenSSL.load(JRuby.runtime)

if RUBY_VERSION >= '2.1.0'
  load('jopenssl21/openssl.rb')
elsif RUBY_VERSION >= '1.9.0'
  load('jopenssl19/openssl.rb')
else
  load('jopenssl18/openssl.rb')
end

require 'openssl/pkcs12'
