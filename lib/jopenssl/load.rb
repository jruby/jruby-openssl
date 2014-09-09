warn 'Loading jruby-openssl in a non-JRuby interpreter' unless defined? JRUBY_VERSION

require 'jopenssl/version'
begin
  version = Jopenssl::Version::BOUNCY_CASTLE_VERSION
  # if we have jar-dependencies we let it track the jars
  require 'jar-dependencies'
  require_jar( 'org.bouncycastle', 'bcpkix-jdk15on', version )
  require_jar( 'org.bouncycastle', 'bcprov-jdk15on', version )
rescue LoadError
  load "org/bouncycastle/bcpkix-jdk15on/#{version}/bcpkix-jdk15on-#{version}.jar"
  load "org/bouncycastle/bcprov-jdk15on/#{version}/bcprov-jdk15on-#{version}.jar"
end unless org.jruby.ext.openssl.OSSLLibrary.provider_available?
# user set up BC security provider in the JVM - probably knows what he's doing

# Load extension
require 'jruby'
require 'jopenssl.jar'
org.jruby.ext.openssl.OSSLLibrary.load(JRuby.runtime)

if RUBY_VERSION >= '2.1.0'
  load('jopenssl21/openssl.rb')
elsif RUBY_VERSION >= '1.9.0'
  load('jopenssl19/openssl.rb')
else
  load('jopenssl18/openssl.rb')
end

require 'openssl/pkcs12'
