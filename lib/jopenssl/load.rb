warn 'Loading jruby-openssl gem in a non-JRuby interpreter' unless defined? JRUBY_VERSION

require 'jopenssl/version'

# NOTE: assuming user does pull in BC .jars from somewhere else on the CP
unless ENV_JAVA['jruby.openssl.load.jars'].eql?('false')
  version = JOpenSSL::BOUNCY_CASTLE_VERSION
  bc_jars = nil
  begin
    require 'jar-dependencies'
    # if we have jar-dependencies we let it track the jars
    require_jar( 'org.bouncycastle', 'bcprov-jdk15on', version )
    require_jar( 'org.bouncycastle', 'bcpkix-jdk15on', version )
    require_jar( 'org.bouncycastle', 'bctls-jdk15on',  version )
    bc_jars = true
  rescue LoadError
    bc_jars = false
  end
  unless bc_jars
    load "org/bouncycastle/bcprov-jdk15on/#{version}/bcprov-jdk15on-#{version}.jar"
    load "org/bouncycastle/bcpkix-jdk15on/#{version}/bcpkix-jdk15on-#{version}.jar"
    load "org/bouncycastle/bctls-jdk15on/#{version}/bctls-jdk15on-#{version}.jar"
  end
end

require 'jopenssl.jar'

if JRuby::Util.respond_to?(:load_ext) # JRuby 9.2
  JRuby::Util.load_ext('org.jruby.ext.openssl.OpenSSL')
else; require 'jruby'
  org.jruby.ext.openssl.OpenSSL.load(JRuby.runtime)
end

if RUBY_VERSION > '2.3'
  load 'jopenssl/_compat23.rb'
end
