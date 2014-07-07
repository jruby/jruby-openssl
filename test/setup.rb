if ENV[ 'BC_VERSIONs' ]
  require 'rubygems'
  require 'jar-dependencies'
  require_jar( 'org.bouncycastle', 'bcpkix-jdk15on', ENV[ 'BC_VERSION' ] )
  require_jar( 'org.bouncycastle', 'bcprov-jdk15on', ENV[ 'BC_VERSION' ] )
  Jars.freeze_loading
end
