# asserts the JVM-level provider setup is really in effect before any test runs
#
# required by the `rake test:*_system` tasks

puts "\nloaded: #{__FILE__}" if $VERBOSE

java.security.Security.getProviders.each_with_index do |provider, i|
  puts "#{i}: #{provider}" if $VERBOSE
end

fail = -> (message) { raise java.lang.AssertionError.new(message) }

unless ENV_JAVA['jruby.openssl.load.jars'] == 'false'
  fail.('jruby.openssl.load.jars is not false, the gem would load its own jars')
end

system_loader = java.lang.ClassLoader.getSystemClassLoader

ENV.fetch('JOSSL_TEST_PROVIDERS').split(',').each do |name|
  provider = java.security.Security.getProvider(name)
  fail.("#{name} provider not registered through java.security") if provider.nil?

  loader = provider.java_class.to_java.getClassLoader
  unless loader == system_loader
    fail.("#{name} provider loaded by #{loader}, expected system class-loader")
  end
end

if ENV_JAVA['jruby.openssl.provider.ssl'] == 'false'
  require 'openssl'
  provider = org.jruby.ext.openssl.SecurityHelper.getSSLContext('TLS').provider.name
  fail.("SSL engine is #{provider}, expected SunJSSE") unless provider == 'SunJSSE'
  puts "SSL engine: #{provider}"
end
