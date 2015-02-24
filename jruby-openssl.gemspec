#-*- mode: ruby -*-

require "#{File.dirname(__FILE__)}/lib/jopenssl/version.rb"

Gem::Specification.new do |s|
  s.name = 'jruby-openssl'
  s.version = Jopenssl::Version::VERSION
  s.platform = 'java'
  s.authors = ['Ola Bini', 'JRuby contributors']
  s.email = "ola.bini@gmail.com"
  s.summary = "JRuby OpenSSL"
  s.homepage = 'https://github.com/jruby/jruby-openssl'
  s.description = 'JRuby-OpenSSL is an add-on gem for JRuby that emulates the' <<
                  ' Ruby OpenSSL native library.'
  s.licenses = [ 'EPL-1.0', 'GPL-2.0', 'LGPL-2.1' ]

  s.require_paths = ['lib']

  s.files = `git ls-files`.split("\n").
    select { |f| f =~ /^(lib)/ || f =~ /^History|LICENSE|README|Rakefile/i } +
    Dir.glob('lib/**/*.jar') # 'lib/jopenssl.jar' and potentially BC jars

  s.requirements << "jar org.bouncycastle:bcpkix-jdk15on, #{Jopenssl::Version::BOUNCY_CASTLE_VERSION}"
  s.requirements << "jar org.bouncycastle:bcprov-jdk15on, #{Jopenssl::Version::BOUNCY_CASTLE_VERSION}"

  s.add_development_dependency 'jar-dependencies', '0.0.9'

  s.add_development_dependency 'mocha', '~> 1.1.0'
  s.add_development_dependency 'ruby-maven'
  # NOTE: runit-maven-plugin will use it's own :
  #s.add_development_dependency 'test-unit', '2.5.5'
end

# vim: syntax=Ruby
