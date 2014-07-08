#-*- mode: ruby -*-

require File.dirname(__FILE__) + "/lib/jopenssl/version.rb"

Gem::Specification.new do |s|
  s.name = 'jruby-openssl'
  s.version = Jopenssl::Version::VERSION
  s.platform = 'java'
  s.authors = ['Ola Bini', 'JRuby contributors']
  s.email = "ola.bini@gmail.com"
  s.summary = "JRuby OpenSSL"
  s.homepage = 'https://github.com/jruby/jruby-openssl'
  s.description = File.read('README.txt').split(/\n{2,}/)[3...4].join("\n\n")
  s.licenses = [ 'EPL-1.0', 'GPL-2.0', 'LGPL-2.1' ]
  s.files = Dir['[A-Z]*'] + Dir['lib/**/*'] + Dir['test/**/*']

  s.requirements << "jar org.bouncycastle:bcpkix-jdk15on, #{Jopenssl::Version::BOUNCY_CASTLE_VERSION}"
  s.requirements << "jar org.bouncycastle:bcprov-jdk15on, #{Jopenssl::Version::BOUNCY_CASTLE_VERSION}"

  s.add_development_dependency 'jar-dependencies', '0.0.4'
end

# vim: syntax=Ruby
