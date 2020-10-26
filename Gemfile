source 'https://rubygems.org'

# Specify your gem's dependencies in the gemspec
gemspec

gem "rake"

# for less surprises with newer releases
gem 'jar-dependencies', '~> 0.3.11', :require => nil

gem 'mocha', '~> 1.4', '< 2.0'

# for the rake task
gem 'ruby-maven', github: 'jruby/ruby-maven'
# due https://github.com/jruby/ruby-maven/pull/1 until ruby-maven is released

# NOTE: runit-maven-plugin will use it's own :
gem 'test-unit', '2.5.5'
