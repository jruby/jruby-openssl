source 'https://rubygems.org'

# Specify your gem's dependencies in the gemspec
gemspec if defined? JRUBY_VERSION

gem "rake", require: false

# for less surprises with newer releases
gem 'jar-dependencies', '>= 0.3.11', platform: :jruby, require: false

gem 'mocha', '~> 1.4', '< 2.0'

# NOTE: runit-maven-plugin will use it's own :
gem 'test-unit'
