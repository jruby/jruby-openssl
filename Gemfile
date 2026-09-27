source 'https://gem.coop'

# Specify your gem's dependencies in the gemspec
gemspec if defined? JRUBY_VERSION

gem "rake", require: false

group :test do
  gem 'base64', require: false
  gem 'mocha', '~> 1.4', '< 2.0'
  gem 'prime', require: false
  gem 'test-unit'
  gem 'test-unit-ruby-core',
      git: 'https://github.com/ruby/test-unit-ruby-core.git',
      tag: 'v1.0.14',
      require: false
end
