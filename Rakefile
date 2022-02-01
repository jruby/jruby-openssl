#-*- mode: ruby -*-

#Rake::Task[:jar].clear rescue nil
desc "Package jopenssl.jar with the compiled classes"
task :jar do
  sh( './mvnw prepare-package -Dmaven.test.skip=true' )
end
namespace :jar do
  desc "Package jopenssl.jar file (and dependendent jars)"
  task :all do
    sh( './mvnw package -Dmaven.test.skip=true' )
  end
end
task :test_prepare do
  sh( './mvnw prepare-package -Dmaven.test.skip=true' )
  sh( './mvnw test-compile' ) # separate step due -Dmaven.test.skip=true
end

task :clean do
  sh( './mvnw clean' )
end

task :build do
  sh( './mvnw clean package -Dmaven.test.skip=true' )
end

task :default => :build

file('lib/jopenssl.jar') { Rake::Task['jar'].invoke }

require 'rake/testtask'
Rake::TestTask.new do |task|
  task.libs << File.expand_path('src/test/ruby', File.dirname(__FILE__))
  test_files = FileList['src/test/ruby/**/test*.rb'].to_a
  task.test_files = test_files.map { |path| path.sub('src/test/ruby/', '') }
  task.verbose = true
  task.loader = :direct
  task.ruby_opts = [ '-C', 'src/test/ruby', '-rbundler/setup' ]
end
task :test => 'lib/jopenssl.jar'

namespace :integration do
  it_path = File.expand_path('../src/test/integration', __FILE__)
  task :install do
    ruby "-C #{it_path} -S bundle install"
  end
  # desc "Run IT tests"
  task :test => 'lib/jopenssl.jar' do
    unless File.exist?(File.join(it_path, 'Gemfile.lock'))
      raise "bundle not installed, run `rake integration:install'"
    end
    loader = "ARGV.each { |f| require f }"
    lib = [ File.expand_path('../lib', __FILE__), it_path ]
    test_files = FileList['src/test/integration/*_test.rb'].map { |path| path.sub('src/test/integration/', '') }
    ruby "-I#{lib.join(':')} -C src/test/integration -e \"#{loader}\" #{test_files.map { |f| "\"#{f}\"" }.join(' ')}"
  end
end
