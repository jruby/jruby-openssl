require 'rake/testtask'

mvnw = File.expand_path('./mvnw', File.dirname(__FILE__))

# reproducible build: SOURCE_DATE_EPOCH shared by jopenssl.jar and gem
# read from env by RubyGems; pass via -D so dev builds don't churn pom.xml
def source_date_epoch!
  ENV['SOURCE_DATE_EPOCH'] ||= `git log -1 --pretty=%ct`.strip
end

def _build_output_timestamp
  "-Dproject.build.outputTimestamp=#{ENV['SOURCE_DATE_EPOCH']}" if ENV['SOURCE_DATE_EPOCH']
end

desc "Package jopenssl.jar with the compiled classes"
task :jar do
  sh("#{mvnw} prepare-package -Dmaven.test.skip=true")
end

task :test_prepare => :jar do
  sh("#{mvnw} test-compile") # separate due -Dmaven.test.skip=true
end

task :clean do
  sh("#{mvnw} clean")
end

task :build_release do
  source_date_epoch!
  sh("#{mvnw} -Prelease -DupdateReleaseInfo=true #{_build_output_timestamp} package")
end

desc "Sanity-check tree/version, then build a reproducible release gem"
task :release => :release_check do
  source_date_epoch! # pin to the release commit so the gem + jar use the same
  puts "SOURCE_DATE_EPOCH=#{ENV['SOURCE_DATE_EPOCH']} (#{Time.at(ENV['SOURCE_DATE_EPOCH'].to_i).utc})"
  Rake::Task[:clean].invoke
  Rake::Task[:build_release].invoke
  gem = release_gem_path
  abort "release aborted - #{gem} was not produced" unless File.exist?(gem)
  puts "built #{gem}"
  puts "publish with: rake push (rubygems) and rake push:coop (gem.coop)"
end

task :release_check do
  dirty = `git status --porcelain`.strip
  abort "release aborted - working tree is not clean:\n#{dirty}" unless dirty.empty?

  version = parsed_version
  begin
    gem_version = Gem::Version.new(version)
    segments = gem_version.release.segments
  rescue ArgumentError => e
    fail "malformed JOpenSSL::VERSION #{version.inspect} - #{e.message}"
  end
  fail "JOpenSSL::VERSION #{version} must be 3 segments (got #{segments.size})" if segments.size != 3

  if gem_version.prerelease? && ENV['PRERELEASE'] != 'true'
    abort "release aborted - #{version} is a prerelease"
  end

  if loaded_version != version
    abort "loaded JOpenSSL::VERSION (#{loaded_version}) and parsed #{version} don't match"
  end

  branch = `git rev-parse --abbrev-ref HEAD`.strip
  warn "WARNING: releasing from '#{branch}' (not 'master')" unless branch == 'master'

  expected_tag = "v#{version}" # release tags are vX.Y.Z
  tags = `git tag --points-at HEAD`.split("\n")
  unless tags.include?(expected_tag)
    found = tags.empty? ? 'none' : tags.join(', ')
    warn "WARNING: no #{expected_tag} tag points at HEAD (tags at HEAD: #{found})"
  end

  puts "release checks passed for #{version}"
end

desc "Build the self-contained jar-release artifacts (-Pjar-release)"
task :jar_release => :release_check do
  source_date_epoch!
  puts "SOURCE_DATE_EPOCH=#{ENV['SOURCE_DATE_EPOCH']} (#{Time.at(ENV['SOURCE_DATE_EPOCH'].to_i).utc})"
  sh("#{mvnw} package -Pjar-release -Dmaven.test.skip=true #{_build_output_timestamp}")
  # deploy (gpg-sign + push): #{File.basename(mvnw)} deploy -Prelease,jar-release -D...
end

task :default => :jar

file('lib/jopenssl.jar') { Rake::Task[:jar].invoke }

file('pkg/test-classes/org/jruby/ext/openssl/SecurityHelperTest.class') do
  Rake::Task[:test_prepare].invoke
end

Rake::TestTask.new do |task|
  task.libs << File.expand_path('test', File.dirname(__FILE__))
  test_files = FileList['test/**/test*.rb'].to_a
  task.test_files = test_files.map { |path| path.sub('test/', '') }
  task.verbose = false # using -v directly instead due issues with rake
  task.loader = :direct
  task.ruby_opts = [ '-v', '-rbundler/setup' ]
end
task :test => ['lib/jopenssl.jar', 'pkg/test-classes/org/jruby/ext/openssl/SecurityHelperTest.class']

require_relative 'tasks/vendor_tests'
define_vendor_test_tasks # root + jopenssl_lib default to this tree

require_relative 'tasks/mri_tests'
define_mri_test_task

require_relative 'tasks/provider_tests'
namespace :test do
  namespace :provider do
    define_provider_test_task :bc_all,
                              description: 'Run tests with BC providers registered',
                              providers: [
                                { name: 'BC', class: 'org.bouncycastle.jce.provider.BouncyCastleProvider' },
                                { name: 'BCJSSE', class: 'org.bouncycastle.jsse.provider.BouncyCastleJsseProvider' }
                              ],
                              jars: -> { FileList['vendor/**/*.jar'].map { |path| File.expand_path(path) } }
    define_provider_test_task :bc_wout_jsse, # BC registered but BC-JSSE n/a
                              description: 'Run tests with BC provider and default SSL engine',
                              providers: [
                                { name: 'BC', class: 'org.bouncycastle.jce.provider.BouncyCastleProvider' },
                              ],
                              extra_ruby_opts: ['-J-Djruby.openssl.provider.ssl=false'], # use built-in SunJSSE
                              jdk_providers: ['SUN', 'SunJSSE', 'SunJCE', 'SunEC'],
                              jars: -> { FileList['vendor/**/*.jar'].map { |path| File.expand_path(path) } }
  end

  desc 'Run regular and provider test suites'
  task :all do
    %w[
      test
      test:provider:bc_all
      test:provider:bc_wout_jsse
    ].each do |name|
      Rake::Task[name].invoke
    end
  end
end

namespace :integration do
  it_path = File.expand_path('integration', File.dirname(__FILE__))
  task :install do
    ruby "-C #{it_path} -S bundle install"
  end
  desc "Run tests via invoker (bc-compat)"
  task :test => 'lib/jopenssl.jar' do
    unless File.exist?(File.join(it_path, 'Gemfile.lock'))
      fail "bundle not installed, run `rake integration:install'"
    end
    loader = "ARGV.each { |file| require(file) }"
    lib = [ File.expand_path('../lib', __FILE__), it_path ]
    test_files = FileList['integration/*_test.rb'].map { |path| path.sub('integration/', '') }
    ruby "-I#{lib.join(':')} -C integration -e \"#{loader}\" #{test_files.map { |f| "\"#{f}\"" }.join(' ')}"
  end
end

def parsed_version
  return @parsed_version if (@parsed_version ||= nil)

  version_rb = File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
  version = File.read(version_rb)[/^\s*VERSION\s*=\s*['"]([^'"]+)['"]/, 1]
  fail "could not parse JOpenSSL::VERSION from #{version_rb}" if version.nil?

  @parsed_version = version
end

def loaded_version
  load File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
  JOpenSSL::VERSION
end

GEM_PUSH_TARGETS = {
  rubygems: { name: 'rubygems', host: 'https://rubygems.org' },
  gem_coop: { name: 'gem.coop', host: 'https://gem.coop/@jossl' }
}

def release_gem_path(version = (ENV['VERSION'] || parsed_version))
  File.join(File.dirname(__FILE__), 'pkg', "org.jruby.openssl.jruby-openssl-#{version}.gem")
end

def push_gem(target_key)
  target = GEM_PUSH_TARGETS.fetch(target_key) { abort "unknown push target: #{target_key}" }
  gem_file = release_gem_path
  abort "missing #{gem_file} - run `rake release` first" unless File.exist?(gem_file)

  require 'rubygems/package'
  spec = Gem::Package.new(gem_file).spec
  unless spec.version.to_s == version
    abort "#{gem_file} is version #{spec.version}, expected #{version}"
  end

  puts "pushing #{File.basename(gem_file)} to #{target[:name]} (#{target[:host]})"
  sh "gem push --host #{target[:host]} #{gem_file}"
end

namespace :push do
  desc 'Push the release gem to rubygems.org'
  task(:rubygems) { push_gem(:rubygems) }

  desc 'Push the release gem to gem.coop'
  task(:coop) { push_gem(:gem_coop) }
end

task :push => 'push:rubygems'
