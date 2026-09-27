require 'rake/testtask'

def define_mri_test_task(root: File.expand_path('..', __dir__),
                         jopenssl_lib: File.expand_path('lib', root),
                         extra_ruby_opts: [])
  dir = File.join(root, 'ruby-openssl')

  namespace :test do
    task :mri_submodule_check do
      next if File.exist?(File.join(dir, 'test/openssl/utils.rb'))

      fail 'ruby-openssl submodule not initialized, run `git submodule update --init ruby-openssl`'
    end

    Rake::TestTask.new(:mri) do |task|
      task.description = 'Run the upstream Ruby/OpenSSL test suite against jruby-openssl'
      task.libs = [jopenssl_lib]
      task.test_files = FileList[File.join(dir, 'test/openssl/test_*.rb')].to_a
      task.verbose = false
      task.loader = :direct
      excludes = File.join(root, 'test/mri/exclude_filter.rb')
      task.ruby_opts = ["-r#{excludes}"] + extra_ruby_opts
    end
    task :mri => ['lib/jopenssl.jar', :mri_submodule_check]
  end
end
