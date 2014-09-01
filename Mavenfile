#-*- mode: ruby -*-

gemspec :jar => 'jopenssl', :include_jars => true

sonatype_url = 'https://oss.sonatype.org/content/repositories/snapshots/'
snapshot_repository :id => 'sonatype', :url => sonatype_url

if model.version.to_s.match /[a-zA-Z]/

  # deploy snapshot versions on sonatype !!!
  model.version = model.version + '-SNAPSHOT'
  plugin :deploy, '2.8.1' do
    execute_goals( :deploy,
                   :skip => false,
                   :altDeploymentRepository => "sonatype-nexus-snapshots::default::#{sonatype_url}" )
  end
end

plugin( :compiler, '3.1', :target => '1.6', :source => '1.6',
        :debug => true, :verbose => false, :showWarnings => true, :showDeprecation => true )

# we need the jruby API here. use the oldest jruby we want to support
jar 'org.jruby:jruby-core', '1.6.8', :scope => :provided

scope :test do
  jar 'junit:junit:4.11'
end

jruby_plugin! :gem do
  # when installing dependent gems we want to use the built in openssl
  # not the one from this lib directory
  execute_goal :id => 'default-initialize', :libDirectory => 'something-which-does-not-exists'
  execute_goals :id => 'default-push', :skip => true
end

supported_bc_versions = [ '1.47', '1.48', '1.49', '1.50' ]

properties( 'jruby.plugins.version' => '1.0.5',
            'jruby.versions' => '1.7.13',
            'bc.versions' => supported_bc_versions.last,
            'invoker.test' => '${bc.versions}',
            # allow to skip all tests with -Dmaven.test.skip
            'invoker.skip' => '${maven.test.skip}',
            'runit.dir' => 'src/test/ruby/**/test_*.rb',
            # use this version of jruby for ALL the jruby-maven-plugins
            'jruby.version' => '1.7.13',
            # dump pom.xml as readonly when running 'rmvn'
            'tesla.dump.pom' => 'pom.xml',
            'tesla.dump.readonly' => true )

plugin :invoker, '1.8' do
  execute_goals( :install, :run,
                 :id => 'tests-with-different-bc-versions',
                 :projectsDirectory => 'integration',
                 :pomIncludes => [ '*/pom.xml' ],
                 :streamLogs => true,
                 # pass those properties on to the test project
                 :properties => {
                   'jruby.versions' => '${jruby.versions}',
                   'jruby.modes' => '${jruby.modes}',
                   'jruby.openssl.version' => '${project.version}',
                   'bc.versions' => '${bc.versions}',
                   'runit.dir' => '${runit.dir}' } )
end

profile :id => 'test-1.6.8' do
  jruby_plugin(:runit) { execute_goal( :test, :runitDirectory => '${runit.dir}' ) }
  properties 'jruby.versions' => '1.6.8', 'jruby.modes' => '1.8,1.9',
             'bc.versions' => supported_bc_versions.join(',')
end

profile :id => 'test-1.7.4' do
  jruby_plugin(:runit) { execute_goal( :test, :runitDirectory => '${runit.dir}' ) }
  properties 'jruby.versions' => '1.7.4', 'jruby.modes' => '1.8,1.9,2.0',
             'bc.versions' => supported_bc_versions.join(',')
end

profile :id => 'test-1.7.13' do
  jruby_plugin(:runit) { execute_goal( :test, :runitDirectory => '${runit.dir}' ) }
  properties 'jruby.versions' => '1.7.13', 'jruby.modes' => '1.8,1.9,2.0',
             'bc.versions' => supported_bc_versions.join(',')
end

profile :id => 'test-9000' do
  jruby_plugin(:runit) { execute_goal( :test, :runitDirectory => '${runit.dir}' ) }
  properties 'jruby.version' => '9000.dev-SNAPSHOT',
             'jruby.versions' => '9000.dev-SNAPSHOT',
             # 'jruby.modes' => '2.1',
             'bc.versions' => supported_bc_versions.join(',')
end

# vim: syntax=Ruby
