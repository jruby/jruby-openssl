#-*- mode: ruby -*-

gemspec :jar => 'jopenssl', :include_jars => true

distribution_management do
  snapshot_repository :id => :ossrh, :url => 'https://oss.sonatype.org/content/repositories/snapshots'
  repository :id => :ossrh, :url => 'https://oss.sonatype.org/service/local/staging/deploy/maven2/'
end

java_target = '1.7'
gen_sources = '${basedir}/target/generated-sources' # hard-coded in AnnotationBinder

plugin( 'org.codehaus.mojo:exec-maven-plugin', '1.3.2' ) do

=begin
  invoker_main  = '-Djruby.bytecode.version=${compiler.target}'
  #invoker_main << ' -classpath '
  invoker_main << ' org.jruby.anno.InvokerGenerator'
  invoker_main << " #{gen_sources}/annotated_classes.txt ${project.build.outputDirectory}"

  dependency 'org.jruby', 'jruby-core', '${jruby.version}'

  execute_goal :java, :id => 'invoker-generator', :phase => 'process-classes',
      :mainClass => 'org.jruby.anno.InvokerGenerator', :classpathScope => 'compile',
      #:arguments => [ '${gen.sources}/annotated_classes.txt', '${project.build.outputDirectory}' ] do
      :commandlineArgs => "#{gen_sources}/annotated_classes.txt ${project.build.outputDirectory}",
      :classpathScope => 'runtime', :additionalClasspathElements => [ '${project.build.outputDirectory}' ],
      :includeProjectDependencies => false, :includePluginDependencies => true do

    #systemProperties do
    #  property '-Djruby.bytecode.version=${compiler.target}'
    #end
=end

  execute_goal :exec, :id => 'invoker-generator', :phase => 'process-classes',
      :executable => 'java', :classpathScope => 'compile',
      :arguments => [ "-Djruby.bytecode.version=#{java_target}",
                      '-classpath', xml( '<classpath/>' ),
                      'org.jruby.anno.InvokerGenerator',
                      "#{gen_sources}/annotated_classes.txt",
                      '${project.build.outputDirectory}' ]
end

plugin( 'org.codehaus.mojo:build-helper-maven-plugin', '1.9' ) do
  execute_goal 'add-source', :phase => 'process-classes', :sources => [ gen_sources ]
end

plugin( :compiler, '3.1',
        :source => '1.7', :target => java_target,
        :encoding => 'UTF-8', :debug => true,
        :showWarnings => true, :showDeprecation => true,

        :generatedSourcesDirectory => gen_sources,
        :annotationProcessors => [ 'org.jruby.anno.AnnotationBinder' ],
        :compilerArgs => [ '-XDignore.symbol.file=true' ] ) do

  #execute_goal :compile, :id => 'annotation-binder', :phase => 'compile',
  #    :generatedSourcesDirectory => gen_sources, #:outputDirectory => gen_sources,
  #    :annotationProcessors => [ 'org.jruby.anno.AnnotationBinder' ],
  #    :proc => 'only', # :compilerReuseStrategy => 'alwaysNew',
  #    :useIncrementalCompilation => false, :fork => true, :verbose => true,
  #    :compilerArgs => [ '-XDignore.symbol.file=true', '-J-Dfile.encoding=UTF-8' ]

  execute_goal :compile, :id => 'compile-populators', :phase => 'process-classes',
      :includes => [ 'org/jruby/gen/**/*.java' ], :optimize => true,
      :compilerArgs => [ '-XDignore.symbol.file=true' ]
      # NOTE: maybe '-J-Xbootclasspath/p:${unsafe.jar}' ... as well ?!
end

plugin :clean do
  execute_goals( 'clean', :id => 'default-clean', :phase => 'clean',
                 'filesets' => [
                    { :directory => 'lib', :includes => [ 'jopenssl.jar' ] },
                    { :directory => 'lib/org' },
                    { :directory => 'target', :includes => [ '*' ] }
                 ],
                 'failOnError' =>  'false' )
end

jar 'org.jruby:jruby-core', '1.7.20', :scope => :provided
jar 'junit:junit', '4.11', :scope => :test

jruby_plugin! :gem do
  # when installing dependent gems we want to use the built in openssl not the one from this lib directory
  # we compile against jruby-core-1.7.20 and want to keep this out of the plugin execution here
  execute_goal :id => 'default-initialize', :addProjectClasspath => false, :libDirectory => 'something-which-does-not-exists'
  execute_goals :id => 'default-push', :skip => true
end

# we want to have the snapshots on oss.sonatype.org and the released gems on maven central
plugin :deploy, '2.8.1' do
  execute_goals( :deploy, :skip => false )
end

supported_bc_versions = %w{ 1.55 1.56 1.57 1.58 1.59 }

default_bc_version = File.read File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
default_bc_version = default_bc_version[/BOUNCY_CASTLE_VERSION\s?=\s?'(.*?)'/, 1]

properties( 'jruby.plugins.version' => '1.0.10',
            'jruby.versions' => '1.7.20',
            'bc.versions' => default_bc_version,
            'invoker.test' => '${bc.versions}',
            # allow to skip all tests with -Dmaven.test.skip
            'invoker.skip' => '${maven.test.skip}',
            'runit.dir' => 'src/test/ruby/**/test_*.rb',
            # use this version of jruby for ALL the jruby-maven-plugins
            'jruby.version' => '1.7.20',
            # dump pom.xml as readonly when running 'rmvn'
            'polyglot.dump.pom' => 'pom.xml',
            'polyglot.dump.readonly' => true,
            'tesla.dump.pom' => 'pom.xml',
            'tesla.dump.readonly' => true )

# make sure we have the embedded jars in place before we run runit plugin
plugin! :dependency do
  execute_goal 'copy-dependencies',
               :phase => 'generate-test-resources',
               :outputDirectory => '${basedir}/lib',
               :useRepositoryLayout => true,
               :includeGroupIds => 'org.bouncycastle'
end

jruby_plugin(:runit) { execute_goal( :test, :runitDirectory => '${runit.dir}' ) }

invoker_run_options = {
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
      'runit.dir' => '${runit.dir}' }
}

jruby_1_7_versions = %w{ 1.7.18 1.7.20 1.7.22 1.7.23 1.7.24 1.7.25 1.7.26 1.7.27 }

jruby_1_7_versions.each { |version|
profile :id => "test-#{version}" do
  plugin :invoker, '1.8' do
    execute_goals( :install, :run, invoker_run_options )
  end
  properties 'jruby.versions' => version, 'jruby.modes' => '1.9,2.0',
             'bc.versions' => supported_bc_versions.join(',')
end
}

jruby_9_K_versions = %w{ 9.0.1.0 9.0.5.0 9.1.2.0 9.1.8.0 9.1.12.0 9.1.16.0 9.1.17.0 9.2.0.0 }

jruby_9_K_versions.each { |version|
profile :id => "test-#{version}" do
  plugin :invoker, '1.8' do
    execute_goals( :install, :run, invoker_run_options )
  end
  # NOTE: we're work-around 9K maven-runit version bug (due minitest changes) !
  # ... still can not build with 9K : https://github.com/jruby/jruby/issues/3184
  properties 'jruby.version' => version, 'jruby.versions' => version,
             'bc.versions' => supported_bc_versions.join(',')
end
}

profile :id => 'release' do
  plugin :gpg, '1.5' do
    execute_goal :sign, :phase => :verify
  end
end

# vim: syntax=Ruby
