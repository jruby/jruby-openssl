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
        :excludes => [ 'module-info.java' ],
        #:jdkToolchain => { :version => '[1.7,11)' },

        :generatedSourcesDirectory => gen_sources,
        :annotationProcessors => [ 'org.jruby.anno.AnnotationBinder' ]) do

  #execute_goal :compile, :id => 'annotation-binder', :phase => 'compile',
  #    :generatedSourcesDirectory => gen_sources, #:outputDirectory => gen_sources,
  #    :annotationProcessors => [ 'org.jruby.anno.AnnotationBinder' ],
  #    :proc => 'only', # :compilerReuseStrategy => 'alwaysNew',
  #    :useIncrementalCompilation => false, :fork => true, :verbose => true,
  #    :compilerArgs => [ '-XDignore.symbol.file=true', '-J-Dfile.encoding=UTF-8' ]

  execute_goal :compile,
               :id => 'compile-populators', :phase => 'process-classes',
               :includes => [ 'org/jruby/gen/**/*.java' ],
               :optimize => true,
               :compilerArgs => [ '', '-XDignore.symbol.file=true' ]
end

profile 'module-info' do
  activation { jdk '[9,)' }
  plugin :compiler, '3.8.1',
         :source => '9', :target => java_target,
         :release => '9',
         :includes => [ 'module-info.java' ]
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
jar 'junit:junit', '[4.13.1,)', :scope => :test

# 9.1.17.0 is Java 7 compatible (till supporting JRuby 1.7)
# NOTE: to build on Java 11 - installing gems fails (due old jossl) with:
#  load error: jopenssl/load -- java.lang.StringIndexOutOfBoundsException
MVN_JRUBY_VERSION = ENV_JAVA['java.version'].to_i >= 9 ? '9.2.9.0' : '9.1.17.0'

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

supported_bc_versions = %w{ 1.58 1.59 1.60 1.61 1.62 1.63 1.64 1.65 }

default_bc_version = File.read File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
default_bc_version = default_bc_version[/BOUNCY_CASTLE_VERSION\s?=\s?'(.*?)'/, 1]

properties( 'jruby.plugins.version' => '1.1.8',
            'jruby.switches' => '-W0', # https://github.com/torquebox/jruby-maven-plugins/issues/94
            'bc.versions' => default_bc_version,
            'invoker.test' => '${bc.versions}',
            # allow to skip all tests with -Dmaven.test.skip
            'invoker.skip' => '${maven.test.skip}',
            'runit.dir' => 'src/test/ruby/**/test_*.rb',
            'mavengem.wagon.version' => '1.0.3', # for jruby plugin
            'mavengem-wagon.version' => '1.0.3', # for polyglot-ruby
            # use this version of jruby for the jruby-maven-plugins
            'jruby.versions' => MVN_JRUBY_VERSION, 'jruby.version' => MVN_JRUBY_VERSION,
            # dump pom.xml when running 'rmvn'
            'polyglot.dump.pom' => 'pom.xml', 'polyglot.dump.readonly' => false )

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

jruby_9_K_versions  = %w{ 9.0.5.0 9.1.2.0 9.1.8.0 9.1.12.0 9.1.16.0 9.1.17.0 }
jruby_9_K_versions += %w{ 9.2.0.0 9.2.5.0 9.2.6.0 9.2.7.0 9.2.8.0 9.2.9.0 }

jruby_9_K_versions.each { |version|
profile :id => "test-#{version}" do
  plugin :invoker, '1.8' do
    execute_goals( :install, :run, invoker_run_options )
  end
  properties 'jruby.version' => version,
             'jruby.versions' => version,
             'bc.versions' => supported_bc_versions.join(',')
end
}

profile :id => 'release' do
  plugin :gpg, '1.6' do
    execute_goal :sign, :phase => :verify
  end
end

# vim: syntax=Ruby
