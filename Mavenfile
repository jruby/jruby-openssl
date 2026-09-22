#-*- mode: ruby -*-

load File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))

gemspec jar: 'jopenssl'
# gemspec defaults to 'rubygems' groupId
# `id` resets the version, so pass full GAV (gem 0.20.0.dev -> Maven -SNAPSHOT)
maven_version = JOpenSSL::VERSION
maven_version += "-SNAPSHOT" if JOpenSSL::VERSION.match?(/[a-zA-Z]/)
id "org.jruby.openssl:jruby-openssl:#{maven_version}"

distribution_management do
  snapshot_repository id: :ossrh, url: 'https://oss.sonatype.org/content/repositories/snapshots'
  repository id: :ossrh, url: 'https://oss.sonatype.org/service/local/staging/deploy/maven2/'
end

java_target = '1.8'
gen_sources = '${basedir}/target/generated-sources' # hard-coded in AnnotationBinder

plugin 'org.codehaus.mojo:exec-maven-plugin', '3.5.0' do
  execute_goal :exec, id: 'invoker-generator', phase: 'process-classes',
      executable: 'java', classpathScope: 'compile',
      arguments: [ "-Djruby.bytecode.version=#{java_target}",
                      '-classpath', xml( '<classpath/>' ),
                      'org.jruby.anno.InvokerGenerator',
                      "#{gen_sources}/annotated_classes.txt",
                      '${project.build.outputDirectory}' ]

  # inlines the shim call sites straight into the compiled classes
  execute_goal :exec, id: 'shim-inliner', phase: 'process-classes',
      executable: 'java', classpathScope: 'compile',
      skip: '${shim.inline.skip}', # -Dshim.inline.skip=true to bypass
      arguments: [ '-classpath', xml( '<classpath/>' ),
                      '${basedir}/src/build/java/ShimInliner.java',
                      '${project.build.outputDirectory}' ]
end

plugin 'org.codehaus.mojo:build-helper-maven-plugin', '3.6.1' do
  execute_goal 'add-source', phase: 'process-classes', sources: [ gen_sources ]
end

# building needs JDK 11+ (module-info + the ShimInliner source launcher)
plugin :enforcer, '3.5.0' do
  execute_goal 'enforce', id: 'enforce-java-version',
               rules: { requireJavaVersion: { version: '[11,)' } }
end

compiler_configuration = {
    source: '1.8', target: java_target, release: '8',
    encoding: 'UTF-8', debug: true,
    showWarnings: true, showDeprecation: true,
    excludes: [ 'module-info.java' ],
    #jdkToolchain: { version: '[1.7,11)' },
    generatedSourcesDirectory: gen_sources,
    annotationProcessors: [ 'org.jruby.anno.AnnotationBinder' ]
}

plugin :compiler, '3.15.0', compiler_configuration do
  execute_goal :compile,
               id: 'compile-populators', phase: 'process-classes',
               includes: [ 'org/jruby/gen/**/*.java' ],
               optimize: true,
               compilerArgs: [ '', '-XDignore.symbol.file=true' ]
end

plugin! :jar, '3.4.1',
        'outputDirectory' => 'lib', 'finalName' => 'jopenssl',
        'excludes' => [ 'annotated_classes.txt' ],
        'archive' => { 'manifestEntries' => { 'JOpenSSL-Variant' => 'main' } }

plugin! :clean, '2.4',
        'filesets' => [
          { directory: 'lib', includes: [ 'jopenssl.jar' ] },
          { directory: 'vendor' },
          { directory: 'target', includes: [ '*' ] }
        ],
        'failOnError' => 'false'

jruby_compile_compat = '9.2.1.0'
jar 'org.jruby:jruby-core', jruby_compile_compat, scope: :provided
jar 'org.ow2.asm:asm-analysis', '9.8', scope: :provided # build-time only (for ShimInliner)
# for invoker generated classes we need to add javax.annotation when on Java > 8
jar 'javax.annotation:javax.annotation-api', '1.3.1', scope: :compile
jar 'org.junit.jupiter:junit-jupiter', '5.11.4', scope: :test
# a test dependency to provide digest and other stdlib bits, needed when loading OpenSSL in Java unit tests
jar 'org.jruby:jruby-stdlib', jruby_compile_compat, scope: :test

plugin :surefire, '3.5.5'

MVN_JRUBY_VERSION = '9.4.14.0'

jruby_plugin! :gem do
  # when installing dependent gems we want to use the built in openssl not the one from this lib directory
  execute_goal id: 'default-package', addProjectClasspath: false, libDirectory: 'something-which-does-not-exists'
  execute_goals id: 'default-push', skip: true
end

# we want to have the snapshots on oss.sonatype.org and the released gems on maven central
plugin :deploy, '3.1.4' do
  # gem.deploy.skip is flipped on by the jar-release profile (jar-only deploy)
  execute_goals( :deploy, skip: '${gem.deploy.skip}' )
end

supported_bc_versions = %w{ 1.80 1.81 1.82 1.83 1.84 1.85 1.86 }

default_bc_version = File.read File.expand_path('lib/jopenssl/version.rb', File.dirname(__FILE__))
default_bc_version = default_bc_version[/BOUNCY_CASTLE_VERSION\s?=\s?'(.*?)'/, 1]

# reproducible builds: Rakefile passes -Dproject.build.outputTimestamp=$SOURCE_DATE_EPOCH
properties( 'shim.inline.skip' => 'false',
            'gem.deploy.skip' => 'false', # jar-release profile sets this true
            'jruby.plugins.version' => '3.0.6',
            'jruby.switches' => '-W0', # https://github.com/torquebox/jruby-maven-plugins/issues/94
            'bc.versions' => default_bc_version,
            'invoker.test' => '${bc.versions}',
            # allow to skip all tests with -Dmaven.test.skip
            'invoker.skip' => '${maven.test.skip}',
            'skipRunit' => 'true',
            'runit.dir' => 'test/**/test_*.rb',
            'mavengem.wagon.version' => '2.0.2', # for jruby plugin
            'mavengem-wagon.version' => '3.0.0', # for polyglot-ruby
            # use this version of jruby for the jruby-maven-plugins
            'jruby.versions' => MVN_JRUBY_VERSION, 'jruby.version' => MVN_JRUBY_VERSION,
            # dump pom.xml when running 'rmvn'
            'polyglot.dump.pom' => 'pom.xml', 'polyglot.dump.readonly' => false )

plugin! :dependency do
  execute_goal 'copy-dependencies',
               phase: 'generate-test-resources',
               outputDirectory: '${basedir}/vendor',
               useRepositoryLayout: true,
               includeGroupIds: 'org.bouncycastle'
end

invoker_run_options = {
    id: 'tests-with-different-bc-versions',
    projectsDirectory: 'src/it',
    pomIncludes: [ '*/pom.xml' ],
    streamLogs: true,
    # pass those properties on to the test project
    properties: {
      'jruby.versions' => '${jruby.versions}',
      'jruby.openssl.version' => '${project.version}',
      'bc.versions' => '${bc.versions}',
      'runit.dir' => '${runit.dir}' }
}

jruby_versions = []
jruby_versions += %w{ 9.2.19.0 9.2.20.1 }
jruby_versions += %w{ 9.3.3.0 9.3.13.0 }
jruby_versions += %w{ 9.4.8.0 9.4.14.0 9.4.15.0 9.4.16.0 }
jruby_versions += %w{ 10.0.1.0 10.0.3.0 10.0.5.0 10.0.6.0 10.0.7.0 10.1.1.0 10.1.2.0 }

jruby_versions.each do |version|
  profile id: "test-#{version}" do
    plugin :invoker, '3.8.1' do
      execute_goals :install, :run, invoker_run_options
    end
    properties 'jruby.version' => version,
               'jruby.versions' => version,
               'bc.versions' => supported_bc_versions.join(',')
  end
end

profile id: 'release' do
  plugin :gpg, '3.1.0' do
    execute_goal :sign, phase: :verify
  end
end

# packages everything (lib/ included) into a self-contained jruby-openssl.jar
# and deploys it as a plain (non-gem) Maven artifact under org.jruby.openssl
profile id: 'jar-release' do
  jar_release_dir = '${project.build.directory}/jar-release'
  jar_release_src_dir = '${project.build.directory}/jar-release-sources'
  jar_release_modpath = '${project.build.directory}/jar-release-modpath'
  jar_release_file = '${project.build.directory}/${project.build.finalName}.jar'
  jar_release_sources = '${project.build.directory}/${project.build.finalName}-sources.jar'

  # ship only what is committed, the same way the gemspec picks its (lib) files
  jar_release_rb = `git ls-files lib`.split("\n").select { |f| f.end_with?('.rb') }
  raise 'no lib/**/*.rb tracked by git - cannot assemble the jar-release' if jar_release_rb.empty?
  jar_release_rb = jar_release_rb.map { |f| f.sub(%r{\Alib/}, '') } # relative to lib directory

  # same rule for the sources jar - explicit list of committed .java files
  jar_release_src = `git ls-files src/main/java`.split("\n").select { |f| f.end_with?('.java') }
  raise 'no src/main/java/**/*.java tracked by git - cannot assemble the jar-release' if jar_release_src.empty?
  jar_release_src = jar_release_src.map { |f| f.sub(%r{\Asrc/main/java/}, '') } # relative to directory

  properties 'gem.deploy.skip' => 'true', # publish only the jar, not the gem
             'jar-release.repositoryId' => 'ossrh',
             # release staging by default; override with the snapshots url for SNAPSHOT versions
             'jar-release.url' => 'https://oss.sonatype.org/service/local/staging/deploy/maven2/'

  plugin :resources, '3.3.1' do
    execute_goal 'copy-resources', id: 'jar-release-classes', phase: 'prepare-package',
        outputDirectory: jar_release_dir,
        resources: [ { directory: '${project.build.outputDirectory}' } ]
    execute_goal 'copy-resources', id: 'jar-release-lib', phase: 'prepare-package',
        outputDirectory: jar_release_dir,
        resources: [ { directory: 'lib', includes: jar_release_rb } ]
    # NOTE: maven-source-plugin refuses to run on a gem-packaged project
    execute_goal 'copy-resources', id: 'jar-release-sources', phase: 'prepare-package',
        outputDirectory: jar_release_src_dir,
        resources: [ { directory: 'src/main/java', includes: jar_release_src } ]
    # the lib/*.rb ships in the sources jar too, same as in the jar-release .jar
    execute_goal 'copy-resources', id: 'jar-release-sources-lib', phase: 'prepare-package',
        outputDirectory: jar_release_src_dir,
        resources: [ { directory: 'lib', includes: jar_release_rb } ]
    # the module descriptor source ships in the sources jar as well
    execute_goal 'copy-resources', id: 'jar-release-sources-module', phase: 'prepare-package',
        outputDirectory: jar_release_src_dir,
        resources: [ { directory: 'src/main/module', includes: [ 'module-info.java' ] } ]
  end

  # a module path for compiling module-info;
  # the full classpath cannot be used as-is (jnr-* jars split jnr.enxio.channels)
  # main sources compile against the 9.2 compat jruby-core (module 'org.jruby'),
  # but the descriptor requires 'org.jruby.dist' - runtime name since 9.4.13
  plugin! :dependency do
    execute_goal 'copy-dependencies', id: 'jar-release-modpath-bc', phase: 'generate-resources',
        outputDirectory: jar_release_modpath,
        includeGroupIds: 'org.bouncycastle'
    execute_goal 'copy', id: 'jar-release-modpath-jruby', phase: 'generate-resources',
        outputDirectory: jar_release_modpath,
        artifactItems: [ { groupId: 'org.jruby', artifactId: 'jruby-core', version: MVN_JRUBY_VERSION } ]
  end

  # module-info targets Java 9 bytecode, so compiled separately from the Java 8
  # main sources; patched onto the already compiled classes dir
  plugin 'org.codehaus.mojo:exec-maven-plugin' do
    execute_goal :exec, id: 'jar-release-module-info', phase: 'process-classes',
        executable: 'javac',
        arguments: [ '--release', '9',
                     '--module-path', jar_release_modpath,
                     '--patch-module', 'org.jruby.ext.openssl=${project.build.outputDirectory}',
                     '-d', jar_release_dir,
                     '${basedir}/src/main/module/module-info.java' ]
  end

  plugin :jar, '3.4.1' do
    execute_goal :jar, id: 'jar-release', phase: 'package',
        classesDirectory: jar_release_dir,
        outputDirectory: '${project.build.directory}',
        finalName: '${project.build.finalName}'

    execute_goal :jar, id: 'jar-release-sources', phase: 'package',
        classesDirectory: jar_release_src_dir,
        outputDirectory: '${project.build.directory}',
        finalName: '${project.build.finalName}',
        classifier: 'sources'
  end

  plugin :deploy, '3.1.4' do
    execute_goal 'deploy-file', id: 'jar-release-deploy', phase: 'deploy',
        file: jar_release_file,
        sources: jar_release_sources,
        groupId: '${project.groupId}',
        artifactId: '${project.artifactId}',
        version: '${project.version}',
        packaging: 'jar',
        repositoryId: '${jar-release.repositoryId}',
        url: '${jar-release.url}'
  end
end
