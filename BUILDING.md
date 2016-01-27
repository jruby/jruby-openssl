## JRuby-OpenSSL

The project is using [Maven](http://maven.apache.org/download.cgi) for build.

Maven enhanced with JRuby using [Polyglot](https://github.com/takari/polyglot-maven),
allows the build to be written using a Ruby DSL - check [*Mavenfile*](Mavenfile).

If you're coming from a Ruby world and do not have Maven setup, you can alternatively
`jruby -S gem install ruby-maven` and use the `rmvn` executable (instead of `mvn`).

### Building

The usual `mvn package` builds a .gem that includes the JRuby extension .jar


### Testing

Tests `mvn test` are run by default with Maven using JRuby plugins.
When the ext .jar is build (`rake jar` or `mvn package -Dmaven.test.skip=true`)
one can run a tests Ruby-style e.g. `jruby -Ilib:. src/test/ruby/test_bn.rb`


### Releasing

* fill in [History.md](History.md) change-log entries for release

* update `VERSION` at [lib/jopenssl/version.rb](lib/jopenssl/version.rb),
  make sure [pom.xml](pom.xml) is regenerated e.g. using `rmvn validate`
  and `git commit` the changes

* (optional) signing artifacts is preferred thus find your GPG key

* `mvn -Prelease -DupdateReleaseInfo=true -Dgpg.keyname=A7A374B9 clean deploy`

* (advised) examine and close the repository to push it to Sonatype's staging

* (advised) run JRuby's full suite using the staged new jruby-openssl gem
  e.g. https://github.com/jruby/jruby/commit/1df6315e9145195f19ad862be5e3a5

* (advised) release the staging repository at Sonatype's if all is well

* (optional) update JRuby to bundle new jruby-openssl gem (remove staging)
  e.g. https://github.com/jruby/jruby/commit/8750e736491825eec1d1954a07d492

* gem push the build gem from pkg/ e.g. `gem push pkg/jruby-openssl-0.9.15.gem`

* tag the release e.g. `git tag v0.9.15`

* update `VERSION` to next SNAPSHOT (e.g. `"0.9.16.dev"`) and commit
  make sure [pom.xml](pom.xml) is regenerated (`rmvn validate`)

* `git push origin master --tags`

* (advised) ... take the rest of the day off!


#### Manually Deploying

When a release went by only pushing to http://rubygems.org/ one can still push
to Sonatype's Maven repos, rename *jruby-openssl-x.x.x-java.gem* (when it is
downloaded from https://rubygems.org/gems/jruby-openssl) to follow Maven's
naming conventions (stripping the *-java* suffix) and "mvn deploy" by hand :

```
mvn deploy:deploy-file -Dfile=jruby-openssl-0.9.15.gem -DpomFile=pom.xml -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/service/local/staging/deploy/maven2/
```