## JRuby-OpenSSL

The project is using [Maven](http://maven.apache.org/download.cgi) for build.

Maven enhanced with JRuby using [Polyglot](https://github.com/takari/polyglot-maven),
allows the build to be written using a Ruby DSL - check [*Mavenfile*](Mavenfile).

If you're coming from a Ruby world and do not have Maven setup, you can alternatively
`jruby -S gem install ruby-maven` and use the `rmvn` executable (instead of `mvn`).

### Building

The usual `./mvnw package -Dmaven.test.skip=true` builds a .gem that includes the JRuby extension .jar

There's a rake target as well that shells out: `jruby -S rake jar`

### Testing

NOTE: the ext .jar needs to be build (see the Building section above on `rake jar`)

The full unit test suite can be boostraped using Rake: `jruby -S rake test`

Tests can also be run individually e.g. `jruby -Ilib:src/test/ruby src/test/ruby/test_bn.rb`

NOTE: make sure to **-Ilib** otherwise you end up using the OpenSSL default gem shipped with JRuby.

### Releasing

* fill in [History.md](History.md) change-log entries for release

* update `VERSION` at [lib/jopenssl/version.rb](lib/jopenssl/version.rb),
  make sure [pom.xml](pom.xml) is regenerated e.g. using `rmvn validate`
  and `git commit` the changes

* `mvn -Prelease -DupdateReleaseInfo=true clean package`

* gem push the build gem from pkg/ e.g. `gem push pkg/jruby-openssl-0.9.15.gem`

* tag the release e.g. `git tag v0.9.15`

* update `VERSION` to next SNAPSHOT (e.g. `"0.9.16.dev"`) and commit
  make sure [pom.xml](pom.xml) is regenerated (`./mvnw validate`)

* `git push origin master --tags`
