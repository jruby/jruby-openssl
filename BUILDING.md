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

Tests can also be run individually e.g. `jruby -Ilib:test test/test_bn.rb`

NOTE: make sure to **-Ilib** otherwise you end up using the OpenSSL default gem shipped with JRuby.

The upstream Ruby/OpenSSL suite is pinned as a submodule. Initialize it and run the
OpenSSL-only MRI tests with:

```
git submodule update --init ruby-openssl
jruby -rbundler/setup -S rake test:mri
```

The local ML-DSA mutual TLS acceptance test requires BCJSSE 1.82 or later
with its ML-DSA signature schemes explicitly enabled. This task starts a
separate JRuby process with the existing JSSE properties set before provider
initialization:

```
jruby -rbundler/setup -S rake test:mldsa_tls
```

It performs actual Net::HTTP GET and POST requests for all three parameter
sets without selecting a client SSL method. It checks the server's authenticated
peer certificate and TLS version, and exercises invalid server and client
identities. It also checks ML-DSA server identities with a default server context.
CI runs it on Java 25 with the default BC version and on Java 11
with BCJSSE 1.82; the task does not skip the deployment acceptance test.
The key and X.509 regressions also run with the regular unit suite.

An optional interoperability test checks that native OpenSSL accepts keys and
signatures produced by JRuby for all three ML-DSA parameter sets. It requires
`openssl` 3.5 or later on `PATH` and runs separately from the regular suite:

```
jruby -rbundler/setup -S rake test:mldsa_openssl
```

### Releasing

* fill in [History.md](History.md) change-log entries for release

* update `VERSION` at [lib/jopenssl/version.rb](lib/jopenssl/version.rb),
  make sure [pom.xml](pom.xml) is regenerated e.g. using `rmvn validate`
  and `git commit` the changes

* `./mvnw -Prelease -DupdateReleaseInfo=true -Dmaven.test.skip=true clean package`

* gem push the build gem from pkg/ e.g. `gem push pkg/jruby-openssl-0.9.15.gem`

* tag the release e.g. `git tag v0.9.15`

* update `VERSION` to next SNAPSHOT (e.g. `"0.9.16.dev"`) and commit
  make sure [pom.xml](pom.xml) is regenerated (`./mvnw validate`)

* `git push origin master --tags`
