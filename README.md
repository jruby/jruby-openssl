# JRuby-OpenSSL

[JRuby-OpenSSL](https://github.com/jruby/jruby-openssl) is an add-on gem for
[JRuby](http://jruby.org) that emulates the Ruby OpenSSL native library.

Under the hood uses the [Bouncy Castle Crypto APIs](http://www.bouncycastle.org/).

Please report bugs and incompatibilities (preferably with test-cases) to either
the JRuby [mailing list][1] or the [bug tracker][2].

## Compatibility

Since version **0.9.5** jruby-openssl aims to be compatible with all JRuby versions
**>= 1.6.8** (including 1.7 and 9k), if it's not we consider that a bug, report.

We (currently - for 0.9.x) require the Bouncy Castle Java API to be **>= 1.47**.

## Testing

[![Build Status][0]](http://travis-ci.org/jruby/jruby-openssl)

    mvn -P test # currently broken

will run junit tests and a (very) few ruby tests with a set of jruby versions.
pick a single jruby version and/or jruby modes (1.8, 1.9, 2.0, 2.1) with

    mvn -P test -Djruby.versions=1.7.12 -Djruby.modes=1.8

for running integration-tests the gem will be first installed and then the same
tests as above run for each possible bouncy-castle version (see [listing][3]).

run all with

    mvn verify

or pick a bouncy-castle version

    mvn verify -Dbc.versions=1.50

or be more picky

    mvn verify -Dbc.versions=1.49 -Djruby.versions=1.7.13 -Djruby.modes=1.9

NOTE: you can pick any jruby version which is on [central][4] or on [ci.jruby][5]

[0]: https://secure.travis-ci.org/jruby/jruby-openssl.png
[1]: http://xircles.codehaus.org/projects/jruby/lists
[2]: https://github.com/jruby/jruby/issues
[3]: https://github.com/jruby/jruby-openssl/tree/master/integration
[4]: http://central.maven.org/maven2/org/jruby/
[5]: http://ci.jruby.org/snapshots/maven/org.jruby/