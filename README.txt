= JRuby-OpenSSL

* https://github.com/jruby/jruby-openssl

== DESCRIPTION:

JRuby-OpenSSL is an add-on gem for JRuby that emulates the Ruby OpenSSL native library.

Please report bugs and incompatibilities (preferably with testcases) to either the JRuby 
mailing list [1] or the JRuby bug tracker [2].

[1]: http://xircles.codehaus.org/projects/jruby/lists
[2]: https://github.com/jruby/jruby/issues

== Testing

      mvn -P test # currently broken

will run junit tests and a (very) few ruby tests with a set of jruby versions. pick a single jruby version and/or jruby modes (1.8, 1.9, 2.0, 2.1) with

      mvn -P test -Djruby.versions=1.7.12 -Djruby.modes=1.8

for running integration-tests where the gem will be first installed and then the same tests as above run for each possible bouncy-castle version (see directory listing <https://github.com/jruby/jruby-openssl/tree/master/integration>. run all with

      mvn verify

or pick a bouncy-castle version

      mvn verify -Dbc.versions=1.50

or be more picky

      mvn verify -Dbc.versions=1.49 -Djruby.versions=1.7.13 -Djruby.modes=1.9

NOTE: you can pick any jruby version which is on maven central or on ci.jruby.org/snapshots/maven
