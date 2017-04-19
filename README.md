# JRuby-OpenSSL

[JRuby-OpenSSL](https://github.com/jruby/jruby-openssl) is an add-on gem for
[JRuby](http://jruby.org) that emulates the Ruby OpenSSL native library.

Under the hood uses the [Bouncy Castle Crypto APIs](http://www.bouncycastle.org/).

Each jruby-openssl gem release includes a certain version, usually the latest available, 
of the library (namely BC Provider and PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL jars).

Please report bugs and incompatibilities (preferably with test-cases) to either
the JRuby [mailing list][1] or the [bug tracker][2].

## Compatibility


| JRuby-OpenSSL | JRuby compat  | JVM compat | supported BC |
| ------------- |:-------------:| ----------:| ------------:|
|         0.9.6 |   1.6.8-9.0.2 |   Java 6-8 |    1.47-1.50 |
|        0.9.12 |   1.6.8-9.0.5 |   Java 6-8 |    1.47-1.52 |
|        0.9.13 |   1.6.8-9.1.2 |   Java 6-8 |    1.49-1.52 |
|        0.9.14 |   1.6.8-9.1.5 |   Java 6-8 |    1.49-1.54 |
|        0.9.17 |   1.6.8-9.1.5 |   Java 6-8 |    1.50-1.54 |
|        0.9.18 |   1.6.8-9.1.7 |   Java 6-8 |    1.50-1.55 |

NOTE: backwards JRuby compatibility was not handled for versions <= **0.9.6** 

## Security

JRuby-OpenSSL is an essential part of [JRuby](http://jruby.org), please report security 
vulnerabilities to `security@jruby.org` as detailed on JRuby's [security page](http://jruby.org/security).
 
Please note that most OpenSSL vulnerabilities do not effect JRuby since its not using 
any of OpenSSL's C code, only Ruby parts (*.rb) are the same as in MRI's OpenSSL library. 

## Testing

[![Build Status][0]](http://travis-ci.org/jruby/jruby-openssl)

    rake jar:all # creates pom.xml and generates jopenssl.jar under lib
    mvn test

will run (junit as well as ruby) tests and a some ruby tests against the default
jruby version. to pick a different version and/or modes (1.8, 1.9, 2.0, 2.1) run

    mvn test -Djruby.versions=1.7.12 -Djruby.modes=1.8

for running integration-tests the gem will be first installed and then the same
tests run for each possible bouncy-castle version (see [listing][3]), run with

    mvn verify -P test-9.0.4.0,test-1.7.22

or pick a bouncy-castle version

    mvn verify -P test-1.6.8 -Dbc.versions=1.50

or simply be more picky

    mvn verify -P test-1.7.4 -Dbc.versions=1.49 -Djruby.modes=1.9

NOTE: you can pick any jruby version which is on [central][4] or on [ci.jruby][5]

## License

(c) 2009-2017 JRuby distributed under EPL 1.0/GPL 2.0/LGPL 2.1

[0]: https://secure.travis-ci.org/jruby/jruby-openssl.svg
[1]: http://xircles.codehaus.org/projects/jruby/lists
[2]: https://github.com/jruby/jruby/issues
[3]: https://github.com/jruby/jruby-openssl/tree/master/integration
[4]: http://central.maven.org/maven2/org/jruby/
[5]: http://ci.jruby.org/snapshots/maven/org.jruby/
