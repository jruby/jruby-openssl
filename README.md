# JRuby-OpenSSL

[JRuby-OpenSSL](https://github.com/jruby/jruby-openssl) is an add-on gem for
[JRuby](https://www.jruby.org/) that emulates the Ruby OpenSSL native library.

Under the hood it uses the [Bouncy Castle Crypto APIs](https://www.bouncycastle.org/java.html).

Each jruby-openssl gem release includes the Bouncy Castle library (BC Provider and
PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL jars), usually the latest available version.

Please report bugs and incompatibilities (preferably with test-cases) to either
the JRuby [mailing list][1] or the [bug tracker][2].

## Compatibility

| JRuby-OpenSSL | JRuby compat | JVM compat | supported BC |
|---------------|:------------:|-----------:|-------------:|
| 0.9.6         | 1.6.8-9.0.2  |   Java 6-8 |    1.47-1.50 |
| 0.9.12        | 1.6.8-9.0.5  |   Java 6-8 |    1.47-1.52 |
| 0.9.13        | 1.6.8-9.1.2  |   Java 6-8 |    1.49-1.52 |
| 0.9.14        | 1.6.8-9.1.5  |   Java 6-8 |    1.49-1.54 |
| 0.9.17        | 1.6.8-9.1.5  |   Java 6-8 |    1.50-1.54 |
| ~>0.9.18      | 1.6.8-9.1.x  |   Java 6-8 |    1.50-1.55 |
| 0.10.0        | 1.7.20-9.2.x |  Java 7-10 |    1.55-1.59 |
| 0.10.3        | 1.7.20-9.2.x |  Java 7-11 |    1.56-1.62 |
| ~>0.10.5      | 1.7.20-9.3.x |  Java 7-11 |    1.60-1.68 |
| ~>0.11.x      | 9.0.x-9.3.x  |  Java 7-11 |    1.62-1.68 |
| ~>0.12.x      | 9.1.x-9.3.x  |  Java 8-15 |    1.65-1.68 |
| ~>0.13.x      | 9.1.x-9.4.x  |  Java 8-17 |    1.68-1.69 |
| ~>0.14.x      | 9.1.x-9.4.x  |  Java 8-21 |    1.71-1.74 |
| ~>0.15.x      | 9.2.x-10.0.x |  Java 8-25 |    1.78-1.83 |
| ~>0.16.x      | 9.3.x-10.0.x |  Java 8-25 |    1.83-1.84 |

## Security

JRuby-OpenSSL is an essential part of [JRuby](https://www.jruby.org/), please report security vulnerabilities to
`security@jruby.org` as detailed on JRuby's [security page](https://www.jruby.org/security) or using [GitHub][0].

Please note that most OpenSSL vulnerabilities do not affect JRuby since it's not using
any of OpenSSL's C code, only Ruby parts (*.rb) are the same as in MRI's OpenSSL library.

## Testing

    rake jar:all # creates pom.xml and generates jopenssl.jar under lib
    mvn test

This will run (JUnit as well as Ruby) tests against the default JRuby version.
To pick a different JRuby version:

    mvn test -Djruby.versions=9.4.14.0

For running integration tests the gem will be installed first and the same
tests run for each supported Bouncy Castle version (see [listing][3]):

    mvn verify -P test-9.4.14.0,test-9.2.21.0

Or pick a specific Bouncy Castle version:

    mvn verify -P test-9.4.14.0 -Dbc.versions=1.78

NOTE: you can pick any JRuby version which is on [Maven Central][4] or on [ci.jruby][5]

## License

(c) 2009-2026 JRuby distributed under EPL 1.0/GPL 2.0/LGPL 2.1

[0]: https://github.com/jruby/jruby-openssl/security
[1]: https://github.com/jruby/jruby/wiki/MailingLists
[2]: https://github.com/jruby/jruby-openssl/issues/new
[3]: https://github.com/jruby/jruby-openssl/tree/master/integration
[4]: https://repo1.maven.org/maven2/org/jruby/
[5]: https://www.jruby.org/nightly
