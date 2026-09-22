# JRuby-OpenSSL

[JRuby-OpenSSL](https://github.com/jruby/jruby-openssl) is an extension gem for
[JRuby](https://www.jruby.org/) that emulates the Ruby `OpenSSL` native library.

Under the hood it uses the [Bouncy Castle Crypto APIs](https://www.bouncycastle.org/java.html).

All jruby-openssl gem releases include the Bouncy Castle library (BC Provider, BC JSSE 
and PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL jars), usually the latest available version.

Please report bugs and incompatibilities (preferably with test-cases) to either
the JRuby [mailing list][1] or the [bug tracker][2].

## Compatibility

Java compatibility is expected to be the same as with supported JRuby versions.

Check latest jruby-openssl gem spec's `jar` *requirements* for (BC) compatibility.

```ruby
require 'openssl'
JOpenSSL::VERSION
```

For older versions of the gem compatibility wasn't reported:

| JRuby-OpenSSL | JRuby compat | JVM compat | supported BC |
|---------------|:------------:|-----------:|-------------:|
| ~>0.12.x      | 9.1.x-9.3.x  |  Java 8-15 |    1.65-1.68 |
| ~>0.13.x      | 9.1.x-9.4.x  |  Java 8-17 |    1.68-1.69 |
| ~>0.14.x      | 9.1.x-9.4.x  |  Java 8-21 |    1.71-1.74 |
| ~>0.15.x      | 9.2.x-10.0.x |  Java 8-25 |    1.78-1.83 |
| ~>0.16.x      | 9.3.x-10.1.x |  Java 8-25 |    1.83-1.86 |

## Security

JRuby-OpenSSL is an essential part of [JRuby](https://www.jruby.org/), please report security vulnerabilities to
`security@jruby.org` as detailed on JRuby's [security page](https://www.jruby.org/security) or using [GitHub][0].

Please note that most OpenSSL vulnerabilities do not affect JRuby since it's not using
any of OpenSSL's C code, only Ruby parts (*.rb) are the same as in MRI's OpenSSL library.

## Supported configuration

Most runtime knobs are Java system properties. 
Under JRuby you pass them as `-J-D...` flags, e.g. `JRUBY_OPTS='-J-Djruby.openssl.debug=true'`.

### Runtime / JVM properties

| Property | Default | Effect                                                                                                                                                               |
|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jruby.openssl.load.jars` | `true` | If set to `false`, `lib/jopenssl/load.rb` skips auto-loading the bundled BouncyCastle jars - handy when the BC jars are on the JVM classpath.                        |
| `jruby.openssl.debug` | `false` | Turns on internal debug logging and stack traces from the Java extension, has the same effect as setting `OpenSSL.debug = true` at runtime.                          |
| `jruby.openssl.warn` | follows JRuby's warning mode (`runtime.warningsEnabled()`) | Enables or disables warnings from the extension, set `false` to stay quiet regardless of `-w`.                                               |
| `jruby.openssl.log.logger` | default stdout/stderr logger | Selects the internal logger implementation, set to `JUL` to route logs through `java.util.logging`.                                                                  |
| `jruby.openssl.log.silence` | `true` | Silences a few noisy BC / BC-JSSE loggers by default, set `false` to leave their levels untouched.                                                                   |
| `jruby.openssl.provider.ssl` | `BCJSSE` | Selects the SSL provider. `BCJSSE`, `BC`, or `true` all mean BC-JSSE, an empty string or `false` falls back to the platform JSSE provider.                           |
| `jruby.openssl.ssl.error_wait_nonblock.backtrace` | falls back to `jruby.errno.backtrace` (which defaults to `false`) | Whether `SSLErrorWaitReadable` / `SSLErrorWaitWritable` carry backtraces.                                |
| `jruby.openssl.x509.lookup.cache` | disabled | Caching for X.509 lookup results. `true` turns on a soft cache; an integer such as `8` gives a bounded strong/soft cache of that size, unset or `false` disables it. |

### Environment variables

| Variable | Default | Effect                                                                                                                                                                       |
|----------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SSL_CERT_FILE` | platform / packaged default CA file | Overrides the default certificate bundle used for X.509 default-path loading, `.crt`, `.cer`, or `.pem` are read as a PEM bundle, otherwise treated as a Java CA store path. |
| `SSL_CERT_DIR` | platform / packaged default CA directory | Overrides the default certificate directory list for X.509 default-path loading, separate multiple directories with the platform path separator.                         |
| `OPENSSL_ALLOW_PROXY_CERTS` | unset / disabled | When set to anything other than `false`, proxy certificates are allowed during certificate chain validation.                                                                 |

### Other supported customizations

- `OpenSSL.debug = true` gives you the same internal debug logging as `-Djruby.openssl.debug=true`
- when `jruby.openssl.warn` is unset, JRuby's own warning mode (`ruby -w`) decides whether warnings show
- `OpenSSL::Config` can look up variables from the process environment through the `ENV` section, matching the upstream Ruby OpenSSL config parser


## Differences from OpenSSL

JRuby-OpenSSL aims to be a source-compatible drop-in for MRI's `openssl` - same Ruby API and
same `require 'openssl'`. But there are limitations on the JVM (with JCE and JSSE) as well as 
Bouncy Castle libraries, so some entry points are unavailable, behave differently, or are no-ops.

**Engine**
- `OpenSSL::Engine` is not implemented - there is no hardware/engine layer, `OpenSSL::Engine.*`
  raises `NameError` (uninitialized constant)

**SSL / TLS** (backed by JSSE)
- `SSLSocket#state` and NPN (`#npn_protocol`) are unimplemented and return `nil` - use ALPN instead
- Forced session resumption (`SSLSocket#session=`) is best-effort and only fully works with the
  BouncyCastle JSSE provider; `session_reused?` may return `nil` ("can't decide")
- `SSL::Session#id=` / `#time=` are no-ops; `SSL::Session.new` on a non-socket raises `NotImplementedError`
- Hostname / `subjectAltName` matching runs over Java's certificate parsing and can differ from
  MRI's `GeneralName` handling in edge cases

**Cipher** (JCE / Bouncy Castle)
- The available cipher set is provider-dependent (what JCE/BC offer on your JVM), not the fixed
  libcrypto list (some OpenSSL ciphers may be missing or vary by JDK)
- CFB1 mode (`*-cfb1`) is excluded (doesn't match OpenSSL under BC)
- AEAD is limited to what JCE exposes; `iv_len=` on a non-AEAD cipher raises

**PKey** (EC / DH / EdDSA)
- EC is limited to prime curves (`:GFp`); binary-field curves (`:GF2m`) fail
- `EC::Point#mul` with array arguments, `:hybrid` point compression, and encrypted EC private-key
  export are not implemented
- `DH#set_pqg` accepts but silently ignores the `q` parameter
- EdDSA (`Ed25519` / `Ed448`) rejects digest arguments

**X509**
- multi-valued RDNs (the `+` separator in a DN string) are not supported and raise `X509::NameError`.
- few `authorityKeyIdentifier` extension configurations are unsupported

**Random**
- randomness comes from the JVM's `SecureRandom`; the EGD and seed-file APIs (`Random.egd`,
  `egd_bytes`, `load_random_file`, `write_random_file`) are no-ops

**Other**
- `OpenSSL.fips_mode = true` raises `NotImplementedError` unless the separate [FIPS variant](#fips)
  gem is installed
- some rarely-used entry points are no-ops (`OpenSSL.check_func`, `deprecated_warning_flag`) and
  `OPENSSL_NO_SOCK` is `nil` rather than a boolean
- a few PKCS7 content types can't be reconstructed purely from ASN.1 (may surface when parsing
  some S/MIME structures)

Hitting something not listed here that MRI's OpenSSL supports? 
Please report it on the [bug tracker][2], ideally with a test case.

## FIPS

A FIPS 140-3 build of jruby-openssl is available as a separate gem.
It's the very same library but uses the NIST-validated BC FIPS module (BC-FJA) instead of 
regular Bouncy Castle, for deployments that need a validated cryptographic module.
Ships separately under GPL 3.0, with commercial licensing available - see the 
[FIPS variant][6] wiki page for details.

NOTE: unlike C OpenSSL, `OpenSSL.fips_mode` cannot be changed at runtime, the flag reports 
which gem variant is activated (`true` under the FIPS gem, `false` otherwise).

## License

(c) 2009-2026 JRuby distributed under EPL 1.0 / GPL 2.0 / LGPL 2.1

[0]: https://github.com/jruby/jruby-openssl/security
[1]: https://github.com/jruby/jruby/wiki/MailingLists
[2]: https://github.com/jruby/jruby-openssl/issues/new
[3]: https://github.com/jruby/jruby-openssl/tree/master/integration
[4]: https://repo1.maven.org/maven2/org/jruby/
[5]: https://www.jruby.org/nightly
[6]: https://github.com/jruby/jruby-openssl/wiki/FIPS
