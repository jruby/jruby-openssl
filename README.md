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

### ML-DSA

| Feature | Minimum provider version |
|---------|--------------------------|
| ML-DSA keys, signatures, certificates, CSRs and CRLs | BC 1.80 |
| ML-DSA mutual TLS | BCJSSE 1.82 |

Java requirements remain those of the selected JRuby version; Java 25 is not
required. BCJSSE's ML-DSA signature schemes must be explicitly enabled before
provider initialization.

Pure ML-DSA-44, ML-DSA-65, and ML-DSA-87 keys use the existing generic
`OpenSSL::PKey::PKey` API:

```ruby
key = OpenSSL::PKey.generate_key('ML-DSA-65')
public_key = OpenSSL::PKey.read(key.public_to_pem)
signature = key.sign(nil, message)
public_key.verify(nil, signature, message)
```

`OpenSSL::PKey.read` accepts PEM/DER SubjectPublicKeyInfo and PKCS#8, including
password-encrypted PKCS#8. Private keys derive their public key through BC.
`public_to_pem` / `public_to_der` export SubjectPublicKeyInfo;
`private_to_pem` / `private_to_der` export unencrypted expanded-only PKCS#8. `oid` reports the
OpenSSL short name (`id-ml-dsa-65`); certificate, CSR, and CRL signature names
are `ML-DSA-65`. All three parameter sets support certificate, CSR, and CRL
signing with a `nil` digest, verification, and PEM/DER serialization.

Signatures use pure ML-DSA with an empty context. Explicit digests, HashML-DSA,
OpenSSL signature/key-generation options, raw-key operations, key agreement,
and encrypted private-key export are outside this implementation. PKCS#8 import
supports standard seed-only, seed-and-expanded, and expanded-only keys.
Prestandard bare encodings emitted by BC 1.80 are not accepted. Inconsistent
seed/expanded or private/public components are rejected; unlike OpenSSL's
default, contradictory expanded data is not ignored in favor of the seed. See the
independent [test fixtures](test/fixtures/mldsa/README.md).

For Net::HTTP client authentication, a default SSL context with an ML-DSA
credential automatically uses the existing TLS provider selection, normally
BCJSSE. No Java-specific application code or `ssl_version` setting is needed.
BCJSSE disables its ML-DSA signature schemes by default; enable them before
provider initialization. For example, start JRuby with the existing JSSE
properties (the classical schemes below allow an RSA server certificate):

```sh
JRUBY_OPTS='-J-Djdk.tls.client.SignatureSchemes=mldsa44,mldsa65,mldsa87,rsa_pss_rsae_sha256,rsa_pkcs1_sha256' jruby client.rb
```

```ruby
require 'net/http'
require 'openssl'

http = Net::HTTP.new('vault.example', 443)
http.use_ssl = true
http.min_version = http.max_version = OpenSSL::SSL::TLS1_3_VERSION
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
http.verify_hostname = true
http.ca_file = 'ca.pem'
http.cert = OpenSSL::X509::Certificate.new(File.read('client.pem'))
http.key = OpenSSL::PKey.read(File.read('client-key.pem'))
response = http.get('/v1/example')
```

The peer must also enable the corresponding ML-DSA client-authentication
signature schemes. A JRuby BCJSSE server uses the existing
`jdk.tls.server.SignatureSchemes` property and `SSLContext.new(:TLS)`.
Contexts without an ML-DSA credential retain their existing provider selection.
Explicit SSL methods, protocol bounds, and the `jruby.openssl.provider.ssl`
property remain effective. TLS support depends on both peers and their policy.
ML-DSA support in the separately distributed FIPS variant is not established
by these regular-BC tests.

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
- `OpenSSL::Engine` is not implemented - there is no hardware/engine layer, `OpenSSL::Engine`
  raises `NameError` (uninitialized constant)

**SSL / TLS** (backed by JSSE)
- `SSLSocket#state` and NPN (`#npn_protocol`) are unimplemented and return `nil` - use ALPN instead
- `SSLSocket#close_write` closes both TLS directions even on TLS 1.3; reading a peer response afterward 
  is unsupported, use message lengths or delimiters to frame requests instead of TLS EOF 
  NOTE: that you can enforce the half-close when using the JDK built-in SunJSSE provider
- Forced session resumption (`SSLSocket#session=`) is best-effort and only fully works with the
  BouncyCastle JSSE provider; `session_reused?` may return `nil` ("can't decide")
- `SSL::Session#id=` / `#time=` are no-ops 
- `SSL::Session.new` on a non-socket raises `NotImplementedError`
- Hostname / `subjectAltName` matching runs over Java's certificate parsing and can differ from
  MRI's `GeneralName` handling in edge cases

**Cipher** (JCE / Bouncy Castle)
- The available cipher set is provider-dependent (what JCE/BC offer on your JVM), not the fixed
  libcrypto list (some OpenSSL ciphers may be missing or vary by JDK)
- CFB1 mode (`*-cfb1`) is excluded (doesn't match OpenSSL under BC)
- AEAD is limited to what JCE exposes; `iv_len=` on a non-AEAD cipher raises

**PKey** (EC / DH / EdDSA)
- EC is limited to prime curves (`:GFp`); binary-field curves (`:GF2m`) fail
- `EC::Point#mul` with array arguments and encrypted EC private-key export are not implemented
- `DH#set_pqg` ignores the `q` parameter (and warns when it is non-`nil`)
- EdDSA (`Ed25519` / `Ed448`) rejects digest arguments

**X509**
- multi-valued RDNs (the `+` separator in a DN string) are not supported and raise `X509::NameError`
- few `authorityKeyIdentifier` extension configurations are unsupported

**Random**
- randomness comes from the JVM's `SecureRandom`; the EGD and seed-file APIs (`Random.egd`,
  `egd_bytes`, `load_random_file`, `write_random_file`) are no-ops

**BN**
- `BN#get_flags` always returns zero; `BN#set_flags(0)` is a no-op; the OpenSSL constant-time mode
  (`BN::CONSTTIME`) is not supported

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
