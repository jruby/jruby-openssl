## 0.15.5

* [deps] upgrade BC to version 1.81
* Improving completeness of ASN1 encoding/decoding (#335)
* [fix] OpenSSL::X509::CRL#to_pem when building CRL from scratch (#163)
* [fix] OpenSSL::ASN1::ASN1Data encoding/decoding compatibility (#265)

## 0.15.4

* Verify hostname by default

This addresses **CVE-2025-46551** and **GHSA-72qj-48g4-5xgx**.

Users can work around this by applying this patch manually to their
own jruby-openssl and jruby installs, or by re-enabling hostname
verification with the following code early in application boot:
```ruby
require 'openssl'

OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:verify_hostname] = true
```

## 0.15.3

* [fix] keep curve name when group is set into another key
* [fix] make sure `OpenSSL::PKey::EC#dup` (copying) works
* [compat] make sure `OpenSSL::PKey::EC#generate_key!` exists
* [compat] missing OpenSSL:BN `to_int`, `-@`, `+@`, `abs`, `negative?`
* [compat] implement PKey::EC `public_to_pem` and `xxx_to_der`
* [fix] initialize @unused_bits = 0 for BitString
* [fix] raise ASN1Error when unused_bits out of range
* [fix] respect @unused_bits in BitString (#323)
* [fix] missing `OpenSSL::ASN1::ObjectId#==` (#311)
* [compat] implement PKey::DSA `public_to_der` and `public_to_pem`
* [compat] implement PKey::RSA `public_to_der` and `public_to_pem`
* [fix] DSA private key should generate after `set_key`
* [refactor] RSA key internals to always consider params
* [fix] DSA key compatibility when `set_pqg`
* [fix] RSA private key should generate after `set_key`
* [compat] add private? and public? methods on `PKey::EC`

## 0.15.2

* [deps] upgrade BC to version 1.79
* [fix] avoid PKey::EC.new failing with specific DER (#318)
* [fix] have a useful OPENSSL_VERSION_NUMBER

## 0.15.1

* [deps] upgrade BC to version 1.78.1

## 0.15.0

This version upgraded to latest Bouncy-Castle (1.78) and the minimum supported
JRuby is now 9.2.

* [refactor] propagate IOError from selector exception
* [fix] convert IOException to Ruby exception correctly
  follow up on the fix (#242) in 0.14.6
* [fix] implement `OpenSSL::PKey::EC::Point#mul` and `#add` (#307)
* [fix] ASN.1 BitString pad bits being out of range
* [compat] support base64digest on `OpenSSL::HMAC`
* [compat] add `Buffering#getbyte` for `SSLSocket`
* [refactor] drop (unused) Config native impl
* [refactor] less locking when there's a shared SSLContext
* [fix] encoding of ASN1::Null primitive to_der
* [fix] ASN.1 tagged object tag-class encoding/decoding
* [fix] ASN1 primitive tagging (encoding) part (#122)
* [fix] encoding/decoding of all ASN1 string types
* [fix] ASN1Data encoding with Array primitive value (#119)
* [refactor] drop security restriction JCE work-around
* [refactor] drop long deprecated OpenSSLReal Java class
* [deps] upgrade BC to version 1.78

## 0.14.6

* [compat] OpenSSL::ConfigError and DEFAULT_CONFIG_FILE (#304)
* [fix] `OpenSSL::PKey::DH#set_pqg` regression (#300)
* Convert `IOException` to Ruby exception correctly (#242)
* [refactor] add exception debugging within SSLSocket#waitSelect
* [fix] sync `SSLContext#setup` as it could be shared (#302)
* [refactor] organize i-var sets (set `@context` after setup)

## 0.14.5

* [fix] `OpenSSL::X509::Request#verify` with DSA public key
  (this was a regression introduced in JOSSL 0.14.4)

## 0.14.4

* [fix] convert `OpenSSL::ASN1::Sequence` to an array on #to_der (#265)
* [feat] implement `PKey::DH.generate` and (dummy) `q` reader (#254)
* [fix] raise `TypeError` when arg isn't a `Group`
* [refactor] make sure `ASN1Error` has native cause
* [fix] stop assuming (JDK) EC key identifier
  "EC" with Sun provider but "ECDSA" with BC
* [fix] do not check empty string as curve name
* [fix] make sure `PKeyEC#group.curve_name` is always set
* [refactor] `PKey.read` to use BC fully when reading public keys
* [fix] `OpenSSL::X509::CRL#sign` to accept string digest
* [fix] `OpenSSL::X509::Request#version` default is -1
* [fix] resolving EC key from `X509::Request.new(pem)`
* [feat] implement `OpenSSL::X509::Request#signature_algorithm`
* [fix] work-around CSR failing with EC key (#294)
* [feat] implement `OpenSSL::PKey::EC#to_text` (#280)
* [feat] partial support for `PKey::EC::Point#to_octet_string(form)`
* [feat] implement `OpenSSL::PKCS7::SignerInfo#signed_time` (#269)
* [feat] implement #oid method for `PKey` classes (#281)
* [fix] raise `PKeyError` from `PKey.read` when no key (#285)
* [fix] restore PKCS#8 EC key handling (see #292)
* [fix] revert `readPrivateKey` so public key is not lost (#292)

## 0.14.3

* [fix] `SSLSocket#alpn_protocol` to be nil when not used (#287)
* [feat] try resolving curve-name from EC public key
* [feat] implement missing `PKey::EC#dsa_verify_asn1` (#241)
* [feat] implement support for `PKey::EC.generate` (#255)
* [refactor] make sure curveName is set when using `PKey.read` (#289)
* [fix] add `Cipher#auth_data(arg)` override (Rails 7.x compatibility) (#290)
* [fix] raise `TypeError` when arg not of expected type (jruby/jruby#7875)

## 0.14.2

* [deps] upgrade BC to latest 1.74
* [fix] for CRL verify when signed with EC key (#276)
* [fix] `OpenSSL::X509::Certificate#public_key` raises for EC keys (#273)

## 0.14.1

* [refactor] improve performance of Diffie-Hellman key exchange (#272)
* Try to use JDK console to prompt for pass (#270)
* [fix] for PKCS8 EC private key support (#267)
* ~~"[fix] handle potential buffer overflow on write" (#242)~~

## 0.14.1 (CR2)

* [fix] Java's default session timeout in 24h
* [fix] handle ArgumentError on `SSLSession#timeout=`
* [fix] handle potential buffer overflow on write (#242)
* [fix] buffer overflow after wrap-ing data - wait
* [refactor] try a few tricks to detect session re-use

## 0.14.0

This version upgraded to latest Bouncy-Castle (1.71) and is only compatible with 
the new version mostly due artifact naming and breaking chances in BC itself.

* [deps] upgrade BC to latest 1.71
* [fix] make set_minmax_proto_version private 

## 0.13.0

* [fix] ASN1::EndOfContent ancestor hierarchy (#228)
* [fix] handle X509::Name type conversion (#206)
* [fix] handle invalid type when creating `X509::Name`
* [fix] `OpenSSL::X509::Name#inspect` compatibility
* [fix] escaping with `OpenSSL::X509::Name::RFC2253`
* [feat] implement `OpenSSL::X509::Name#to_utf8`
* [fix] compat missing `OpenSSL::SSL::OP_NO_TLSv1_3`
* [refactor] performance - do not encode/decode cert objects
* [fix] make sure `Context.ciphers` are not mutated (#219)
* [feat] support `to_java` conversion for CRL
* [feat] support `to_java` protocol for PKey (#250)

## 0.12.2

* [fix] work-around JRuby 9.2 autoload behavior (#248)
  to be able to install jruby-openssl >= 0.12 on JRuby 9.2
  while the default gem (shipped with JRuby) is < 0.12
* [feat] support alpn negotiation in ssl context (#247)
* [feat] support Java cipher names on `SSLContext#ciphers=`
* [fix] properly handle `require_jar` fallback

## 0.12.1

* improved compatibility with the openssl gem (version 2.2.1)
* JOSSL now ships with a single set of openssl .rb files
  - providing compat with `required_ruby_version = '>= 2.3.0'`
  - flat set of .rb files at *lib/openssl/* (based on openssl gem) 
* revisited `OpenSSL::SSL::SSLContext::DEFAULT_PARAMS` defaults
  - implicit `verify_hostname` default .rb callback still a noop
  - TLS continues to rely on the Java SSL engine for hostname checks
* working TLS 1.3 support
* droped Java 1.7 support (at least Java 8 needed to use the gem)
* fixed `SSLContext#options` matches C OpenSSL (using `OP_ALL`)
* no longer filter out SSLv2 (for improved OpenSSL compatibility) 
* implemented naive `SSLContext#ciphers` caching to speed-up TLS
* `StoreError` raised due a Java exception now retain native cause

## 0.12.0 (yanked)

There were Java 8 and JRuby 9.3 regressions in this release, use 0.12.1 instead.

## 0.11.0

NOTE: This release aims to adapt the certificate verification logic to be aligned 
with OpenSSL 1.1.1 as a resolution to issues due *DST Root CA X3* expiration, more
details at: https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/ 

The port is expected to be superior compared to the simple legacy verification,
however in case of issues the previous algorithm is still around and can be toggled 
using `JRUBY_OPTS="-J-Djruby.openssl.x509.store.verify=legacy"` system property.

* **OpenSSL 1.1.1 cert verification port** (fixes #236) (#239)
 - as a side-effect part of the PR to "allow multiple certs with same SubjectDN" 
   (#198) got reverted, this has been causing verification regressions (since 0.10.5) 
   for some users (#232) and is expected to be fixed   
* [fix] replace deprecated getPeerCertificateChain (#231)

## 0.10.7

* [feat] upgrade BC library to 1.68
* [fix] SSLContext#ciphers= (fixes #221 and jruby/jruby#3100) (#222)
* [fix] Java::JavaLang::StringIndexOutOfBoundsException on ctx.cipher=[] (fixes #220) (#223)
* [fix] SSLContext#ciphers= compatibility (fixes #223) (#220)
* [fix] Match OpenSSL::X509::Name.hash implementation with Ruby (#216, #218)
* [fix] OpenSSL::SSL::SSLContext#min_version= failure (#215)
* [fix] adds OpenSSL::Cipher#iv_len= setter (#208)

## 0.10.6 (yanked)

Due several regressions please update to version 0.10.7 or higher.

## 0.10.5

* [fix] EC key sign/verify (#193)
* [feat] upgrade BC library to 1.65
* [refactor] clean security helpers to avoid reflection (#197)
* Just use normal getInstance to get KeyFactory (fixes #197)
* Allow multiple Certificates with the same SubjectDN in the store (#198)
* Try direct path for MessageDigest before invasive path (#194) 
  (relates to jruby/jruby#6098)
* [refactor] avoid NativeException usage (jruby/jruby#5646) 

## 0.10.4

* Use CertificateFactory.getInstance rather than reflection
  eliminates one of the module warnings we have been seeing (#161)

## 0.10.3

* [fix] implement (missing) PKey::DSA#params
* [fix] authorityKeyIdentifier ext (general-name) value
* [fix] authority keyid extension's :always part optional (#174)
* [fix] work-around for not setting certificate serial
  raise a more friendly error (jruby/jruby#1691)
* [fix] PKey.read not parsing RSA pub-key (#176)
* [feat] support reading DSA (public key) in full DER
* [fix] RSA key DER format to closely follow OpenSSL
* [fix] add missing ASN1 factory methods (Null, EndOfContent)
* [fix] support getting password from block for PKeys
* [fix] incorrect ASN.1 for wrapped Integer type
* [fix] correct public key for subjectKeyIdentifier ext (#173)
* [fix] invalid Cert#sign handling -> raise (instead of ClassCastException)
* [feat] more TLS (GCM) ciphers - supported on Java 8+
* [feat] add ECDHE-RSA-AES128-GCM-SHA256 as supported cipher (#185)
* [feat] add support for ECDHE-RSA-AES256-GCM-SHA384 (#187)
* [fix] try hard not to fail on unkown oids (OpenSSL::X509::Certificate#to_text)
* update Bouncy-Castle to 1.62 (and handle supported BC compatibility)

## 0.10.2

* update Bouncy-Castle to 1.61 (and handle supported BC compatibility)
* [fix] avoid NPE when CRL fails to parse (invalid str) (jruby/jruby#5619)
* hide (deprecated) Jopenssl constant 
* default OpenSSL.warn to warnings-enabled flag
* only un-restrict jce when its restricted
* OpenSSL::Cipher#update additional buffer argument (#170) (jruby/jruby#5242)

## 0.10.1

* loading JOpenSSL's native ext part the JRuby 9.2 (internal) way
* avoid, once again, installing BC provider on boot (due OCSP support)
* [feat] support OpenSSL::KDF as a (semi) OpenSSL::PKCS5 replacement
* rename ugly-sh "Jopenssl" constant to **JOpenSSL**
* support PKCS7#decrypt with 1 argument (pkey only - without certificate)
* undo some of the call-sites in SSLSocket - account for sub-classes (#165)
* follow-up to provide == for X.509 types (like C-OpenSSL does in 2.1) 
* validate iter parameter on Cipher#pkcs5_keyivgen (since OpenSSL 2.0.8)
* remove openssl/pkcs7.rb -> since 1.8 no longer supported

## 0.10.0

**NOTE:** dropped support for anything below ~ JRuby 1.7.20

* drop support for Java 1.6 and compile using Java 7
* improve java.version detection for Java 9/10 (pre-releases)
* subject alt name parsing fixes (#140) - thanks @roadrunner2
* fix loading of Subject/Issuer-Alt-Name extensions. (#144)
* normalize all constants in CipherStrings as public (#146)
* upgrade BC to **1.59** and dropped support for BC < 1.55
* include BC's JSSE provider as we're planning on using it, eventually
* setup OpenSSL::ExtConfig emulation - mostly (conservative) guesses
* at last, do BN comparison `==` vs `eql?` properly - just like MRI
* get `BN.new("...", 0)` working as OpenSSL does - using MPI format
* allow for SSLContext#dup to work (copy-ing Ruby level i-vars only)
* fix signature-alg to default to NULL and report it as 0.0 (like MRI)
* account for ASN1Integers when transforming issuer serial numbers 
  to_text in AuthorityKeyIdentifier extensions (#147) - thanks @lampad
* copy bytes since it might be a shared (unsafe) buffer (#150)
* don't use padding for streaming cipher modes (#155) - thanks @dgolombek
* avoid ByteList#length() usage for forward (JRuby 9.2) compatibility
* prepare for using BC's JSSE implementation as an SSL support backend
  allow to set SSL provider name (-Djruby.openssl.ssl.provider=...)

## 0.9.21

* adjust X.509 value handling to parse subjectAltName recursively (#134)
* SKI expected to be always octet wrapped - do not check for length (#131)
* respect jruby.preferred.prng and use/tune its SecureRandom defaults
  trying to avoid BC generator's constant attempts for seeding itself
  as an attempt to 'fix' low-entropy systems wating for */dev/random*
* Random#add; Random#egd shall return true on JVM
* move "DEFAULT" special case handling to match OpenSSL behaviour (#136)
  (jruby/jruby#2193)
* If data is not provided, extract it from the PKCS7 instance (#132)
* Add cipher suite strings for IBM JRE (#126) - thanks @ysohda
* use the helper to printStackTrace (no System.err printing by default)
* add OCSP support (#124) - thanks so very much @lampad
* add support for renegotiation_cb on SSLContext (#121) - thanks @lampad

## 0.9.20

* upgrade Bouncy-Castle to 1.56 http://bouncycastle.org/releasenotes.html
  (additional security and robustness with 10 CVEs submitted as a result)
* add a dummy SSLContext#security_level= implementation
* no dup-ing for SSLContext/SSLSocket and X509 Store/StoreContext
* implement PKey initialize_copy (dup-ing)
* digest can be passed in as a String on PKey#sign/verify
* DSA+SHA1 is actually a supported algorithm
* reset signed-request -> sub-sequent req.verify will work correctly
* allow for digest name to be passed into Cert#sign
* be less fatal on Java 9
  won't attempt reflective SPIs when accessibility checks fail!
* remove obsolete (deprecated) renamed classes
* verify correct WaitReadable is raised on connect_nonblock (jruby/jruby#1716)
* non-connected ssl socket raises EPIPE on connect_nonblock (MRI compat)
* fine to close a SSLSocket which is not-yet-connected (like in MRI)
* fix NPE when reading private keys (with passwd) (jruby/jruby#1784)

## 0.9.19

* re-use secure random from thread-context on SSL context initialization
* preliminary OpenSSL 1.1 (Ruby 2.4) compatibility bits (#112)
* try using thread-shared secure random gen (in PKey-s) where possible
* implement PKeyDSA#syssign and PKeyDSA#sysverify methods
* avoid (unnecessary) byte[] copies in PKey#sign/verify
* fix ClassCastException error in X509Store.verify (#113)
* align BH#hash with eql? (+ equals/hashCode on Java)

## 0.9.18

* handle X.509 authorityKeyIdentifier parsing somehow right (#102)
* simple resolution for handling subjectAltName multiple DNS: names (#102)
* upgrading BC to 1.55
  normalize "brainpoolP512t1" curve name for BC 1.55 compatibility
* allow for X509::Certificate to be converted to a Java certificate
* at least OpenSSL.debug potential env read failure on set_default_paths
* negative BN values are always considered not prime.
* Don't print a warning for missing client certs (#110)

## 0.9.17

* temporarily register BC provider on X.509 factory (work-around for #94)
* support Cipher#auth_tag and auth_data for GCM ciphers (e.g. aes-128-gcm)
* need to drop support for BC <= 1.50 due EC support (N/A in older BCs)
* (somehow working) draft at implementing PKey::EC (elliptic curve support)
  DH encryption expected to behave correctly
* make sure (initial) BC security provider registration works!
  ... when **-Djruby.openssl.provider.register=true** (due #94)
* Make ALL cipherstring match ECDHE cihphers (#91)
* fix X.509 indexBySubject returning correct index
* try to handle `SSLContext.session=` and also try answering `session_reused?`
* handle equals/hashCode on SSL::Session and raise on timeout int overflow
* Allow DSA private keys to be initialized from parameters. (#83)
* Instantiate both the private and public keys when setting parameters. (#82)

## 0.9.16

* add hard dependency to jar-dependencies (#74)
* Recognize Android java.version (#81)

## 0.9.15

* always return a Fixnum from `OpenSSL::SSL::Session#timeout`, OpenSSL defaults
  to 300 (been causing net/http.rb issues with timeouts on JRuby 9K)

## 0.9.14

* upgrade to using BC **1.54** as default (all versions >= 1.49 are supported)
  for Bouncy-Castle release notes see http://bouncycastle.org/releasenotes.html
* basic support for prompting for PEM password (working for RSA/DSA priv.key)
* avoid NPE due version field in X509Cert - make sure it's treated as 0 (#78)
  and fix settting ceritificate.serial = number
* default WairReadable/Writable backtraces to JRuby's -Xerrno.backtrace
* use hardcoded jks type for loading cacerts - for Java 9 compatibility (#79)

## 0.9.13

JRuby-OpenSSL is the first release that aims to be Ruby **2.3** compatible.

* SSLSocket#sysread do not copy bytes from buffer - re-use the backing array
* handle read_nonblock EOF as nil when exception: false (Ruby 2.3 compatibility)
* start exposing VERSION constant(s) directly on Jopenssl module
* better not throw EOF on SSLSocket#sysclose for compatibility with MRI
* setup "dummy" OpenSSL::OPENSSL_LIBRARY_VERSION constant for compatibility
* Ruby 2.3 compatibility - adjust to changes in MRI's openssl .rb parts
* update openssl/ssl.rb based on MRI 2.2's version
* disable backtrace generation for wait non-block errors (use an empty array)
* support SSLSocket#accept_nonblock/connect_nonblock with exception: false
* support `exception: false` with syswrite_nonblock and sysread_nonblock
* remove 'RSA' from RSA public key headers (#76)

## 0.9.12

* when the Cipher/Signature needs to be created via java reflection use a constructor
  which avoids verifying the bouncy-castle jars (which is the main reason for using
  reflection since some classloader setups fails to verify those jars) (#73)
* force US locale for date formatting
  otherwise it uses system locale, which is inconsistent with MRI.
* X509::Store.set_default_paths ignores FileNotFound errors like MRI does (#68)
* check type on X509::Store.verify
  throw a TypeError if the argument is not a OpenSSL::X509::Certificate (#69)
* keep the default x509 certs and directories in line with MRI, only if
  they do not exists fallback on cacerts from the java.home/lib/security/cacerts
* bring the default ca-certs paths/location more in line with MRI and fallback on
  jvm truststore (java.home/lib/security/cacerts) when needed

## 0.9.11

* add TLSv1_1_client, TLSv1_1_server, TLSv1_2_client and TLSv1_2_server options
  to ssl_version (#65)
* **regression** make sure we hold a buffered reader so that the loop continues
  reading PEMs - previously introduced an incompatibility with cert verify (#67)
* support negotiating up to TLS1_1 and TLS1_2 when the server supports these
  ssl_versions (#63)

## 0.9.10

* **regression** reverted fix for #49 (as it needs more work/testing) :
  keep the default x509 certs and directories in line with MRI (#49), only if
  they do not exists fallback on cacerts from the java.home/lib/security/cacerts

## 0.9.9

* **regression** causing to re-package a RaiseException in `SSLSocket#accept`
* fix load error: jopenssl/load -- java.lang.VerifyError: using BC 1.51 or 1.52 (#62)
* keep the default x509 certs and directories in line with MRI (#49), only if
  they do not exists fallback on cacerts from the java.home/lib/security/cacerts

## 0.9.8

* refactor `PKCS5.pbkdf2_hmac_sha1` to use BC APIs
  thus less dependent on provider internals (jruby/jruby#3025)
* HMAC - use our SimpleKey impl so that there's less[] copy
  ... also allows for an empty key to work like MRI (jruby/jruby#2854)
* fixing oaep encryption to use correct algorithm (#54)
* [experimental] support NOT loading any (BC) jars on our own ... (#10)
* disable DHE (by default) on Java <= 7 ... on Java 8 we (still) force 1024/2048
  (see jruby/jruby#2872 and #45)
* **regression** handle parsing of "incomplete" X.509 certs like MRI does (#42)
* implement a CRL/certificate caching (for now off by default) in Lookup
  ... set *-J-Djruby.openssl.x509.lookup.cache=true* to enable
* improve Store helper concurrency (with less synchronization)
* reviewed OpenSSL's .rb parts to match those present in MRI 1.9.3 / 2.2.2
* initial support for `OpenSSL::SSL::Session` (id, time, timeout work)
* session_cache_mode as present in OpenSSL makes no sense with Java APIs
* use the set SSLContext#session_cache_size on the underlying javax.net API
* tidy up SSLSocket's internals + add stack-trace debugging on accept/connect
* add SSLSocket ssl_version property like MRI has (#38)
* avoid unnecessary `_initialize` naming - it's confusing to see in JVM tools
* use SecurityHelper to get a X.509 certificate factory
  we'll know prefer BC's X.509 factory over the built-in (Sun provider) one

## 0.9.7

* put in some more ossl to jsse mappings for SSL/TLS
  (SSL_DHE_xxx, TLS_ECDH_xxx, TLS_ECDHE_xxx)
* exclude SSLv2 in reported METHODS (all fine to close jruby/jruby#1874)
* support passing ssl_version as an argument to initialize SSLContext.new ...
* now that we've matched w MRI's SSLContext::METHODS don't report custom ones
* more ssl_version= compatibility fixes that match MRI (jruby/jruby#1736)
* support setting ssl_version = "TLSv1_1" (or "TLSv1_2") just like MRI
* **regression** make sure version is set when reading encoded certificate
  + signature algorithm should be read as well when decoding certificate (#39)
* better accept handshake errors instead of "General SSLEngine problem (#37)
* trying to decode DER application specific objects (based on patch from #36)
* we've not been compatible with MRI's DES (EDE) - partly due DES(3) ECB
  fixing jruby/jruby#2617 as well as jruby/jruby#931
* exclude reporting algorithms with CFB-1 cipher mode as supported (due #35)
* do not change CFB1 to CFB ... it's something different (although broken on BC)
* attempt to deal with update/final buffering incompatibility with MRI
* fix HMAC digest incorrect when data contains invalid characters (#33)
* add Gemfile and specify ruby-maven as dependency
* use SafePropertyAccessor to access properties instead of directly (#28)
* make sure SSLSocket's cipher and hostname are nil by default (avoids NPE)
* update to (packed) BC version 1.50 + start declaring 1.51 as semi-supported

## 0.9.6

* ClassCastException still happen deep within BC - turn them into SignatureExeption
* make sure empty object can be serialize via to_pem
* use the classname as message in case the exception has no message (jruby/jruby#2249)
* make sure X509Object list is synchronized properly
* use JRubyFile to get input-stream to file-resource fixes #11
* Cache the discovered classes for digest engines. Fixes #15.
* avoid the rest of Ruby.getGlobalRuntime usages - only worked in 1 runtime envs
* refactored CRL - using light-weight BC API (avoids deprecated X.509 generator)
* implement X509::Certificate#to_text for happiness (the MRI-way - only RSA for now)
* allow to "fake" our inspect() support and match MRI's X509::Certificate#inspect
* decode BC's ASN1Enumarated into a OpenSSL::ASN1::Enumerated
* we can (ASN.1) encode an infinite-length bit-string constructive
* turns out all ASN1 primitives in MRI have the infinite_length attribute
* support (so-far only dummy) @servername_cb attribute on SSLSocket
* handle (CRL) extension's issuerAltName wrapping without an exception
* fix SSL (cert) verification - now working on 1.8/1.9 better than before
* do not skip first 2 bytes of key identifier hash when encoding to hex!
* match X.509 extension short-comings of the Java API in order to align with MRI
* improve cert.extension's value - *extendedKeyUsage* was not returned correctly
* make sure ASN1::ObjectId.new(...).ln and ASN1::ObjectId.new(...).sn are correct!
* better working to_der conversion esp. with constructives (indefinite lengths)
* improve our ASN1 decoding for better MRI compatibility
* avoiding Krypt gem dependency completely (was used for OpenSSL::PKCS5)
* cleanup OpenSSL::Digest internals - make sure block_length works for more
* OpenSSL deprecated_warning_flag and check_func API compatibility stubs
* do not force loading of jar-dependencies + possibly respect jars skipped
* X509::Name.to_a compatibility - MRI seems to never return "UNDEF"
 experimental support for passing down "real" Java JCE cipher names
* rewriten Cipher internals - now faster, slimmer and more compatible than ever!
* rebuilt our global ASN1Registry and refactored it (back) internally to use string oids
* report OpenSSL::VERSION **1.1.0** since 1.9.3
* fill RaiseException's cause whenever we use a factory passing down a Throwable
* allow X509::Revoked.serial= to receive an integer
* make sure X509::CRL's to_text representation si (fully) MRI compatible
* handle authority key-id unwrapping correctly in X509::Extension#value
* long time coming - OpenSSL::X509::CRL support for loading revoked entries (#5)
* Reflect Java cacert location in DEFAULT_CERT_* constants (jruby/jruby#1953)
* X509::Certificate.new MRI compatibility + make sure inspect works the same
* BN.inspect() and make sure BN.new(0) works just fine (both as in MRI)
* X509::CRL instantiation compatibility with MRI
* inspect() X509::Certificate an X509::CRL just like MRI does
* handle OpenSSL::X509::Store.add error messages correctly (fix based on #6)
* update to using BC 1.49 by default (still compatible with older versions)
* implement X509::StoreContext#current_crl method
* support X509::StoreContext cleanup and error_depth instance methods
* support disabling of warnings using system property -Djruby.openssl.warn
* Throw error when chain certs are *not* OpenSSL::X509::Certificate (#3)
* avoid using JRuby IO APIs (will likely not work in 9k)
* make 'jopenssl/load' also work on jruby-1.6.8 mode 1.9

## 0.9.5

MASSIVE internal "rewrite" to avoid depending on a registered (BC) security
provider. This releases restores compatibility with BC version 1.47 while being
compatible with newer bouncy-castle jars as well (1.48, 1.49 and 1.50).

* handle SSLErrorWaitReadable/Writable as SSLErrors on Ruby 1.8 and 1.9 mode
* Treat SSL NOT_HANDSHAKING as FINISHED
* only add DER.TRUE when encoding X.509 extension when non-critical
* do not der encode non-critical flag in X509::Extension (jruby/jruby#389)
* SSLContext internals + support `SSLContext::METHODS` correctly (jruby/jruby#1596)
* correct visibility of initialize* and respond_to_missing? methods
* fix spinning indefinitely on partial TLS record (jruby/jruby#1280)
* Support file input for PKey::RSA.new
* fix bug https://github.com/jruby/jruby/issues/1156
* openssl: add handling for base 0 to new and to_s

## 0.9.4

* Fix compatibility wiht Bouncy Castle 1.49.

## 0.9.3

* Allow options passed to nonblock methods (not impl'ed yet)
* Make ClassIndex into an enum, to prevent issues like jruby/jruby#1004


== ...


## 0.7.7

This release includes bug fixes.

* JRUBY-6622: Support loading encrypted RSA key with PBES2
* JRUBY-4326: Confusing (and late) OpenSSL error message
* JRUBY-6579: Avoid ClassCastException for public key loading
* JRUBY-6515: sending UTF-8 data over SSL can hang with openssl
* Update tests to sync with CRuby ruby_1_9_3

## 0.7.6

This release includes initial implementation of PKCS12 by Owen Ou.

* JRUBY-5066: Implement OpenSSL::PKCS12 (only for simple case)
* JRUBY-6385: Assertion failure with -J-ea

## 0.7.5

This release improved 1.9 mode support with help of
Duncan Mak <duncan@earthaid.net>.  Now jruby-ossl gem includes both 1.8 and 1.9
libraries and part of features should work fine on 1.9 mode, too.

* JRUBY-6270: Wrong keyUsage check for SSL server
* JRUBY-6260: OpenSSL::ASN1::Integer#value incompatibility
* JRUBY-6044: Improve Ecrypted RSA/DSA pem support
* JRUBY-5972: Allow to load/dump empty PKCS7 data
* JRUBY-5834: Fix X509Name handling; X509Name RDN can include multiple elements
* JRUBY-5362: Improved 1.9 support
* JRUBY-4992: Warn if loaded by non JRuby interpreter

## 0.7.4

* JRUBY-5519: Avoid String encoding dependency in DER loading. PEM loading
  failed on JRuby 1.6.x. Fixed.
* JRUBY-5510: Add debug information to released jar
* JRUBY-5478: Update bouncycastle jars to the latest version. (1.46)

## 0.7.3

* JRUBY-5200: Net::IMAP + SSL(imaps) login could hang. Fixed.
* JRUBY-5253: Allow to load the certificate file which includes private
  key for activemarchant compatibility.
* JRUBY-5267: Added SSL socket error-checks to avoid busy loop under an
  unknown condition.
* JRUBY-5316: Improvements for J9's IBMJCE support. Now all testcases
  pass on J9 JDK 6.

## 0.7.2

* JRUBY-5126: Ignore Cipher#reset and Cipher#iv= when it's a stream
  cipher (Net::SSH compatibility)
* JRUBY-5125: let Cipher#name for 'rc4' to be 'RC4' (Net::SSH
  compatibility)
* JRUBY-5096: Fixed inconsistent Certificate verification behavior
* JRUBY-5060: Avoid NPE from to_pem for empty X509 Objects
* JRUBY-5059: SSLSocket ignores Timeout (Fixed)
* JRUBY-4965: implemented OpenSSL::Config
* JRUBY-5023: make Certificate#signature_algorithm return correct algo
  name; "sha1WithRSAEncryption" instead of "SHA1"
* JRUBY-5024: let HMAC.new accept a String as a digest name
* JRUBY-5018: SSLSocket holds selectors, keys, preventing quick
  cleanup of resources when dereferenced

## 0.7.1

NOTE: Now BouncyCastle jars has moved out to its own gem "bouncy-castle-java"
http://rubygems.org/gems/bouncy-castle-java. You don't need to care about it
because "jruby-openssl" gem depends on it from now on.

* JRUBY-4826 net/https client possibly raises "rbuf_fill': End of file
  reached (EOFError)" for HTTP chunked read.

* JRUBY-4900: Set proper String to OpenSSL::OPENSSL_VERSION. Make sure
  it's not an OpenSSL artifact: "OpenSSL 0.9.8b 04 May 2006
  (JRuby-OpenSSL fake)" -> "jruby-ossl 0.7.1"
* JRUBY-4975: Moving BouncyCastle jars out to its own gem.

## 0.7

* Follow MRI 1.8.7 openssl API changes
* Fixes so that jruby-openssl can run on appengine
* Many bug and compatibility fixes, see below.
* This is the last release that will be compatible with JRuby 1.4.x.
* Compatibility issues
 - JRUBY-4342: Follow ruby-openssl of CRuby 1.8.7.
 - JRUBY-4346: Sync tests with tests for ruby-openssl of CRuby 1.8.7.
 - JRUBY-4444: OpenSSL crash running RubyGems tests
 - JRUBY-4075: Net::SSH gives OpenSSL::Cipher::CipherError "No message
   available"
 - JRUBY-4076: Net::SSH padding error using 3des-cbc on Solaris
 - JRUBY-4541: jruby-openssl doesn't load on App Engine.
 - JRUBY-4077: Net::SSH "all authorization methods failed" Solaris -> Solaris
 - JRUBY-4535: Issues with the BouncyCastle provider
 - JRUBY-4510: JRuby-OpenSSL crashes when JCE fails a initialise bcprov
 - JRUBY-4343: Update BouncyCastle jar to upstream version; jdk14-139 ->
   jdk15-144
 Cipher issues
 - JRUBY-4012: Initialization vector length handled differently than in MRI
   (longer IV sequence are trimmed to fit the required)
 - JRUBY-4473: Implemented DSA key generation
 - JRUBY-4472: Cipher does not support RC4 and CAST
 - JRUBY-4577: InvalidParameterException 'Wrong keysize: must be equal to 112 or
   168' for DES3 + SunJCE
 SSL and X.509(PKIX) issues
 - JRUBY-4384: TCP socket connection causes busy loop of SSL server
 - JRUBY-4370: Implement SSLContext#ciphers
 - JRUBY-4688: SSLContext#ciphers does not accept 'DEFAULT'
 - JRUBY-4357: SSLContext#{setup,ssl_version=} are not implemented
 - JRUBY-4397: SSLContext#extra_chain_cert and SSLContext#client_ca
 - JRUBY-4684: SSLContext#verify_depth is ignored
 - JRUBY-4398: SSLContext#options does not affect to SSL sessions
 - JRUBY-4360: Implement SSLSocket#verify_result and dependents
 - JRUBY-3829: SSLSocket#read should clear given buffer before concatenating
   (ByteBuffer.java:328:in `allocate': java.lang.IllegalArgumentException when
   returning SOAP queries over a certain size)
 - JRUBY-4686: SSLSocket can drop last chunk of data just before inbound channel
   close
 - JRUBY-4369: X509Store#verify_callback is not called
 - JRUBY-4409: OpenSSL::X509::Store#add_file corrupts when it includes
   certificates which have the same subject (problem with
   ruby-openid-apps-discovery (github jruby-openssl issue #2))
 - JRUBY-4333: PKCS#8 formatted privkey read
 - JRUBY-4454: Loading Key file as a Certificate causes NPE
 - JRUBY-4455: calling X509::Certificate#sign for the Certificate initialized
   from PEM causes IllegalStateException
 PKCS#7 issues
 - JRUBY-4379: PKCS7#sign failed for DES3 cipher algorithm
 - JRUBY-4428: Allow to use DES-EDE3-CBC in PKCS#7 w/o the Policy Files (rake
   test doesn't finish on JDK5 w/o policy files update)
 Misc
 - JRUBY-4574: jruby-openssl deprecation warning cleanup
 - JRUBY-4591: jruby-1.4 support

## 0.6

* This is a recommended upgrade to jruby-openssl. A security problem
  involving peer certificate verification was found where failed
  verification silently did nothing, making affected applications
  vulnerable to attackers. Attackers could lead a client application
  to believe that a secure connection to a rogue SSL server is
  legitimate. Attackers could also penetrate client-validated SSL
  server applications with a dummy certificate. Your application would
  be vulnerable if you're using the 'net/https' library with
  OpenSSL::SSL::VERIFY_PEER mode and any version of jruby-openssl
  prior to 0.6. Thanks to NaHi (NAKAMURA Hiroshi) for finding the
  problem and providing the fix. See
  http://www.jruby.org/2009/12/07/vulnerability-in-jruby-openssl.html
  for details.
* This release addresses CVE-2009-4123 which was reserved for the
  above vulnerability.
* Many fixes from NaHi, including issues related to certificate
  verification and certificate store purpose verification.
  - implement OpenSSL::X509::Store#set_default_paths
  - MRI compat. fix: OpenSSL::X509::Store#add_file
  - Fix nsCertType handling.
  - Fix Cipher#key_len for DES-EDE3: 16 should be 24.
  - Modified test expectations around Cipher#final.
* Public keys are lazily instantiated when the
  X509::Certificate#public_key method is called (Dave Garcia)

## 0.5.2

Multiple bugs fixed:

* JRUBY-3895	Could not verify server signature with net-ssh against Cygwin
* JRUBY-3864	jruby-openssl depends on Base64Coder from JvYAMLb
* JRUBY-3790	JRuby-OpenSSL test_post_connection_check is not passing
* JRUBY-3767	OpenSSL ssl implementation doesn't support client auth
* JRUBY-3673	jRuby-OpenSSL does not properly load certificate authority file

## 0.5.1

* Multiple fixes by Brice Figureau to get net/ssh working. Requires JRuby 1.3.1
  to be 100%
* Fix by Frederic Jean for a character-decoding issue for some certificates

## 0.5

* Fixed JRUBY-3614: Unsupported HMAC algorithm (HMACSHA-256)
* Fixed JRUBY-3570: ActiveMerchant's AuthorizeNet Gateway throws OpenSSL Cert
  Validation Error, when there should be no error
* Fixed JRUBY-3557 Class cast exception in PKeyRSA.java
* Fixed JRUBY-3468 X.509 certificates: subjectKeyIdentifier corrupted
* Fixed JRUBY-3285 Unsupported HMAC algorithm (HMACSHA1) error when generating
  digest
* Misc code cleanup

## 0.2

* Enable remaining tests; fix a nil string issue in SSLSocket.sysread
  (JRUBY-1888)
* Fix socket buffering issue by setting socket IO sync = true
* Fix bad file descriptor issue caused by unnecessary close (JRUBY-2152)
* Fix AES key length (JRUBY-2187)
* Fix cipher initialization (JRUBY-1100)
* Now, only compatible with JRuby 1.1

## 0.1.1

* Fixed blocker issue preventing HTTPS/SSL from working (JRUBY-1222)

## 0.1

* PLEASE NOTE: This release is not compatible with JRuby releases earlier than
  1.0.3 or 1.1b2. If you must use JRuby 1.0.2 or earlier, please install the
  0.6 release.
* Release coincides with JRuby 1.0.3 and JRuby 1.1b2 releases
* Simultaneous support for JRuby trunk and 1.0 branch
* Start of support for OpenSSL::BN

## 0.0.5 and prior

* Initial versions with maintenance updates
