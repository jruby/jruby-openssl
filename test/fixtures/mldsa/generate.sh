#!/bin/sh
# Regenerate independent test fixtures with OpenSSL 3.5 or later.
set -eu
cd "$(dirname "$0")"
openssl version
: > empty.bin
printf '\000\001\002\177\200\376\377JRuby\000OpenSSL\n' > binary.bin
for parameter in 44 65 87; do
  name="ml-dsa-$parameter"
  openssl genpkey -algorithm "$name" -out "$name-seed-priv.pem"
  openssl pkey -provparam ml-dsa.output_formats=seed-only \
    -in "$name-seed-priv.pem" -out "$name-seed.pem"
  openssl pkey -provparam ml-dsa.output_formats=priv-only \
    -in "$name-seed-priv.pem" -out "$name-expanded.pem"
  openssl pkey -in "$name-seed.pem" -pubout -out "$name-public.pem"
  openssl pkcs8 -provparam ml-dsa.output_formats=priv-only -topk8 -in "$name-expanded.pem" -v2 aes-256-cbc -iter 2048 \
    -passout pass:mldsa-test-password -out "$name-encrypted.pem"
  for message in binary; do
    openssl pkeyutl -sign -inkey "$name-seed.pem" -in "$message.bin" \
      -out "$name-$message.sig"
    openssl pkeyutl -verify -pubin -inkey "$name-public.pem" \
      -in "$message.bin" -sigfile "$name-$message.sig"
  done
  # pkeyutl 3.5.7 cannot allocate its buffer for an empty file; use libcrypto.
  ruby -ropenssl -e '
    abort "native Ruby is required for independent fixtures" if defined?(JRUBY_VERSION)
    name = ARGV.fetch(0)
    key = OpenSSL::PKey.read(File.binread("#{name}-seed.pem"))
    signature = key.sign(nil, "")
    File.binwrite("#{name}-empty.sig", signature)
    abort "invalid empty-message signature" unless key.verify(nil, signature, "")
  ' "$name"
  # Verify every private encoding derives the same public key.
  for encoding in seed seed-priv expanded; do
    openssl pkey -in "$name-$encoding.pem" -pubout | cmp - "$name-public.pem"
  done
  openssl pkey -in "$name-encrypted.pem" -passin pass:mldsa-test-password \
    -pubout | cmp - "$name-public.pem"
done

chmod 644 *.pem *.bin *.sig
