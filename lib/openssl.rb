# frozen_string_literal: true

require 'jopenssl/load'

module OpenSSL
  autoload :Config, 'openssl/config' unless const_defined?(:Config, false)
  autoload :PKCS12, 'openssl/pkcs12'
end

=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'LICENCE'.)
=end

require_relative 'openssl/bn'
require_relative 'openssl/pkey'
require_relative 'openssl/cipher'
#require_relative 'openssl/config' if OpenSSL.const_defined?(:Config, false)
require_relative 'openssl/digest'
require_relative 'openssl/hmac'
require_relative 'openssl/x509'
require_relative 'openssl/ssl'
require_relative 'openssl/pkcs5'

module OpenSSL
  # call-seq:
  #   OpenSSL.secure_compare(string, string) -> boolean
  #
  # Constant time memory comparison. Inputs are hashed using SHA-256 to mask
  # the length of the secret. Returns +true+ if the strings are identical,
  # +false+ otherwise.
  def self.secure_compare(a, b)
    hashed_a = OpenSSL::Digest.digest('SHA256', a)
    hashed_b = OpenSSL::Digest.digest('SHA256', b)
    OpenSSL.fixed_length_secure_compare(hashed_a, hashed_b) && a == b
  end
end
