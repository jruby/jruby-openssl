=begin
= $RCSfile$ -- Ruby-space predefined Cipher subclasses

= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licenced under the same licence as Ruby.
  (See the file 'LICENCE'.)

= Version
  $Id$
=end

##
# Should we care what if somebody require this file directly?
#require 'openssl'

module OpenSSL
  class Cipher

    # Generate, set, and return a random key.
    # You must call cipher.encrypt or cipher.decrypt before calling this method.
    def random_key
      str = OpenSSL::Random.random_bytes(self.key_len)
      self.key = str
      return str
    end

    # Generate, set, and return a random iv.
    # You must call cipher.encrypt or cipher.decrypt before calling this method.
    def random_iv
      str = OpenSSL::Random.random_bytes(self.iv_len)
      self.iv = str
      return str
    end

    # This class is only provided for backwards compatibility.  Use OpenSSL::Digest in the future.
    class Cipher < Cipher
      # add warning
    end
  end # Cipher
end # OpenSSL
