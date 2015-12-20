# frozen_string_literal: false
#--
# = Ruby-space predefined Digest subclasses
#
# = Info
# 'OpenSSL for Ruby 2' project
# Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
# All rights reserved.
#
# = Licence
# This program is licensed under the same licence as Ruby.
# (See the file 'LICENCE'.)
#++

module OpenSSL
  class Digest
    # Deprecated.
    #
    # This class is only provided for backwards compatibility.
    class Digest < Digest # :nodoc:
      # Deprecated.
      #
      # See OpenSSL::Digest.new
      def initialize(*args)
        warn('Digest::Digest is deprecated; use Digest')
        super(*args)
      end
    end

  end # Digest

  # Returns a Digest subclass by +name+.
  #
  #   require 'openssl'
  #
  #   OpenSSL::Digest("MD5")
  #   # => OpenSSL::Digest::MD5
  #
  #   Digest("Foo")
  #   # => NameError: wrong constant name Foo

  def Digest(name)
    OpenSSL::Digest.const_get(name)
  end

  module_function :Digest

end # OpenSSL
