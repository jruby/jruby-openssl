require 'base64'

Base64.module_eval do

  def self.strict_encode64(bin)
    [ bin ].pack("m0")
  end unless defined? Base64.strict_encode64

  def self.urlsafe_encode64(bin)
    strict_encode64(bin).tr("+/", "-_")
  end unless defined? Base64.urlsafe_encode64

  def self.strict_decode64(str)
    str.unpack("m0").first
  end unless defined? Base64.strict_decode64

  def self.urlsafe_decode64(str)
    strict_decode64(str.tr("-_", "+/"))
  end unless defined? Base64.urlsafe_decode64

end