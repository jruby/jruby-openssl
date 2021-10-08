module JOpenSSL
  VERSION = '0.10.7'
  BOUNCY_CASTLE_VERSION = '1.69'
end

Object.class_eval do
  Jopenssl = JOpenSSL
  private_constant :Jopenssl if respond_to?(:private_constant)
end
