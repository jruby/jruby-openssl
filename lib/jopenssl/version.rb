module JOpenSSL
  VERSION = '0.12.1.dev'
  BOUNCY_CASTLE_VERSION = '1.68'
end

Object.class_eval do
  Jopenssl = JOpenSSL
  private_constant :Jopenssl if respond_to?(:private_constant)
end
