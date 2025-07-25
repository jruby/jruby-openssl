module JOpenSSL
  VERSION = '0.15.6.dev'
  BOUNCY_CASTLE_VERSION = '1.81'
end

Object.class_eval do
  Jopenssl = JOpenSSL
  private_constant :Jopenssl if respond_to?(:private_constant)
  deprecate_constant :Jopenssl if respond_to?(:deprecate_constant)
end
