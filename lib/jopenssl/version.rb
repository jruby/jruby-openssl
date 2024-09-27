module JOpenSSL
  VERSION = '0.15.1'
  BOUNCY_CASTLE_VERSION = '1.78.1'
end

Object.class_eval do
  Jopenssl = JOpenSSL
  private_constant :Jopenssl if respond_to?(:private_constant)
  deprecate_constant :Jopenssl if respond_to?(:deprecate_constant)
end
