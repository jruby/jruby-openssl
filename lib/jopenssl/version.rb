module JOpenSSL
  VERSION = '0.16.3.dev'
  BOUNCY_CASTLE_VERSION = '1.85'
end

Object.class_eval do
  Jopenssl = JOpenSSL
  private_constant :Jopenssl if respond_to?(:private_constant)
  deprecate_constant :Jopenssl if respond_to?(:deprecate_constant)
end
