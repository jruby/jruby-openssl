# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSecurityHelper < TestCase

  def setup; require 'openssl'; require 'java'
    super
  end

  def test_cert_factory_provider_leak # GH-94
    assert provider = org.jruby.ext.openssl.SecurityHelper.getSecurityProvider
    assert_equal 'BC', provider.name
    factory1 = org.jruby.ext.openssl.SecurityHelper.getCertificateFactory('X.509')
    factory2 = org.jruby.ext.openssl.SecurityHelper.getCertificateFactory('X.509')
    assert_not_same factory1, factory2
    assert_equal 'BC', factory1.provider.name
    assert_equal 'BC', factory2.provider.name
    # assert_same factory1.getProvider, factory2.getProvider

    java.security.cert.CertificateFactory.class_eval do
      field_reader :certFacSpi
    end

    spi1 = factory1.certFacSpi; spi2 = factory2.certFacSpi

    if spi1.is_a? org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory
      org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory.class_eval do
        field_reader :bcHelper
      end
      if (spi1.bcHelper rescue nil)
        org.bouncycastle.jcajce.util.ProviderJcaJceHelper.class_eval do
          field_reader :provider rescue nil
        end
        if spi1.bcHelper.respond_to?(:provider)
          assert_same spi1.bcHelper.provider, spi2.bcHelper.provider
        end
      end
    end
  end if defined? JRUBY_VERSION

end