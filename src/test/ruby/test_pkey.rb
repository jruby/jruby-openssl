# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestPKey < TestCase

  def test_pkey_read
    key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArTlm5TxJp3WHMNmWIfo/\nWvkyhJCXc1S78Y9B8lSXxXnkRqX8Twxu5EkdUP0TwgD5gp0TGy7UPm/SgWlQOcqX\nqtdOWq/Hk29Ve9z6k6wTmst7NTefmm/7OqkeYmBhfhoECLCKBADM8ctjoqD63R0e\n3bUW2knq6vCS5YMmD76/5UoU647BzB9CjgDzjuTKEbXL5AvcO5wWDgHSp7CA+2t4\nIFQvQMrPso5mvm2hNvD19vI0VjiY21rKgkJQAXSrLgkJg/fTL2wQiz10d2GnYsmx\nDeJCiBMwC+cmRW2eWePqaCPaWJwr92KsIiry+LgyGb3y01SUVV8kQgQXazutHqfu\ncQIDAQAB\n-----END PUBLIC KEY-----\n"

    # assert OpenSSL::PKey::RSA.new(key).public?

    pkey = OpenSSL::PKey.read(key)
    assert_same OpenSSL::PKey::RSA, pkey.class
    assert pkey.public?
    assert_equal OpenSSL::PKey::RSA.new(key).n, pkey.n
    assert_equal OpenSSL::PKey::RSA.new(key).e, pkey.e
  end

end
