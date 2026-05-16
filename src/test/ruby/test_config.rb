# coding: US-ASCII
require File.expand_path('test_helper', File.dirname(__FILE__))
require "tempfile"

class TestSSL < TestCase
  def setup
    super
    file = Tempfile.open("openssl.cnf")
    file << <<__EOD__
HOME = .
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ./demoCA
certs                =                  ./certs
__EOD__
    file.close
    @tmpfile = file
    @it = OpenSSL::Config.new(file.path)
  end

  def test_s_parse
    c = OpenSSL::Config.parse('')
    assert_equal("[ default ]\n\n", c.to_s)
    c = OpenSSL::Config.parse(@it.to_s)
    assert_equal(['CA_default', 'ca', 'default'], c.sections.sort)
  end

  def test_s_parse_config
    ret = OpenSSL::Config.parse_config(@it.to_s)

    assert_equal(@it.sections.sort, ret.keys.sort)
    assert_equal(@it["default"], ret["default"])
  end

  def test_sections
    assert_equal(['CA_default', 'ca', 'default'], @it.sections.sort)
    Tempfile.create("openssl.cnf") { |f|
      f.write File.read(@tmpfile.path)
      f.puts "[ new_section ]"
      f.puts "foo = bar"
      f.puts "[ empty_section ]"
      f.close

      c = OpenSSL::Config.new(f.path)
      assert_equal(['CA_default', 'ca', 'default', 'empty_section', 'new_section'],
                   c.sections.sort)
    }
  end
end