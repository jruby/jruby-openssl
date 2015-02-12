require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLSocket < TestCase

  def setup; super; require 'openssl' end

  def test_cipher
    io_stub = File.new __FILE__
    socket = OpenSSL::SSL::SSLSocket.new(io_stub)

    assert_nil socket.cipher
  end

  def test_hostname
    io_stub = File.new __FILE__
    socket = OpenSSL::SSL::SSLSocket.new(io_stub)

    assert_nil socket.hostname
  end

end