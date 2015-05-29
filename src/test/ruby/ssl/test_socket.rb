require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLSocket < TestCase

  def setup; super; require 'openssl' end

  def test_cipher
    io_stub = File.new __FILE__
    socket = OpenSSL::SSL::SSLSocket.new(io_stub)

    assert_nil socket.cipher
  end

  def test_attr_methods
    io_stub = File.new __FILE__
    socket = OpenSSL::SSL::SSLSocket.new(io_stub)

    assert socket.io
    assert_equal socket.io, socket.to_io
    assert ! socket.respond_to?(:'io=')
    # due compatibility :
    assert_equal socket.io, socket.instance_variable_get(:@io)

    assert socket.context
    assert ! socket.respond_to?(:'context=')
    # due compatibility :
    assert_equal socket.context, socket.instance_variable_get(:@context)

    assert_nil socket.hostname
    socket.hostname = '1.1.1.1'
    assert_equal '1.1.1.1', socket.hostname

    # MRI sync is false by default :
    # assert_equal false, socket.sync
    socket.sync = true
    assert_equal true, socket.sync

    # assert_equal false, socket.sync_close
    socket.sync_close = true
    assert_equal true, socket.sync_close

    socket.inspect
  end

end