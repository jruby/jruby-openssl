# frozen_string_literal: false
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

  def test_sync_close_without_connect
    require 'socket'
    Socket.open(:INET, :STREAM) do |socket|
      assert ! socket.closed?
      ssl = OpenSSL::SSL::SSLSocket.new(socket)
      ssl.sync_close = true
      assert ! ssl.closed?
      ssl.close
      assert socket.closed?
    end
  end

  include SSLTestHelper

  def test_ssl_sysread_blocking_error
    start_server(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      server_connect(port) do |ssl|
        ssl.write("abc\n")
        # assert_raise(TypeError) { ssl.sysread(4, exception: false) }
        buf = ''
        assert_raise(ArgumentError) { ssl.sysread(4, buf, exception: false) }
        assert_equal '', buf
        assert_equal buf.object_id, ssl.sysread(4, buf).object_id
        assert_equal "abc\n", buf
      end
    end
  end if RUBY_VERSION > '2.0'

end