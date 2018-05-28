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
    assert ! socket.respond_to?('io=')
    # due compatibility :
    assert_equal socket.io, socket.instance_variable_get(:@io)

    assert socket.context
    assert ! socket.respond_to?('context=')
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
    if RUBY_VERSION > '2.2'
      Socket.open(:INET, :STREAM) do |socket|
        assert ! socket.closed?
        ssl = OpenSSL::SSL::SSLSocket.new(socket)
        ssl.sync_close = true
        assert ! ssl.closed?
        ssl.close
        assert socket.closed?
      end
    else
      begin
        socket = UDPSocket.new :INET
        assert ! socket.closed?
        ssl = OpenSSL::SSL::SSLSocket.new(socket)
        ssl.sync_close = true
        assert ! ssl.closed?
        ssl.close
        assert socket.closed?
      ensure
        socket && socket.close rescue nil
      end
    end
  end

  include SSLTestHelper

  def test_ssl_sysread_blocking_error
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      server_connect(port) do |ssl|
        ssl.write("abc\n")
        # assert_raise(TypeError) { eval 'ssl.sysread(4, exception: false)' }
        buf = ''
        assert_raise(ArgumentError) { eval 'ssl.sysread(4, buf, exception: false)' }
        assert_equal '', buf
        assert_equal buf.object_id, ssl.sysread(4, buf).object_id
        assert_equal "abc\n", buf
      end
    end
  end if RUBY_VERSION > '2.2'

  def test_read_nonblock_no_exception
    ssl_pair do |s1, s2|
      assert_equal :wait_readable, eval('s2.read_nonblock 10, exception: false')
      s1.write "abc\ndef\n"
      IO.select [ s2 ]
      ret = eval('s2.read_nonblock 2, exception: false')
      assert_equal "ab", ret
      assert_equal "c\n", s2.gets
      ret = eval('s2.read_nonblock 10, exception: false')
      assert_equal("def\n", ret)
      s1.close
      sleep 0.1
      opts = { :exception => false }
      assert_equal nil, s2.read_nonblock(10, opts)
    end
  end if RUBY_VERSION > '2.2'

  def test_connect_non_connected; require 'socket'
    socket = OpenSSL::SSL::SSLSocket.new(Socket.new(:INET, :STREAM))
    begin
      socket.connect_nonblock
    rescue => e
      assert_equal Errno::EPIPE, e.class
      puts e.inspect if $VERBOSE
    ensure
      socket.close
    end
  end if RUBY_VERSION > '2.2'

  def test_connect_nonblock
    ssl_server = server
    thread = Thread.new do
      ssl_server.accept.tap { ssl_server.close }
    end

    host = "127.0.0.1"
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.ciphers = "ADH"
    client = TCPSocket.new host, server_port(ssl_server)
    client = OpenSSL::SSL::SSLSocket.new(client, ctx)
    begin
      client.connect_nonblock
    rescue OpenSSL::SSL::SSLErrorWaitReadable => e
      # #<OpenSSL::SSL::SSLErrorWaitReadable: read would block>
      puts e.inspect if $VERBOSE
    ensure
      thread.kill if thread.alive?
      client.close unless client.closed?
    end
  end if RUBY_VERSION > '2.2'

  def test_inherited_socket; require 'socket'
    inheritedSSLSocket = Class.new(OpenSSL::SSL::SSLSocket)

    io_stub = STDERR.dup
    ctx = OpenSSL::SSL::SSLContext.new

    assert socket = inheritedSSLSocket.new(io_stub, ctx) # does not raise
    assert socket.io.nonblock? if STDERR.respond_to?(:nonblock=) # >= 2.3
    socket.sync = true
    assert_equal true, socket.sync
  end

  private

  def server; require 'socket'
    host = "127.0.0.1"; port = 0
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.ciphers = "ADH"
    server = TCPServer.new(host, port)
    OpenSSL::SSL::SSLServer.new(server, ctx)
  end

  def client(port); require 'socket'
    host = "127.0.0.1"
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.ciphers = "ADH"
    client = TCPSocket.new(host, port)
    ssl = OpenSSL::SSL::SSLSocket.new(client, ctx)
    ssl.connect
    ssl.sync_close = true
    ssl
  end

  def server_port(ssl_server = server)
    ssl_server.to_io.local_address.ip_port
  end

  def ssl_pair
    ssl_server = server
    thread = Thread.new do
      ssl_server.accept.tap { ssl_server.close }
    end
    ssl_client = client server_port(ssl_server)
    ssl_socket = thread.value
    if block_given?
      begin
        yield ssl_client, ssl_socket
      ensure
        ssl_client.close unless ssl_client.closed?
        ssl_socket.close unless ssl_socket.closed?
      end
    else
      return ssl_client, ssl_socket
    end
  ensure
    thread.tap { thread.kill; thread.join } if thread && thread.alive?
  end

end