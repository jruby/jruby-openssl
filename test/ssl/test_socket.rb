# frozen_string_literal: false
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLSocket < TestCase

  def setup; super; require 'openssl' end

  def test_cipher
    io_stub = File.new __FILE__
    socket = OpenSSL::SSL::SSLSocket.new(io_stub)

    assert_nil socket.cipher
  end

  # a connected socket's #cipher is [name, version, bits, alg_bits]
  # and the tuple must match an entry in ctx.ciphers so using_anon_cipher? works
  def test_cipher_connected_returns_tuple
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) do |server, port|
      ctx = OpenSSL::SSL::SSLContext.new
      server_connect(port, ctx) do |ssl|
        c = ssl.cipher
        assert_instance_of Array, c
        assert_equal 4, c.size
        assert_instance_of String, c[0] # cipher name
        assert_kind_of Integer, c[2]    # bits
        assert_kind_of Integer, c[3]    # alg_bits
        assert_include ctx.ciphers, c # foundation of using_anon_cipher?
      end
    end
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

  def test_blocking_sysread_interrupted_by_concurrent_close
    iterations = Integer(ENV.fetch('SSL_CLOSE_RACE_ITERATIONS', ITERATIONS))
    server_proc = proc { |_ctx, ssl| ssl.read rescue nil }
    completed = 0

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :server_proc => server_proc) do |_, port|
      iterations.times do |iteration|
        server_connect(port) do |ssl|
          started_queue = Queue.new
          reader = Thread.new do
            Thread.current.report_on_exception = false
            started_queue << true
            ssl.sysread(1)
          rescue IOError, EOFError, OpenSSL::SSL::SSLError, SystemCallError
          end

          started_queue.pop
          ssl.close

          if reader.join(1)
            completed += 1
          else
            backtrace = reader.backtrace
            # reader.kill
            # reader.join
            flunk "blocking sysread did not stop after concurrent close " \
                  "(iteration #{iteration + 1}/#{iterations}):\n  #{backtrace.join("\n  ")}"
          end
        ensure
          reader.kill if reader&.alive?
          reader.join if reader
        end
      end
    end

    assert_equal iterations, completed
  end

  def test_read_nonblock
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true) { |_, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION # avoid TLS 1.3 post-handshake records (see test_read_nonblock_tls13)
      server_connect(port, ctx) do |ssl|
        assert_equal :wait_readable, ssl.read_nonblock(100, exception: false)
        ssl.write("abc\n")
        IO.select [ssl]
        assert_equal('a', ssl.read_nonblock(1))
        assert_equal("bc\n", ssl.read_nonblock(100))
        assert_equal :wait_readable, ssl.read_nonblock(100, exception: false)
      end
    }
  end

  def test_partial_tls_record_read_nonblock
    ready = Queue.new
    written = Queue.new
    result = Queue.new
    server_proc = proc do |_ctx, ssl|
      ready << true
      written.pop
      begin
        ssl.read_nonblock(1)
        result << :read
      rescue IO::WaitReadable
        result << :wait_readable
      end
    end

    ctx_proc = proc { |ctx| ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, ctx_proc: ctx_proc, server_proc: server_proc) do |_, port|
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
      server_connect(port, ctx) do |ssl|
        ready.pop
        ssl.io.write("\x17") # TLS application-data record type
        written << true
        assert_equal :wait_readable, result.pop
      end
    end
  end

  def test_readbyte
    server_proc = proc do |_ctx, ssl|
      ssl.write("ab")
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true, server_proc: server_proc) do |_, port|
      server_connect(port) do |ssl|
        assert_equal "a".ord, ssl.readbyte
        assert_equal "b".ord, ssl.readbyte
        assert_raise(EOFError) { ssl.readbyte }
      end
    end
  end

  def test_gets_chomp
    server_proc = proc do |_ctx, ssl|
      ssl.write("abc\n")
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true, server_proc: server_proc) do |_, port|
      server_connect(port) do |ssl|
        assert_equal "abc", ssl.gets(chomp: true)
        assert_nil ssl.gets(chomp: true)
      end
    end
  end

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
    host = "127.0.0.1"; port = 0
    server = TCPServer.new(host, port)
    ssl_server = OpenSSL::SSL::SSLServer.new(server, OpenSSL::SSL::SSLContext.new)
    # accept without running the server handshake: cert-less default context would
    # otherwise fail and close the socket, racing the client's non-blocking read and
    # surfacing a generic SSLError instead of WaitReadable
    ssl_server.start_immediately = false

    accepted = nil
    thread = Thread.new { accepted = ssl_server.accept rescue nil }

    host = "127.0.0.1"
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.ciphers = "AES"
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
      accepted&.close
      ssl_server.close
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

  def test_pending
    server_proc = proc do |_ctx, ssl|
      ssl.write("hello")
      ssl.read rescue nil # keep the connection open until the client is done
    end

    start_server(OpenSSL::SSL::VERIFY_NONE, true, server_proc: server_proc) do |_, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)

      assert_equal 0, ssl.pending # session not started yet

      ssl.connect
      assert_equal 0, ssl.pending # nothing decrypted yet

      assert_equal 'h', ssl.sysread(1) # blocking read decrypts the record into the SSL buffer
      assert_equal 4, ssl.pending # "ello" still buffered (decrypted)
      assert_equal 'ello', ssl.sysread(4)
      assert_equal 0, ssl.pending

      ssl.close
    end
  end


  def test_read_returns_after_peer_close_notify; require 'socket'
    server = TCPServer.new('127.0.0.1', 0)
    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ready = Queue.new

    server_thread = Thread.new do
      raw = server.accept
      raw.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)
      peer = OpenSSL::SSL::SSLSocket.new(raw, server_ctx)
      peer.accept
      peer.close # send close_notify but keep raw socket open
      server_ready << true
      sleep(4.5) # do not read; keep the client's TCP send buffer full
    rescue Exception => error
      server_ready << error
    ensure
      peer.close rescue nil if peer
      raw.close rescue nil if raw
    end

    sock = TCPSocket.new('127.0.0.1', server.addr[1])
    sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
    ssl = OpenSSL::SSL::SSLSocket.new(sock)
    ssl.sync_close = true
    ssl.connect
    ready = server_ready.pop
    fail(ready) if ready.is_a?(Exception)

    omit 'IO#nonblock= is unavailable' unless ssl.io.respond_to?(:nonblock=)
    ssl.io.nonblock = true

    filled = 0
    loop do
      written = ssl.io.write_nonblock('x' * 16_384)
      filled += written if written.is_a?(Integer)
      break if written == 0 || written == :wait_writable
    rescue IO::WaitWritable
      break
    end

    loop do
      written = ssl.io.write_nonblock('x')
      filled += written if written.is_a?(Integer)
      break if written == 0 || written == :wait_writable
    rescue IO::WaitWritable
      break
    end

    assert_operator filled, :>, 0

    close_thread = Thread.new { ssl.read(1) rescue nil }
    assert close_thread.join(2), 'read blocked while processing peer close_notify'
  ensure
    ssl&.io&.close rescue nil
    sock&.close rescue nil
    server&.close rescue nil
    server_thread&.join(5)
    close_thread&.join(1.5)
  end

  private

  def server(ssl_version: nil); require 'socket'
    host = "127.0.0.1"; port = 0
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.ssl_version = ssl_version if ssl_version
    server = TCPServer.new(host, port)
    OpenSSL::SSL::SSLServer.new(server, ctx)
  end

  def client(port, ssl_version: nil); require 'socket'
    host = "127.0.0.1"
    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.ssl_version = ssl_version if ssl_version
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
    ssl_server = server ssl_version: 'TLSv1_2'
    thread = Thread.new do
      ssl_server.accept.tap { ssl_server.close }
    end
    ssl_client = client server_port(ssl_server), ssl_version: 'TLSv1_2'
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
