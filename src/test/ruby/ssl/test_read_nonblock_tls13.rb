# frozen_string_literal: false
# Regression tests for:
#   https://github.com/jruby/jruby-openssl/issues/271
#   https://github.com/jruby/jruby-openssl/issues/305
#   https://github.com/jruby/jruby-openssl/issues/317
#
# Root cause: readAndUnwrap() in SSLSocket.java called doHandshake(blocking)
# (the 1-arg overload that hardcodes exception=true) when processing TLS 1.3
# post-handshake records (NewSessionTicket).  When selectNow()==0 inside that
# doHandshake, it threw SSLErrorWaitReadable even when the caller passed
# exception:false, violating the non-blocking contract.
#
# Fix: readAndUnwrap now accepts and forwards the exception flag to
# doHandshake(blocking, exception), and returns a WOULD_BLOCK sentinel
# that propagates back through read() and sysreadImpl() as :wait_readable.
#
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestReadNonblockTLS13 < TestCase

  include SSLTestHelper

  # ── helpers ──────────────────────────────────────────────────────────

  # Set up a TLS 1.3 server where the server does NOT read, so the
  # client's send buffer saturates. Yields |ssl, port| to the block.
  # This forces selectNow()==0 inside doHandshake when processing
  # TLS 1.3 post-handshake records.
  def with_saturated_tls13_client
    require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.ssl_version = "TLSv1_3"

    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)
    ssl_server.start_immediately = true

    server_ready = Queue.new
    server_thread = Thread.new do
      Thread.current.report_on_exception = false
      begin
        ssl_conn = ssl_server.accept
        server_ready << :ready
        # Do NOT read — the client's send buffer will fill up
        sleep 5
        ssl_conn.close rescue nil
      rescue
        server_ready << :error
      end
    end

    begin
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)

      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      server_ready.pop  # wait for server accept

      # Saturate send buffer
      chunk = "X" * 16384
      100.times do
        begin
          ssl.write_nonblock(chunk)
        rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
          break
        rescue
          break
        end
      end

      yield ssl
    ensure
      ssl.close rescue nil
      sock.close rescue nil
      tcp_server.close rescue nil
      server_thread.kill rescue nil
      server_thread.join(2) rescue nil
    end
  end

  # Same as above but for TLS 1.2 (control)
  def with_saturated_tls12_client
    require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION

    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)
    ssl_server.start_immediately = true

    server_ready = Queue.new
    server_thread = Thread.new do
      Thread.current.report_on_exception = false
      begin
        ssl_conn = ssl_server.accept
        server_ready << :ready
        sleep 5
        ssl_conn.close rescue nil
      rescue
        server_ready << :error
      end
    end

    begin
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)

      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      server_ready.pop

      chunk = "X" * 16384
      100.times do
        begin
          ssl.write_nonblock(chunk)
        rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
          break
        rescue
          break
        end
      end

      yield ssl
    ensure
      ssl.close rescue nil
      sock.close rescue nil
      tcp_server.close rescue nil
      server_thread.kill rescue nil
      server_thread.join(2) rescue nil
    end
  end

  # ── TLS 1.3 + saturated buffer (the exact production bug scenario) ──

  # Core reproducer: exception:false must return :wait_readable, not throw.
  def test_read_nonblock_exception_false_saturated_tls13
    with_saturated_tls13_client do |ssl|
      assert_equal "TLSv1.3", ssl.ssl_version

      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result
    end
  end

  # exception:true must raise SSLErrorWaitReadable (not EAGAIN or IOError).
  def test_read_nonblock_exception_true_saturated_tls13
    with_saturated_tls13_client do |ssl|
      assert_equal "TLSv1.3", ssl.ssl_version

      raised = assert_raise(OpenSSL::SSL::SSLErrorWaitReadable) do
        ssl.read_nonblock(1024)
      end
      assert_equal "read would block", raised.message
    end
  end

  # httprb code path: read_nonblock with buffer + exception:false
  def test_read_nonblock_with_buffer_exception_false_saturated_tls13
    with_saturated_tls13_client do |ssl|
      buf = ''
      result = ssl.read_nonblock(1024, buf, exception: false)
      assert_equal :wait_readable, result
    end
  end

  # Calling through sysread_nonblock directly (as some gems do)
  def test_sysread_nonblock_exception_false_saturated_tls13
    with_saturated_tls13_client do |ssl|
      result = ssl.send(:sysread_nonblock, 1024, exception: false)
      assert_equal :wait_readable, result
    end
  end

  # Multiple consecutive read_nonblock calls must all return :wait_readable
  def test_read_nonblock_repeated_calls_saturated_tls13
    with_saturated_tls13_client do |ssl|
      5.times do |i|
        result = ssl.read_nonblock(1024, exception: false)
        assert_equal :wait_readable, result, "iteration #{i}"
      end
    end
  end

  # ── TLS 1.2 + saturated buffer (control — no post-handshake messages) ─

  # TLS 1.2 has no post-handshake messages, so the bug path is never hit.
  def test_read_nonblock_exception_false_saturated_tls12
    with_saturated_tls12_client do |ssl|
      assert_equal "TLSv1.2", ssl.ssl_version

      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result
    end
  end

  def test_read_nonblock_exception_true_saturated_tls12
    with_saturated_tls12_client do |ssl|
      assert_equal "TLSv1.2", ssl.ssl_version

      assert_raise(OpenSSL::SSL::SSLErrorWaitReadable) do
        ssl.read_nonblock(1024)
      end
    end
  end

  # ── TLS 1.3 normal (unsaturated) tests ─────────────────────────────

  def test_read_nonblock_exception_false_tls13
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      10.times do
        result = ssl.read_nonblock(1024, exception: false)
        assert [:wait_readable, String].any? { |t| t === result },
               "Expected :wait_readable or String, got #{result.inspect}"
        break if result == :wait_readable
      end
      ssl.close
    end
  end

  def test_read_nonblock_exception_true_tls13
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      assert_raise(OpenSSL::SSL::SSLErrorWaitReadable) do
        10.times { ssl.read_nonblock(1024) }
      end
      ssl.close
    end
  end

  # ── TLS 1.2 normal (unsaturated) tests (control) ───────────────────

  def test_read_nonblock_exception_false_tls12
    ctx_proc = Proc.new { |ctx| ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.2", ssl.ssl_version

      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result
      ssl.close
    end
  end

  # ── Data round-trip: TLS 1.3 read/write still works ────────────────

  def test_write_read_roundtrip_tls13
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      ssl.write("hello\n")
      # Wait for echo data to arrive with a generous timeout
      IO.select([ssl], nil, nil, 5)
      # The first read_nonblock may consume a post-handshake message;
      # retry until we get the application data.
      data = nil
      10.times do
        begin
          data = ssl.read_nonblock(1024)
          break
        rescue OpenSSL::SSL::SSLErrorWaitReadable
          IO.select([ssl], nil, nil, 2)
        end
      end
      assert_equal "hello\n", data

      ssl.close
    end
  end

  def test_write_read_roundtrip_nonblock_exception_false_tls13
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      ssl.write("world\n")
      # Wait for echo data to arrive
      IO.select([ssl], nil, nil, 5)

      # Read with exception:false — might get :wait_readable first if
      # the engine is processing a post-handshake record.
      result = nil
      10.times do
        result = ssl.read_nonblock(1024, exception: false)
        if result == :wait_readable
          IO.select([ssl], nil, nil, 2)
          next
        end
        break
      end
      assert_kind_of String, result
      assert_equal "world\n", result

      # No more data — should return :wait_readable
      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result

      ssl.close
    end
  end

  # ── Post-write read with saturated buffer ───────────────────────────

  # After a write+read cycle the post-handshake messages are consumed;
  # a subsequent read_nonblock should simply return :wait_readable.
  def test_read_nonblock_after_write_tls13
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      ssl.write("test\n")
      sleep 0.1
      begin; ssl.read_nonblock(1024); rescue OpenSSL::SSL::SSLErrorWaitReadable; end

      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result
      ssl.close
    end
  end

  # ── connect_nonblock + read_nonblock ────────────────────────────────

  def test_read_nonblock_with_connect_nonblock_tls13
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true

      begin
        ssl.connect_nonblock
      rescue IO::WaitReadable
        IO.select([ssl]); retry
      rescue IO::WaitWritable
        IO.select(nil, [ssl]); retry
      end

      assert_equal "TLSv1.3", ssl.ssl_version
      sleep 0.05

      10.times do
        result = ssl.read_nonblock(1024, exception: false)
        assert [:wait_readable, String].any? { |t| t === result },
               "Expected :wait_readable or String, got #{result.inspect}"
        break if result == :wait_readable
      end
      ssl.close
    end
  end

  # connect_nonblock + saturated buffer + read_nonblock
  def test_read_nonblock_connect_nonblock_saturated_tls13
    require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.ssl_version = "TLSv1_3"

    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)
    ssl_server.start_immediately = true

    server_ready = Queue.new
    server_thread = Thread.new do
      Thread.current.report_on_exception = false
      begin
        ssl_conn = ssl_server.accept
        server_ready << :ready
        sleep 5
        ssl_conn.close rescue nil
      rescue
        server_ready << :error
      end
    end

    begin
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)

      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true

      begin
        ssl.connect_nonblock
      rescue IO::WaitReadable
        IO.select([ssl]); retry
      rescue IO::WaitWritable
        IO.select(nil, [ssl]); retry
      end

      assert_equal "TLSv1.3", ssl.ssl_version
      server_ready.pop

      chunk = "X" * 16384
      100.times do
        begin
          ssl.write_nonblock(chunk)
        rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
          break
        rescue
          break
        end
      end

      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result
    ensure
      ssl.close rescue nil
      sock.close rescue nil
      tcp_server.close rescue nil
      server_thread.kill rescue nil
      server_thread.join(2) rescue nil
    end
  end

  # ── Concurrent stress ──────────────────────────────────────────────

  def test_read_nonblock_tls13_concurrent_stress
    ctx_proc = Proc.new { |ctx| ctx.ssl_version = "TLSv1_3" }
    errors = Queue.new

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      threads = 5.times.map do |t|
        Thread.new do
          20.times do |i|
            begin
              sock = TCPSocket.new("127.0.0.1", port)
              ssl = OpenSSL::SSL::SSLSocket.new(sock)
              ssl.sync_close = true
              ssl.connect

              5.times do
                result = ssl.read_nonblock(1024, exception: false)
                break if result == :wait_readable
              end
            rescue OpenSSL::SSL::SSLErrorWaitReadable
              errors << "Thread #{t} iter #{i}: SSLErrorWaitReadable thrown with exception:false"
            rescue Errno::EAGAIN
              errors << "Thread #{t} iter #{i}: EAGAIN thrown with exception:false"
            rescue
              # Other errors (connection reset, etc.) are acceptable
            ensure
              ssl.close rescue nil
              sock.close rescue nil
            end
          end
        end
      end

      threads.each { |t| t.join(10) }
    end

    collected = []
    collected << errors.pop until errors.empty?
    assert collected.empty?, "Got #{collected.size} exception leaks:\n#{collected.first(5).join("\n")}"
  end

end
