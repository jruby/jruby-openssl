# frozen_string_literal: false

require File.expand_path('test_helper', File.dirname(__FILE__))

class TestReadNonblockTLS13 < TestCase

  include SSLTestHelper

  # ── helpers ──────────────────────────────────────────────────────────

  # Set up a TLS 1.3 server where the server does NOT read, so the
  # client's send buffer saturates. Yields |ssl, port| to the block.
  # This forces selectNow()==0 inside doHandshake when processing
  # TLS 1.3 post-handshake records.
  def with_saturated_tls13_client; require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.min_version = server_ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION

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
  def with_saturated_tls12_client; require 'socket'

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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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
  def test_read_nonblock_connect_nonblock_saturated_tls13; require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.min_version = server_ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION

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
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
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

  # ── Buffered I/O: multi-chunk read_nonblock ──────────────────────
  #
  # Write a large payload (bigger than one TLS record ~16KB), read it
  # back in small read_nonblock chunks.  Exercises:
  #   - appReadData having leftover bytes across read() calls
  #   - netReadData having multiple TLS records
  #   - the netReadData.position()==0 guard NOT firing when there IS data

  def test_multi_chunk_read_nonblock_tls13
    large = "A" * 1024 + "\n"  # each line is 1025 bytes
    total_lines = 30            # ~30KB total, exceeds one TLS record
    payload = large * total_lines

    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      # Write the payload — the echo server will echo each line back
      ssl.write(payload)

      # Read it all back in small non-blocking chunks
      received = +""
      deadline = Time.now + 5
      while received.bytesize < payload.bytesize && Time.now < deadline
        begin
          chunk = ssl.read_nonblock(1024)
          received << chunk
        rescue OpenSSL::SSL::SSLErrorWaitReadable
          IO.select([ssl], nil, nil, 1)
        end
      end

      assert_equal payload.bytesize, received.bytesize
      assert_equal payload, received
      ssl.close
    end
  end

  def test_multi_chunk_read_nonblock_tls12
    large = "A" * 1024 + "\n"
    total_lines = 30
    payload = large * total_lines

    ctx_proc = Proc.new { |ctx| ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.2", ssl.ssl_version

      ssl.write(payload)

      received = +""
      deadline = Time.now + 5
      while received.bytesize < payload.bytesize && Time.now < deadline
        begin
          chunk = ssl.read_nonblock(1024)
          received << chunk
        rescue OpenSSL::SSL::SSLErrorWaitReadable
          IO.select([ssl], nil, nil, 1)
        end
      end

      assert_equal payload.bytesize, received.bytesize
      assert_equal payload, received
      ssl.close
    end
  end

  # ── Buffered I/O: multi-chunk with exception:false ─────────────────

  def test_multi_chunk_read_nonblock_exception_false_tls13
    large = "B" * 1024 + "\n"
    total_lines = 30
    payload = large * total_lines

    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      ssl.write(payload)

      received = +""
      deadline = Time.now + 5
      while received.bytesize < payload.bytesize && Time.now < deadline
        result = ssl.read_nonblock(1024, exception: false)
        case result
        when :wait_readable
          IO.select([ssl], nil, nil, 1)
        when :wait_writable
          IO.select(nil, [ssl], nil, 1)
        when String
          received << result
        end
      end

      assert_equal payload.bytesize, received.bytesize
      assert_equal payload, received
      ssl.close
    end
  end

  # ── Buffered I/O: partial read_nonblock ────────────────────────────
  #
  # Adapted from MRI's test_read_nonblock_without_session pattern.
  # Write data, read a small amount (leaves data in appReadData buffer),
  # then read the rest.

  def test_partial_read_nonblock_tls13
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      ssl.write("hello world\n")
      IO.select([ssl], nil, nil, 5)

      # Read just 5 bytes — the rest stays in appReadData buffer
      first = nil
      10.times do
        begin
          first = ssl.read_nonblock(5)
          break
        rescue OpenSSL::SSL::SSLErrorWaitReadable
          IO.select([ssl], nil, nil, 2)
        end
      end
      assert_equal "hello", first

      # Read the rest — should come from the buffer, no network I/O needed
      rest = ssl.read_nonblock(100)
      assert_equal " world\n", rest

      # Nothing left
      result = ssl.read_nonblock(100, exception: false)
      assert_equal :wait_readable, result

      ssl.close
    end
  end

  # ── Buffered I/O: multiple write+read cycles ───────────────────────
  #
  # Adapted from MRI's test_parallel pattern (single connection version).
  # Verifies the engine state stays clean across many exchanges after
  # TLS 1.3 post-handshake processing.

  def test_multiple_write_read_cycles_tls13
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      str = "x" * 1000 + "\n"
      10.times do |i|
        ssl.puts(str)
        response = ssl.gets
        assert_equal str, response, "cycle #{i}: data mismatch"
      end

      ssl.close
    end
  end

  def test_multiple_write_read_cycles_tls12
    ctx_proc = Proc.new { |ctx| ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.2", ssl.ssl_version

      str = "x" * 1000 + "\n"
      10.times do |i|
        ssl.puts(str)
        response = ssl.gets
        assert_equal str, response, "cycle #{i}: data mismatch"
      end

      ssl.close
    end
  end

  # ── Buffered I/O: sysread/syswrite round-trip ──────────────────────
  #
  # Adapted from MRI's test_sysread_and_syswrite: multiple cycles of
  # syswrite/sysread with exact byte counts.  Exercises the blocking
  # sysreadImpl path on TLS 1.3.

  def test_sysread_syswrite_tls13
    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true, :ctx_proc => ctx_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      str = "x" * 100 + "\n"

      # Cycle 1: basic syswrite/sysread
      ssl.syswrite(str)
      newstr = ssl.sysread(str.bytesize)
      assert_equal str, newstr

      # Cycle 2: sysread into a buffer
      buf = String.new
      ssl.syswrite(str)
      assert_same buf, ssl.sysread(str.bytesize, buf)
      assert_equal str, buf

      # Cycle 3: another round
      ssl.syswrite(str)
      assert_equal str, ssl.sysread(str.bytesize)

      ssl.close
    end
  end

  # ── Buffered I/O: large payload to exercise netReadData leftovers ──
  #
  # The server writes a large payload in one shot.  The client reads
  # it in small read_nonblock chunks.  When socketChannelImpl().read()
  # pulls in multiple TLS records at once, netReadData has leftover
  # bytes (position > 0) after the first unwrap.  The sysreadImpl loop
  # must continue processing (NOT call waitSelect) when netReadData
  # still has data.
  #
  # This is the critical regression test for the
  # netReadData.position()==0 guard — it must NOT wait when there's
  # still buffered network data.

  def test_large_server_write_small_client_reads_tls13
    # Custom server_proc: read a size header, then send that many bytes
    server_proc = Proc.new do |context, ssl|
      begin
        line = ssl.gets  # read the request
        if line && line.strip =~ /^SEND (\d+)$/
          size = $1.to_i
          data = "Z" * size + "\n"
          ssl.write(data)
        end
      rescue IOError, OpenSSL::SSL::SSLError
      ensure
        ssl.close rescue nil
      end
    end

    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                  :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      # Ask the server to send 48KB — this will be split across multiple
      # TLS records (~16KB each), giving us netReadData with leftover bytes.
      expected_size = 48 * 1024
      ssl.puts("SEND #{expected_size}")

      received = +""
      expected_total = expected_size + 1  # +1 for the trailing "\n"
      deadline = Time.now + 5
      while received.bytesize < expected_total && Time.now < deadline
        result = ssl.read_nonblock(4096, exception: false)
        case result
        when :wait_readable
          IO.select([ssl], nil, nil, 1)
        when :wait_writable
          IO.select(nil, [ssl], nil, 1)
        when String
          received << result
        end
      end

      assert_equal expected_total, received.bytesize,
        "Expected #{expected_total} bytes but got #{received.bytesize}"
      assert_equal "Z" * expected_size + "\n", received
      ssl.close
    end
  end

  def test_large_server_write_small_client_reads_tls12
    server_proc = Proc.new do |context, ssl|
      begin
        line = ssl.gets
        if line && line.strip =~ /^SEND (\d+)$/
          size = $1.to_i
          data = "Z" * size + "\n"
          ssl.write(data)
        end
      rescue IOError, OpenSSL::SSL::SSLError
      ensure
        ssl.close rescue nil
      end
    end

    ctx_proc = Proc.new { |ctx| ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                  :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.2", ssl.ssl_version

      expected_size = 48 * 1024
      ssl.puts("SEND #{expected_size}")

      received = +""
      expected_total = expected_size + 1
      deadline = Time.now + 5
      while received.bytesize < expected_total && Time.now < deadline
        result = ssl.read_nonblock(4096, exception: false)
        case result
        when :wait_readable
          IO.select([ssl], nil, nil, 1)
        when :wait_writable
          IO.select(nil, [ssl], nil, 1)
        when String
          received << result
        end
      end

      assert_equal expected_total, received.bytesize
      assert_equal "Z" * expected_size + "\n", received
      ssl.close
    end
  end

  # ── Wasted iteration detection ─────────────────────────────────────
  #
  # TLS 1.3 post-handshake record (NewSessionTicket) that produces 0 app bytes, status is OK
  #
  # We detect this by inspecting the internal `status` field after read_nonblock returns :wait_readable.
  # If status is BUFFER_UNDERFLOW, the extra iteration occurred.  If status is OK, sysreadImpl handled
  # the read==0/status==OK case directly.
  def test_internal_no_wasted_readAndUnwrap_iteration_tls13; require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.ssl_version = "TLSv1_3"

    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)
    ssl_server.start_immediately = true

    server_thread = Thread.new do
      Thread.current.report_on_exception = false
      begin
        conn = ssl_server.accept
        sleep 5
        conn.close rescue nil
      rescue
      end
    end

    begin
      sock = TCPSocket.new("127.0.0.1", port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect
      assert_equal "TLSv1.3", ssl.ssl_version

      # Wait for the server's NewSessionTicket to arrive on the wire
      # after the blocking connect has finished.
      sleep 0.1

      # Access the private `status` field via Java reflection
      java_cls = Java::OrgJrubyExtOpenssl::SSLSocket.java_class
      status_field = java_cls.declared_field("status")
      status_field.accessible = true
      java_ssl = ssl.to_java(Java::OrgJrubyExtOpenssl::SSLSocket)

      result = ssl.read_nonblock(1024, exception: false)
      assert_equal :wait_readable, result

      status_after = status_field.value(java_ssl).to_s
      # If sysreadImpl properly handles read==0 with any status (not just BUFFER_UNDERFLOW),
      # only one readAndUnwrap call is made and status stays OK.
      assert_equal "OK", status_after,
        "Expected status OK (single readAndUnwrap call) but got #{status_after} " \
        "(extra wasted iteration through readAndUnwrap occurred)"

      ssl.close
    ensure
      ssl.close rescue nil
      sock.close rescue nil
      tcp_server.close rescue nil
      server_thread.kill rescue nil
      server_thread.join(2) rescue nil
    end
  end if defined?(JRUBY_VERSION)
end
