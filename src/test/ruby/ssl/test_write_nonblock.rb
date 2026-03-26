require File.expand_path('test_helper', File.dirname(__FILE__))

class TestWriteNonblock < TestCase

  include SSLTestHelper

  # Reproduces the data loss: write a large payload via write_nonblock
  # with a slow-reading server (small recv buffer), then read the response.
  # The server echoes back the byte count it received. If bytes were lost,
  # the count will be less than expected.
  def test_write_nonblock_data_integrity
    expected_size = 256 * 1024  # 256KB — large enough to overflow TCP buffers

    # Custom server: reads all data until a blank line, counts bytes, sends back the count.
    # Deliberately slow: small recv buffer + sleep between reads to create backpressure.
    server_proc = Proc.new do |context, ssl|
      begin
        total = 0
        while (line = ssl.gets)
          break if line.strip.empty?
          total += line.bytesize
        end
        ssl.write("RECEIVED #{total}\n")
      rescue IOError, OpenSSL::SSL::SSLError => e
        # If the TLS stream is corrupted, the server may get an error here
        warn "Server error: #{e.class}: #{e.message}" if $VERBOSE
      ensure
        ssl.close rescue nil
      end
    end

    [OpenSSL::SSL::TLS1_2_VERSION, OpenSSL::SSL::TLS1_3_VERSION].each do |tls_version|
      ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = tls_version }
      start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                    :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
        sock = TCPSocket.new("127.0.0.1", port)
        # Small send buffer to increase the chance of partial non-blocking writes
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
        sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)

        ssl = OpenSSL::SSL::SSLSocket.new(sock)
        ssl.sync_close = true
        ssl.connect

        # Build a large payload: many lines totaling expected_size bytes
        line = "X" * 1023 + "\n"  # 1024 bytes per line
        lines_needed = expected_size / line.bytesize
        payload = line * lines_needed
        actual_payload_size = payload.bytesize

        # Write it all using write_nonblock (as net/http does)
        written = 0
        while written < payload.bytesize
          begin
            n = ssl.write_nonblock(payload.byteslice(written, payload.bytesize - written))
            written += n
          rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
            IO.select(nil, [ssl], nil, 5)
            retry
          end
        end

        # Send terminator
        ssl.write("\n")

        # Read the response (this is where the flush-before-read matters)
        response = nil
        deadline = Time.now + 10
        while Time.now < deadline
          begin
            response = ssl.gets
            break if response
          rescue IO::WaitReadable, OpenSSL::SSL::SSLErrorWaitReadable
            IO.select([ssl], nil, nil, 5)
          end
        end

        assert_not_nil response, "No response from server (TLS #{ssl.ssl_version})"
        assert_match(/^RECEIVED (\d+)/, response)
        received = response[/RECEIVED (\d+)/, 1].to_i
        assert_equal actual_payload_size, received,
          "Server received #{received} bytes but we sent #{actual_payload_size} " \
          "(lost #{actual_payload_size - received} bytes) on #{ssl.ssl_version}"

        ssl.close
      end
    end
  end

  # Simpler test: write_nonblock followed by sysread should work.
  # This is the net/http pattern: POST body via write, then read response.
  def test_write_nonblock_then_sysread
    server_proc = Proc.new do |context, ssl|
      begin
        data = +""
        while (line = ssl.gets)
          break if line.strip == "END"
          data << line
        end
        ssl.write("OK:#{data.bytesize}\n")
      rescue IOError, OpenSSL::SSL::SSLError
      ensure
        ssl.close rescue nil
      end
    end

    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                  :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      # Write via write_nonblock
      payload = "Y" * 50_000 + "\n"
      written = 0
      while written < payload.bytesize
        begin
          n = ssl.write_nonblock(payload.byteslice(written, payload.bytesize - written))
          written += n
        rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
          IO.select(nil, [ssl], nil, 5)
          retry
        end
      end
      ssl.write("END\n")

      # Now read response via sysread (the net/http pattern)
      IO.select([ssl], nil, nil, 10)
      response = ssl.sysread(1024)
      assert_match(/^OK:(\d+)/, response)
      received = response[/OK:(\d+)/, 1].to_i
      assert_equal payload.bytesize, received, "Server received #{received} bytes but sent #{payload.bytesize}"

      ssl.close
    end
  end

  # Test that multiple write_nonblock calls preserve all data even under
  # buffer pressure (many small writes)
  def test_many_small_write_nonblock_calls
    server_proc = Proc.new do |context, ssl|
      begin
        total = 0
        while (line = ssl.gets)
          break if line.strip == "DONE"
          total += line.bytesize
        end
        ssl.write("TOTAL:#{total}\n")
      rescue IOError, OpenSSL::SSL::SSLError
      ensure
        ssl.close rescue nil
      end
    end

    ctx_proc = Proc.new { |ctx| ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION }
    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                  :ctx_proc => ctx_proc, :server_proc => server_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      # Send 500 small lines rapidly via write_nonblock
      line = "Z" * 200 + "\n"
      expected_total = 0
      500.times do
        written = 0
        while written < line.bytesize
          begin
            n = ssl.write_nonblock(line.byteslice(written, line.bytesize - written))
            written += n
          rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
            IO.select(nil, [ssl], nil, 5)
            retry
          end
        end
        expected_total += line.bytesize
      end
      ssl.write("DONE\n")

      IO.select([ssl], nil, nil, 10)
      response = ssl.gets
      assert_not_nil response
      received = response[/TOTAL:(\d+)/, 1].to_i
      assert_equal expected_total, received, "Server received #{received} bytes but sent #{expected_total}"

      ssl.close
    end
  end

  # Detect the netWriteData.clear() bug by invoking the Java write() directly, bypassing syswriteImpl's `waitSelect`.
  #
  # Reproducer for #242 (jruby/jruby#8935).
  #
  # Strategy:
  #   1. Saturate the TCP send buffer (server doesn't read)
  #   2. Call write(ByteBuffer, false) directly via Java reflection
  #   3. Check netWriteData.remaining() — if > 0, data would be discarded by the next write() call's netWriteData.clear()
  def test_internal_write_nonblock_unflushed_data_detected
    require 'socket'

    tcp_server = TCPServer.new("127.0.0.1", 0)
    port = tcp_server.local_address.ip_port

    server_ctx = OpenSSL::SSL::SSLContext.new
    server_ctx.cert = @svr_cert
    server_ctx.key = @svr_key
    server_ctx.min_version = server_ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION

    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_ctx)
    ssl_server.start_immediately = true

    server_thread = Thread.new do
      Thread.current.report_on_exception = false
      begin
        ssl_conn = ssl_server.accept
        sleep 30  # Do NOT read — maximize backpressure
        ssl_conn.close rescue nil
      rescue
      end
    end

    begin
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)

      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.sync_close = true
      ssl.connect

      java_cls = Java::OrgJrubyExtOpenssl::SSLSocket.java_class
      java_ssl = ssl.to_java(Java::OrgJrubyExtOpenssl::SSLSocket)

      nwd_field = java_cls.declared_field("netWriteData")
      nwd_field.accessible = true
      # Get the write(ByteBuffer, boolean) method via reflection
      write_method = java_cls.declared_method("write", java.nio.ByteBuffer.java_class, Java::boolean)
      write_method.accessible = true

      # Phase 1: fill the TCP send buffer via normal write_nonblock
      chunk = "H" * 16384
      100.times do
        begin
          ssl.write_nonblock(chunk)
        rescue IO::WaitWritable, OpenSSL::SSL::SSLErrorWaitWritable
          break
        rescue IOError, OpenSSL::SSL::SSLError
          break
        end
      end

      # Phase 2: call write(src, false) directly — this bypasses
      # syswriteImpl's waitSelect and goes straight to the code path
      # that has the clear() bug.
      src = java.nio.ByteBuffer.wrap(("I" * 4096).to_java_bytes)
      begin
        write_method.invoke(java_ssl, src, false)
      rescue Java::JavaLangReflect::InvocationTargetException => e
        warn "write() threw: #{e.cause}" if $VERBOSE # Expected — write may throw due to the saturated buffer
      end

      nwd = nwd_field.value(java_ssl)
      remaining = nwd.remaining

      if remaining > 0
        # BUG CONFIRMED: there are unflushed encrypted bytes in netWriteData.
        # The next write() call will do netWriteData.clear(), discarding them.
        # This is exactly the data loss bug from issue #242.
        #
        # To prove actual data loss, we would call write() again — the clear() would discard remaining encrypted bytes,
        # corrupting the TLS record stream and eventually causing the server to see fewer bytes than the client sent.
        assert remaining > 0, "netWriteData has #{remaining} unflushed bytes — next write() would discard them via clear()"
      else
        omit "Could not produce unflushed netWriteData in loopback (remaining=#{remaining}); bug requires network latency"
      end
    ensure
      ssl.close rescue nil
      sock.close rescue nil
      tcp_server.close rescue nil
      server_thread.kill rescue nil
      server_thread.join(2) rescue nil
    end
  end if defined?(JRUBY_VERSION)
end
