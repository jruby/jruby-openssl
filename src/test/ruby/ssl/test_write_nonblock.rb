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

  # NOTE: the netWriteData compact-vs-clear unit test for #242 (jruby/jruby#8935) is now a
  # Java test in SSLSocketTest — it can access package-private state directly without reflection.
end
