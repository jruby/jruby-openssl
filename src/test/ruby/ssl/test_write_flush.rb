# frozen_string_literal: false
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLWriteFlush < TestCase

  include SSLTestHelper

  # write_nonblock a large payload then read the server's response.
  #
  # This exercises the write -> read transition used by net/http for POST
  # requests. Two bugs in SSLSocket caused data loss here:
  #   1. write() called netWriteData.clear() after a partial non-blocking
  #      flush, discarding encrypted bytes not yet sent to the socket.
  #   2. sysreadImpl() did not flush pending netWriteData before reading.
  #
  # Without the fix the TLS stream is corrupted and the connection breaks
  # with EPIPE.
  def test_write_nonblock_then_read
    data_size = 256 * 1024
    data = "X" * data_size

    server_proc = proc { |ctx, ssl|
      begin
        received = ""
        begin
          while received.bytesize < data_size
            received << ssl.readpartial(8192)
          end
        rescue EOFError
        end
        ssl.write("GOT:#{received.bytesize}")
      ensure
        ssl.close rescue nil
      end
    }

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                  server_proc: server_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 2048)
      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      ssl.sync_close = true

      remaining = data
      while remaining.bytesize > 0
        begin
          written = ssl.write_nonblock(remaining)
          remaining = remaining.byteslice(written..-1)
        rescue IO::WaitWritable
          IO.select(nil, [ssl])
          retry
        end
      end

      response = ""
      deadline = Time.now + 30
      loop do
        remaining_time = deadline - Time.now
        break if remaining_time <= 0
        if IO.select([ssl], nil, nil, [remaining_time, 1].min)
          begin
            chunk = ssl.read_nonblock(16384, exception: false)
            case chunk
            when :wait_readable then next
            when nil then break
            else response << chunk
            end
          rescue EOFError
            break
          end
        end
      end

      assert_match(/^GOT:#{data_size}$/, response,
        "Server should receive all #{data_size} bytes")
      ssl.close
    end
  end

end
