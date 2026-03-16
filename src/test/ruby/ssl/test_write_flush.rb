# frozen_string_literal: false
require File.expand_path('test_helper', File.dirname(__FILE__))

class TestSSLWriteFlush < TestCase

  include SSLTestHelper

  # Exercises the write_nonblock -> read transition used by net/http for POST
  # requests. The bug (clear() instead of compact()) loses encrypted bytes that
  # remain in netWriteData after a partial flushData on the *last* write_nonblock.
  #
  # We run multiple request/response rounds on the same TLS connection with
  # varying payload sizes to increase the probability that at least one round
  # triggers a partial flush at the write->read boundary.
  #
  # NOTE: On localhost the loopback interface rarely causes partial socket writes,
  # so this test may not reliably catch regressions to clear(). The definitive
  # coverage is in the Java-level SSLSocketTest which can control buffer state
  # directly. This test serves as an integration smoke test for the write->read
  # data path.
  #
  # https://github.com/jruby/jruby-openssl/issues/242
  def test_write_nonblock_data_integrity
    # Payload sizes chosen to exercise different alignments with the TLS record
    # layer (~16 KB records) and socket send buffer. Primes avoid lucky alignment.
    payload_sizes = [
      8_191,      # just under 8 KB — fits in one TLS record
      16_381,     # just under 16 KB — nearly one full TLS record
      65_521,     # ~64 KB — several TLS records, common chunk size
      262_139,    # ~256 KB — large payload, many partial flushes likely
    ]

    # The server reads a 4-byte big-endian length prefix, then that many bytes
    # of payload, and responds with "OK:<hex_digest>" where hex_digest is the
    # SHA-256 of the received payload. This is repeated for each payload size.
    server_proc = proc { |ctx, ssl|
      begin
        payload_sizes.length.times do
          # read 4-byte length prefix
          header = read_exactly(ssl, 4)
          break unless header && header.bytesize == 4
          expected_len = header.unpack('N')[0]

          # read payload
          payload = read_exactly(ssl, expected_len)
          break unless payload && payload.bytesize == expected_len

          digest = OpenSSL::Digest::SHA256.hexdigest(payload)
          response = "OK:#{digest}"
          ssl.write(response)
        end
      ensure
        ssl.close rescue nil
      end
    }

    start_server0(PORT, OpenSSL::SSL::VERIFY_NONE, true,
                  server_proc: server_proc) do |server, port|
      sock = TCPSocket.new("127.0.0.1", port)
      # Constrain the send buffer to make partial flushes more likely.
      # The kernel may round this up, but even a modest reduction helps.
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 2048)
      sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

      ssl = OpenSSL::SSL::SSLSocket.new(sock)
      ssl.connect
      ssl.sync_close = true

      payload_sizes.each do |size|
        data = generate_test_data(size)
        expected_digest = OpenSSL::Digest::SHA256.hexdigest(data)

        # Send length-prefixed payload via write_nonblock
        message = [size].pack('N') + data
        write_nonblock_all(ssl, message)

        # Immediately switch to reading — this is where the bug manifests:
        # if compact() was replaced with clear(), residual encrypted bytes
        # from the last write_nonblock are lost and the server never
        # receives the complete payload.
        response = read_with_timeout(ssl, 5)

        assert_equal "OK:#{expected_digest}", response,
          "Data integrity failure for #{size}-byte payload: " \
          "server did not receive the complete payload or it was corrupted"
      end

      ssl.close
    end
  end

  private

  # Generate non-trivial test data that won't compress well in TLS.
  # Uses a seeded PRNG so failures are reproducible, and avoids
  # OpenSSL::Random which has a per-call size limit in some BC versions.
  def generate_test_data(size)
    rng = Random.new(size) # seeded for reproducibility
    (0...size).map { rng.rand(256).chr }.join.b
  end

  # Write all of +data+ via write_nonblock, retrying on WaitWritable.
  # Does NOT do any extra flushing after the last write — this is critical
  # for exercising the bug where clear() loses the tail of encrypted data.
  def write_nonblock_all(ssl, data)
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
  end

  # Read a complete response from the SSL socket with a timeout.
  # Returns the accumulated data, or fails the test on timeout.
  def read_with_timeout(ssl, timeout_sec)
    response = ""
    deadline = Time.now + timeout_sec
    loop do
      remaining = deadline - Time.now
      if remaining <= 0
        flunk "Timed out after #{timeout_sec}s waiting for server response " \
              "(got #{response.bytesize} bytes so far: #{response.inspect[0, 80]})"
      end
      if IO.select([ssl], nil, nil, [remaining, 0.5].min)
        begin
          chunk = ssl.read_nonblock(16384, exception: false)
          case chunk
          when :wait_readable then next
          when nil then break   # EOF
          else
            response << chunk
            # Our protocol responses are short ("OK:<64 hex chars>"), so if
            # we've received a plausible amount we can stop.
            break if response.include?("OK:")  && response.bytesize >= 67
          end
        rescue IO::WaitReadable
          # Can occur despite exception: false and IO.select — TLS protocol
          # data (e.g. post-handshake messages) made the socket look readable
          # but no application data is available yet.
          next
        rescue EOFError
          break
        end
      end
    end
    response
  end

  # Read exactly +n+ bytes from an SSL socket, retrying partial reads.
  def self.read_exactly(ssl, n)
    buf = ""
    while buf.bytesize < n
      chunk = ssl.readpartial(n - buf.bytesize)
      buf << chunk
    end
    buf
  rescue EOFError
    buf
  end

  # Instance method wrapper for use in server_proc
  def read_exactly(ssl, n)
    self.class.read_exactly(ssl, n)
  end

end
