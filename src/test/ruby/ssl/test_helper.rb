require File.expand_path('../test_helper', File.dirname(__FILE__))

module SSLTestHelper

  # RUBY = EnvUtil.rubybin
  SSL_SERVER = File.join(File.dirname(__FILE__), "ssl_server.rb")
  PORT = 20443
  ITERATIONS = ($0 == __FILE__) ? 100 : 10

  def setup; require 'openssl'

    @ca_key  = OpenSSL::PKey::RSA.new TEST_KEY_RSA2048
    @svr_key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1024
    @cli_key = OpenSSL::PKey::DSA.new TEST_KEY_DSA256
    @ca  = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")
    @svr = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost")
    @cli = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost")
    ca_exts = [
      [ "basicConstraints", "CA:TRUE", true ],
      [ "keyUsage", "cRLSign,keyCertSign", true ],
    ]
    ee_exts = [
      [ "keyUsage", "keyEncipherment,digitalSignature", true ],
    ]
    now = Time.at(Time.now.to_i)
    @ca_cert  = issue_cert(@ca, @ca_key, 1, now, now + 3600, ca_exts, nil, nil, OpenSSL::Digest::SHA1.new)
    @svr_cert = issue_cert(@svr, @svr_key, 2, now, now + 1800, ee_exts, @ca_cert, @ca_key, OpenSSL::Digest::SHA1.new)
    @cli_cert = issue_cert(@cli, @cli_key, 3, now, now + 1800, ee_exts, @ca_cert, @ca_key, OpenSSL::Digest::SHA1.new)
    @server = nil
  end

  private

  # threads should respond to shift method.
  # Array can be used.
  def assert_join_threads(threads, message = nil)
    errs = []; values = []
    while th = threads.shift
      begin
        values << th.value
      rescue Exception
        errs << [th, $!]
      end
    end
    unless errs.empty?
      msg = "exceptions on #{errs.length} threads:\n" +
          errs.map {|t, err|
            "#{t.inspect}:\n" +
                err.backtrace.map.with_index {|line, i|
                  if i == 0
                    "#{line}: #{err.message} (#{err.class})"
                  else
                    "\tfrom #{line}"
                  end
                }.join("\n")
          }.join("\n---\n")
      msg = "#{message}\n#{msg}" if message
      fail msg # raise MiniTest::Assertion, msg
    end
    values
  end

  protected

  def start_server0(port0, verify_mode, start_immediately, args = {}, &block); require 'socket'
    ctx_proc = args[:ctx_proc]
    server_proc = args[:server_proc]
    server_proc ||= method(:readwrite_loop)

    store = OpenSSL::X509::Store.new
    store.add_cert(@ca_cert)
    store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
    context = OpenSSL::SSL::SSLContext.new
    context.cert_store = store
    # context.extra_chain_cert = [ ca_cert ]
    context.cert = @svr_cert
    context.key = @svr_key
    context.tmp_dh_callback = proc { OpenSSL::PKey::DH.new(TEST_KEY_DH1024) }
    context.verify_mode = verify_mode
    ctx_proc.call(context) if ctx_proc

    Socket.do_not_reverse_lookup = true
    tcp_server = nil
    port = port0
    begin
      tcp_server = TCPServer.new("127.0.0.1", port)
    rescue Errno::EADDRINUSE
      port += 1
      retry
    end

    ssls = OpenSSL::SSL::SSLServer.new(tcp_server, context)
    ssls.start_immediately = start_immediately

    begin
      server = Thread.new do
        Thread.current.abort_on_exception = true
        server_loop0(context, ssls, server_proc)
      end

      $stderr.printf("%s started: pid=%d port=%d\n", SSL_SERVER, $$, port) #if $DEBUG

      block.call(server, port.to_i)
    ensure
      tcp_server_close(server, tcp_server)
    end
  end

  def start_server(verify_mode, start_immediately, args = {}, &block); require 'socket'
    IO.pipe do |stop_pipe_r, stop_pipe_w|
      ctx_proc = args[:ctx_proc]
      server_proc = args[:server_proc]
      ignore_listener_error = args.fetch(:ignore_listener_error, false)
      use_anon_cipher = args.fetch(:use_anon_cipher, false)
      server_proc ||= method(:readwrite_loop)

      store = OpenSSL::X509::Store.new
      store.add_cert(@ca_cert)
      store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ciphers = "ADH-AES256-GCM-SHA384" if use_anon_cipher
      ctx.cert_store = store
      #ctx.extra_chain_cert = [ ca_cert ]
      ctx.cert = @svr_cert
      ctx.key = @svr_key
      ctx.tmp_dh_callback = proc { OpenSSL::TestUtils::TEST_KEY_DH1024 }
      ctx.verify_mode = verify_mode
      ctx_proc.call(ctx) if ctx_proc

      Socket.do_not_reverse_lookup = true

      tcps = TCPServer.new("127.0.0.1", 0)
      port = tcps.connect_address.ip_port

      ssls = OpenSSL::SSL::SSLServer.new(tcps, ctx)
      ssls.start_immediately = start_immediately

      threads = []
      begin
        server = Thread.new do
          # Thread.current.abort_on_exception = true
          begin
            server_loop(ctx, ssls, stop_pipe_r, ignore_listener_error, server_proc, threads)
          ensure
            tcps.close
          end
        end
        threads.unshift server

        $stderr.printf("SSL server started: pid=%d port=%d\n", $$, port) if $DEBUG

        client = Thread.new do
          begin
            block.call(server, port.to_i)
          ensure
            stop_pipe_w.close
          end
        end
        threads.unshift client
      ensure
        assert_join_threads(threads)
      end
    end
  end

  def tcp_server_close(thread, tcp_server)
    begin
      tcp_server.shutdown
    rescue Errno::ENOTCONN
      # when `Errno::ENOTCONN: Socket is not connected' on some platforms,
      # call #close instead of #shutdown.
      tcp_server.close
      tcp_server = nil
    end if (tcp_server)
    if thread
      thread.join(5)
      if thread.alive?
        thread.kill
        thread.join
        flunk("TCPServer was closed and SSLServer is still alive") unless $!
      end
    end
  ensure
    tcp_server.close if tcp_server
  end

  def tcp_server_close(thread, tcp_server)
    tcp_server.close if (tcp_server)
    if thread
      thread.join(5)
      if thread.alive?
        thread.kill
        thread.join
        flunk("TCPServer was closed and SSLServer is still alive") unless $!
      end
    end
  end if RUBY_VERSION < '1.9.0' ||
  ( defined? JRUBY_VERSION && JRUBY_VERSION < '1.7.0' )
  private :tcp_server_close

  def server_loop0(context, server, server_proc)
    loop do
      ssl = nil
      begin
        ssl = server.accept
      rescue OpenSSL::SSL::SSLError
        retry
      end

      Thread.start do
        Thread.current.abort_on_exception = true
        server_proc.call(context, ssl)
      end
    end
  rescue Errno::EBADF, IOError, Errno::EINVAL, Errno::ECONNABORTED, Errno::ENOTSOCK, Errno::ECONNRESET
  end

  def server_loop(ctx, ssls, stop_pipe_r, ignore_listener_error, server_proc, threads)
    loop do
      ssl = nil
      begin
        readable, = IO.select([ssls, stop_pipe_r])
        return if readable.include? stop_pipe_r
        ssl = ssls.accept
      rescue OpenSSL::SSL::SSLError
        if ignore_listener_error
          retry
        else
          raise
        end
      end

      threads << Thread.start do
        # Thread.current.abort_on_exception = true
        server_proc.call(ctx, ssl)
      end
    end
  rescue Errno::EBADF, IOError, Errno::EINVAL, Errno::ECONNABORTED, Errno::ENOTSOCK, Errno::ECONNRESET => ex
    raise(ex) unless ignore_listener_error
    puts ex.inspect if $VERBOSE
  end

  def server_connect(port, ctx = nil)
    sock = TCPSocket.new('127.0.0.1', port)
    ssl = ctx ? OpenSSL::SSL::SSLSocket.new(sock, ctx) : OpenSSL::SSL::SSLSocket.new(sock)
    ssl.sync_close = true
    ssl.connect
    yield ssl if block_given?
  ensure
    if ssl
      ssl.close
    elsif sock
      sock.close
    end
  end

  def starttls(ssl)
    ssl.puts("STARTTLS")
    #sleep 1 # When this line is eliminated, process on Cygwin blocks
    #        # forever at ssl.connect. But I don't know why it does.
    ssl.connect
  end

  def readwrite_loop(context, ssl)
    while line = ssl.gets
      if line =~ /^STARTTLS$/
        ssl.accept
        next
      end
      ssl.write(line)
    end
  rescue IOError, OpenSSL::SSL::SSLError
  ensure
    ssl.close rescue nil
  end

  TEST_KEY_RSA1024 = <<-_end_of_pem_
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDLwsSw1ECnPtT+PkOgHhcGA71nwC2/nL85VBGnRqDxOqjVh7Cx
aKPERYHsk4BPCkE3brtThPWc9kjHEQQ7uf9Y1rbCz0layNqHyywQEVLFmp1cpIt/
Q3geLv8ZD9pihowKJDyMDiN6ArYUmZczvW4976MU3+l54E6lF/JfFEU5hwIDAQAB
AoGBAKSl/MQarye1yOysqX6P8fDFQt68VvtXkNmlSiKOGuzyho0M+UVSFcs6k1L0
maDE25AMZUiGzuWHyaU55d7RXDgeskDMakD1v6ZejYtxJkSXbETOTLDwUWTn618T
gnb17tU1jktUtU67xK/08i/XodlgnQhs6VoHTuCh3Hu77O6RAkEA7+gxqBuZR572
74/akiW/SuXm0SXPEviyO1MuSRwtI87B02D0qgV8D1UHRm4AhMnJ8MCs1809kMQE
JiQUCrp9mQJBANlt2ngBO14us6NnhuAseFDTBzCHXwUUu1YKHpMMmxpnGqaldGgX
sOZB3lgJsT9VlGf3YGYdkLTNVbogQKlKpB8CQQDiSwkb4vyQfDe8/NpU5Not0fII
8jsDUCb+opWUTMmfbxWRR3FBNu8wnym/m19N4fFj8LqYzHX4KY0oVPu6qvJxAkEA
wa5snNekFcqONLIE4G5cosrIrb74sqL8GbGb+KuTAprzj5z1K8Bm0UW9lTjVDjDi
qRYgZfZSL+x1P/54+xTFSwJAY1FxA/N3QPCXCjPh5YqFxAMQs2VVYTfg+t0MEcJD
dPMQD5JX6g5HKnHFg2mZtoXQrWmJSn7p8GJK8yNTopEErA==
-----END RSA PRIVATE KEY-----
  _end_of_pem_

  TEST_KEY_RSA2048 = <<-_end_of_pem_
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuV9ht9J7k4NBs38jOXvvTKY9gW8nLICSno5EETR1cuF7i4pN
s9I1QJGAFAX0BEO4KbzXmuOvfCpD3CU+Slp1enenfzq/t/e/1IRW0wkJUJUFQign
4CtrkJL+P07yx18UjyPlBXb81ApEmAB5mrJVSrWmqbjs07JbuS4QQGGXLc+Su96D
kYKmSNVjBiLxVVSpyZfAY3hD37d60uG+X8xdW5v68JkRFIhdGlb6JL8fllf/A/bl
NwdJOhVr9mESHhwGjwfSeTDPfd8ZLE027E5lyAVX9KZYcU00mOX+fdxOSnGqS/8J
DRh0EPHDL15RcJjV2J6vZjPb0rOYGDoMcH+94wIDAQABAoIBAAzsamqfYQAqwXTb
I0CJtGg6msUgU7HVkOM+9d3hM2L791oGHV6xBAdpXW2H8LgvZHJ8eOeSghR8+dgq
PIqAffo4x1Oma+FOg3A0fb0evyiACyrOk+EcBdbBeLo/LcvahBtqnDfiUMQTpy6V
seSoFCwuN91TSCeGIsDpRjbG1vxZgtx+uI+oH5+ytqJOmfCksRDCkMglGkzyfcl0
Xc5CUhIJ0my53xijEUQl19rtWdMnNnnkdbG8PT3LZlOta5Do86BElzUYka0C6dUc
VsBDQ0Nup0P6rEQgy7tephHoRlUGTYamsajGJaAo1F3IQVIrRSuagi7+YpSpCqsW
wORqorkCgYEA7RdX6MDVrbw7LePnhyuaqTiMK+055/R1TqhB1JvvxJ1CXk2rDL6G
0TLHQ7oGofd5LYiemg4ZVtWdJe43BPZlVgT6lvL/iGo8JnrncB9Da6L7nrq/+Rvj
XGjf1qODCK+LmreZWEsaLPURIoR/Ewwxb9J2zd0CaMjeTwafJo1CZvcCgYEAyCgb
aqoWvUecX8VvARfuA593Lsi50t4MEArnOXXcd1RnXoZWhbx5rgO8/ATKfXr0BK/n
h2GF9PfKzHFm/4V6e82OL7gu/kLy2u9bXN74vOvWFL5NOrOKPM7Kg+9I131kNYOw
Ivnr/VtHE5s0dY7JChYWE1F3vArrOw3T00a4CXUCgYEA0SqY+dS2LvIzW4cHCe9k
IQqsT0yYm5TFsUEr4sA3xcPfe4cV8sZb9k/QEGYb1+SWWZ+AHPV3UW5fl8kTbSNb
v4ng8i8rVVQ0ANbJO9e5CUrepein2MPL0AkOATR8M7t7dGGpvYV0cFk8ZrFx0oId
U0PgYDotF/iueBWlbsOM430CgYEAqYI95dFyPI5/AiSkY5queeb8+mQH62sdcCCr
vd/w/CZA/K5sbAo4SoTj8dLk4evU6HtIa0DOP63y071eaxvRpTNqLUOgmLh+D6gS
Cc7TfLuFrD+WDBatBd5jZ+SoHccVrLR/4L8jeodo5FPW05A+9gnKXEXsTxY4LOUC
9bS4e1kCgYAqVXZh63JsMwoaxCYmQ66eJojKa47VNrOeIZDZvd2BPVf30glBOT41
gBoDG3WMPZoQj9pb7uMcrnvs4APj2FIhMU8U15LcPAj59cD6S6rWnAxO8NFK7HQG
4Jxg3JNNf8ErQoCHb1B3oVdXJkmbJkARoDpBKmTCgKtP8ADYLmVPQw==
-----END RSA PRIVATE KEY-----
  _end_of_pem_

  TEST_KEY_DSA256 = <<-_end_of_pem_
-----BEGIN DSA PRIVATE KEY-----
MIH3AgEAAkEAhk2libbY2a8y2Pt21+YPYGZeW6wzaW2yfj5oiClXro9XMR7XWLkE
9B7XxLNFCS2gmCCdMsMW1HulaHtLFQmB2wIVAM43JZrcgpu6ajZ01VkLc93gu/Ed
AkAOhujZrrKV5CzBKutKLb0GVyVWmdC7InoNSMZEeGU72rT96IjM59YzoqmD0pGM
3I1o4cGqg1D1DfM1rQlnN1eSAkBq6xXfEDwJ1mLNxF6q8Zm/ugFYWR5xcX/3wFiT
b4+EjHP/DbNh9Vm5wcfnDBJ1zKvrMEf2xqngYdrV/3CiGJeKAhRvL57QvJZcQGvn
ISNX5cMzFHRW3Q==
-----END DSA PRIVATE KEY-----
  _end_of_pem_

  TEST_KEY_DSA512 = <<-_end_of_pem_
-----BEGIN DSA PRIVATE KEY-----
MIH4AgEAAkEA5lB4GvEwjrsMlGDqGsxrbqeFRh6o9OWt6FgTYiEEHaOYhkIxv0Ok
RZPDNwOG997mDjBnvDJ1i56OmS3MbTnovwIVAJgub/aDrSDB4DZGH7UyarcaGy6D
AkB9HdFw/3td8K4l1FZHv7TCZeJ3ZLb7dF3TWoGUP003RCqoji3/lHdKoVdTQNuR
S/m6DlCwhjRjiQ/lBRgCLCcaAkEAjN891JBjzpMj4bWgsACmMggFf57DS0Ti+5++
Q1VB8qkJN7rA7/2HrCR3gTsWNb1YhAsnFsoeRscC+LxXoXi9OAIUBG98h4tilg6S
55jreJD3Se3slps=
-----END DSA PRIVATE KEY-----
  _end_of_pem_

  TEST_KEY_DH1024 = <<-_end_of_pem_
-----BEGIN DH PARAMETERS-----
MIGHAoGBAKnKQ8MNK6nYZzLrrcuTsLxuiJGXoOO5gT+tljOTbHBuiktdMTITzIY0
pFxIvjG05D7HoBZQfrR0c92NGWPkAiCkhQKB8JCbPVzwNLDy6DZ0pmofDKrEsYHG
AQjjxMXhwULlmuR/K+WwlaZPiLIBYalLAZQ7ZbOPeVkJ8ePao0eLAgEC
-----END DH PARAMETERS-----
  _end_of_pem_

end