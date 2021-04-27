require File.expand_path('../test_helper', File.dirname(__FILE__))
require 'openssl'

module SSLTestHelper

  # RUBY = EnvUtil.rubybin
  SSL_SERVER = File.join(File.dirname(__FILE__), "ssl_server.rb")
  PORT = 20443
  ITERATIONS = ($0 == __FILE__) ? 100 : 10

  def setup;

    @ca_key  = OpenSSL::PKey::RSA.new TEST_KEY_RSA2
    @svr_key = OpenSSL::PKey::RSA.new TEST_KEY_RSA1
    @cli_key = OpenSSL::PKey::DSA.new TEST_KEY_DSA512
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
    @ca_cert  = issue_cert(@ca, @ca_key, 1, now, now + 3600, ca_exts, nil, nil, OpenSSL::Digest::SHA256.new)
    @svr_cert = issue_cert(@svr, @svr_key, 2, now, now + 1800, ee_exts, @ca_cert, @ca_key, OpenSSL::Digest::SHA256.new)
    @cli_cert = issue_cert(@cli, @cli_key, 3, now, now + 1800, ee_exts, @ca_cert, @ca_key, OpenSSL::Digest::SHA256.new)
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
    # context.extra_chain_cert = [ @ca_cert ]
    context.cert = @svr_cert
    context.key = @svr_key
    context.tmp_dh_callback = proc { OpenSSL::PKey::DH.new(TEST_KEY_DH1) }
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
      # ctx.extra_chain_cert = [ @ca_cert ]
      ctx.cert = @svr_cert
      ctx.key = @svr_key
      ctx.tmp_dh_callback = proc { OpenSSL::TestUtils::TEST_KEY_DH1 }
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
        begin
          server_proc.call(ctx, ssl)
        ensure
          ssl.close
        end
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

  TEST_KEY_RSA1 = <<-_end_of_pem_
-----BEGIN RSA PRIVATE KEY-----
MIIJJwIBAAKCAgEArIEJUYZrXhMfUXXdl2gLcXrRB4ciWNEeXt5UVLG0nPhygZwJ
xis8tOrjXOJEpUXUsfgF35pQiJLD4T9/Vp3zLFtMOOQjOR3AxjIelbH9KPyGFEr9
TcPtsJ24zhcG7RbwOGXR4iIcDaTx+bCLSAd7BjG3XHQtyeepGGRZkGyGUvXjPorH
XP+dQjQnMd09wv0GMZSqQ06PedUUKQ4PJRfMCP+mwjFP+rB3NZuThF0CsNmpoixg
GdoQ591Yrf5rf2Bs848JrYdqJlKlBL6rTFf2glHiC+mE5YRny7RZtv/qIkyUNotV
ce1cE0GFrRmCpw9bqulDDcgKjFkhihTg4Voq0UYdJ6Alg7Ur4JerKTfyCaRGF27V
fh/g2A2/6Vu8xKYYwTAwLn+Tvkx9OTVZ1t15wM7Ma8hHowNoO0g/lWkeltgHLMji
rmeuIYQ20BQmdx2RRgWKl57D0wO/N0HIR+Bm4vcBoNPgMlk9g5WHA6idHR8TLxOr
dMMmTiWfefB0/FzGXBv7DuuzHN3+urdCvG1QIMFQ06kHXhr4rC28KbWIxg+PJGM8
oGNEGtGWAOvi4Ov+BVsIdbD5Sfyb4nY3L9qqPl6TxRxMWTKsYCYx11jC8civCzOu
yL1z+wgIICJ6iGzrfYf6C2BiNV3BC1YCtp2XsG+AooIxCwjL2CP/54MuRnUCAwEA
AQKCAgAP4+8M0HoRd2d6JIZeDRqIwIyCygLy9Yh7qrVP+/KsRwKdR9dqps73x29c
Pgeexdj67+Lynw9uFT7v/95mBzTAUESsNO+9sizw1OsWVQgB/4kGU4YT5Ml/bHf6
nApqSqOkPlTgJM46v4f+vTGHWBEQGAJRBO62250q/wt1D1osSDQ/rZ8BxRYiZBV8
NWocDRzF8nDgtFrpGSS7R21DuHZ2Gb6twscgS6MfkA49sieuTM6gfr/3gavu/+fM
V1Rlrmc65GE61++CSjijQEEdTjkJ9isBd+hjEBhTnnBpOBfEQxOgFqOvU/MYXv/G
W0Q6yWJjUwt3OIcoOImrY5L3j0vERneA1Alweqsbws3fXXMjA+jhLxlJqjPvSAKc
POi7xu7QCJjSSLAzHSDPdmGmfzlrbdWS1h0mrC5YZYOyToLajfnmAlXNNrytnePg
JV9/1136ZFrJyEi1JVN3kyrC+1iVd1E+lWK0U1UQ6/25tJvKFc1I+xToaUbK10UN
ycXib7p2Zsc/+ZMlPRgCxWmpIHmKhnwbO7vtRunnnc6wzhvlQQNHWlIvkyQukV50
6k/bzWw0M6A98B4oCICIcxcpS3njDlHyL7NlkCD+/OfZp6X3RZF/m4grmA2doebz
glsaNMyGHFrpHkHq19Y63Y4jtBdW/XuBv06Cnr4r3BXdjEzzwQKCAQEA5bj737Nk
ZLA0UgzVVvY67MTserTOECIt4i37nULjRQwsSFiz0AWFOBwUCBJ5N2qDEelbf0Fa
t4VzrphryEgzLz/95ZXi+oxw1liqCHi8iHeU2wSclDtx2jKv2q7bFvFSaH4CKC4N
zBJNfP92kdXuAjXkbK/jWwr64fLNh/2KFWUAmrYmtGfnOjjyL+yZhPxBatztE58q
/T61pkvP9NiLfrr7Xq8fnzrwqGERhXKueyoK6ig9ZJPZ2VTykMUUvNYJJ7OYQZru
EYA3zkuEZifqmjgF57Bgg7dkkIh285TzH3CNf3MCMTmjlWVyHjlyeSPYgISB9Mys
VKKQth+SvYcChQKCAQEAwDyCcolA7+bQBfECs6GXi7RYy2YSlx562S5vhjSlY9Ko
WiwVJWviF7uSBdZRnGUKoPv4K4LV34o2lJpSSTi5Xgp7FH986VdGePe3p4hcXSIZ
NtsKImLVLnEjrmkZExfQl7p0MkcU/LheCf/eEZVp0Z84O54WCs6GRm9wHYIUyrag
9FREqqxTRVNhQQ2EDVGq1slREdwB+aygE76axK/qosk0RaoLzGZiMn4Sb8bpJxXO
mee+ftq5bayVltfR0DhC8eHkcPPFeQMll1g+ML7HbINwHTr01ONm3cFUO4zOLBOO
ws/+vtNfiv6S/lO1RQSRoiApbENBLdSc3V8Cy70PMQKCAQBOcZN4uP5gL5c+KWm0
T1KhxUDnSdRPyAwY/xC7i7qlullovvlv4GK0XUot03kXBkUJmcEHvF5o6qYtCZlM
g/MOgHCHtF4Upl5lo1M0n13pz8PB4lpBd+cR1lscdrcTp4Y3bkf4RnmppNpXA7kO
ZZnnoVWGE620ShSPkWTDuj0rvxisu+SNmClqRUXWPZnSwnzoK9a86443efF3fs3d
UxCXTuxFUdGfgvXo2XStOBMCtcGSYflM3fv27b4C13mUXhY0O2yTgn8m9LyZsknc
xGalENpbWmwqrjYl8KOF2+gFZV68FZ67Bm6otkJ4ta80VJw6joT9/eIe6IA34KIw
G+ktAoIBAFRuPxzvC4ZSaasyX21l25mQbC9pdWDKEkqxCmp3VOyy6R4xnlgBOhwS
VeAacV2vQyvRfv4dSLIVkkNSRDHEqCWVlNk75TDXFCytIAyE54xAHbLqIVlY7yim
qHVB07F/FC6PxdkPPziAAU2DA5XVedSHibslg6jbbD4jU6qiJ1+hNrAZEs+jQC+C
n4Ri20y+Qbp0URb2+icemnARlwgr+3HjzQGL3gK4NQjYNmDBjEWOXl9aWWB90FNL
KahGwfAhxcVW4W56opCzwR7nsujV4eDXGba83itidRuQfd5pyWOyc1E86TYGwD/b
79OkEElv6Ea8uXTDVS075GmWATRapQECggEAd9ZAbyT+KouTfi2e6yLOosxSZfns
eF06QAJi5n9GOtdfK5fqdmHJqJI7wbubCnd0oxPeL71lRjrOAMXufaQRdZtfXSMn
B1TljteNrh1en5xF451rCPR/Y6tNKBvIKnhy1waO27/vA+ovXrm17iR9rRuGZ29i
IurlKA6z/96UdrSdpqITTCyTjSOBYg34f49ueGjlpL4+8HJq2wor4Cb1Sbv8ErqA
bsQ/Jz+KIGUiuFCfNa6d6McPRXIrGgzpprXgfimkV3nj49QyrnuCF/Pc4psGgIaN
l3EiGXzRt/55K7DQVadtbcjo9zREac8QnDD6dS/gOfJ82L7frQfMpNWgQA==
-----END RSA PRIVATE KEY-----
  _end_of_pem_

  TEST_KEY_RSA2 = <<-_end_of_pem_
-----BEGIN RSA PRIVATE KEY-----
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
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

  TEST_KEY_DH1 = <<-_end_of_pem_
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEAvRzXYxY6L2DjeYmm1eowtMDu1it3j+VwFr6s6PRWzc1apMtztr9G
xZ2mYndUAJLgNLO3n2fUDCYVMB6ZkcekW8Siocof3xWiMA6wqZ6uw0dsE3q7ZX+6
TLjgSjaXeGvjutvuEwVrFeaUi83bMgfXN8ToxIQVprIF35sYFt6fpbFATKfW7qqi
P1pQkjmCskU4tztaWvlLh0qg85wuQGnpJaQT3gS30378i0IGbA0EBvJcSpTHYbLa
nsdI9bfN/ZVgeolVMNMU9/n8R8vRhNPcHuciFwaqS656q+HavCIyxw/LfjSwwFvR
TngCn0wytRErkzFIXnRKckh8/BpI4S+0+l1NkOwG4WJ55KJ/9OOdZW5o/QCp2bDi
E0JN1EP/gkSom/prq8JR/yEqtsy99uc5nUxPmzv0IgdcFHZEfiQU7iRggEbx7qfQ
Ve55XksmmJInmpCy1bSabAEgIKp8Ckt5KLYZ0RgTXUhcEpsxEo6cuAwoSJT5o4Rp
yG3xow2ozPcqZkvb+d2CHj1sc54w9BVFAjVANEKmRil/9WKz14bu3wxEhOPqC54n
QojjLcoXSoT66ZUOQnYxTSiLtzoKGPy8cAVPbkBrXz2u2sj5gcvr1JjoGjdHm9/3
qnqC8fsTz8UndKNIQC337o4K0833bQMzRGl1/qjbAPit2B7E3b6xTZMCAQI=
-----END DH PARAMETERS-----
  _end_of_pem_

end