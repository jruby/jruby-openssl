# Creates a connected SSL socket pair for Java unit tests.
# Returns [client_ssl, server_ssl]
#
# OpenSSL extension is loaded by SSLSocketTest.setUp via OpenSSL.load(runtime).

require 'socket'

key = OpenSSL::PKey::RSA.new(2048)
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 1
cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=Test')
cert.public_key = key.public_key
cert.not_before = Time.now
cert.not_after = Time.now + 3600
cert.sign(key, OpenSSL::Digest::SHA256.new)

tcp_server = TCPServer.new('127.0.0.1', 0)
port = tcp_server.local_address.ip_port
ctx = OpenSSL::SSL::SSLContext.new
ctx.cert = cert
ctx.key = key
ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, ctx)
ssl_server.start_immediately = true

server_ssl = nil
server_thread = Thread.new { server_ssl = ssl_server.accept }

sock = TCPSocket.new('127.0.0.1', port)
sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 4096)
sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF, 4096)
client_ssl = OpenSSL::SSL::SSLSocket.new(sock)
client_ssl.sync_close = true
client_ssl.connect
server_thread.join(5)

[client_ssl, server_ssl]
