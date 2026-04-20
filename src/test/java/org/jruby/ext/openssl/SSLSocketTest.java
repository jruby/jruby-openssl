package org.jruby.ext.openssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLEngine;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyString;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.builtin.IRubyObject;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SSLSocketTest extends OpenSSLHelper {

    /** Loads the ssl_pair.rb script that creates a connected SSL socket pair. */
    private String start_ssl_server_rb() { return readResource("/start_ssl_server.rb"); }

    @BeforeEach
    public void setUp() throws Exception {
        setUpRuntime();
    }

    @AfterEach
    public void tearDown() {
        tearDownRuntime();
    }

    /**
     * Real-world scenario: {@code gem push} sends a large POST body via {@code syswrite_nonblock},
     * then reads the HTTP response via {@code sysread}.
     *
     * Approximates the {@code gem push} scenario:
     * <ol>
     *   <li>Write 256KB via {@code syswrite_nonblock} in a loop (the net/http POST pattern)</li>
     *   <li>Server reads via {@code sysread} and counts bytes</li>
     *   <li>Assert: server received exactly what client sent</li>
     * </ol>
     *
     * With the old {@code clear()} bug, encrypted bytes were silently
     * discarded during partial non-blocking writes, so the server would
     * receive fewer bytes than sent.
     */
    @Test
    public void syswriteNonblockDataIntegrity() throws Exception {
        final RubyArray pair = (RubyArray) runtime.evalScriptlet(start_ssl_server_rb());
        SSLSocket client = (SSLSocket) pair.entry(0).toJava(SSLSocket.class);
        SSLSocket server = (SSLSocket) pair.entry(1).toJava(SSLSocket.class);

        try {
            final int expectedBytes = 64 * 4096;

            // Server: read an exact payload size in the background so the assertion
            // does not depend on EOF timing or close-path behavior
            final ServerReadResult serverResult = new ServerReadResult();
            Thread serverReader = startServerReader(server, expectedBytes, serverResult);

            // Client: write a large POST body in one request; net/http ultimately
            // retries write_nonblock internally until the full body is flushed
            byte[] payload = new byte[expectedBytes];
            java.util.Arrays.fill(payload, (byte) 'P'); // P for POST body

            long totalSent = writeNonblockWithRetry(client, payload);
            assertTrue(totalSent > 0, "should have sent data");
            assertEquals(expectedBytes, totalSent, "test must send the full payload");

            assertTrue(serverResult.await(10, TimeUnit.SECONDS),
                    "server must finish reading the expected payload"
            );
            serverReader.join(1_000);
            assertFalse(serverReader.isAlive(), "server reader must exit after reading expected bytes");
            if (serverResult.failure != null) {
                throw new AssertionError("server reader failed unexpectedly", serverResult.failure);
            }

            assertEquals(totalSent, serverResult.bytesRead,
                    "server must receive exactly what client sent — mismatch means encrypted bytes were lost!"
            );
        } finally {
            closeQuietly(pair);
        }
    }

    private Thread startServerReader(final SSLSocket server, final long expectedBytes,
                                     final ServerReadResult serverResult) {
        Thread serverReader = new Thread(() -> {
            try {
                RubyFixnum len = RubyFixnum.newFixnum(runtime, 8192);
                while (serverResult.bytesRead < expectedBytes) {
                    IRubyObject data = server.sysread(currentContext(), len);
                    serverResult.bytesRead += ((RubyString) data).getByteList().getRealSize();
                }
                if (serverResult.bytesRead != expectedBytes) {
                    throw new AssertionError("server read " + serverResult.bytesRead +
                            " bytes, expected " + expectedBytes);
                }
            } catch (Throwable t) {
                serverResult.failure = t;
            } finally {
                serverResult.finish();
            }
        }, "ssl-server-reader");
        serverReader.start();
        return serverReader;
    }

    private static final class ServerReadResult {
        private final CountDownLatch done = new CountDownLatch(1);
        private volatile long bytesRead;
        private volatile Throwable failure;

        private boolean await(final long timeout, final TimeUnit unit) throws InterruptedException {
            return done.await(timeout, unit);
        }

        private void finish() {
            done.countDown();
        }
    }

    private int writeNonblockWithRetry(final SSLSocket socket, final byte[] data) throws Exception {
        int offset = 0;
        while (offset < data.length) {
            final RubyString payload = RubyString.newString(runtime, data, offset, data.length - offset);
            try {
                IRubyObject written = socket.syswrite_nonblock(currentContext(), payload);
                final int len = ((RubyInteger) written).getIntValue();
                offset += len;
            } catch (RaiseException e) {
                final String errorName = e.getException().getMetaClass().getName();
                if ("OpenSSL::SSL::SSLErrorWaitWritable".equals(errorName)) {
                    System.out.println("syswrite_nonblock expected: " + e.getMessage());
                    waitUntilReady(socket, SelectionKey.OP_WRITE, 5_000);
                } else if ("OpenSSL::SSL::SSLErrorWaitReadable".equals(errorName)) {
                    System.out.println("syswrite_nonblock expected: " + e.getMessage());
                    waitUntilReady(socket, SelectionKey.OP_READ, 5_000);
                } else {
                    System.err.println("syswrite_nonblock unexpected: " + e.getMessage());
                    throw e;
                }
            }
        }
        return offset;
    }

    private void waitUntilReady(final SSLSocket socket, final int operation, final long timeoutMillis)
            throws Exception {
        final SocketChannel channel = (SocketChannel) socket.io().getChannel();
        final boolean blocking = channel.isBlocking();

        try (Selector selector = Selector.open()) {
            if (blocking) channel.configureBlocking(false);
            channel.register(selector, operation);
            final int ready = selector.select(timeoutMillis);
            assertTrue(ready > 0, "socket did not become ready in time");
        } finally {
            if (blocking) channel.configureBlocking(true);
        }
    }

    /**
     * After saturating the TCP send buffer with {@code syswrite_nonblock},
     * inspect {@code netWriteData} to verify the buffer is consistent.
     */
    @Test
    public void syswriteNonblockNetWriteDataConsistency() {
        final RubyArray pair = (RubyArray) runtime.evalScriptlet(start_ssl_server_rb());
        SSLSocket client = (SSLSocket) pair.entry(0).toJava(SSLSocket.class);

        try {
            assertNotNull(client.netWriteData, "netWriteData initialized after handshake");

            // Saturate: server is not reading yet, so backpressure builds
            byte[] chunk = new byte[16384];
            java.util.Arrays.fill(chunk, (byte) 'S');
            RubyString payload = RubyString.newString(runtime, chunk);

            int successWrites = 0;
            for (int i = 0; i < 200; i++) {
                try {
                    client.syswrite_nonblock(currentContext(), payload);
                    successWrites++;
                } catch (RaiseException e) {
                    if ("OpenSSL::SSL::SSLErrorWaitWritable".equals(e.getException().getMetaClass().getName())) {
                        System.out.println("saturate-loop expected: " + e.getMessage());
                        break; // buffer saturated — expected
                    }
                    System.err.println("saturate-loop unexpected: " + e.getMessage());
                    throw e;
                }
            }
            assertTrue(successWrites > 0, "at least one write should succeed");

            ByteBuffer netWriteData = client.netWriteData;
            assertTrue(netWriteData.position() <= netWriteData.limit(), "position <= limit");
            assertTrue(netWriteData.limit() <= netWriteData.capacity(), "limit <= capacity");

            // If there are unflushed bytes, compact() preserved them
            if (netWriteData.remaining() > 0) {
                // The bytes should be valid TLS record data, not zeroed memory
                byte b = netWriteData.get(netWriteData.position());
                assertNotEquals(0, b, "preserved bytes should be TLS data, not zeroed");
            }

        } finally {
            closeQuietly(pair);
        }
    }

    private void closeQuietly(final RubyArray sslPair) {
        for (int i = 0; i < sslPair.getLength(); i++) {
            final IRubyObject elem = sslPair.entry(i);
            try { elem.callMethod(currentContext(), "close"); }
            catch (RaiseException e) { // already closed?
                System.err.println("close raised (" + elem.inspect() + ") : " + e.getMessage());
            }
        }
    }

    // ----------

    /**
     * MRI's ossl_ssl_read_internal returns :wait_writable (or raises SSLErrorWaitWritable / "write would block")
     * when SSL_read hits SSL_ERROR_WANT_WRITE. Pending netWriteData is JRuby's equivalent state.
     */
    @Test
    public void sysreadNonblockReturnsWaitWritableWhenPendingEncryptedBytesRemain() {
        final SSLSocket socket = newSSLSocket(runtime, partialWriteChannel(1));
        final SSLEngine engine = socket.ossl_ssl_setup(currentContext(), false);
        engine.setUseClientMode(true);

        socket.netWriteData = ByteBuffer.wrap(new byte[] { 1, 2 });

        final RubyHash opts = RubyHash.newKwargs(runtime, "exception", runtime.getFalse()); // exception: false
        final IRubyObject result = socket.sysread_nonblock(currentContext(), runtime.newFixnum(1), opts);

        assertEquals("wait_writable", result.asJavaString());
        assertEquals(1, socket.netWriteData.remaining());
    }

    @Test
    public void sysreadNonblockRaisesWaitWritableWhenPendingEncryptedBytesRemain() {
        final SSLSocket socket = newSSLSocket(runtime, partialWriteChannel(1));
        final SSLEngine engine = socket.ossl_ssl_setup(currentContext(), false);
        engine.setUseClientMode(true);

        socket.netWriteData = ByteBuffer.wrap(new byte[] { 1, 2 });

        try {
            socket.sysread_nonblock(currentContext(), runtime.newFixnum(1));
            fail("expected SSLErrorWaitWritable");
        }
        catch (RaiseException ex) {
            assertEquals("OpenSSL::SSL::SSLErrorWaitWritable", ex.getException().getMetaClass().getName());
            assertTrue(ex.getMessage().contains("write would block"));
            assertEquals(1, socket.netWriteData.remaining());
        }
    }

    private static SSLSocket newSSLSocket(final Ruby runtime, final SSLSocket.SocketChannelImpl socketChannel) {
        final SSLContext sslContext = new SSLContext(runtime);
        sslContext.doSetup(runtime.getCurrentContext());
        final SSLSocket sslSocket = new SSLSocket(runtime, runtime.getObject());
        sslSocket.sslContext = sslContext;
        sslSocket.socketChannel = socketChannel;
        return sslSocket;
    }

    private static SSLSocket.SocketChannelImpl partialWriteChannel(final int bytesPerWrite) {
        return new SSLSocket.SocketChannelImpl() {
            public boolean isOpen() { return true; }
            public int read(final ByteBuffer dst) { return 0; }
            public int write(final ByteBuffer src) {
                final int written = Math.min(bytesPerWrite, src.remaining());
                src.position(src.position() + written);
                return written;
            }
            public int getRemotePort() { return 443; }
            public boolean isSelectable() { return false; }
            public boolean isBlocking() { return false; }
            public void configureBlocking(final boolean block) { }
            public SelectionKey register(final Selector selector, final int ops) throws IOException {
                throw new UnsupportedOperationException();
            }
        };
    }
}
