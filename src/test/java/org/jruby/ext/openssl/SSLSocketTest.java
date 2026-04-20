package org.jruby.ext.openssl;

import java.nio.ByteBuffer;

import org.jruby.RubyArray;
import org.jruby.RubyFixnum;
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
    @org.junit.jupiter.api.Test
    public void syswriteNonblockDataIntegrity() throws Exception {
        final RubyArray pair = (RubyArray) runtime.evalScriptlet(start_ssl_server_rb());
        SSLSocket client = (SSLSocket) pair.entry(0).toJava(SSLSocket.class);
        SSLSocket server = (SSLSocket) pair.entry(1).toJava(SSLSocket.class);

        try {
            // Server: read all data in a background thread, counting bytes
            final long[] serverReceived = { 0 };
            Thread serverReader = startServerReader(server, serverReceived);

            // Client: write 256KB in 4KB chunks via syswrite_nonblock
            byte[] chunk = new byte[4096];
            java.util.Arrays.fill(chunk, (byte) 'P'); // P for POST body
            RubyString payload = RubyString.newString(runtime, chunk);

            long totalSent = 0;
            for (int i = 0; i < 64; i++) { // 64 * 4KB = 256KB
                try {
                    IRubyObject written = client.syswrite_nonblock(currentContext(), payload);
                    totalSent += ((RubyInteger) written).getLongValue();
                } catch (RaiseException e) {
                    if ("OpenSSL::SSL::SSLErrorWaitWritable".equals(e.getException().getMetaClass().getName())) {
                        System.out.println("syswrite_nonblock expected: " + e.getMessage());
                        // Expected: non-blocking write would block — retry as blocking
                        IRubyObject written = client.syswrite(currentContext(), payload);
                        totalSent += ((RubyInteger) written).getLongValue();
                    } else {
                        System.err.println("syswrite_nonblock unexpected: " + e.getMessage());
                        throw e;
                    }
                }
            }
            assertTrue(totalSent > 0, "should have sent data");

            // Close client to signal EOF, let server finish reading
            client.callMethod(currentContext(), "close");
            serverReader.join(10_000);

            assertEquals(totalSent, serverReceived[0],
                    "server must receive exactly what client sent — mismatch means encrypted bytes were lost!"
            );
        } finally {
            closeQuietly(pair);
        }
    }

    private Thread startServerReader(final SSLSocket server, final long[] serverReceived) {
        Thread serverReader = new Thread(() -> {
            try {
                RubyFixnum len = RubyFixnum.newFixnum(runtime, 8192);
                while (true) {
                    IRubyObject data = server.sysread(currentContext(), len);
                    serverReceived[0] += ((RubyString) data).getByteList().getRealSize();
                }
            } catch (RaiseException e) {
                String errorName = e.getException().getMetaClass().getName();
                if ("EOFError".equals(errorName) || "IOError".equals(errorName)) { // client closes connection
                    System.out.println("server-reader expected: " + e.getMessage());
                } else {
                    System.err.println("server-reader unexpected: " + e.getMessage());
                    e.printStackTrace(System.err);
                    throw e;
                }
            }
        });
        serverReader.start();
        return serverReader;
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
}
