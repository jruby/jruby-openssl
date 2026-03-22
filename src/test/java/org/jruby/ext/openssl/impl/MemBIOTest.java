package org.jruby.ext.openssl.impl;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for MemBIO buffer management, verifying behavior consistent
 * with C OpenSSL's BIO_s_mem (crypto/bio/bss_mem.c).
 */
public class MemBIOTest {

    // C OpenSSL: BIO_write returns number of bytes written
    @Test
    public void writeReturnsLenOnSuccess() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = new byte[] { 1, 2, 3, 4, 5 };
        assertEquals(5, bio.write(data, 0, data.length));
    }

    // C OpenSSL: BIO_read returns number of bytes read, 0 at EOF
    @Test
    public void readAfterWrite() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] written = "hello".getBytes("ISO8859-1");
        bio.write(written, 0, written.length);

        byte[] buf = new byte[10];
        int read = bio.read(buf, 0, buf.length);
        assertEquals(5, read);
        assertEquals('h', buf[0]);
        assertEquals('o', buf[4]);
    }

    // C OpenSSL: BIO_read returns 0 when no data available
    @Test
    public void readOnEmptyReturnsZero() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] buf = new byte[10];
        assertEquals(0, bio.read(buf, 0, buf.length));
    }

    // C OpenSSL: mem_write returns 0 for inl <= 0
    @Test
    public void writeZeroLenReturnsZero() throws IOException {
        MemBIO bio = new MemBIO();
        assertEquals(0, bio.write(new byte[0], 0, 0));
        assertEquals(0, bio.length());
    }

    // C OpenSSL: mem_write returns 0 for inl <= 0
    @Test
    public void writeNegativeLenReturnsZero() throws IOException {
        MemBIO bio = new MemBIO();
        assertEquals(0, bio.write(new byte[1], 0, -1));
        assertEquals(0, bio.length());
    }

    // Buffer grows automatically on write (C OpenSSL uses BUF_MEM_grow_clean)
    @Test
    public void writeGrowsBeyondInitialBuffer() throws IOException {
        MemBIO bio = new MemBIO();
        // Initial buffer is 1024; write more than that
        byte[] data = new byte[2048];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);

        assertEquals(2048, bio.write(data, 0, data.length));
        assertEquals(2048, bio.length());

        byte[] result = bio.toBytes();
        assertEquals(2048, result.length);
        assertEquals((byte) 0, result[0]);
        assertEquals((byte) 0xFF, result[255]);
    }

    // Multiple writes accumulate (C OpenSSL appends to BUF_MEM)
    @Test
    public void multipleWritesAccumulate() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] a = "abc".getBytes("ISO8859-1");
        byte[] b = "def".getBytes("ISO8859-1");

        bio.write(a, 0, a.length);
        bio.write(b, 0, b.length);

        assertEquals(6, bio.length());
        assertEquals("abcdef", new String(bio.toBytes(), "ISO8859-1"));
    }

    // Write with offset
    @Test
    public void writeWithOffset() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = "XXhelloXX".getBytes("ISO8859-1");

        bio.write(data, 2, 5); // write "hello"
        assertEquals(5, bio.length());
        assertEquals("hello", new String(bio.toBytes(), "ISO8859-1"));
    }

    // Partial read leaves remaining data available
    @Test
    public void partialReadAdvancesPointer() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = "abcdef".getBytes("ISO8859-1");
        bio.write(data, 0, data.length);

        byte[] buf = new byte[3];
        assertEquals(3, bio.read(buf, 0, 3));
        assertEquals("abc", new String(buf, "ISO8859-1"));

        assertEquals(3, bio.read(buf, 0, 3));
        assertEquals("def", new String(buf, "ISO8859-1"));

        // Now exhausted
        assertEquals(0, bio.read(buf, 0, 3));
    }

    // C OpenSSL: BIO_reset rewinds read pointer
    @Test
    public void resetRewindsReadPointer() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = "hello".getBytes("ISO8859-1");
        bio.write(data, 0, data.length);

        byte[] buf = new byte[5];
        bio.read(buf, 0, 5);
        assertEquals(0, bio.read(buf, 0, 5)); // exhausted

        bio.reset();
        assertEquals(5, bio.read(buf, 0, 5)); // readable again
        assertEquals("hello", new String(buf, "ISO8859-1"));
    }

    // gets reads up to newline (C OpenSSL BIO_gets behavior)
    @Test
    public void getsReadsUpToNewline() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = "line1\nline2\n".getBytes("ISO8859-1");
        bio.write(data, 0, data.length);

        byte[] buf = new byte[20];
        int n = bio.gets(buf, 20);
        assertEquals(6, n); // "line1\n"
        assertEquals("line1\n", new String(buf, 0, n, "ISO8859-1"));

        n = bio.gets(buf, 20);
        assertEquals(6, n); // "line2\n"
        assertEquals("line2\n", new String(buf, 0, n, "ISO8859-1"));
    }

    // gets returns 0 when no data (C OpenSSL BIO_gets returns 0)
    @Test
    public void getsOnEmptyReturnsZero() {
        MemBIO bio = new MemBIO();
        assertEquals(0, bio.gets(new byte[10], 10));
    }

    @Test
    public void largeWriteGrowsInternalBuffer() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = new byte[1024 * 16];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);

        assertEquals(data.length, bio.write(data, 0, data.length));
        assertEquals(data.length, bio.length());
        assertArrayEquals(data, bio.toBytes());
        assertEquals(bio.buffer.length, bio.length());

        bio.write(new byte[] { 1, 2 }, 0, 2);
        assertTrue(bio.buffer.length > bio.length());
    }

    // toBytes / getMemCopy return a copy (C OpenSSL BIO_get_mem_copy semantics)
    @Test
    public void toBytesReturnsCopy() throws IOException {
        MemBIO bio = new MemBIO();
        byte[] data = "test".getBytes("ISO8859-1");
        bio.write(data, 0, data.length);

        byte[] copy1 = bio.toBytes();
        byte[] copy2 = bio.getMemCopy();
        assertNotSame(copy1, copy2);
        assertArrayEquals(copy1, copy2);

        // Mutating the copy doesn't affect the BIO
        copy1[0] = 'X';
        assertArrayEquals("test".getBytes("ISO8859-1"), bio.toBytes());
    }
}
