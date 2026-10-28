package org.jruby.ext.openssl;

import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class SimpleSecretKeyTest {

    @Test
    public void getEncodedReturnsCopy() {
        final byte[] value = { 1, 2, 3, 4 };
        final SimpleSecretKey key = new SimpleSecretKey("AES", value);
        key.getEncoded()[0] = 0;
        assertArrayEquals(new byte[] { 1, 2, 3, 4 }, key.getEncoded());
        assertArrayEquals(new byte[] { 1, 2, 3, 4 }, value);
    }

    // SunJCE wipes the encoded key bytes after init
    @Test
    public void keyBytesSurviveSunJCEInit() throws Exception {
        assumeTrue(Security.getProvider("SunJCE") != null);

        final byte[] value = new byte[16]; Arrays.fill(value, (byte) 'k');

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, new SimpleSecretKey("AES", value));
        final byte[] out1 = cipher.doFinal(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, new SimpleSecretKey("AES", value));
        assertArrayEquals(out1, cipher.doFinal(new byte[16]));

        Mac mac = Mac.getInstance("HmacSHA256", "SunJCE");
        mac.init(new SimpleSecretKey("HmacSHA256", value));

        final byte[] expected = new byte[16]; Arrays.fill(expected, (byte) 'k');
        assertArrayEquals(expected, value);
    }

}
