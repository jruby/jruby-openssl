
package org.jruby.ext.openssl;

import org.junit.*;
import static org.junit.Assert.*;

/**
 * @author kares
 */
public class CipherTest {

    @Test
    public void ciphersGetLazyInitialized() {
        assertTrue( Cipher.supportedCiphers.isEmpty() );
        assertFalse( Cipher.isSupportedCipher("UNKNOWN") );
        assertFalse( Cipher.supportedCiphers.isEmpty() );
        assertTrue( Cipher.supportedCiphers.contains("DES") );
        assertTrue( Cipher.isSupportedCipher("DES") );
        assertTrue( Cipher.isSupportedCipher("des") );
    }

    @Test
    public void jsseToOssl() {
        String alg;
        alg = Cipher.Algorithm.jsseToOssl("RC2/CBC/PKCS5Padding", 40);
        assertEquals("RC2-40-CBC", alg);
        alg = Cipher.Algorithm.jsseToOssl("RC2/CFB/PKCS5Padding", 40);
        assertEquals("RC2-40-CFB", alg);
        alg = Cipher.Algorithm.jsseToOssl("Blowfish", 60);
        assertEquals("BF-60-CBC", alg);
        alg = Cipher.Algorithm.jsseToOssl("DESede", 24);
        assertEquals("DES-EDE3-CBC", alg);
    }

    @Test
    public void osslToJsse() {
        Cipher.Algorithm alg;
        alg = Cipher.Algorithm.osslToJava("RC2-40-CBC");
        assertEquals("RC2", alg.base);
        assertEquals("40", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("RC2/CBC/PKCS5Padding", alg.realName);

        alg = Cipher.Algorithm.osslToJava("DES-EDE3-CBC");
        assertEquals("DES", alg.base);
        assertEquals("EDE3", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("DESede/CBC/PKCS5Padding", alg.realName);

        alg = Cipher.Algorithm.osslToJava("BF");
        assertEquals("Blowfish", alg.base);
        assertEquals("Blowfish/CBC/PKCS5Padding", alg.realName);

        alg = Cipher.Algorithm.osslToJava("AES-128-XTS");
        assertEquals("AES", alg.base);
        assertEquals("128", alg.version);
        assertEquals("XTS", alg.mode);
        assertEquals("PKCS5Padding", alg.padding);
        assertEquals("AES/XTS/PKCS5Padding", alg.realName);

        alg = Cipher.Algorithm.osslToJava("AES256");
        assertEquals("AES256", alg.base);
        assertEquals(null, alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("PKCS5Padding", alg.padding);
        assertEquals("AES/CBC/PKCS5Padding", alg.realName);

        alg = Cipher.Algorithm.osslToJava("AES-256-CBC-HMAC-SHA1");
        assertEquals("AES", alg.base);

        assertEquals("CBC", alg.mode);
        assertEquals("256", alg.version);

        assertEquals("PKCS5Padding", alg.padding);
        assertEquals("AES/CBC/PKCS5Padding", alg.realName);
    }

    @Test
    public void osslKeyIvLength() {
        int[] len;
        len = Cipher.Algorithm.osslKeyIvLength("RC2-40-CBC");
        assertEquals(5, len[0]);
        assertEquals(8, len[1]);

        len = Cipher.Algorithm.osslKeyIvLength("DES-EDE3-CBC");
        assertEquals(24, len[0]);
        assertEquals(8, len[1]);

        len = Cipher.Algorithm.osslKeyIvLength("DES");
        assertEquals(8, len[0]);
        assertEquals(8, len[1]);

        len = Cipher.Algorithm.osslKeyIvLength("BF");
        assertEquals(16, len[0]);
        assertEquals(8, len[1]);

        len = Cipher.Algorithm.osslKeyIvLength("CAST");
        assertEquals(16, len[0]);
        assertEquals(8, len[1]);
    }

    @Test
    public void getAlgorithmBase() throws Exception {
        javax.crypto.Cipher cipher; String algBase;
        cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
        algBase = Cipher.Algorithm.getAlgorithmBase(cipher);
        assertEquals("DES", algBase);

        cipher = javax.crypto.Cipher.getInstance("DES");
        algBase = Cipher.Algorithm.getAlgorithmBase(cipher);
        assertEquals("DES", algBase);
    }

}
