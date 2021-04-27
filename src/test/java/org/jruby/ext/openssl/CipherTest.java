package org.jruby.ext.openssl;

import org.junit.*;
import static org.junit.Assert.*;

/**
 * @author kares
 */
public class CipherTest {

    @Test
    public void ciphersGetLazyInitialized() {
        //assertTrue( Cipher.Algorithm.AllSupportedCiphers.CIPHERS_MAP.isEmpty() );
        assertFalse( Cipher.isSupportedCipher("UNKNOWN") );
        assertFalse( Cipher.Algorithm.AllSupportedCiphers.CIPHERS_MAP.isEmpty() );
        assertTrue( Cipher.Algorithm.AllSupportedCiphers.CIPHERS_MAP.get("DES") != null );
        assertTrue( Cipher.isSupportedCipher("DES") );
        assertTrue( Cipher.isSupportedCipher("des") );
        assertTrue( Cipher.isSupportedCipher("AES") );
        assertTrue( Cipher.isSupportedCipher("BF") );
        assertTrue( Cipher.isSupportedCipher("des3") );
    }

    @Test
    public void jsseToOssl() {
        String alg;
        alg = Cipher.Algorithm.javaToOssl("RC2/CBC/PKCS5Padding", 40);
        assertEquals("RC2-40-CBC", alg);
        alg = Cipher.Algorithm.javaToOssl("RC2/CFB/PKCS5Padding", 40);
        assertEquals("RC2-40-CFB", alg);
        alg = Cipher.Algorithm.javaToOssl("Blowfish", 60);
        assertEquals("BF-60-CBC", alg);
        alg = Cipher.Algorithm.javaToOssl("DESede", 24);
        assertEquals("DES-EDE3-CBC", alg);
    }

    @Test
    public void osslToJsse() {
        doTestOsslToJsse();
    }

    private void doTestOsslToJsse() {
        Cipher.Algorithm alg;
        alg = Cipher.Algorithm.osslToJava("RC2-40-CBC");
        assertEquals("RC2", alg.base);
        assertEquals("40", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("RC2/CBC/PKCS5Padding", alg.getRealName());

        System.out.println("running ...");
        alg = Cipher.Algorithm.osslToJava("DES-EDE3-CBC");
        assertEquals("DES", alg.base);
        assertEquals("EDE3", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("DESede/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES3");
        assertEquals("DES", alg.base);
        assertEquals("EDE3", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("DESede/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES-EDE");
        assertEquals("DES", alg.base);
        assertEquals("EDE", alg.version);
        assertEquals("ECB", alg.mode);
        assertEquals("DESede/ECB/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES-EDE3");
        assertEquals("DES", alg.base);
        assertEquals("EDE3", alg.version);
        assertEquals("ECB", alg.mode);
        assertEquals("DESede/ECB/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES-EDE-CBC");
        assertEquals("DES", alg.base);
        assertEquals("EDE", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("DESede/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES-EDE3-CBC");
        assertEquals("DES", alg.base);
        assertEquals("EDE3", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("DESede/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES-EDE3-CFB");
        assertEquals("DES", alg.base);
        assertEquals("EDE3", alg.version);
        assertEquals("CFB", alg.mode);
        assertEquals("DESede/CFB/NoPadding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES-CFB");
        assertEquals("DES", alg.base);
        assertEquals(null, alg.version);
        assertEquals("CFB", alg.mode);
        assertEquals("DES/CFB/NoPadding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("DES3");
        assertEquals("DES", alg.base);
        //assertEquals("EDE", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("DESede/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("BF");
        assertEquals("BF", alg.base);
        assertEquals("Blowfish/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("AES-128-XTS");
        assertEquals("AES", alg.base);
        assertEquals("128", alg.version);
        assertEquals("XTS", alg.mode);
        assertEquals("PKCS5Padding", alg.getPadding());
        assertEquals("AES/XTS/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("AES256");
        assertEquals("AES", alg.base);
        assertEquals("256", alg.version);
        assertEquals("CBC", alg.mode);
        assertEquals("PKCS5Padding", alg.getPadding());
        assertEquals("AES/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("AES-256-OFB");
        assertEquals("AES", alg.base);
        assertEquals("256", alg.version);
        assertEquals("OFB", alg.mode);
        assertEquals("AES/OFB/NoPadding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("AES-256-CTR");
        assertEquals("AES", alg.base);
        assertEquals("256", alg.version);
        assertEquals("CTR", alg.mode);
        assertEquals("AES/CTR/NoPadding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("AES-256-CBC-HMAC-SHA1");
        assertEquals("AES", alg.base);
        assertEquals("CBC", alg.mode);
        assertEquals("256", alg.version);
        assertEquals("PKCS5Padding", alg.getPadding());
        assertEquals("AES/CBC/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("RC4");
        assertEquals("RC4", alg.base);
        assertEquals(null, alg.version);
        assertEquals(null, alg.mode);
        assertEquals(null, alg.getPadding());
        assertEquals("RC4", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("RC4-40");
        assertEquals("RC4", alg.base);
        assertEquals("40", alg.version);
        assertEquals(null, alg.mode);
        assertEquals(null, alg.getPadding());
        assertEquals("RC4", alg.getRealName());

        // keeps "invalid" modes :

        alg = Cipher.Algorithm.osslToJava("DES-3X3");
        assertEquals("DES", alg.base);
        assertEquals(null, alg.version);
        assertEquals("3X3", alg.mode);
        assertEquals("DES/3X3/PKCS5Padding", alg.getRealName());

        alg = Cipher.Algorithm.osslToJava("MES-123-XXX");
        assertEquals("MES", alg.base);
        assertEquals("123", alg.version);
        assertEquals("XXX", alg.mode);
        assertEquals("MES/XXX/PKCS5Padding", alg.getRealName());
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
