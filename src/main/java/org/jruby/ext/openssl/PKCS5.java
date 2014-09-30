/*
 * The MIT License
 *
 * Copyright 2014 Karol Bucek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.jruby.Ruby;
import org.jruby.RubyModule;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * OpenSSL::PKCS5
 *
 * @author kares
 */
@JRubyModule(name = "OpenSSL::PKCS5")
public class PKCS5 {

    public static void createPKCS5(final Ruby runtime, final RubyModule ossl) {
        final RubyModule PKCS5 = ossl.defineModuleUnder("PKCS5");
        PKCS5.defineAnnotatedMethods(PKCS5.class);
    }

    // def pbkdf2_hmac_sha1(pass, salt, iter, keylen)
    @JRubyMethod(meta = true, required = 4)
    public static IRubyObject pbkdf2_hmac_sha1(final IRubyObject self, final IRubyObject[] args) {
        final char[] pass = args[0].asString().toString().toCharArray();
        final byte[] salt = args[1].asString().getBytes();
        final int iter = (int) args[2].convertToInteger().getLongValue();
        final int keylen = (int) args[3].convertToInteger().getLongValue(); // e.g. 64

        return generatePBEKey(self.getRuntime(), pass, salt, iter, keylen, "PBKDF2WithHmacSHA1");
    }

    // def pbkdf2_hmac_sha1(pass, salt, iter, keylen, digest)
    @JRubyMethod(meta = true, required = 5)
    public static IRubyObject pbkdf2_hmac(final IRubyObject self, final IRubyObject[] args) {
        final byte[] pass = args[0].asString().getBytes();
        final byte[] salt = args[1].asString().getBytes();
        final int iter = (int) args[2].convertToInteger().getLongValue();
        final int keylen = (int) args[3].convertToInteger().getLongValue();

        final String digestAlg;
        final IRubyObject digest = args[4];
        if ( digest instanceof Digest ) {
            digestAlg = mapDigestName( ((Digest) digest).getRealName() );
        }
        else {
            digestAlg = mapDigestName( digest.asString().toString() );
        }

        // NOTE: on our own since e.g. "PBKDF2WithHmacMD5" not supported by Java

        final String macAlg = "Hmac" + digestAlg;
        final Ruby runtime = self.getRuntime();
        try {
            final Mac mac = SecurityHelper.getMac( macAlg );
            mac.init( new SecretKeySpec( pass, macAlg ) );
            final byte[] key = deriveKey(mac, salt, iter, keylen);
            return StringHelper.newString(runtime, key);
        }
        catch (NoSuchAlgorithmException ex) {
            throw Utils.newRuntimeError(runtime, ex); // should no happen
        }
        catch (InvalidKeyException ex) {
            throw Utils.newRuntimeError(runtime, ex); // TODO
        }
    }

    private static String mapDigestName(final String name) {
        final String mapped = name.toUpperCase();
        if ( mapped.startsWith("SHA-") ) { // SHA-512
            return "SHA" + mapped.substring(4); // SHA512
        }
        return mapped;
    }

    private static RubyString generatePBEKey(final Ruby runtime,
        final char[] pass, final byte[] salt, final int iter, final int keylen,
        final String alg) {

        final PBEKeySpec keySpec = new PBEKeySpec(pass, salt, iter, keylen * 8);
        try {
            SecretKey key = SecurityHelper.getSecretKeyFactory(alg).generateSecret(keySpec);
            return StringHelper.newString(runtime, key.getEncoded());
        }
        catch (NoSuchAlgorithmException ex) {
            throw Utils.newRuntimeError(runtime, ex); // should no happen
        }
        catch (InvalidKeySpecException ex) {
            throw Utils.newRuntimeError(runtime, ex); // TODO
        }
    }

    // http://stackoverflow.com/questions/9147463/java-pbkdf2-with-hmacsha256-as-the-prf

    public static byte[] deriveKey( final Mac prf, byte[] salt, int iterationCount, int dkLen )
        throws NoSuchAlgorithmException, InvalidKeyException {

        // Note: hLen, dkLen, l, r, T, F, etc. are horrible names for
        //       variables and functions in this day and age, but they
        //       reflect the terse symbols used in RFC 2898 to describe
        //       the PBKDF2 algorithm, which improves validation of the
        //       code vs. the RFC.
        //
        // dklen is expressed in bytes. (16 for a 128-bit key)

        int hLen = prf.getMacLength();   // 20 for SHA1
        int l = Math.max( dkLen, hLen); //  1 for 128bit (16-byte) keys
        int r = dkLen - (l-1)*hLen;      // 16 for 128bit (16-byte) keys
        byte T[] = new byte[l * hLen];
        int ti_offset = 0;
        for (int i = 1; i <= l; i++) {
            F( T, ti_offset, prf, salt, iterationCount, i );
            ti_offset += hLen;
        }

        if (r < hLen) {
            // Incomplete last block
            byte DK[] = new byte[dkLen];
            System.arraycopy(T, 0, DK, 0, dkLen);
            return DK;
        }
        return T;
    }


    private static void F( byte[] dest, int offset, Mac prf, byte[] S, int c, int blockIndex ) {
        final int hLen = prf.getMacLength();
        byte U_r[] = new byte[ hLen ];
        // U0 = S || INT (i);
        byte U_i[] = new byte[S.length + 4];
        System.arraycopy( S, 0, U_i, 0, S.length );
        doINT( U_i, S.length, blockIndex );
        for( int i = 0; i < c; i++ ) {
            U_i = prf.doFinal( U_i );
            doXOR( U_r, U_i );
        }

        System.arraycopy( U_r, 0, dest, offset, hLen );
    }

    private static void doXOR( byte[] dest, byte[] src ) {
        for( int i = 0; i < dest.length; i++ ) {
            dest[i] ^= src[i];
        }
    }

    private static void doINT( byte[] dest, int offset, int i ) {
        dest[offset + 0] = (byte) (i / (256 * 256 * 256));
        dest[offset + 1] = (byte) (i / (256 * 256));
        dest[offset + 2] = (byte) (i / (256));
        dest[offset + 3] = (byte) (i);
    }

}
