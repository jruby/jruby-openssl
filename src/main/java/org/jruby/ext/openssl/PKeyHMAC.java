/*
 * The MIT License
 *
 * Copyright (C) 2026 Karol Bucek
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

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Mac;

import org.jruby.Ruby;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.OpenSSL.throwOperationErrorOrOriginal;

public class PKeyHMAC extends PKey {

    private final byte[] key;

    private PKeyHMAC(final Ruby runtime, final byte[] key) {
        super(runtime, PKey._PKey(runtime).getClass("PKey"));
        this.key = key;
    }

    static PKeyHMAC newInstance(final Ruby runtime, final RubyString key) {
        return new PKeyHMAC(runtime, key.getBytes());
    }

    @Override
    public PublicKey getPublicKey() {
        return null;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return null;
    }

    @Override
    public String getAlgorithm() {
        return "HMAC";
    }

    @Override
    public String getKeyType() {
        return "HMAC";
    }

    @Override
    public boolean isPrivateKey() {
        return true;
    }

    @Override
    public IRubyObject raw_private_key(final ThreadContext context) {
        return RubyString.newString(context.runtime, new ByteList(key));
    }

    @Override
    public IRubyObject sign(final IRubyObject digest, final IRubyObject data) {
        final Ruby runtime = getRuntime();
        final String algName = HMAC.getDigestAlgorithmName(digest);
        final ByteList bytes = data.convertToString().getByteList();
        try {
            final Mac mac = HMAC.getMacInstance(algName);
            mac.init(SimpleSecretKey.copy(mac.getAlgorithm(), key));
            mac.update(bytes.getUnsafeBytes(), bytes.getBegin(), bytes.getRealSize());
            return RubyString.newString(runtime, new ByteList(mac.doFinal(), false));
        }
        catch (NoSuchAlgorithmException e) {
            throw runtime.newNotImplementedError("Unsupported MAC algorithm (HMAC[-]" + algName + ")");
        }
        catch (GeneralSecurityException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
    }

    @Override
    public IRubyObject verify(final IRubyObject digest, final IRubyObject sign, final IRubyObject data) {
        throw newPKeyError(getRuntime(), "EVP_PKEY_verify");
    }

    @Override
    public RubyString to_der() {
        throw newPKeyError(getRuntime(), "EVP_PKEY_export");
    }

    @Override
    public RubyString to_pem(final ThreadContext context, final IRubyObject[] args) {
        throw newPKeyError(context.runtime, "EVP_PKEY_export");
    }

    @Override
    public IRubyObject oid() {
        return getRuntime().newString("HMAC");
    }

    @Override
    public RubyString to_text() {
        return getRuntime().newString("HMAC Private-Key");
    }
}
