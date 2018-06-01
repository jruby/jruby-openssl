/*
 * The MIT License
 *
 * Copyright (c) 2018 Karol Bucek LTD.
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

import org.jruby.*;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.Utils.extractKeywordArgs;

/**
 * Provides functionality of various KDFs (key derivation function).
 *
 * @author kares
 */
@JRubyModule(name = "OpenSSL::KDF")
public class KDF {

    static void createKDF(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        RubyModule KDF = OpenSSL.defineModuleUnder("KDF");
        KDF.defineClassUnder("KDFError", OpenSSLError, OpenSSLError.getAllocator());
        KDF.defineAnnotatedMethods(KDF.class);
    }

    private static final String[] PBKDF2_ARGS = new String[] { "salt", "iterations", "length", "hash" };

    @JRubyMethod(module = true) // pbkdf2_hmac(pass, salt:, iterations:, length:, hash:)
    public static IRubyObject pbkdf2_hmac(ThreadContext context, IRubyObject self, IRubyObject pass, IRubyObject opts) {
        IRubyObject[] args = extractKeywordArgs(context, (RubyHash) opts, PBKDF2_ARGS, 1);
        args[0] = pass;
        try {
            return PKCS5.pbkdf2Hmac(context.runtime, args);
        }
        catch (NoSuchAlgorithmException|InvalidKeyException e) {
            throw newKDFError(context.runtime, e.getMessage());
        }
    }

    static RaiseException newKDFError(Ruby runtime, String message) {
        return Utils.newError(runtime, _KDF(runtime).getClass("KDFError"), message);
    }

    static RubyClass _KDF(final Ruby runtime) {
        return (RubyClass) runtime.getModule("OpenSSL").getConstant("KDF");
    }

}
