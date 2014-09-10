/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl;

import java.util.Map;

import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.ext.openssl.x509store.X509Error;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class OpenSSLReal {

    private OpenSSLReal() { /* no instances */ }

    @Deprecated
    public static interface Runnable {
        public void run() throws GeneralSecurityException;
    }

    public static interface Callable<T> {
        public T call() throws GeneralSecurityException;
    }

    /**
     * Run a block of code with 'BC' provider installed.
     *
     * @deprecated No longer used within the JRuby-OpenSSL code-base, please avoid!
     *
     * @param block
     * @throws GeneralSecurityException
     */
    @Deprecated
    public static void doWithBCProvider(final Runnable block) throws GeneralSecurityException {
        getWithBCProvider(new Callable<Void>() {
            public Void call() throws GeneralSecurityException {
                block.run(); return null;
            }
        });
    }

    /**
     * Adds BouncyCastleProvider if it's allowed (no security exceptions thrown)
     * and runs the block of code. Once added the provider will stay registered
     * within <code>java.security.Security</code> API. This might lead to memory
     * leaks e.g. when the Ruby runtime that loaded BC is teared down.
     *
     * Removing the 'BC' provided (once the block run) can remove pre-installed
     * or another runtime-added BC provider thus causing unknown runtime errors.
     *
     * @deprecated No longer used within the JRuby-OpenSSL code-base, please avoid!
     *
     * @param <T>
     * @param block
     * @return
     * @throws GeneralSecurityException
     */
    @Deprecated
    public static <T> T getWithBCProvider(final Callable<T> block) throws GeneralSecurityException {
        try {
            final Provider provider = SecurityHelper.getSecurityProvider(); // BC
            if (provider != null && java.security.Security.getProvider(provider.getName()) == null) {
                java.security.Security.addProvider(provider);
            }
            return block.call();
        } catch (NoSuchProviderException nspe) {
            throw new GeneralSecurityException(bcExceptionMessage(nspe), nspe);
        } catch (Exception e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
    }

    public static String bcExceptionMessage(NoSuchProviderException nspe) {
        return "You need to configure JVM/classpath to enable BouncyCastle Security Provider: " + nspe.getMessage();
    }

    public static String bcExceptionMessage(NoClassDefFoundError ncdfe) {
        return "You need to configure JVM/classpath to enable BouncyCastle Security Provider: NoClassDefFoundError: " + ncdfe.getMessage();
    }

    public static void createOpenSSL(final Ruby runtime) {
        boolean registerProvider = Boolean.getBoolean("jruby.openssl.provider.register");
        SecurityHelper.setRegisterProvider( registerProvider );

        final RubyModule _OpenSSL = runtime.getOrCreateModule("OpenSSL");
        RubyClass _StandardError = runtime.getClass("StandardError");
        _OpenSSL.defineClassUnder("OpenSSLError", _StandardError, _StandardError.getAllocator());
        _OpenSSL.defineAnnotatedMethods(OpenSSLModule.class);

        // those are BC provider free (uses BC class but does not use BC provider)
        PKey.createPKey(runtime, _OpenSSL);
        BN.createBN(runtime, _OpenSSL);
        Digest.createDigest(runtime, _OpenSSL);
        Cipher.createCipher(runtime, _OpenSSL);
        Random.createRandom(runtime, _OpenSSL);
        HMAC.createHMAC(runtime, _OpenSSL);
        Config.createConfig(runtime, _OpenSSL);
        ASN1.createASN1(runtime, _OpenSSL);
        X509.createX509(runtime, _OpenSSL);
        NetscapeSPKI.createNetscapeSPKI(runtime, _OpenSSL);
        PKCS7.createPKCS7(runtime, _OpenSSL);
        SSL.createSSL(runtime, _OpenSSL);

        runtime.getLoadService().require("jopenssl/version");

        // MRI 1.8.7 :
        // OpenSSL::VERSION: "1.0.0"
        // OpenSSL::OPENSSL_VERSION: "OpenSSL 1.0.1c 10 May 2012"
        // OpenSSL::OPENSSL_VERSION_NUMBER: 268439615
        // MRI 1.9.3 / 2.1.2 :
        // OpenSSL::VERSION: "1.1.0"
        // OpenSSL::OPENSSL_VERSION: "OpenSSL 1.0.1f 6 Jan 2014"
        // OpenSSL::OPENSSL_VERSION_NUMBER: 268439663

        final byte[] version = { '1','.','1','.','0' };

        if ( runtime.is1_8() ) version[2] = '0'; // 1.0.0 compatible on 1.8
        _OpenSSL.setConstant("VERSION", StringHelper.newString(runtime, version));

        final RubyModule _Jopenssl = runtime.getModule("Jopenssl");
        final RubyModule _Version = (RubyModule) _Jopenssl.getConstantAt("Version");
        final RubyString jVERSION = _Version.getConstantAt("VERSION").asString();

        final byte[] JRuby_OpenSSL_ = { 'J','R','u','b','y','-','O','p','e','n','S','S','L',' ' };
        final int OPENSSL_VERSION_NUMBER = 999999999; // 9469999 do smt useful with it ?

        ByteList OPENSSL_VERSION = new ByteList( jVERSION.getByteList().length() + JRuby_OpenSSL_.length );
        OPENSSL_VERSION.setEncoding( jVERSION.getEncoding() );
        OPENSSL_VERSION.append( JRuby_OpenSSL_ );
        OPENSSL_VERSION.append( jVERSION.getByteList() );
        _OpenSSL.setConstant("OPENSSL_VERSION", runtime.newString(OPENSSL_VERSION));
        _OpenSSL.setConstant("OPENSSL_VERSION_NUMBER", runtime.newFixnum(OPENSSL_VERSION_NUMBER));

        OpenSSLModule.setDebug(_OpenSSL, runtime.newBoolean( Boolean.getBoolean("jruby.openssl.debug") ) );

        final String warn = System.getProperty("jruby.openssl.warn");
        if ( warn != null ) OpenSSLReal.warn = Boolean.parseBoolean(warn);
    }

    private static boolean debug;

    // on by default, warnings can be disabled using -Djruby.openssl.warn=false
    private static boolean warn = true;

    static boolean isDebug() {
        return debug;
    }

    static void debugStackTrace(final Throwable e) {
        if ( isDebug() ) e.printStackTrace(System.out);
    }

    static void debug(final String msg) {
        if ( isDebug() ) System.out.println(msg);
    }

    static void debug(final String msg, final Throwable e) {
        if ( isDebug() ) System.out.println(msg + ' ' + e);
    }

    static boolean isDebug(final Ruby runtime) {
        RubyModule ossl = runtime.getModule("OpenSSL");
        return OpenSSLModule.getDebug(ossl).isTrue();
    }

    static void debugStackTrace(final Ruby runtime, final Throwable e) {
        if ( isDebug(runtime) ) e.printStackTrace(runtime.getOut());
    }

    static void debug(final Ruby runtime, final String msg) {
        if ( isDebug(runtime) ) runtime.getOut().println(msg);
    }

    static void debug(final Ruby runtime, final String msg, final Throwable e) {
        if ( isDebug(runtime) ) runtime.getOut().println(msg + ' ' + e);
    }

    static void warn(final ThreadContext context, final String msg) {
        warn(context, RubyString.newString(context.runtime, msg));
    }

    static void warn(final ThreadContext context, final IRubyObject msg) {
        if ( warn ) context.runtime.getModule("OpenSSL").callMethod(context, "warn", msg);
    }

    @JRubyModule(name = "OpenSSL")
    public static class OpenSSLModule {

        @JRubyMethod(name = "errors", meta = true)
        public static IRubyObject errors(IRubyObject self) {
            Ruby runtime = self.getRuntime();
            RubyArray result = runtime.newArray();
            for (Map.Entry<Integer, String> e : X509Error.getErrors().entrySet()) {
                result.add( runtime.newString( e.getValue() ) );
            }
            return result;
        }

        @JRubyMethod(name = "debug", meta = true)
        public static IRubyObject getDebug(IRubyObject self) {
            return (IRubyObject) ((RubyModule) self).getInternalVariable("debug");
        }

        @JRubyMethod(name = "debug=", meta = true)
        public static IRubyObject setDebug(IRubyObject self, IRubyObject debug) {
            ((RubyModule) self).setInternalVariable("debug", debug);
            OpenSSLReal.debug = debug.isTrue();
            return debug;
        }

        // Added in 2.0; not masked because it does nothing anyway
        @JRubyMethod(meta = true)
        public static IRubyObject fips_mode(ThreadContext context, IRubyObject self) {
            return context.runtime.getFalse();
        }

        // Added in 2.0; not masked because it does nothing anyway
        @JRubyMethod(name = "fips_mode=", meta = true)
        public static IRubyObject fips_mode_set(ThreadContext context, IRubyObject self, IRubyObject value) {
            if ( value.isTrue() ) {
                OpenSSLReal.warn(context, "WARNING: FIPS mode not supported on JRuby OpenSSL");
            }
            return self;
        }
    }

}