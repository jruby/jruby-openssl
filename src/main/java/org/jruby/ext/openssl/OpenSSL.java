/*
 * The MIT License
 *
 * Copyright (c) 2014 Karol Bucek LTD.
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

import java.security.SecureRandom;
import java.util.Map;

import org.jruby.*;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.util.SafePropertyAccessor;

/**
 * OpenSSL (methods as well as an entry point)
 *
 * @author kares
 */
@JRubyModule(name = "OpenSSL")
public final class OpenSSL {

    public static void load(final Ruby runtime) {
        createOpenSSL(runtime);
    }

    public static boolean isProviderAvailable() {
        return SecurityHelper.isProviderAvailable("BC");
    }

    public static void createOpenSSL(final Ruby runtime) {
        SecurityHelper.setRegisterProvider( SafePropertyAccessor.getBoolean("jruby.openssl.provider.register") );

        final RubyModule _OpenSSL = runtime.getOrCreateModule("OpenSSL");

        RubyClass StandardError = runtime.getStandardError();
        final RubyClass OpenSSLError = _OpenSSL.defineClassUnder("OpenSSLError", StandardError, StandardError.getAllocator());

        _OpenSSL.defineAnnotatedMethods(OpenSSL.class);

        // set OpenSSL debug internal flag early on so it can print traces even while loading extension
        setDebug(_OpenSSL, runtime.newBoolean( SafePropertyAccessor.getBoolean("jruby.openssl.debug") ) );

        final String warn = SafePropertyAccessor.getProperty("jruby.openssl.warn");
        if ( warn != null ) OpenSSL.warn = Boolean.parseBoolean(warn);
        else OpenSSL.warn = runtime.warningsEnabled();

        // Config.createConfig(runtime, _OpenSSL);
        ExtConfig.create(runtime, _OpenSSL);
        PKey.createPKey(runtime, _OpenSSL, OpenSSLError);
        BN.createBN(runtime, _OpenSSL, OpenSSLError);
        Digest.createDigest(runtime, _OpenSSL, OpenSSLError);
        Cipher.createCipher(runtime, _OpenSSL, OpenSSLError);
        Random.createRandom(runtime, _OpenSSL, OpenSSLError);
        HMAC.createHMAC(runtime, _OpenSSL, OpenSSLError);
        ASN1.createASN1(runtime, _OpenSSL, OpenSSLError);
        X509.createX509(runtime, _OpenSSL, OpenSSLError);
        NetscapeSPKI.createNetscapeSPKI(runtime, _OpenSSL, OpenSSLError);
        SSL.createSSL(runtime, _OpenSSL, OpenSSLError);
        PKCS7.createPKCS7(runtime, _OpenSSL, OpenSSLError);
        PKCS5.createPKCS5(runtime, _OpenSSL);
        OCSP.createOCSP(runtime, _OpenSSL, OpenSSLError);
        KDF.createKDF(runtime, _OpenSSL, OpenSSLError);

        runtime.getLoadService().require("jopenssl/version");

        // MRI 1.8.7 :
        // OpenSSL::VERSION: "1.0.0"
        // OpenSSL::OPENSSL_VERSION: "OpenSSL 1.0.1c 10 May 2012"
        // OpenSSL::OPENSSL_VERSION_NUMBER: 268439615
        // MRI 1.9.3 / 2.2.3 :
        // OpenSSL::VERSION: "1.1.0"
        // OpenSSL::OPENSSL_VERSION: "OpenSSL 1.0.1f 6 Jan 2014"
        // OpenSSL::OPENSSL_VERSION_NUMBER: 268439663
        // OpenSSL::OPENSSL_LIBRARY_VERSION: ""OpenSSL 1.0.2d 9 Jul 2015"
        // OpenSSL::FIPS: false

        final byte[] version = { '1','.','1','.','0' };

        _OpenSSL.setConstant("VERSION", StringHelper.newString(runtime, version));

        final RubyModule JOpenSSL = runtime.getModule("JOpenSSL");
        final RubyString jVERSION = JOpenSSL.getConstantAt("VERSION").asString();

        final byte[] JRuby_OpenSSL_ = { 'J','R','u','b','y','-','O','p','e','n','S','S','L',' ' };
        final int OPENSSL_VERSION_NUMBER = 999999999; // NOTE: smt more useful?

        ByteList OPENSSL_VERSION = new ByteList( jVERSION.getByteList().getRealSize() + JRuby_OpenSSL_.length );
        OPENSSL_VERSION.setEncoding( jVERSION.getEncoding() );
        OPENSSL_VERSION.append( JRuby_OpenSSL_ );
        OPENSSL_VERSION.append( jVERSION.getByteList() );

        final RubyString VERSION;
        _OpenSSL.setConstant("OPENSSL_VERSION", VERSION = runtime.newString(OPENSSL_VERSION));
        _OpenSSL.setConstant("OPENSSL_VERSION_NUMBER", runtime.newFixnum(OPENSSL_VERSION_NUMBER));
        // MRI 2.3 tests do: /\AOpenSSL +0\./ !~ OpenSSL::OPENSSL_LIBRARY_VERSION
        _OpenSSL.setConstant("OPENSSL_LIBRARY_VERSION", VERSION);
        _OpenSSL.setConstant("OPENSSL_FIPS", runtime.getFalse());
    }

    static RubyClass _OpenSSLError(final Ruby runtime) {
        return (RubyClass) runtime.getModule("OpenSSL").getConstantAt("OpenSSLError");
    }

    // OpenSSL module methods :

    @JRubyMethod(name = "errors", meta = true)
    public static IRubyObject errors(IRubyObject self) {
        final Ruby runtime = self.getRuntime();
        RubyArray result = runtime.newArray();
        for (Map.Entry<Integer, String> e : X509.getErrors().entrySet()) {
            result.add( runtime.newString( e.getValue() ) );
        }
        return result;
    }

    @JRubyMethod(name = "debug", meta = true)
    public static IRubyObject getDebug(IRubyObject self) {
        return (IRubyObject) getDebug((RubyModule) self);
    }

    private static Object getDebug(RubyModule self) {
        return self.getInternalVariable("debug");
    }

    @JRubyMethod(name = "debug=", meta = true)
    public static IRubyObject setDebug(IRubyObject self, IRubyObject debug) {
        ((RubyModule) self).setInternalVariable("debug", debug);
        OpenSSL.debug = debug.isTrue();
        return debug;
    }

    @JRubyMethod(name = "Digest", meta = true)
    public static IRubyObject Digest(final IRubyObject self, final IRubyObject name) {
        // OpenSSL::Digest("MD5") -> OpenSSL::Digest::MD5
        final Ruby runtime = self.getRuntime();
        final RubyClass Digest = runtime.getModule("OpenSSL").getClass("Digest");
        return Digest.getConstantAt( name.asJavaString() );
    }

    // API "stubs" in JRuby-OpenSSL :

    @JRubyMethod(meta = true)
    public static IRubyObject deprecated_warning_flag(final IRubyObject self) {
        return self.getRuntime().getNil(); // no-op in JRuby-OpenSSL
    }

    @JRubyMethod(meta = true, rest = true) // check_func(func, header)
    public static IRubyObject check_func(final IRubyObject self, final IRubyObject[] args) {
        return self.getRuntime().getNil(); // no-op in JRuby-OpenSSL
    }

    // Added in 2.0; not masked because it does nothing anyway (there's no reader in MRI)
    @JRubyMethod(name = "fips_mode=", meta = true)
    public static IRubyObject set_fips_mode(ThreadContext context, IRubyObject self, IRubyObject value) {
        if ( value.isTrue() ) {
            warn(context, "FIPS mode not supported on JRuby-OpenSSL");
        }
        return value;
    }

    // internal (package-level) helpers :

    /**
     * PRIMARILY MEANT FOR TESTING ONLY, USAGE IS DISCOURAGED!
     * @see org.jruby.ext.openssl.util.CryptoSecurity
     */
    @JRubyMethod(name = "_disable_security_restrictions!", visibility = Visibility.PRIVATE, meta = true)
    public static IRubyObject _disable_security_restrictions(ThreadContext context, IRubyObject self) {
        Boolean unrestrict = org.jruby.ext.openssl.util.CryptoSecurity.unrestrictSecurity();
        Boolean allPerm = org.jruby.ext.openssl.util.CryptoSecurity.setAllPermissionPolicy();
        if ( unrestrict == null || allPerm == null ) return context.nil;
        return context.runtime.newBoolean( unrestrict && allPerm );
    }


    private static boolean debug;

    // on by default, warnings can be disabled using -Djruby.openssl.warn=false
    private static boolean warn = true;

    static boolean isDebug() { return debug; }

    public static void debugStackTrace(final Throwable e) {
        if ( isDebug() ) e.printStackTrace(System.out);
    }

    public static void debug(final String msg) {
        if ( isDebug() ) System.out.println(msg);
    }

    public static void debug(final String msg, final Throwable e) {
        if ( isDebug() ) System.out.println(msg + ' ' + e);
    }

    static boolean isDebug(final Ruby runtime) {
        final RubyModule OpenSSL = runtime.getModule("OpenSSL");
        if ( OpenSSL == null ) return debug; // debug early on
        return getDebug( OpenSSL ) == runtime.getTrue();
    }

    static void debugStackTrace(final Ruby runtime, final Throwable e) {
        if ( isDebug(runtime) ) e.printStackTrace(runtime.getOut());
    }

    public static void debug(final Ruby runtime, final CharSequence msg) {
        if ( isDebug(runtime) ) runtime.getOut().println(msg.toString());
    }

    public static void debug(final Ruby runtime, final CharSequence msg, final Throwable e) {
        if ( isDebug(runtime) ) runtime.getOut().println(msg.toString() + ' ' + e);
    }

    static void warn(final ThreadContext context, final CharSequence msg) {
        if ( warn ) warn(context, RubyString.newString(context.runtime, msg));
    }

    static void warn(final ThreadContext context, final RubyString msg) {
        warn(context, (IRubyObject) msg);
    }

    static void warn(final ThreadContext context, final IRubyObject msg) {
        if ( warn ) context.runtime.getModule("OpenSSL").callMethod(context, "warn", msg);
    }

    private static String javaVersion(final String def, final int len) {
        String javaVersion = SafePropertyAccessor.getProperty("java.version", def);
        if ( "0".equals(javaVersion) ) javaVersion = "1.7.0"; // Android
        return javaVersion.length() > len && len > -1 ? javaVersion.substring(0, len) : javaVersion;
    }

    static boolean javaVersion7(final boolean atLeast) {
        final int gt = "1.7".compareTo( javaVersion("0.0", 3) );
        return atLeast ? gt <= 0 : gt == 0;
    }

    static boolean javaVersion8(final boolean atLeast) {
        final int gt = "1.8".compareTo( javaVersion("0.0", 3) );
        return atLeast ? gt <= 0 : gt == 0;
    }

    public static boolean javaVersion9(final boolean atLeast) {
        final int major = parseIntDot( javaVersion("0", -1) );
        return atLeast ? major >= 9 : major == 9;
    }

    static boolean javaVersion10(final boolean atLeast) {
        final int major = parseIntDot( javaVersion("0", -1) );
        return atLeast ? major >= 10 : major == 10;
    }

    private static int parseIntDot(String version) {
        String[] parts = version.split("[-_]")[0].split("\\.");
        try {
            return Integer.parseInt(parts[0]);
        }
        catch (NumberFormatException ex) {
            return -1;
        }
    }

    private static String javaName(final String def) {
        // Sun Java 6 or Oracle Java 7/8/9/10
        // "Java HotSpot(TM) Server VM" or "Java HotSpot(TM) 64-Bit Server VM"
        // OpenJDK :
        // "OpenJDK 64-Bit Server VM"
        return SafePropertyAccessor.getProperty("java.vm.name", def);
    }

    public static boolean javaHotSpot() {
        return javaName("").contains("HotSpot(TM)");
    }

    public static boolean javaOpenJDK() {
        return javaName("").contains("OpenJDK");
    }

    // shared secure-random :

    private static boolean tryContextSecureRandom = true;

    static SecureRandom getSecureRandom(final Ruby runtime) {
        return getSecureRandom(runtime, false);
    }


    static SecureRandom getSecureRandom(final Ruby runtime, final boolean nullByDefault) {
        if ( tryContextSecureRandom ) {
            SecureRandom random = getSecureRandomFrom(runtime.getCurrentContext());
            if ( random != null ) return random;
        }
        return nullByDefault ? null : new SecureRandom();
    }

    static SecureRandom getSecureRandomFrom(final ThreadContext context) {
        if ( tryContextSecureRandom ) {
            try {
                SecureRandom random = context.secureRandom;
                if (random == null) { // public SecureRandom getSecureRandom() on 9K
                    random = (SecureRandom) context.getClass().getMethod("getSecureRandom").invoke(context);
                }
                return random;
            }
            catch (Throwable ex) {
                tryContextSecureRandom = false;
                debug(context.runtime, "JRuby-OpenSSL failed to retrieve secure random from thread-context", ex);
            }
        }
        return null;
    }

    // internals

    static IRubyObject to_der_if_possible(final ThreadContext context, IRubyObject obj) {
        if ( obj instanceof RubyString || obj instanceof RubyIO ) return obj;
        if ( ! obj.respondsTo("to_der"))  return obj;
        return obj.callMethod(context, "to_der");
    }

    //

    static String bcExceptionMessage(Throwable ex) {
        return "You need to configure JVM/classpath to enable BouncyCastle Security Provider: " + ex;
    }

}
