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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import org.bouncycastle.util.Arrays;
import org.jruby.*;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.ext.openssl.log.LoggingSupport;
import org.jruby.ext.openssl.util.ExceptionUtil;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.callsite.FunctionalCachingCallSite;
import org.jruby.util.ByteList;
import org.jruby.util.SafePropertyAccessor;

import static org.jruby.ext.openssl.util.RubySupport.newSecurityError;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * OpenSSL (methods as well as an entry point)
 *
 * @author kares
 */
@JRubyModule(name = "OpenSSL")
public class OpenSSL {

    OpenSSL() { /* no instances */ }

    static {
        // NOTE: no guarantee when user manually initializes other Java class (using `Logger.getLogger`)
        LoggingSupport.boostrapLoggerFactory();
    }

    static final Logger LOG = Logger.getLogger(OpenSSL.class);

    private static final FunctionalCachingCallSite WARN_CALL_SITE = new FunctionalCachingCallSite("warn");

    private static boolean loaded = false;

    public static void load(final Ruby runtime) {
        doLoad(runtime, false);
    }

    static void doLoad(final Ruby runtime, final boolean fipsGem) {
        SecurityHelper.setFipsVariant(fipsGem);
        SecurityHelper.checkAndRegisterProviderOnce();
        LoggingSupport.silenceBouncyCastleLoggers();

        createOpenSSL(runtime);
        loaded = true;
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public static void createOpenSSL(final Ruby runtime) {
        final RubyModule _OpenSSL = runtime.getOrCreateModule("OpenSSL");

        RubyClass StandardError = runtime.getStandardError();
        final RubyClass OpenSSLError = _OpenSSL.defineClassUnder("OpenSSLError", StandardError, StandardError.getAllocator());

        _OpenSSL.defineAnnotatedMethods(OpenSSL.class);

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
        PKCS12.createPKCS12(runtime, _OpenSSL, OpenSSLError);
        PKCS5.createPKCS5(runtime, _OpenSSL);
        OCSP.createOCSP(runtime, _OpenSSL, OpenSSLError);
        KDF.createKDF(runtime, _OpenSSL, OpenSSLError);
        Timestamp.createTimestamp(runtime, _OpenSSL, OpenSSLError);

        runtime.getLoadService().require("jopenssl/version");

        final byte[] version = { '2','.','2','.','3' }; // C OpenSSL gem version

        _OpenSSL.setConstant("VERSION", newString(runtime, version));

        final RubyModule JOpenSSL = runtime.getModule("JOpenSSL");
        final RubyString jVERSION = JOpenSSL.getConstantAt("VERSION").asString();

        final byte[] JRuby_OpenSSL_ = { 'J','R','u','b','y','-','O','p','e','n','S','S','L',' ' };
        ByteList OPENSSL_VERSION = new ByteList( jVERSION.getByteList().getRealSize() + JRuby_OpenSSL_.length );
        OPENSSL_VERSION.setEncoding( jVERSION.getEncoding() );
        OPENSSL_VERSION.append( JRuby_OpenSSL_ );
        OPENSSL_VERSION.append( jVERSION.getByteList() );

        // < 3.0.0 until we have decent (full) compatibility
        final byte OPENSSL_VERSION_MAJOR = 2;
        final byte OPENSSL_VERSION_MINOR = 9;
        final byte OPENSSL_VERSION_PATCH = 9;
        final byte OPENSSL_VERSION_PRE_RELEASE = 0;
        final int OPENSSL_VERSION_NUMBER = OPENSSL_VERSION_MAJOR << 28 | OPENSSL_VERSION_MINOR << 20 | OPENSSL_VERSION_PATCH << 4 | OPENSSL_VERSION_PRE_RELEASE;

        final RubyString VERSION;
        _OpenSSL.setConstant("OPENSSL_VERSION", VERSION = runtime.newString(OPENSSL_VERSION));
        _OpenSSL.setConstant("OPENSSL_VERSION_NUMBER", runtime.newFixnum(OPENSSL_VERSION_NUMBER));
        // MRI 2.3 tests do: /\AOpenSSL +0\./ !~ OpenSSL::OPENSSL_LIBRARY_VERSION
        _OpenSSL.setConstant("OPENSSL_LIBRARY_VERSION", VERSION);
        // whether the library is FIPS-capable - not whether FIPS is being enforced, that
        // is OpenSSL.fips_mode (C reports OPENSSL_FIPS true even with no FIPS provider up)
        _OpenSSL.setConstant("OPENSSL_FIPS", runtime.newBoolean(SecurityHelper.isFipsVariant()));
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
    public static IRubyObject getDebug(ThreadContext context, IRubyObject self) {
        final Ruby runtime = context.runtime;
        return runtime.newBoolean(OpenSSL.LOG.isDebug(runtime));
    }

    @JRubyMethod(name = "debug=", meta = true)
    public static IRubyObject setDebug(ThreadContext context, IRubyObject self, IRubyObject debug) {
        OpenSSL.debug = debug.isTrue();
        return getDebug(context, self);
    }

    @Deprecated
    public static IRubyObject getDebug(IRubyObject self) {
        return self.getRuntime().newBoolean(OpenSSL.debug);
    }

    @Deprecated
    public static IRubyObject setDebug(IRubyObject self, IRubyObject debug) {
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

    @JRubyMethod(meta = true)
    public static IRubyObject fixed_length_secure_compare(ThreadContext context, IRubyObject self, IRubyObject arg1, IRubyObject arg2) {
        final ByteList str1 = arg1.convertToString().getByteList();
        final ByteList str2 = arg2.convertToString().getByteList();
        if (str1.length() != str2.length()) throw context.runtime.newArgumentError("inputs must be of equal length");
        boolean equal = Arrays.constantTimeAreEqual(str1.length(), str1.unsafeBytes(), str1.begin(), str2.unsafeBytes(), str2.begin());
        return context.runtime.newBoolean(equal);
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

    @JRubyMethod(name = "fips_mode", meta = true)
    public static IRubyObject get_fips_mode(ThreadContext context, IRubyObject self) {
        // OpenSSL returns whether FIPS is enforced (EVP_default_properties_is_fips_enabled)
        // always a boolean - having FIPS module loaded but not enforcing reads as `false`
        return context.runtime.newBoolean(SecurityHelper.isApprovedOnlyMode());
    }

    @JRubyMethod(name = "fips_mode=", meta = true)
    public static IRubyObject set_fips_mode(ThreadContext context, IRubyObject self, IRubyObject mode) {
        final Ruby runtime = context.runtime;
        if (mode.isTrue() && !SecurityHelper.isApprovedOnlyMode()) {
            if (!SecurityHelper.isFipsVariant()) {
                throw runtime.newNotImplementedError("FIPS mode not available for this gem");
            }
            // approved-only is read when the module starts up, there is no turning it on later
            throw runtime.newNotImplementedError("FIPS mode can not be enabled at runtime" +
                    " (use -Dorg.bouncycastle.fips.approved_only=true)");
        }
        // NOTE: unlike C we do not let FIPS be turned off
        if (!mode.isTrue() && SecurityHelper.isApprovedOnlyMode()) {
            throw runtime.newSecurityError("FIPS mode can not be disabled at runtime");
        }
        return get_fips_mode(context, self);
    }

    // internal (package-level) helpers :

    public static void debug(CharSequence msg, Throwable ex) {
        LOG.debug(msg, ex);
    }

    // set OpenSSL debug internal flag early so it can print even while loading extension
    private static boolean debug = SafePropertyAccessor.getBoolean("jruby.openssl.debug");
    private static boolean warn = true;
    static {
        final String warn = SafePropertyAccessor.getProperty("jruby.openssl.warn");
        if (warn != null) OpenSSL.warn = Boolean.parseBoolean(warn);
    }

    public static boolean isDebug() { return debug; }

    public static boolean isWarn() { return warn; }

    public static void doWarn(final ThreadContext context, final CharSequence msg) {
        doWarn(context, (IRubyObject) RubyString.newString(context.runtime, msg));
    }

    private static void doWarn(final ThreadContext context, final IRubyObject msg) {
        final RubyModule _OpenSSL = context.runtime.getModule("OpenSSL");
        WARN_CALL_SITE.call(context, _OpenSSL, _OpenSSL, msg);
    }

    private static String javaVersion(final String def, final int len) {
        String javaVersion = SafePropertyAccessor.getProperty("java.version", def);
        if ( "0".equals(javaVersion) ) javaVersion = "1.7.0"; // Android
        return javaVersion.length() > len && len > -1 ? javaVersion.substring(0, len) : javaVersion;
    }

    static boolean javaVersion8(final boolean atLeast) {
        final int gt = "1.8".compareTo( javaVersion("0.0", 3) );
        return atLeast ? gt <= 0 : gt == 0;
    }

    private static String javaName(final String def) {
        // Sun Java 6 or Oracle Java 7/8/9/10
        // "Java HotSpot(TM) Server VM" or "Java HotSpot(TM) 64-Bit Server VM"
        // OpenJDK :
        // "OpenJDK 64-Bit Server VM"
        return SafePropertyAccessor.getProperty("java.vm.name", def);
    }

    static boolean javaHotSpot() {
        return javaName("").contains("HotSpot(TM)");
    }

    static boolean javaOpenJDK() {
        return javaName("").contains("OpenJDK");
    }

    // shared secure-random :

    private static boolean tryContextSecureRandom = true;

    static SecureRandom getSecureRandom(final ThreadContext context) throws NoSuchAlgorithmException {
        if (tryContextSecureRandom) {
            if (SecurityHelper.isFipsVariant()) { // in FIPS mode BC rejects non-approved RNGs
                tryContextSecureRandom = false;
            } else {
                SecureRandom random = getSecureRandomFrom(context);
                if (random != null) return random;
            }
        }
        return SecurityHelper.getSecureRandom();
    }

    private static SecureRandom getSecureRandomFrom(final ThreadContext context) {
        try {
            return context.getSecureRandom();
        }
        catch (Throwable ex) {
            tryContextSecureRandom = false;
            LOG.debug(context.runtime, "failed to retrieve secure random from thread-context", ex);
        }
        return null;
    }

    // internals

    static <T> T handlePotentialOperationError(final Ruby runtime, Throwable e) {
        ExceptionUtil.handlePotentialOperationError(e, ex -> newSecurityError(runtime, ex));
        return null; // never happens
    }

    /**
     * @implNote matches <code>ossl_to_der_if_possible</code>
     * @return obj or obj.to_der converted to string
     */
    static IRubyObject to_der_if_possible(final ThreadContext context, IRubyObject obj) {
        if (obj instanceof RubyString) return obj; // avoid checks for common value
        if (!obj.respondsTo("to_der")) return obj;
        return obj.callMethod(context, "to_der").asString();
    }

    //

    static String bcExceptionMessage(Throwable ex) {
        return "You need to configure JVM/classpath to enable BouncyCastle security provider: " + ex;
    }

}
