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

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.anno.JRubyMethod;
import org.jruby.anno.JRubyModule;
import org.jruby.exceptions.RaiseException;
import org.jruby.internal.runtime.methods.DynamicMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.SafePropertyAccessor;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSL {

    public static final int VERIFY_NONE =                                   0x00;
    public static final int VERIFY_PEER =                                   0x01;
    public static final int VERIFY_FAIL_IF_NO_PEER_CERT =                   0x02;
    public static final int VERIFY_CLIENT_ONCE =                            0x04;

    public static final long OP_ALL =                                       0x00000FFFL;
    public static final long OP_NO_TICKET =                                 0x00004000L;
    public static final long OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION =    0x00010000L;
    public static final long OP_NO_COMPRESSION =                            0x00020000L;
    public static final long OP_SINGLE_ECDH_USE =                           0x00080000L;
    public static final long OP_SINGLE_DH_USE =                             0x00100000L;
    public static final long OP_EPHEMERAL_RSA =                             0x00200000L;
    public static final long OP_CIPHER_SERVER_PREFERENCE =                  0x00400000L;
    public static final long OP_TLS_ROLLBACK_BUG =                          0x00800000L;

    public static final long OP_NO_SSLv2 =                                  0x01000000L; // supported
    public static final long OP_NO_SSLv3 =                                  0x02000000L; // supported
    public static final long OP_NO_TLSv1 =                                  0x04000000L; // supported
    public static final long OP_NO_TLSv1_2 =                                0x08000000L;
    public static final long OP_NO_TLSv1_1 =                                0x10000000L;
    public static final long OP_NO_TLSv1_3 =                                0x20000000L;

    // define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)

    /* Deprecated in OpenSSL 1.0.1. */
    static final long OP_PKCS1_CHECK_1 =                             0x08000000L;
    /* Deprecated in OpenSSL 1.0.1. */
    static final long OP_PKCS1_CHECK_2 =                             0x10000000L;
    /* Deprecated in OpenSSL 1.1.0. */
    static final long OP_NETSCAPE_CA_DN_BUG =                        0x20000000L;
    /* Deprecated in OpenSSL 1.1.0. */
    static final long OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG =           0x40000000L;

    public static final int SSL2_VERSION = 0x0002;
    public static final int SSL3_VERSION = 0x0300;
    public static final int TLS1_VERSION = 0x0301;
    public static final int TLS1_1_VERSION = 0x0302;
    public static final int TLS1_2_VERSION = 0x0303;
    /* OpenSSL 1.1.1 */
    public static final int TLS1_3_VERSION = 0x0304;

    // define TLS_MAX_VERSION  TLS1_3_VERSION

    private static final String JSSE_TLS_ephemeralDHKeySize = "jdk.tls.ephemeralDHKeySize" ;
    private static final String JSSE_TLS_ephemeralDHKeySize_default = "matched" ;
    private static final String JSSE_TLS_disabledAlgorithms = "jdk.tls.disabledAlgorithms" ;
    private static final String JSSE_TLS_disabledAlgorithms_default = "SSLv3, DHE" ;

    static { configureJSSE(); }

    private static void configureJSSE() {
        if ( OpenSSL.javaVersion8(true) ) { // >= 1.8
            try {
                if ( System.getProperty(JSSE_TLS_ephemeralDHKeySize) == null ) {
                    // The key size is the same as the authentication certificate,
                    // but must be between 1024 bits and 2048 bits, inclusively.
                    // However, the SunJCE provider only supports 2048-bit DH keys larger
                    // than 1024 bits. Consequently, you may use the values 1024 or 2048 only.
                    System.setProperty(JSSE_TLS_ephemeralDHKeySize, JSSE_TLS_ephemeralDHKeySize_default);
                }
            }
            catch (SecurityException ex) {
                OpenSSL.debug("setting " + JSSE_TLS_ephemeralDHKeySize + " failed: " + ex);
            }
        }
        else { // on JDK 7 DHE is weak - disable completely (unless user-set)
            try {
                if ( System.getProperty(JSSE_TLS_disabledAlgorithms) == null ) {
                    System.setProperty(JSSE_TLS_disabledAlgorithms, JSSE_TLS_disabledAlgorithms_default);
                }
            }
            catch (SecurityException se) {
                OpenSSL.debug("setting " + JSSE_TLS_disabledAlgorithms + " failed: " + se);
            }
        }
    }

    static RaiseException handleCouldNotGenerateDHKeyPairError(final Ruby runtime, final RuntimeException ex) {
        String message = ex.getMessage();
        if ( OpenSSL.javaHotSpot() || OpenSSL.javaOpenJDK() ) {
            if ( OpenSSL.javaVersion8(false) ) { // == 1.8
                message += " (try disabling DHE using -D"+ JSSE_TLS_disabledAlgorithms +" as only keys of size 1024/2048 are supported in Java 8)";
            }
            else if ( ! OpenSSL.javaVersion8(true) ) { // < 1.8
                message += " (try disabling DHE using -D"+ JSSE_TLS_disabledAlgorithms +" as prior to Java 8 only keys of size < 1024 are supported)";
            }
        }
        return newSSLError(runtime, message, ex);
    }

    static void createSSL(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule SSL = OpenSSL.defineModuleUnder("SSL");
        final RubyClass SSLError = SSL.defineClassUnder("SSLError", OpenSSLError, OpenSSLError.getAllocator());

        final IRubyObject WaitReadable = runtime.getIO().getConstantAt("WaitReadable");
        if ( WaitReadable != null ) { // since 2.0 (do not exist in 1.9)
            SSL.defineClassUnder("SSLErrorWaitReadable", SSLError, OpenSSLError.getAllocator()).
                include(new IRubyObject[]{ WaitReadable });
        }
        final IRubyObject WaitWritable = runtime.getIO().getConstantAt("WaitWritable");
        if ( WaitWritable != null ) { // since 2.0 (do not exist in 1.9)
            SSL.defineClassUnder("SSLErrorWaitWritable", SSLError, OpenSSLError.getAllocator()).
                include(new IRubyObject[]{ WaitWritable });
        }

        SSL.setConstant("VERIFY_NONE", runtime.newFixnum(VERIFY_NONE));
        SSL.setConstant("VERIFY_PEER", runtime.newFixnum(VERIFY_PEER));
        SSL.setConstant("VERIFY_FAIL_IF_NO_PEER_CERT", runtime.newFixnum(VERIFY_FAIL_IF_NO_PEER_CERT));
        SSL.setConstant("VERIFY_CLIENT_ONCE", runtime.newFixnum(VERIFY_CLIENT_ONCE));

        SSL.setConstant("OP_ALL", runtime.newFixnum(OP_ALL));
        SSL.setConstant("OP_NO_TICKET", runtime.newFixnum(OP_NO_TICKET));
        SSL.setConstant("OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION", runtime.newFixnum(OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION));
        SSL.setConstant("OP_NO_COMPRESSION", runtime.newFixnum(OP_NO_COMPRESSION));
        SSL.setConstant("OP_SINGLE_ECDH_USE", runtime.newFixnum(OP_SINGLE_ECDH_USE));
        SSL.setConstant("OP_SINGLE_DH_USE", runtime.newFixnum(OP_SINGLE_DH_USE));
        SSL.setConstant("OP_EPHEMERAL_RSA", runtime.newFixnum(OP_EPHEMERAL_RSA));
        SSL.setConstant("OP_CIPHER_SERVER_PREFERENCE", runtime.newFixnum(OP_CIPHER_SERVER_PREFERENCE));
        SSL.setConstant("OP_TLS_ROLLBACK_BUG", runtime.newFixnum(OP_TLS_ROLLBACK_BUG));
        SSL.setConstant("OP_NO_SSLv2", runtime.newFixnum(OP_NO_SSLv2));
        SSL.setConstant("OP_NO_SSLv3", runtime.newFixnum(OP_NO_SSLv3));
        SSL.setConstant("OP_NO_TLSv1", runtime.newFixnum(OP_NO_TLSv1));
        SSL.setConstant("OP_NO_TLSv1_1", runtime.newFixnum(OP_NO_TLSv1_1));
        SSL.setConstant("OP_NO_TLSv1_2", runtime.newFixnum(OP_NO_TLSv1_2));
        //SSL.setConstant("OP_NO_TLSv1_3", runtime.newFixnum(OP_NO_TLSv1_3));
        SSL.setConstant("OP_PKCS1_CHECK_1", runtime.newFixnum(OP_PKCS1_CHECK_1));
        SSL.setConstant("OP_PKCS1_CHECK_2", runtime.newFixnum(OP_PKCS1_CHECK_2));
        SSL.setConstant("OP_NETSCAPE_CA_DN_BUG", runtime.newFixnum(OP_NETSCAPE_CA_DN_BUG));
        SSL.setConstant("OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG", runtime.newFixnum(OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG));

        SSL.setConstant("SSL2_VERSION", runtime.newFixnum(SSL2_VERSION));
        SSL.setConstant("SSL3_VERSION", runtime.newFixnum(SSL3_VERSION));
        SSL.setConstant("TLS1_VERSION", runtime.newFixnum(TLS1_VERSION));
        SSL.setConstant("TLS1_1_VERSION", runtime.newFixnum(TLS1_1_VERSION));
        SSL.setConstant("TLS1_2_VERSION", runtime.newFixnum(TLS1_2_VERSION));
        //SSL.setConstant("TLS1_3_VERSION", runtime.newFixnum(TLS1_3_VERSION));

        SSLContext.createSSLContext(runtime, SSL);
        SSLSocket.createSSLSocket(runtime, SSL);
        SSLSession.createSession(runtime, SSL, OpenSSLError);

        createNonblock(SSL);
    }

    public static RaiseException newSSLError(Ruby runtime, Exception ex) {
        return Utils.newError(runtime, _SSL(runtime).getClass("SSLError"), ex);
    }

    public static RaiseException newSSLError(Ruby runtime, String message) {
        return Utils.newError(runtime, _SSL(runtime).getClass("SSLError"), message, false);
    }

    private static RaiseException newSSLError(Ruby runtime, String message, Exception ex) {
        return Utils.newError(runtime, _SSL(runtime).getClass("SSLError"), message, ex);
    }

    public static RaiseException newSSLErrorWaitReadable(Ruby runtime, String message) {
        return newWaitSSLError(runtime, "SSLErrorWaitReadable", message);
    }

    public static RaiseException newSSLErrorWaitWritable(Ruby runtime, String message) {
        return newWaitSSLError(runtime, "SSLErrorWaitWritable", message);
    }

    // -Djruby.openssl.ssl.error_wait_nonblock.backtrace=false disables backtrace for WaitReadable/Writable
    private static final boolean waitErrorBacktrace;

    static {
        String backtrace = SafePropertyAccessor.getProperty("jruby.openssl.ssl.error_wait_nonblock.backtrace");
        if (backtrace == null) {
            // default to JRuby's Option<Boolean> ERRNO_BACKTRACE =
            // ... "Generate backtraces for heavily-used Errno exceptions (EAGAIN)."
            backtrace = SafePropertyAccessor.getProperty("jruby.errno.backtrace", "false");
        }
        waitErrorBacktrace = Boolean.parseBoolean(backtrace);
    }

    private static RaiseException newWaitSSLError(final Ruby runtime, final String name,
        final String message) {
        RubyClass errorClass = _SSL(runtime).getClass(name);
        if ( errorClass == null ) { // < Ruby 2.0
            errorClass = _SSL(runtime).getClass("SSLError"); // fallback
        }
        if ( waitErrorBacktrace ) {
            return Utils.newError(runtime, errorClass, message, false);
        }
        return Utils.newErrorWithoutTrace(runtime, errorClass, message);
    }

    static RubyModule _SSL(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstant("SSL");
    }

    private static RubyModule createNonblock(final RubyModule SSL) { // OpenSSL::SSL
        final RubyModule Nonblock = SSL.defineModuleUnder("Nonblock");
        Nonblock.defineAnnotatedMethods(Nonblock.class);
        return Nonblock;
    }

    @JRubyModule(name = "OpenSSL::SSL::Nonblock")
    public static class Nonblock {

        @JRubyMethod(rest = true, frame = true) // framed due super
        public static IRubyObject initialize(ThreadContext context, IRubyObject self, IRubyObject[] args) {
            final Ruby runtime = context.runtime;

            IRubyObject flag = runtime.getFile().getConstant("NONBLOCK"); // File::NONBLOCK

            IRubyObject Fcntl = runtime.getObject().getConstantAt("Fcntl");
            if ( /* Fcntl != null && */ Fcntl instanceof RubyModule ) {
                final IRubyObject io = self.getInstanceVariables().getInstanceVariable("@io");

                final RubyClass ioClass = self.getMetaClass();
                final DynamicMethod fcntl = ioClass.searchMethod("fcntl");

                IRubyObject F_GETFL = ((RubyModule) Fcntl).getConstantAt("F_GETFL");
                if ( F_GETFL != null ) { // if defined?(Fcntl::F_GETFL)
                    // flag |= @io.fcntl(Fcntl::F_GETFL) :
                    flag = or(context, flag, fcntl.call(context, io, ioClass, "fcntl", F_GETFL));
                }

                IRubyObject F_SETFL = ((RubyModule) Fcntl).getConstant("F_SETFL");
                fcntl.call(context, io, ioClass, "fcntl", new IRubyObject[] { F_SETFL, flag }); // @io.fcntl(Fcntl::F_SETFL, flag)
            }
            return Utils.invokeSuper(context, self, args, Block.NULL_BLOCK); // super
        }

        private static IRubyObject or(final ThreadContext context, final IRubyObject flag, final IRubyObject flags) {
            if ( flag instanceof RubyFixnum && flags instanceof RubyFixnum ) {
                final long f = ((RubyFixnum) flag).getLongValue();
                final long fs = ((RubyFixnum) flags).getLongValue();
                return RubyFixnum.newFixnum(context.runtime, f | fs);
            }
            return flag.callMethod(context, "|", flags);
        }

    } // Nonblock

}// SSL
