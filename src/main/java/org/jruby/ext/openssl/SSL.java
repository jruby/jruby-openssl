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
import org.jruby.RubyModule;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.builtin.IRubyObject;

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
    public static final long OP_SINGLE_ECDH_USE =                           0x00080000L;
    public static final long OP_SINGLE_DH_USE =                             0x00100000L;
    public static final long OP_EPHEMERAL_RSA =                             0x00200000L;
    public static final long OP_CIPHER_SERVER_PREFERENCE =                  0x00400000L;
    public static final long OP_TLS_ROLLBACK_BUG =                          0x00800000L;
    public static final long OP_NO_SSLv2 =                                  0x01000000L; // supported
    public static final long OP_NO_SSLv3 =                                  0x02000000L; // supported
    public static final long OP_NO_TLSv1 =                                  0x04000000L; // supported
    public static final long OP_PKCS1_CHECK_1 =                             0x08000000L;
    public static final long OP_PKCS1_CHECK_2 =                             0x10000000L;
    public static final long OP_NETSCAPE_CA_DN_BUG =                        0x20000000L;
    public static final long OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG =           0x40000000L;

    public static void createSSL(final Ruby runtime, final RubyModule OpenSSL) {
        final RubyModule SSL = OpenSSL.defineModuleUnder("SSL");
        final RubyClass OpenSSLError = OpenSSL.getClass("OpenSSLError");
        final RubyClass SSLError = SSL.defineClassUnder("SSLError", OpenSSLError, OpenSSLError.getAllocator());

        final IRubyObject WaitReadable = runtime.getIO().getConstantAt("WaitReadable");
        if ( WaitReadable != null ) { // since 2.0 (do not exist in 1.8 / 1.9)
            SSL.defineClassUnder("SSLErrorWaitReadable", SSLError, OpenSSLError.getAllocator()).
                include(new IRubyObject[]{ WaitReadable });
        }
        final IRubyObject WaitWritable = runtime.getIO().getConstantAt("WaitWritable");
        if ( WaitWritable != null ) { // since 2.0 (do not exist in 1.8 / 1.9)
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
        SSL.setConstant("OP_SINGLE_ECDH_USE", runtime.newFixnum(OP_SINGLE_ECDH_USE));
        SSL.setConstant("OP_SINGLE_DH_USE", runtime.newFixnum(OP_SINGLE_DH_USE));
        SSL.setConstant("OP_EPHEMERAL_RSA", runtime.newFixnum(OP_EPHEMERAL_RSA));
        SSL.setConstant("OP_CIPHER_SERVER_PREFERENCE", runtime.newFixnum(OP_CIPHER_SERVER_PREFERENCE));
        SSL.setConstant("OP_TLS_ROLLBACK_BUG", runtime.newFixnum(OP_TLS_ROLLBACK_BUG));
        SSL.setConstant("OP_NO_SSLv2", runtime.newFixnum(OP_NO_SSLv2));
        SSL.setConstant("OP_NO_SSLv3", runtime.newFixnum(OP_NO_SSLv3));
        SSL.setConstant("OP_NO_TLSv1", runtime.newFixnum(OP_NO_TLSv1));
        SSL.setConstant("OP_PKCS1_CHECK_1", runtime.newFixnum(OP_PKCS1_CHECK_1));
        SSL.setConstant("OP_PKCS1_CHECK_2", runtime.newFixnum(OP_PKCS1_CHECK_2));
        SSL.setConstant("OP_NETSCAPE_CA_DN_BUG", runtime.newFixnum(OP_NETSCAPE_CA_DN_BUG));
        SSL.setConstant("OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG", runtime.newFixnum(OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG));

        SSLContext.createSSLContext(runtime, SSL);
        SSLSocket.createSSLSocket(runtime, SSL);
    }

    public static RaiseException newSSLError(Ruby runtime, Exception exception) {
        return Utils.newError(runtime, _SSL(runtime).getClass("SSLError"), exception);
    }

    public static RaiseException newSSLError(Ruby runtime, String message) {
        return Utils.newError(runtime, _SSL(runtime).getClass("SSLError"), message, false);
    }

    public static RaiseException newSSLErrorWaitReadable(Ruby runtime, String message) {
        return newCustomSSLError(runtime, "SSLErrorWaitReadable", message);
    }

    public static RaiseException newSSLErrorWaitWritable(Ruby runtime, String message) {
        return newCustomSSLError(runtime, "SSLErrorWaitWritable", message);
    }

    private static RaiseException newCustomSSLError(final Ruby runtime, final String name,
        final String message) {
        RubyClass errorClass = _SSL(runtime).getClass(name);
        if ( errorClass == null ) { // < Ruby 2.0
            errorClass = _SSL(runtime).getClass("SSLError"); // fallback
        }
        return Utils.newError(runtime, errorClass, message, false);
    }

    static RubyModule _SSL(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstant("SSL");
    }

}// SSL
