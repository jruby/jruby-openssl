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
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.ext.openssl.x509store.X509Error;
import org.jruby.ext.openssl.x509store.X509Utils;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509 {

    static void createX509(final Ruby runtime, final RubyModule _OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule _X509 = _OpenSSL.defineModuleUnder("X509");

        X509Name.createX509Name(runtime, _X509, OpenSSLError);
        X509Cert.createX509Cert(runtime, _X509, OpenSSLError);
        X509Extension.createX509Extension(runtime, _X509, OpenSSLError);
        X509CRL.createX509CRL(runtime, _X509, OpenSSLError);
        X509Revoked.createX509Revoked(runtime, _X509, OpenSSLError);
        X509Store.createX509Store(runtime, _X509, OpenSSLError);
        X509Request.createRequest(runtime, _X509, OpenSSLError);
        X509Attribute.createAttribute(runtime, _X509, OpenSSLError);

        final RubyFixnum _1 = runtime.newFixnum(1);
        final RubyFixnum _2 = runtime.newFixnum(2);
        final RubyFixnum _3 = runtime.newFixnum(3);
        final RubyFixnum _4 = runtime.newFixnum(4);
        final RubyFixnum _5 = runtime.newFixnum(5);
        final RubyFixnum _6 = runtime.newFixnum(6);
        final RubyFixnum _7 = runtime.newFixnum(7);
        final RubyFixnum _8 = runtime.newFixnum(8);

        _X509.setConstant("V_OK",runtime.newFixnum(0));
        _X509.setConstant("V_ERR_UNABLE_TO_GET_ISSUER_CERT",_2);
        _X509.setConstant("V_ERR_UNABLE_TO_GET_CRL",_3);
        _X509.setConstant("V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE",_4);
        _X509.setConstant("V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE",_5);
        _X509.setConstant("V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",_6);
        _X509.setConstant("V_ERR_CERT_SIGNATURE_FAILURE",_7);
        _X509.setConstant("V_ERR_CRL_SIGNATURE_FAILURE",_8);
        _X509.setConstant("V_ERR_CERT_NOT_YET_VALID",runtime.newFixnum(9));
        _X509.setConstant("V_ERR_CERT_HAS_EXPIRED",runtime.newFixnum(10));
        _X509.setConstant("V_ERR_CRL_NOT_YET_VALID",runtime.newFixnum(11));
        _X509.setConstant("V_ERR_CRL_HAS_EXPIRED",runtime.newFixnum(12));
        _X509.setConstant("V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD",runtime.newFixnum(13));
        _X509.setConstant("V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD",runtime.newFixnum(14));
        _X509.setConstant("V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD",runtime.newFixnum(15));
        _X509.setConstant("V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD",runtime.newFixnum(16));
        _X509.setConstant("V_ERR_OUT_OF_MEM",runtime.newFixnum(17));
        _X509.setConstant("V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT",runtime.newFixnum(18));
        _X509.setConstant("V_ERR_SELF_SIGNED_CERT_IN_CHAIN",runtime.newFixnum(19));
        _X509.setConstant("V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",runtime.newFixnum(20));
        _X509.setConstant("V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE",runtime.newFixnum(21));
        _X509.setConstant("V_ERR_CERT_CHAIN_TOO_LONG",runtime.newFixnum(22));
        _X509.setConstant("V_ERR_CERT_REVOKED",runtime.newFixnum(23));
        _X509.setConstant("V_ERR_INVALID_CA",runtime.newFixnum(24));
        _X509.setConstant("V_ERR_PATH_LENGTH_EXCEEDED",runtime.newFixnum(25));
        _X509.setConstant("V_ERR_INVALID_PURPOSE",runtime.newFixnum(26));
        _X509.setConstant("V_ERR_CERT_UNTRUSTED",runtime.newFixnum(27));
        _X509.setConstant("V_ERR_CERT_REJECTED",runtime.newFixnum(28));
        _X509.setConstant("V_ERR_SUBJECT_ISSUER_MISMATCH",runtime.newFixnum(29));
        _X509.setConstant("V_ERR_AKID_SKID_MISMATCH",runtime.newFixnum(30));
        _X509.setConstant("V_ERR_AKID_ISSUER_SERIAL_MISMATCH",runtime.newFixnum(31));
        _X509.setConstant("V_ERR_KEYUSAGE_NO_CERTSIGN",runtime.newFixnum(32));
        _X509.setConstant("V_ERR_APPLICATION_VERIFICATION",runtime.newFixnum(50));
        _X509.setConstant("V_FLAG_CRL_CHECK",_4);
        _X509.setConstant("V_FLAG_CRL_CHECK_ALL",_8);
        _X509.setConstant("PURPOSE_SSL_CLIENT",_1);
        _X509.setConstant("PURPOSE_SSL_SERVER",_2);
        _X509.setConstant("PURPOSE_NS_SSL_SERVER",_3);
        _X509.setConstant("PURPOSE_SMIME_SIGN",_4);
        _X509.setConstant("PURPOSE_SMIME_ENCRYPT",_5);
        _X509.setConstant("PURPOSE_CRL_SIGN",_6);
        _X509.setConstant("PURPOSE_ANY",_7);
        _X509.setConstant("PURPOSE_OCSP_HELPER",_8);
        _X509.setConstant("TRUST_COMPAT",_1);
        _X509.setConstant("TRUST_SSL_CLIENT",_2);
        _X509.setConstant("TRUST_SSL_SERVER",_3);
        _X509.setConstant("TRUST_EMAIL",_4);
        _X509.setConstant("TRUST_OBJECT_SIGN",_5);
        _X509.setConstant("TRUST_OCSP_SIGN",_6);
        _X509.setConstant("TRUST_OCSP_REQUEST",_7);

        // These should eventually point to correct things.
        _X509.setConstant("DEFAULT_CERT_AREA", runtime.newString(X509Utils.X509_CERT_AREA));
        _X509.setConstant("DEFAULT_CERT_DIR", runtime.newString(X509Utils.X509_CERT_DIR));
        _X509.setConstant("DEFAULT_CERT_FILE", runtime.newString(X509Utils.X509_CERT_FILE));
        _X509.setConstant("DEFAULT_CERT_DIR_ENV", runtime.newString(X509Utils.X509_CERT_DIR_EVP));
        _X509.setConstant("DEFAULT_CERT_FILE_ENV", runtime.newString(X509Utils.X509_CERT_FILE_EVP));
        _X509.setConstant("DEFAULT_PRIVATE_DIR", runtime.newString(X509Utils.X509_PRIVATE_DIR));
    }

    static RubyModule _X509(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstant("X509");
    }

    static Map<Integer, String> getErrors() {
        return X509Error.getErrors();
    }

}// X509
