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
package org.jruby.ext.openssl.x509store;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.jruby.ext.openssl.x509store.X509Utils.*;

/**
 * Provide a dynamically-growing list of X509 error messages.
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Error {

    public static String getMessage(int reason) {
        switch (reason) {
            case X509_R_BAD_X509_FILETYPE:
                return "bad x509 filetype";
            case X509_R_BASE64_DECODE_ERROR:
                return "base64 decode error";
            case X509_R_CANT_CHECK_DH_KEY:
                return "cant check dh key";
            case X509_R_CERT_ALREADY_IN_HASH_TABLE:
                return "cert already in hash table";
            case X509_R_ERR_ASN1_LIB:
                return "err asn1 lib";
            case X509_R_INVALID_DIRECTORY:
                return "invalid directory";
            case X509_R_INVALID_FIELD_NAME:
                return "invalid field name";
            case X509_R_INVALID_TRUST:
                return "invalid trust";
            case X509_R_KEY_TYPE_MISMATCH:
                return "key type mismatch";
            case X509_R_KEY_VALUES_MISMATCH:
                return "key values mismatch";
            case X509_R_LOADING_CERT_DIR:
                return "loading cert dir";
            case X509_R_LOADING_DEFAULTS:
                return "loading defaults";
            case X509_R_METHOD_NOT_SUPPORTED:
                return "method not supported";
            case X509_R_NO_CERT_SET_FOR_US_TO_VERIFY:
                return "no cert set for us to verify";
            case X509_R_PUBLIC_KEY_DECODE_ERROR:
                return "public key decode error";
            case X509_R_PUBLIC_KEY_ENCODE_ERROR:
                return "public key encode error";
            case X509_R_SHOULD_RETRY:
                return "should retry";
            case X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN:
                return "unable to find parameters in chain";
            case X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY:
                return "unable to get certs public key";
            case X509_R_UNKNOWN_KEY_TYPE:
                return "unknown key type";
            case X509_R_UNKNOWN_NID:
                return "unknown nid";
            case X509_R_UNKNOWN_PURPOSE_ID:
                return "unknown purpose id";
            case X509_R_UNKNOWN_TRUST_ID:
                return "unknown trust id";
            case X509_R_UNSUPPORTED_ALGORITHM:
                return "unsupported algorithm";
            case X509_R_WRONG_LOOKUP_TYPE:
                return "wrong lookup type";
            case X509_R_WRONG_TYPE:
                return "wrong type";

            default:
                return "(unknown X509 error)";
        }
    }

    private static final ThreadLocal<Map<Integer, String>> errors = new ThreadLocal<Map<Integer, String>>();

    public static void addError(int reason) {
        getErrors().put(reason, getMessage(reason));
    }

    // define X509err(f, r) ERR_raise_data(ERR_LIB_X509, (r), NULL)
    //public static void addError(int f, int r) {
    //    getErrors().put(r, getMessage(r));
    //}

    public static void clearErrors() {
        synchronized (errors) {
            if ( errors.get() != null ) newErrorsMap();
        }
    }

    public static Integer getLastError() {
        Map<Integer, String> errorsMap = getErrorsImpl(false);
        if ( errorsMap == null || errorsMap.isEmpty() ) return null;
        final Iterator<Integer> i = errorsMap.keySet().iterator();
        Integer lastError = null;
        while ( i.hasNext() ) lastError = i.next();
        if ( lastError != null ) i.remove(); // remove last
        return lastError;
    }

    public static String getLastErrorMessage() {
        final Integer lastError = getLastError();
        return lastError == null ? null : getMessage(lastError);
    }

    public static Map<Integer, String> getErrors() {
        return getErrorsImpl(true);
    }

    public static Map<Integer, String> getErrorsImpl(boolean required) {
        Map<Integer, String> errorsMap = errors.get();
        if ( errorsMap == null && required ) {
            synchronized (errors) {
                errorsMap = errors.get();
                if ( errorsMap == null ) errorsMap = newErrorsMap();
            }
        }
        return errorsMap;
    }

    private static Map<Integer, String> newErrorsMap() {
        Map<Integer, String> map = new LinkedHashMap<Integer, String>(8);
        errors.set(map);
        return map;
    }

}// Err
