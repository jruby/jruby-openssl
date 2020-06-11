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

import static org.jruby.ext.openssl.x509store.X509Utils.X509_FILETYPE_DEFAULT;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_FILETYPE_PEM;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_R_CERT_ALREADY_IN_HASH_TABLE;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.jruby.Ruby;
import org.jruby.ext.openssl.OpenSSL;

/**
 * c: X509_STORE
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Store implements X509TrustManager {

    public static interface VerifyFunction extends Function1<StoreContext> {
        public static final VerifyFunction EMPTY = new VerifyFunction(){
            public int call(StoreContext context) {
                return -1;
            }
        };
    }
    public static interface VerifyCallbackFunction extends Function2<StoreContext, Integer> {
        public static final VerifyCallbackFunction EMPTY = new VerifyCallbackFunction(){
            public int call(StoreContext context, Integer outcome) {
                return -1;
            }
        };
    }
    static interface GetIssuerFunction extends Function3<StoreContext, X509AuxCertificate[], X509AuxCertificate> {
        public static final GetIssuerFunction EMPTY = new GetIssuerFunction(){
            public int call(StoreContext context, X509AuxCertificate[] issuer, X509AuxCertificate cert) {
                return -1;
            }
        };
    }
    static interface CheckIssuedFunction extends Function3<StoreContext, X509AuxCertificate, X509AuxCertificate> {
        public static final CheckIssuedFunction EMPTY = new CheckIssuedFunction(){
            public int call(StoreContext context, X509AuxCertificate cert, X509AuxCertificate issuer) throws Exception {
                return -1;
            }
        };
    }
    static interface CheckRevocationFunction extends Function1<StoreContext> {
        public static final CheckRevocationFunction EMPTY = new CheckRevocationFunction(){
            public int call(StoreContext context) {
                return -1;
            }
        };
    }
    static interface GetCRLFunction extends Function3<StoreContext, java.security.cert.X509CRL[], X509AuxCertificate> {
        public static final GetCRLFunction EMPTY = new GetCRLFunction(){
            public int call(StoreContext context, java.security.cert.X509CRL[] crls, X509AuxCertificate cert) {
                return -1;
            }
        };
    }
    static interface CheckCRLFunction extends Function2<StoreContext, java.security.cert.X509CRL> {
        public static final CheckCRLFunction EMPTY = new CheckCRLFunction(){
            public int call(StoreContext context, java.security.cert.X509CRL crl) {
                return -1;
            }
        };
    }
    static interface CertificateCRLFunction extends Function3<StoreContext, java.security.cert.X509CRL, X509AuxCertificate> {
        public static final CertificateCRLFunction EMPTY = new CertificateCRLFunction(){
            public int call(StoreContext context, java.security.cert.X509CRL crl, X509AuxCertificate cert) {
                return -1;
            }
        };
    }
    static interface CleanupFunction extends Function1<StoreContext> {
        public static final CleanupFunction EMPTY = new CleanupFunction(){
            public int call(StoreContext context) {
                return -1;
            }
        };
    }

    // @Deprecated int cache = 1; // not-used

    private static final X509Object[] NULL_OBJECTS = new X509Object[0];
    private static final Lookup[] NULL_LOOKUP = new Lookup[0];

    private volatile X509Object[] objects = NULL_OBJECTS;
    private volatile Lookup[] certLookups = NULL_LOOKUP;

    public final VerifyParameter verifyParameter;

    VerifyFunction verify = VerifyFunction.EMPTY;
    VerifyCallbackFunction verifyCallback = VerifyCallbackFunction.EMPTY;

    GetIssuerFunction getIssuer = GetIssuerFunction.EMPTY;
    CheckIssuedFunction checkIssued = CheckIssuedFunction.EMPTY;
    CheckRevocationFunction checkRevocation = CheckRevocationFunction.EMPTY;
    GetCRLFunction getCRL = GetCRLFunction.EMPTY;
    CheckCRLFunction checkCRL = CheckCRLFunction.EMPTY;
    CertificateCRLFunction certificateCRL = CertificateCRLFunction.EMPTY;
    CleanupFunction cleanup = CleanupFunction.EMPTY;

    private final List<Object> extraData;

    /**
     * c: X509_STORE_new
     */
    public Store() {
        verifyParameter = new VerifyParameter();

        extraData = new ArrayList<Object>(10);
        this.extraData.add(null); this.extraData.add(null); this.extraData.add(null);
        this.extraData.add(null); this.extraData.add(null); this.extraData.add(null);
        this.extraData.add(null); this.extraData.add(null); this.extraData.add(null);
    }

    public List<X509Object> getObjects() {
        return Arrays.asList(objects);
    }

    public List<Lookup> getCertificateMethods() {
        return Arrays.asList(certLookups);
    }

    public VerifyParameter getVerifyParameter() {
        return verifyParameter;
    }

    public VerifyFunction getVerifyFunction() {
        return verify;
    }

    /**
     * c: X509_STORE_set_verify_func
     */
    public void setVerifyFunction(VerifyFunction func) {
        verify = func;
    }

    public VerifyCallbackFunction getVerifyCallback() {
        return verifyCallback;
    }

    /**
     * c: X509_STORE_set_verify_cb_func
     */
    public void setVerifyCallbackFunction(VerifyCallbackFunction func) {
        verifyCallback = func;
    }

    /**
     * c: X509_STORE_free
     */
    public void free() throws Exception {
       for (Lookup lu : certLookups) {
           lu.shutdown();
           lu.free();
        }
        if (verifyParameter != null) {
            verifyParameter.free();
        }
    }

    /**
     * c: X509_set_ex_data
     */
    public int setExtraData(int idx, Object data) {
        synchronized (extraData) {
            extraData.set(idx, data);
            return 1;
        }
    }

    /**
     * c: X509_get_ex_data
     */
    public Object getExtraData(int idx) {
        synchronized (extraData) {
            return extraData.get(idx);
        }
    }

    /**
     * c: X509_STORE_set_depth
     */
    public int setDepth(int depth) {
        verifyParameter.setDepth(depth);
        return 1;
    }

    /**
     * c: X509_STORE_set_flags
     */
    public int setFlags(long flags) {
        return verifyParameter.setFlags(flags);
    }

    /**
     * c: X509_STORE_set_purpose
     */
    public int setPurpose(int purpose) {
        return verifyParameter.setPurpose(purpose);
    }

    /**
     * c: X509_STORE_set_trust
     */
    public int setTrust(int trust) {
        return verifyParameter.setTrust(trust);
    }

    /**
     * c: X509_STORE_set1_param
     */
    public int setParam(VerifyParameter param) {
        return verifyParameter.set(param);
    }

    /**
     * c: X509_STORE_add_lookup
     */
    public Lookup addLookup(final Ruby runtime, final LookupMethod method) {
        final Lookup[] certLookups = this.certLookups;
        Lookup foundLookup = findLookupMethod(certLookups, method);
        if ( foundLookup != null ) return foundLookup;

        final Lookup newLookup = new Lookup(runtime, method); newLookup.store = this;
        synchronized (this) {
            final int length = this.certLookups.length;
            if ( certLookups.length != length ) {
                foundLookup = findLookupMethod(this.certLookups, method);
                if ( foundLookup != null ) return foundLookup;
            }
            Lookup[] newCertLookups = Arrays.copyOf(this.certLookups, length + 1);
            newCertLookups[length] = newLookup;
            this.certLookups = newCertLookups;
        }
        return newLookup;
    }

    private static Lookup findLookupMethod(final Lookup[] lookups, final LookupMethod method) {
        for ( final Lookup lookup : lookups ) {
            if ( lookup.method.equals(method) ) return lookup;
        }
        return null;
    }

    /**
     * c: X509_STORE_add_cert
     */
    public int addCertificate(final X509Certificate cert) {
        if ( cert == null ) return 0;

        final Certificate certObj = new Certificate(StoreContext.ensureAux(cert));

        final X509Object[] objects = this.objects;
        if ( matchedObject(objects, certObj) ) {
            X509Error.addError(X509_R_CERT_ALREADY_IN_HASH_TABLE);
            return 0;
        }

        return addObject(certObj, objects.length);
    }

    /**
     * c: X509_STORE_add_crl
     */
    public int addCRL(final java.security.cert.CRL crl) {
        if ( crl == null ) return 0;

        final CRL crlObj = new CRL(crl);

        final X509Object[] objects = this.objects;
        if ( matchedObject(objects, crlObj) ) {
            X509Error.addError(X509_R_CERT_ALREADY_IN_HASH_TABLE);
            return 0;
        }

        return addObject(crlObj, objects.length);
    }

    private static boolean matchedObject(final X509Object[] objects, final X509Object xObject) {
        for ( int i = 0; i< objects.length; i++ ) {
            if ( objects[i].matches(xObject) ) return true;
        }
        return false;
    }

    private synchronized int addObject(final X509Object xObject, final int prevLength) {
        final int length = objects.length;
        if ( length != prevLength ) { // something added concurrently
            if ( matchedObject(objects, xObject) ) {
                X509Error.addError(X509_R_CERT_ALREADY_IN_HASH_TABLE);
                return 0;
            }
        }
        X509Object[] newObjects = new X509Object[length + 1];

        int idx = length;
        if (xObject instanceof Certificate) {
            final X500Principal p1 = ((Certificate) xObject).cert.getIssuerX500Principal();
            final Name n1 = new Name(p1);

            for (idx = 0; idx < objects.length; idx++) {
                X509Object xMember  = objects[idx];
                if (xMember instanceof Certificate) {
                    X500Principal p2 = ((Certificate) xMember).cert.getIssuerX500Principal();
                    if (n1.equalTo(p2)) break;
                }
            }
        }

        System.arraycopy(objects, 0, newObjects, 0, idx);
        System.arraycopy(objects, idx, newObjects, idx + 1, length-idx);
        newObjects[idx] = xObject;
        objects = newObjects;
        return 1;
    }

    /**
     * c: X509_STORE_load_locations
     */
    public int loadLocations(Ruby runtime, final String file, final String path) throws Exception {
        if ( file != null ) {
            final Lookup lookup = addLookup( runtime, Lookup.fileLookup() );
            if ( lookup == null ) {
                return 0;
            }
            if ( lookup.loadFile(new CertificateFile.Path(file, X509_FILETYPE_PEM)) != 1 ) {
                return 0;
            }
        }

        if ( path != null ) {
            final Lookup lookup = addLookup( runtime, Lookup.hashDirLookup() );
            if ( lookup == null ) {
                return 0;
            }
            if ( lookup.addDir(new CertificateHashDir.Dir(path, X509_FILETYPE_PEM)) != 1 ) {
                return 0;
            }
        }

        if ( path == null && file == null ) return 0;
        return 1;
    }

    /**
     * c: X509_STORE_set_default_paths
     */
    public int setDefaultPaths(Ruby runtime) throws Exception {

        Lookup lookup = addLookup(runtime, Lookup.fileLookup());

        try {
            lookup.loadFile(new CertificateFile.Path(null, X509_FILETYPE_DEFAULT));
        }
        catch (FileNotFoundException e) {
            // set_default_paths ignores FileNotFound
        }
        catch (IOException e) {
            // this is for older jrubies as they do not have a
            // org.jruby.util.ResourceException.NotFound
            if (!e.getClass().getSimpleName().equals("NotFound")) {
                throw e;
            }
            OpenSSL.debug(runtime, "add X509_CERT_FILER_CTX (to default paths)", e);
        }

        lookup = addLookup(runtime, Lookup.hashDirLookup());

        try {
            lookup.addDir(new CertificateHashDir.Dir(null, X509_FILETYPE_DEFAULT));
        }
        catch (FileNotFoundException e) {
            // set_default_paths ignores FileNotFound
        }
        catch (IOException e) {
            if (!e.getClass().getSimpleName().equals("NotFound")) {
                throw e;
            }
            OpenSSL.debug(runtime, "add X509_HASH_DIR_CTX (to default paths)", e);
        }

        X509Error.clearErrors();
        return 1;
    }


    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        final X509Object[] objects = this.objects;
        final ArrayList<X509Certificate> issuers = new ArrayList<X509Certificate>(objects.length);
        for ( int i = 0; i< objects.length; i++ ) {
            final X509Object object = objects[i];
            if ( object instanceof Certificate ) {
                issuers.add(( (Certificate) object ).cert);
            }
        }
        return issuers.toArray( new X509Certificate[ issuers.size() ] );
    }

}// X509_STORE
