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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.jruby.ext.openssl.OpenSSL;
import org.jruby.ext.openssl.SecurityHelper;
import org.jruby.util.SafePropertyAccessor;

import static org.jruby.ext.openssl.x509store.X509Error.addError;
import static org.jruby.ext.openssl.x509store.X509Utils.*;

/**
 * c: X509_STORE_CTX
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class StoreContext {

    private static final Integer ZERO = 0;

    private final Store store;

    X509AuxCertificate cert;
    List<X509AuxCertificate> untrusted;
    List<X509CRL> crls;

    private VerifyParameter verifyParameter;
    private ArrayList<Object> extraData;

    private List<X509AuxCertificate> otherContext;

    public StoreContext(final Store store) {
        this.store = store;
    }

    interface CheckPolicyFunction extends Function1<StoreContext> {}

    Store.VerifyFunction verify;
    Store.VerifyCallbackFunction verifyCallback;
    Store.GetIssuerFunction getIssuer;
    Store.CheckIssuedFunction checkIssued;
    Store.CheckRevocationFunction checkRevocation;
    Store.GetCRLFunction getCRL;
    Store.CheckCRLFunction checkCRL;
    Store.CertificateCRLFunction certificateCRL;
    CheckPolicyFunction checkPolicy;
    Store.CleanupFunction cleanup;

    Store.LookupCerts lookup_certs;

    public boolean isValid;

    private int num_untrusted; // last_untrusted (OpenSSL 1.0.2) in the chain

    private ArrayList<X509AuxCertificate> chain;

    private PolicyTree tree;
    private int explicit_policy;

    int error;
    int error_depth;

    X509AuxCertificate current_cert;
    X509AuxCertificate current_issuer;
    X509CRL current_crl;

    private StoreContext parent; // NOTE: not implemented - dummy null for now

    public Store getStore() {
        return store;
    }

    /**
     * c: X509_STORE_CTX_set_depth
     */
    public void setDepth(int depth) {
        verifyParameter.setDepth(depth);
    }

    /**
     * c: X509_STORE_CTX_set_app_data
     */
    public void setApplicationData(Object data) {
        setExtraData(0, data);
    }

    /**
     * c: X509_STORE_CTX_get_app_data
     */
    public Object getApplicationData() {
        return getExtraData(0);
    }

    /*-
     * Try to get issuer certificate from store. Due to limitations
     * of the API this can only retrieve a single certificate matching
     * a given subject name. However it will fill the cache with all
     * matching certificates, so we can examine the cache for all
     * matches.
     *
     * Return values are:
     *  1 lookup successful.
     *  0 certificate not found.
     * -1 some other error.
     *
     * int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
     */
    int getFirstIssuer(final X509AuxCertificate[] _issuer, final X509AuxCertificate x) throws Exception {
        int ok;
        // _issuer[0] = null;
        final Name xn = new Name( x.getIssuerX500Principal() );
        final X509Object[] s_obj = new X509Object[1];
        ok = store == null ? 0 : getBySubject(X509_LU_X509, xn, s_obj);
        if (ok != 1) {
            if ( ok == X509Utils.X509_LU_RETRY ) {
                X509Error.addError(X509Utils.X509_R_SHOULD_RETRY);
                return -1;
            }
            else if ( ok != X509Utils.X509_LU_FAIL ) {
                return -1;
            }
            return 0;
        }
        /* If certificate matches all OK */
        X509Object obj = s_obj[0];
        if ( checkIssued.call(this, x, ((Certificate) obj).cert) != 0 ) {
            X509AuxCertificate issuer = ((Certificate) obj).cert;
            if (x509_check_cert_time(issuer, -1)) {
                _issuer[0] = issuer;
                return 1;
            }
        }

        List<X509Object> objects = store.getObjects();
        int idx = X509Object.indexBySubject(objects, X509Utils.X509_LU_X509, xn);
        if ( idx == -1 ) return 0;

        int ret = 0;
        /* Look through all matching certificates for a suitable issuer */
        for ( int i = idx; i < objects.size(); i++ ) {
            final X509Object pobj = objects.get(i);
            /* See if we've run past the matches */
            if (pobj.type() != X509_LU_X509) {
                break; // return 0
            }
            final X509AuxCertificate x509 = ((Certificate) pobj).cert;
            if ( ! xn.equalTo( x509.getSubjectX500Principal() ) ) {
                break; // return 0
            }
            if ( checkIssued.call(this, x, x509) != 0 ) {
                _issuer[0] = x509;
                ret = 1;
                /*
                 * If times check, exit with match, otherwise keep looking.
                 * Leave last match in issuer so we return nearest
                 * match if no certificate time is OK.
                 */
                if (x509_check_cert_time(x509, -1)) break; // return 1;
            }
        }
        return ret;
    }

    // NOTE: not based on OpenSSL - self invented (till JOSSL 1.1.1 port)
    private int getValidIssuers(final X509AuxCertificate x, final List<X509AuxCertificate> _issuers)
        throws Exception {
        final Name xn = new Name( x.getIssuerX500Principal() );
        final X509Object[] s_obj = new X509Object[1];
        int ok = store == null ? 0 : getBySubject(X509Utils.X509_LU_X509, xn, s_obj);
        if ( ok != X509Utils.X509_LU_X509 ) {
            if ( ok == X509Utils.X509_LU_RETRY ) {
                X509Error.addError(X509Utils.X509_R_SHOULD_RETRY);
                return -1;
            }
            else if ( ok != X509Utils.X509_LU_FAIL ) {
                return -1;
            }
            return 0;
        }
        int ret = 0;
        /* If certificate matches all OK */
        X509Object obj = s_obj[0];
        if ( checkIssued.call(this, x, ((Certificate) obj).cert) != 0 ) {
            X509AuxCertificate issuer = ((Certificate) obj).cert;
            if (x509_check_cert_time(issuer, -1)) {
                _issuers.add(issuer);
                ret = 1;
            }
        }

        List<X509Object> objects = store.getObjects();

        int idx = X509Object.indexBySubject(objects, X509Utils.X509_LU_X509, xn);
        if ( idx == -1 ) return ret;

        /* Look through all matching certificates for a suitable issuer */
        for ( int i = idx; i < objects.size(); i++ ) {
            final X509Object pobj = objects.get(i);
            if ( pobj.type() != X509Utils.X509_LU_X509 ) {
                continue;
            }
            final X509AuxCertificate x509 = ((Certificate) pobj).cert;
            if ( ! xn.equalTo( x509.getSubjectX500Principal() ) ) {
                continue;
            }

            if ( checkIssued.call(this, x, x509) != 0 ) {
                if (x509_check_cert_time(x509, -1)) {
                    _issuers.add(x509);
                    ret = 1;
                }
            }
        }
        return ret;
    }

    public static List<X509AuxCertificate> ensureAux(final Collection<X509Certificate> input) {
        if ( input == null ) return null;

        List<X509AuxCertificate> out = new ArrayList<X509AuxCertificate>(input.size());
        for ( X509Certificate cert : input ) out.add( ensureAux(cert) );
        return out;
    }

    public static List<X509AuxCertificate> ensureAux(final X509Certificate[] input) {
        if ( input == null ) return null;

        List<X509AuxCertificate> out = new ArrayList<X509AuxCertificate>(input.length);
        for ( X509Certificate cert : input ) out.add( ensureAux(cert) );
        return out;
    }

    public static X509AuxCertificate ensureAux(final X509Certificate input) {
        if ( input == null ) return null;

        if ( input instanceof X509AuxCertificate ) {
            return (X509AuxCertificate) input;
        }
        return new X509AuxCertificate(input);
    }

    /**
     * int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *cert,
     *                         STACK_OF(X509) *chain)
     *
     * @param cert the certificate (to be verified)
     * @param untrusted_chain the (untrusted) chain of certs returned by the server
     * @return 1
     */
    public int init(X509AuxCertificate cert, List<X509AuxCertificate> untrusted_chain) {
        // int ret = 1;
        this.cert = cert;
        this.untrusted = untrusted_chain;
        this.crls = null;
        this.num_untrusted = 0;
        this.otherContext = null;
        this.isValid = false;
        this.chain = null;
        this.error = V_OK;
        this.explicit_policy = 0;
        this.error_depth = 0;
        this.current_cert = null;
        this.current_issuer = null;
        this.current_crl = null;
        this.tree = null;
        this.parent = null;

        /* store->cleanup is always 0 in OpenSSL, if set must be idempotent */
        if ( store != null ) {
            this.cleanup = store.cleanup;
        } else {
            this.cleanup = null;
        }

        this.checkIssued = VERIFY_LEGACY ? check_issued_legacy : check_issued;
        this.getIssuer = getFirstIssuer;
        this.verifyCallback = nullCallback;
        this.verify = null;
        this.checkRevocation = StoreContext.check_revocation;
        this.getCRL = defaultGetCRL;
        this.checkCRL = check_crl_legacy;
        this.certificateCRL = defaultCertificateCRL;

        if ( store != null ) {
            if ( store.checkIssued != null ) {
                this.checkIssued = store.checkIssued;
            }
            if ( store.getIssuer != null ) {
                this.getIssuer = store.getIssuer;
            }
            if ( store.verifyCallback != null ) {
                this.verifyCallback = store.verifyCallback;
            }
            if ( store.verify != null ) {
                this.verify = store.verify;
            }
            if ( store.checkRevocation != null ) {
                this.checkRevocation = store.checkRevocation;
            }
            if ( store.getCRL != null ) {
                this.getCRL = store.getCRL;
            }
            if( store.checkCRL != null ) {
                this.checkCRL = store.checkCRL;
            }
            if ( store.certificateCRL != null ) {
                this.certificateCRL = store.certificateCRL;
            }
        }

        if (store != null && store.lookup_certs != null) {
            this.lookup_certs = store.lookup_certs;
        } else {
            this.lookup_certs = new Store.LookupCerts() {
                public List<X509AuxCertificate> call(StoreContext ctx, Name name) throws Exception {
                    return ctx.get1_certs(name);
                }
            };
        }

        // store->check_policy
        this.checkPolicy = StoreContext.check_policy;

        this.verifyParameter = new VerifyParameter();

        if ( store != null ) {
            verifyParameter.inherit(store.verifyParameter);
        } else {
            verifyParameter.inheritFlags |= X509_VP_FLAG_DEFAULT | X509_VP_FLAG_ONCE;
        }

        verifyParameter.inherit(VerifyParameter.lookup("default"));

        /*
         * XXX: For now, continue to inherit trust from VPM, but infer from the
         * purpose if this still yields the default value.
         */
        if (verifyParameter.trust == X509_TRUST_DEFAULT) {
            int idx = Purpose.getByID(verifyParameter.purpose);
            Purpose xp = Purpose.getFirst(idx);

            if (xp != null) {
                verifyParameter.trust = xp.trust; // X509_PURPOSE_get_trust
            }
        }

        // getExtraData(); // CRYPTO_new_ex_data
        return 1;
    }

    /**
     * c: X509_STORE_CTX_trusted_stack
     */
    public void trustedStack(List<X509AuxCertificate> sk) {
        otherContext = sk;
        getIssuer = getIssuerStack;
    }

    /**
     * c: X509_STORE_CTX_cleanup
     */
    public void cleanup() throws Exception {
        if (cleanup != null) {
            cleanup.call(this);
        }
        verifyParameter = null;
        tree = null;
        chain = null;
        extraData = null;
    }

    // NOTE: 0 is reserved for getApplicationData() (X509_STORE_CTX_get_app_data)

    /**
     * index for @verify_callback in ex_data
     */
    public static final int ossl_ssl_ex_vcb_idx = 1;
    /**
     * index for holding the SSLContext instance in ex_data
     */
    public static final int ossl_ssl_ex_ptr_idx = 2; // TODO needs impl

    static final int MAX_EXTRA_DATA_SIZE = 4;

    /**
     * c: X509_STORE_CTX_set_ex_data
     */
    public final void setExtraData(final int idx, final Object data) {
        if (extraData == null) {
            if (data == null) return;
            extraData = new ArrayList<>(MAX_EXTRA_DATA_SIZE);
        } else {
            extraData.ensureCapacity(idx + 1);
        }
        while (extraData.size() <= idx) extraData.add(null);
        extraData.set(idx, data);
        // return 1;
    }

    /**
     * c: X509_STORE_CTX_get_ex_data
     */
    public final Object getExtraData(final int idx) {
        if (extraData == null) return null;
        if (extraData.size() < idx) return null;
        return extraData.get(idx);
    }

    /**
     * c: X509_STORE_CTX_get_error
     */
    public int getError() {
        return error;
    }

    /**
     * c: X509_STORE_CTX_set_error
     */
    public void setError(int s) {
        this.error = s;
    }

    /**
     * c: X509_STORE_CTX_get_error_depth
     */
    public int getErrorDepth() {
        return error_depth;
    }

    /**
     * c: X509_STORE_CTX_get_current_cert
     */
    public X509AuxCertificate getCurrentCertificate() {
        return current_cert;
    }

    public X509CRL getCurrentCRL() {
        return current_crl;
    }

    /**
     * c: X509_STORE_CTX_get_chain
     */
    public List<X509AuxCertificate> getChain() {
        return chain;
    }

    /**
     * c: X509_STORE_CTX_get1_chain
     */
    public List<X509AuxCertificate> getFirstChain() {
        if ( chain == null ) return null;
        return new ArrayList<X509AuxCertificate>(chain);
    }

    /**
     * c: X509_STORE_CTX_set_cert
     */
    public void setCertificate(X509AuxCertificate x) {
        this.cert = x;
    }

    public void setCertificate(X509Certificate x) {
        this.cert = ensureAux(x);
    }

    /**
     * c: X509_STORE_CTX_set_chain
     */
    public void setChain(List<X509Certificate> chain) {
        this.untrusted = ensureAux(chain);
    }

    public void setChain(X509Certificate[] sk) {
        this.untrusted = ensureAux(sk);
    }

    /**
     * c: X509_STORE_CTX_set0_crls
     */
    public void setCRLs(List<X509CRL> sk) {
        this.crls = sk;
    }

    /**
     * int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose)
     * @return 0 || 1
     */
    public int setPurpose(int purpose) {
        return purposeInherit(0, purpose, 0);
    }

    /**
     * int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust)
     * @return 0 || 1
     */
    public int setTrust(int trust) {
        return purposeInherit(0, 0, trust);
    }

    /*
    private void resetSettingsToWithoutStore() {
        store = null;
        this.verifyParameter = new VerifyParameter();
        this.verifyParameter.flags |= X509Utils.X509_VP_FLAG_DEFAULT | X509Utils.X509_VP_FLAG_ONCE;
        this.verifyParameter.inherit(VerifyParameter.lookup("default"));
        this.cleanup = Store.CleanupFunction.EMPTY;
        this.checkIssued = defaultCheckIssued;
        this.getIssuer = getFirstIssuer;
        this.verifyCallback = nullCallback;
        this.verify = internalVerify;
        this.checkRevocation = defaultCheckRevocation;
        this.getCRL = defaultGetCRL;
        this.checkCRL = defaultCheckCRL;
        this.certificateCRL = defaultCertificateCRL;
    } */

    /**
     * c: SSL_CTX_load_verify_locations
     */
    /*
    public int loadVerifyLocations(Ruby runtime, String CAfile, String CApath) {
        boolean reset = false;
        try {
            if ( store == null ) {
                reset = true;
                store = new Store();
                this.verifyParameter.inherit(store.verifyParameter);
                verifyParameter.inherit(VerifyParameter.lookup("default"));
                this.cleanup = store.cleanup;
                if ( store.checkIssued != null && store.checkIssued != Store.CheckIssuedFunction.EMPTY ) {
                    this.checkIssued = store.checkIssued;
                }
                if ( store.getIssuer != null && store.getIssuer != Store.GetIssuerFunction.EMPTY ) {
                    this.getIssuer = store.getIssuer;
                }
                if ( store.verify != null && store.verify != Store.VerifyFunction.EMPTY ) {
                    this.verify = store.verify;
                }
                if ( store.verifyCallback != null && store.verifyCallback != Store.VerifyCallbackFunction.EMPTY ) {
                    this.verifyCallback = store.verifyCallback;
                }
                if ( store.checkRevocation != null && store.checkRevocation != Store.CheckRevocationFunction.EMPTY ) {
                    this.checkRevocation = store.checkRevocation;
                }
                if ( store.getCRL != null && store.getCRL != Store.GetCRLFunction.EMPTY ) {
                    this.getCRL = store.getCRL;
                }
                if ( store.checkCRL != null && store.checkCRL != Store.CheckCRLFunction.EMPTY ) {
                    this.checkCRL = store.checkCRL;
                }
                if ( store.certificateCRL != null && store.certificateCRL != Store.CertificateCRLFunction.EMPTY ) {
                    this.certificateCRL = store.certificateCRL;
                }
            }

            final int ret = store.loadLocations(runtime, CAfile, CApath);
            if ( ret == 0 && reset ) resetSettingsToWithoutStore();

            return ret;
        }
        catch (Exception e) {

            if ( reset ) resetSettingsToWithoutStore();
            return 0;
        }
    } */

    /*
     * int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
     *                                    int purpose, int trust)
     */
    private int purposeInherit(final int def_purpose, int purpose, int trust) {
        int idx;
        /* If purpose not set use default */
        if (purpose == 0) {
            purpose = def_purpose;
        }
        /* If we have a purpose then check it is valid */
        if (purpose != 0) {
            idx = Purpose.getByID(purpose); // X509_PURPOSE_get_by_id
            if (idx == -1) {
                X509Error.addError(X509Utils.X509_R_UNKNOWN_PURPOSE_ID);
                return 0;
            }
            Purpose ptmp = Purpose.getFirst(idx); // X509_PURPOSE_get0
            if (ptmp.trust == X509Utils.X509_TRUST_DEFAULT) {
                idx = Purpose.getByID(def_purpose);
                if (idx == -1) {
                    X509Error.addError(X509Utils.X509_R_UNKNOWN_PURPOSE_ID);
                    return 0;
                }
                ptmp = Purpose.getFirst(idx); // X509_PURPOSE_get0
            }
            /* If trust not set then get from purpose default */
            if (trust == 0) {
                trust = ptmp.trust;
            }
        }
        if (trust != 0) {
            idx = Trust.getByID(trust); // X509_TRUST_get_by_id
            if (idx == -1) {
                X509Error.addError(X509Utils.X509_R_UNKNOWN_TRUST_ID);
                return 0;
            }
        }

        if (purpose != 0 && getParam().purpose == 0) {
            getParam().purpose = purpose;
        }
        if (trust != 0 && getParam().trust == 0) {
            getParam().trust = trust;
        }
        return 1;
    }

    /**
     * c: X509_STORE_CTX_set_flags
     */
    public void setFlags(long flags) {
        verifyParameter.setFlags(flags);
    }

    /**
     * c: X509_STORE_CTX_set_time
     */
    public void setTime(long flags,Date t) {
        verifyParameter.setTime(t);
    }

    /**
     * c: X509_STORE_CTX_set_verify_cb
     */
    public void setVerifyCallback(Store.VerifyCallbackFunction verifyCallback) {
        this.verifyCallback = verifyCallback;
    }

    /**
     * c: X509_STORE_CTX_get0_policy_tree
     */
    PolicyTree getPolicyTree() {
        return tree;
    }

    /**
     * c: X509_STORE_CTX_get_explicit_policy
     */
    public int getExplicitPolicy() {
        return explicit_policy;
    }

    /**
     * c: X509_STORE_CTX_get0_param
     */
    public VerifyParameter getParam() {
        return verifyParameter;
    }

    /**
     * c: X509_STORE_CTX_set0_param
     */
    public void setParam(VerifyParameter param) {
        this.verifyParameter = param;
    }

    /**
     * c: X509_STORE_CTX_set_default
     */
    public void setDefault(String name) {
        VerifyParameter p = VerifyParameter.lookup(name);
        if ( p == null ) return; // return 0
        verifyParameter.inherit(p); // return 1
    }

    /*
     * int X509_STORE_CTX_get_by_subject(X509_STORE_CTX *vs, X509_LOOKUP_TYPE type,
     *                                   X509_NAME *name, X509_OBJECT *ret)
     */
    public int getBySubject(int type, Name name, X509Object[] ret) throws Exception {
        final Store store = this.store;

        if (store == null) return 0;

        X509Object tmp = X509Object.retrieveBySubject(store.getObjects(), type, name);
        if (tmp == null || type == X509_LU_CRL) {
            for (Lookup lu : store.getCertificateMethods()) {
                X509Object[] stmp = new X509Object[1];
                int j = lu.bySubject(type, name, stmp);
                if (j != 0) {
                    tmp = stmp[0];
                    break;
                }
            }
            if (tmp == null) return 0;
        }
        ret[0] = tmp;
        return 1;
    }

    /*
     * STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *ctx, X509_NAME *nm)
     */
    List<X509AuxCertificate> get1_certs(final Name nm) throws Exception {
        if (store == null) return null;

        // NOTE: very rough draft that resembles OpenSSL bits

        List<X509AuxCertificate> sk = matchCachedCertObjectsFromStore(nm);

        if (sk.isEmpty()) {
            /*
             * Nothing found in cache: do lookup to possibly add new objects to cache
             */
            boolean found = false;
            for (Lookup lu : store.getCertificateMethods()) {
                X509Object[] stmp = new X509Object[1];
                if (lu.bySubject(X509_LU_X509, nm, stmp) != 0) found = true;
            }
            if (!found) return sk;
        }

        sk = matchCachedCertObjectsFromStore(nm);
        return sk;
    }

    /* Get issuer, without duplicate suppression */
    private int get_issuer(X509AuxCertificate[] issuer, X509AuxCertificate cert) throws Exception {
        final ArrayList saved_chain = this.chain;
        int ok;

        this.chain = null;
        try {
            ok = this.getIssuer.call(this, issuer, cert);
        } finally {
            this.chain = saved_chain;
        }
        return ok;
    }

    private List<X509AuxCertificate> matchCachedCertObjectsFromStore(final Name name) {
        ArrayList<X509AuxCertificate> sk = new ArrayList<X509AuxCertificate>();
        for (X509Object obj : store.getObjects()) {
            if (obj.type() == X509_LU_X509 && obj.isName(name)) {
                sk.add(((Certificate) obj).cert);
            }
        }
        return sk;
    }

    /*
     * c: int X509_verify_cert(X509_STORE_CTX *ctx)
     */
    public int verifyCertificate() throws Exception {
        if (cert == null) {
            addError(X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
            this.error = V_ERR_INVALID_CALL;
            return -1;
        }

        if (chain != null) {
            /*
             * This X509_STORE_CTX has already been used to verify a cert. We cannot do another one.
             */
            addError(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            this.error = V_ERR_INVALID_CALL;
            return -1;
        }

        /*
         * first we make sure the chain we are going to build is present and that
         * the first entry is in place
         */
        //if (chain == null) {
            chain = new ArrayList<X509AuxCertificate>(8);
            chain.add(cert);
            num_untrusted = 1;
        //}

        // NOTE: NOT IMPLEMENTED
        /* If the peer's public key is too weak, we can stop early. */

        int ret = verifyChain();

        /*
         * Safety-net.  If we are returning an error, we must also set ctx->error,
         * so that the chain is not considered verified should the error be ignored
         * (e.g. TLS with SSL_VERIFY_NONE).
         */
        if (ret <= 0 && this.error == V_OK) {
            this.error = V_ERR_UNSPECIFIED;
        }
        return ret;
    }

    private static final boolean VERIFY_LEGACY;
    static {
        String verify = SafePropertyAccessor.getProperty("jruby.openssl.x509.store.verify");
        VERIFY_LEGACY = "legacy".equals(verify);
    }

    private int verifyChain() throws Exception {
        if (VERIFY_LEGACY) return verify_chain_legacy();
        return verify_chain();
    }

    /*
     @ @note: based on pre OpenSSL 1.0 code
     *
     * c: static int verify_chain(X509_STORE_CTX *ctx)
     */
    @SuppressWarnings("deprecation")
    int verify_chain_legacy() throws Exception {
        X509AuxCertificate x, xtmp = null, chain_ss = null;
        int bad_chain = 0, depth, i, num;

        // We use a temporary STACK so we can chop and hack at it

        LinkedList<X509AuxCertificate> sktmp = untrusted != null ? new LinkedList<>(untrusted) : null;

        num = chain.size();
        x = chain.get(num - 1);
        depth = verifyParameter.depth;
        for(;;) {
            if ( depth < num ) break;

            if ( checkIssued.call(this, x, x) != 0 ) break;

            if ( sktmp != null ) {
                xtmp = findIssuer(sktmp, x, true);
                if ( xtmp != null ) {
                    chain.add(xtmp);
                    sktmp.remove(xtmp);
                    num_untrusted++;
                    x = xtmp;
                    num++;
                    continue;
                }
            }
            break;
        }

        // at this point, chain should contain a list of untrusted
        // certificates.  We now need to add at least one trusted one,
        // if possible, otherwise we complain.

        // Examine last certificate in chain and see if it is self signed.

        i = chain.size();
        x = chain.get(i - 1);

        if ( checkIssued.call(this, x, x) != 0 ) {
            // we have a self signed certificate
            if ( chain.size() == 1 ) {
                // We have a single self signed certificate: see if
                // we can find it in the store. We must have an exact
                // match to avoid possible impersonation.
                X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
                int ok = getIssuer.call(this, p_xtmp, x);
                xtmp = p_xtmp[0];
                if ( ok <= 0 || ! x.equals(xtmp) ) {
                    error = X509Utils.V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
                    current_cert = x;
                    error_depth = i-1;
                    bad_chain = 1;
                    ok = verifyCallback.call(this, ZERO);
                    if ( ok == 0 ) return ok;
                } else {
                    // We have a match: replace certificate with store version
                    // so we get any trust settings.
                    x = xtmp;
                    chain.set(i-1,x);
                    num_untrusted = 0;
                }
            } else {
                // extract and save self signed certificate for later use
                chain_ss = chain.remove(chain.size()-1);
                num_untrusted--;
                num--;
                x = chain.get(num-1);
            }
        }

        // We now lookup certs from the certificate store
        for(;;) {
            // If we have enough, we break
            if ( depth < num ) break;
            // If we are self signed, we break
            if ( checkIssued.call(this, x, x) != 0 ) break;

            X509AuxCertificate[] p_xtmp = new X509AuxCertificate[]{ xtmp };
            int ok = getIssuer.call(this, p_xtmp, x);
            xtmp = p_xtmp[0];

            if ( ok < 0 ) return ok;
            if ( ok == 0 ) break;

            x = xtmp;

            chain.add(x);
            num++;
        }

        /* we now have our chain, lets check it... */

        /* Is last certificate looked up self signed? */
        if ( checkIssued.call(this, x, x) == 0 ) {
            if ( chain_ss == null || checkIssued.call(this, x, chain_ss) == 0 ) {
                if (num_untrusted >= num) {
                    error = X509Utils.V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
                } else {
                    error = X509Utils.V_ERR_UNABLE_TO_GET_ISSUER_CERT;
                }
                current_cert = x;
            } else {
                chain.add(chain_ss);
                num++;
                num_untrusted = num;
                current_cert = chain_ss;
                error = X509Utils.V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
            }
            error_depth = num - 1;
            bad_chain = 1;
            int ok = verifyCallback.call(this, ZERO);
            if ( ok == 0 ) return ok;
        }

        // We have the chain complete: now we need to check its purpose
        int ok = checkChainExtensions();
        if ( ok == 0 ) return ok;

        /* TODO: Check name constraints (from 1.0.0) */

        // The chain extensions are OK: check trust
        if ( verifyParameter.trust > 0 ) ok = checkTrust();
        if ( ok == 0 ) return ok;

        // Check revocation status: we do this after copying parameters
        // because they may be needed for CRL signature verification.
        ok = checkRevocation.call(this);
        if ( ok == 0 ) return ok;

        /* At this point, we have a chain and need to verify it */
        if ( verify != null ) {
            ok = verify.call(this);
        } else {
            ok = internalVerify.call(this);
        }
        if ( ok == 0 ) return ok;

        /* TODO: RFC 3779 path validation, now that CRL check has been done (from 1.0.0) */

        /* If we get this far evaluate policies */
        if ( bad_chain == 0 && (verifyParameter.flags & X509Utils.V_FLAG_POLICY_CHECK) != 0 ) {
            ok = checkPolicy.call(this);
        }
        return ok;
    }

    /*
     @ @note: based OpenSSL 1.1.1
     *
     * c: static int verify_chain(X509_STORE_CTX *ctx)
     */
    int verify_chain() throws Exception {
        int err;
        int ok;

        /*
         * Before either returning with an error, or continuing with CRL checks,
         * instantiate chain public key parameters.
         */
        if ((ok = build_chain()) == 0 ||
            (ok = check_chain_extensions()) == 0 ||
            //(ok = check_auth_level(ctx)) == 0 ||
            //(ok = check_id()) == 0 ||
            true);
        if (ok == 0 || (ok = checkRevocation.call(this)) == 0)
            return ok;

        //err = X509_chain_check_suiteb(&ctx->error_depth, NULL, ctx->chain, ctx->param->flags);
        //if (err != V_OK) {
        //    if ((ok = verify_cb_cert(null, this.errorDepth, err)) == 0)
        //        return ok;
        //}

        /* Verify chain signatures and expiration times */
        ok = verify != null ? verify.call(this) : internal_verify();
        if (ok == 0) return ok;

        //if ((ok = check_name_constraints(ctx)) == 0)
        //    return ok;

        /* If we get this far evaluate policies */
        if ((getParam().flags & V_FLAG_POLICY_CHECK) != 0) {
            ok = checkPolicy.call(this);
        }
        return ok;
    }

    private static final short S_DOUNTRUSTED = (1 << 0); /* Search untrusted chain */
    private static final short S_DOTRUSTED = (1 << 1);   /* Search trusted store */
    private static final short S_DOALTERNATE = (1 << 2); /* Retry with pruned alternate chain */

    /*
     * x509_vfy.c: static int build_chain(X509_STORE_CTX *ctx)
     */
    int build_chain() throws Exception {
        int num = chain.size();
        X509AuxCertificate cert = chain.get(num - 1);
        boolean ss = cert_self_signed(cert);
        short search;
        boolean may_trusted = false;
        boolean may_alternate = false;
        int trust = X509_TRUST_UNTRUSTED;
        int alt_untrusted = 0;
        int depth;
        int ok;

        /* Our chain starts with a single untrusted element. */
        assert num == 1 && num_untrusted == num;

        /*
         * Set up search policy, untrusted if possible, trusted-first if enabled.
         * If we're doing DANE and not doing PKIX-TA/PKIX-EE, we never look in the
         * trust_store, otherwise we might look there first.  If not trusted-first,
         * and alternate chains are not disabled, try building an alternate chain
         * if no luck with untrusted first.
         */
        search = untrusted != null ? S_DOUNTRUSTED : 0;
        //if (DANETLS_HAS_PKIX(dane) || !DANETLS_HAS_DANE(dane)) {
            if (search == 0 || (getParam().flags & V_FLAG_TRUSTED_FIRST) != 0) {
                search |= S_DOTRUSTED;
            } else if ((getParam().flags & V_FLAG_NO_ALT_CHAINS) == 0) {
                may_alternate = true;
            }
            may_trusted = true;
        //}

        /*
         * Shallow-copy the stack of untrusted certificates (with TLS, this is
         * typically the content of the peer's certificate message) so can make
         * multiple passes over it, while free to remove elements as we go.
         */
        LinkedList<X509AuxCertificate> sktmp = untrusted != null ? new LinkedList<>(untrusted) : null;

        depth = getParam().depth;

        /*
         * Still absurdly large, but arithmetically safe, a lower hard upper bound
         * might be reasonable.
         */
        if (depth > Integer.MAX_VALUE / 2) depth = Integer.MAX_VALUE / 2;

        /*
         * Try to Extend the chain until we reach an ultimately trusted issuer.
         * Build chains up to one longer the limit, later fail if we hit the limit,
         * with an X509_V_ERR_CERT_CHAIN_TOO_LONG error code.
         */
        depth = depth + 1;

        while (search != 0) {
            X509AuxCertificate x, xtmp = null;

            /*
             * Look in the trust store if enabled for first lookup, or we've run
             * out of untrusted issuers and search here is not disabled.  When we
             * reach the depth limit, we stop extending the chain, if by that point
             * we've not found a trust-anchor, any trusted chain would be too long.
             *
             * The error reported to the application verify callback is at the
             * maximal valid depth with the current certificate equal to the last
             * not ultimately-trusted issuer.  For example, with verify_depth = 0,
             * the callback will report errors at depth=1 when the immediate issuer
             * of the leaf certificate is not a trust anchor.  No attempt will be
             * made to locate an issuer for that certificate, since such a chain
             * would be a-priori too long.
             */
            if ((search & S_DOTRUSTED) != 0) {
                num = chain.size(); int i = num;
                if ((search & S_DOALTERNATE) != 0) {
                    /*
                     * As high up the chain as we can, look for an alternative
                     * trusted issuer of an untrusted certificate that currently
                     * has an untrusted issuer.  We use the alt_untrusted variable
                     * to track how far up the chain we find the first match.  It
                     * is only if and when we find a match, that we prune the chain
                     * and reset ctx->num_untrusted to the reduced count of
                     * untrusted certificates.  While we're searching for such a
                     * match (which may never be found), it is neither safe nor
                     * wise to preemptively modify either the chain or
                     * ctx->num_untrusted.
                     *
                     * Note, like ctx->num_untrusted, alt_untrusted is a count of
                     * untrusted certificates, not a "depth".
                     */
                    i = alt_untrusted;
                }
                x = chain.get(i - 1);

                X509AuxCertificate[] p_xtmp = new X509AuxCertificate[] { xtmp };
                ok = (depth < num) ? 0 : getIssuer.call(this, p_xtmp, x); // get_issuer(&xtmp, ctx, x)
                xtmp = p_xtmp[0];

                if (ok < 0) {
                    trust = X509_TRUST_REJECTED;
                    this.error = V_ERR_STORE_LOOKUP;
                    search = 0;
                    continue;
                }

                if (ok > 0) {
                    /*
                     * Alternative trusted issuer for a mid-chain untrusted cert?
                     * Pop the untrusted cert's successors and retry.  We might now
                     * be able to complete a valid chain via the trust store.  Note
                     * that despite the current trust-store match we might still
                     * fail complete the chain to a suitable trust-anchor, in which
                     * case we may prune some more untrusted certificates and try
                     * again.  Thus the S_DOALTERNATE bit may yet be turned on
                     * again with an even shorter untrusted chain!
                     *
                     * We might find a suitable trusted certificate among the ones from the trust store.
                     */
                    if ((search & S_DOALTERNATE) != 0) {
                        if (!(num > i && i > 0 && ss == false)) { // ossl_assert
                            OpenSSL.debug(this + " assert failure (num > i && i > 0 && ss == false)");
                            addError(ERR_R_INTERNAL_ERROR);
                            trust = X509_TRUST_REJECTED;
                            this.error = V_ERR_UNSPECIFIED;
                            search = 0;
                            continue;
                        }
                        search &= ~S_DOALTERNATE;
                        for (; num > i; --num) chain.remove(chain.size() - 1); // pop
                        num_untrusted = num;
                    }

                    /*
                     * Self-signed untrusted certificates get replaced by their
                     * trusted matching issuer.  Otherwise, grow the chain.
                     */
                    if (ss == false) {
                        chain.add(x = xtmp);
                        ss = cert_self_signed(x);
                    } else if (num == num_untrusted) {
                        /*
                         * We have a self-signed certificate that has the same
                         * subject name (and perhaps keyid and/or serial number) as
                         * a trust-anchor.  We must have an exact match to avoid
                         * possible impersonation via key substitution etc.
                         */
                        if (!x.equals(xtmp)) {
                            /* Self-signed untrusted mimic. */
                            ok = 0;
                        } else {
                            num_untrusted = --num;
                            chain.set(num, x = xtmp);
                        }
                    }

                    /*
                     * We've added a new trusted certificate to the chain, recheck
                     * trust.  If not done, and not self-signed look deeper.
                     * Whether or not we're doing "trusted first", we no longer
                     * look for untrusted certificates from the peer's chain.
                     *
                     * At this point ctx->num_trusted and num must reflect the
                     * correct number of untrusted certificates, since the DANE
                     * logic in check_trust() depends on distinguishing CAs from
                     * "the wire" from CAs from the trust store.  In particular, the
                     * certificate at depth "num" should be the new trusted
                     * certificate with ctx->num_untrusted <= num.
                     */
                    if (ok != 0) {
                        if (!(num_untrusted <= num)) { // ossl_assert
                            OpenSSL.debug(this + " assert failure (num_untrusted <= num)");
                            addError(ERR_R_INTERNAL_ERROR);
                            trust = X509_TRUST_REJECTED;
                            this.error = V_ERR_UNSPECIFIED;
                            search = 0;
                            continue;
                        }
                        search &= ~S_DOUNTRUSTED;
                        switch (trust = check_trust(num)) {
                            case X509_TRUST_TRUSTED:
                            case X509_TRUST_REJECTED:
                                search = 0;
                                continue;
                        }
                        if (ss == false) continue;
                    }
                }

                /*
                 * No dispositive decision, and either self-signed or no match, if
                 * we were doing untrusted-first, and alt-chains are not disabled,
                 * do that, by repeatedly losing one untrusted element at a time,
                 * and trying to extend the shorted chain.
                 */
                if ((search & S_DOUNTRUSTED) == 0) {
                    /* Continue search for a trusted issuer of a shorter chain? */
                    if ((search & S_DOALTERNATE) != 0 && --alt_untrusted > 0)
                        continue;
                    /* Still no luck and no fallbacks left? */
                    if (!may_alternate || (search & S_DOALTERNATE) != 0 || num_untrusted < 2)
                        break;
                    /* Search for a trusted issuer of a shorter chain */
                    search |= S_DOALTERNATE;
                    alt_untrusted = num_untrusted - 1;
                    ss = false;
                }
            }

            /*
             * Extend chain with peer-provided certificates
             */
            if ((search & S_DOUNTRUSTED) != 0) {
                num = chain.size();
                if (!(num == num_untrusted)) { // ossl_assert
                    OpenSSL.debug(this + " assert failure (num == num_untrusted)");
                    addError(ERR_R_INTERNAL_ERROR);
                    trust = X509_TRUST_REJECTED;
                    this.error = V_ERR_UNSPECIFIED;
                    search = 0;
                    continue;
                }
                x = chain.get(num-1);

                /*
                 * Once we run out of untrusted issuers, we stop looking for more
                 * and start looking only in the trust store if enabled.
                 */
                xtmp = (ss || depth < num) ? null : find_issuer(sktmp, x);
                if (xtmp == null) {
                    search &= ~S_DOUNTRUSTED;
                    if (may_trusted) search |= S_DOTRUSTED;
                    continue;
                }

                /* Drop this issuer from future consideration */
                sktmp.remove(xtmp);

                chain.add(xtmp);

                x = xtmp;
                ++num_untrusted;
                ss = cert_self_signed(xtmp);

                trust = X509_TRUST_UNTRUSTED; // switch (trust = check_dane_issuer(...))
            }
        }
        // sk_X509_free(sktmp)

        /*
         * Last chance to make a trusted chain, either bare DANE-TA public-key
         * signers, or else direct leaf PKIX trust.
         */
        num = chain.size();
        if (num <= depth) {
            if (trust == X509_TRUST_UNTRUSTED && num == num_untrusted) {
                trust = check_trust(num);
            }
        }

        switch (trust) {
            case X509_TRUST_TRUSTED:
                return 1;
            case X509_TRUST_REJECTED:
                /* Callback already issued */
                return 0;
            case X509_TRUST_UNTRUSTED:
            default:
                num = chain.size();
                if (num > depth) {
                    return verify_cb_cert(null, num - 1, V_ERR_CERT_CHAIN_TOO_LONG);
                }
                if (ss && num == 1) {
                    return verify_cb_cert(null, num - 1, V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
                }
                if (ss) {
                    return verify_cb_cert(null, num - 1, V_ERR_SELF_SIGNED_CERT_IN_CHAIN);
                }
                if (num_untrusted < num) {
                    return verify_cb_cert(null, num - 1, V_ERR_UNABLE_TO_GET_ISSUER_CERT);
                }
                return verify_cb_cert(null, num - 1, V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
        }
    }

    @Deprecated // legacy find_issuer
    private X509AuxCertificate findIssuer(final List<X509AuxCertificate> certs,
        final X509AuxCertificate cert, final boolean check_time) throws Exception {
        for ( X509AuxCertificate issuer : certs ) {
            if ( checkIssued.call(this, cert, issuer) != 0 ) {
                if (!check_time || x509_check_cert_time(issuer, -1)) return issuer;
            }
        }
        return null;
    }

    /*
     * Given a STACK_OF(X509) find the issuer of cert (if any)
     *
     * x509_vfy.c: static int build_chain(X509_STORE_CTX *ctx)
     */
    private X509AuxCertificate find_issuer(List<X509AuxCertificate> sk, X509AuxCertificate x) throws Exception {
        X509AuxCertificate rv = null;

        for (X509AuxCertificate issuer : sk) {
            if (checkIssued.call(this, x, issuer) != 0) {
                rv = issuer;
                if (x509_check_cert_time(rv, -1)) break;
            }
        }
        return rv;
    }

    private final static Set<String> CRITICAL_EXTENSIONS = new HashSet<String>(8);
    static {
        CRITICAL_EXTENSIONS.add("2.16.840.1.113730.1.1"); // netscape cert type, NID 71
        CRITICAL_EXTENSIONS.add("2.5.29.15"); // key usage, NID 83
        CRITICAL_EXTENSIONS.add("2.5.29.17"); // subject alt name, NID 85
        CRITICAL_EXTENSIONS.add("2.5.29.19"); // basic constraints, NID 87
        CRITICAL_EXTENSIONS.add("2.5.29.37"); // ext key usage, NID 126
        CRITICAL_EXTENSIONS.add("1.3.6.1.5.5.7.1.14"); // proxy cert info, NID 661
    }

    private static boolean supportsCriticalExtension(final String oid) {
        return CRITICAL_EXTENSIONS.contains(oid);
    }

    private static boolean unhandledCritical(final X509Extension ext) {
        final Set<String> criticalOIDs = ext.getCriticalExtensionOIDs();
        if ( criticalOIDs == null || criticalOIDs.size() == 0 ) {
            return false;
        }
        for ( final String oid : criticalOIDs ) {
            if ( ! supportsCriticalExtension(oid) ) return true;
        }
        return false;
    }

    /**
     * c: check_chain_extensions
     */
    public int checkChainExtensions() throws Exception {
        int ok, must_be_ca;
        X509AuxCertificate x;
        int proxy_path_length = 0;
        int allow_proxy_certs = (verifyParameter.flags & X509Utils.V_FLAG_ALLOW_PROXY_CERTS) != 0 ? 1 : 0;
        must_be_ca = -1;

        try {
            final String allowProxyCerts = System.getenv("OPENSSL_ALLOW_PROXY_CERTS");
            if ( allowProxyCerts != null && ! "false".equalsIgnoreCase(allowProxyCerts) ) {
                allow_proxy_certs = 1;
            }
        }
        catch (SecurityException e) { /* ignore if we can't use System.getenv */ }

        for ( int i = 0; i < num_untrusted; i++ ) { // lastUntrusted
            int ret;
            x = chain.get(i);
            if ( (verifyParameter.flags & X509Utils.V_FLAG_IGNORE_CRITICAL) == 0 && unhandledCritical(x) ) {
                error = X509Utils.V_ERR_UNHANDLED_CRITICAL_EXTENSION;
                error_depth = i;
                current_cert = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }
            if ( allow_proxy_certs == 0 && x.getExtensionValue("1.3.6.1.5.5.7.1.14") != null ) {
                error = X509Utils.V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED;
                error_depth = i;
                current_cert = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }

            ret = Purpose.checkCA(x);
            switch(must_be_ca) {
            case -1:
                if((verifyParameter.flags & X509Utils.V_FLAG_X509_STRICT) != 0 && ret != 1 && ret != 0) {
                    ret = 0;
                    error = X509Utils.V_ERR_INVALID_CA;
                } else {
                    ret = 1;
                }
                break;
            case 0:
                if(ret != 0) {
                    ret = 0;
                    error = X509Utils.V_ERR_INVALID_NON_CA;
                } else {
                    ret = 1;
                }
                break;
            default:
                if(ret == 0 || ((verifyParameter.flags & X509Utils.V_FLAG_X509_STRICT) != 0 && ret != 1)) {
                    ret = 0;
                    error = X509Utils.V_ERR_INVALID_CA;
                } else {
                    ret = 1;
                }
                break;
            }
            if(ret == 0) {
                error_depth = i;
                current_cert = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }
            if(verifyParameter.purpose > 0) {
                ret = Purpose.checkPurpose(x,verifyParameter.purpose, must_be_ca > 0 ? 1 : 0);
                if(ret == 0 || ((verifyParameter.flags & X509Utils.V_FLAG_X509_STRICT) != 0 && ret != 1)) {
                    error = X509Utils.V_ERR_INVALID_PURPOSE;
                    error_depth = i;
                    current_cert = x;
                    ok = verifyCallback.call(this, ZERO);
                    if(ok == 0) {
                        return ok;
                    }
                }
            }

            if(i > 1 && x.getBasicConstraints() != -1 && x.getBasicConstraints() != Integer.MAX_VALUE && (i > (x.getBasicConstraints() + proxy_path_length + 1))) {
                error = X509Utils.V_ERR_PATH_LENGTH_EXCEEDED;
                error_depth = i;
                current_cert = x;
                ok = verifyCallback.call(this, ZERO);
                if ( ok == 0 ) return ok;
            }

            if(x.getExtensionValue("1.3.6.1.5.5.7.1.14") != null) {
                ASN1Sequence pci = (ASN1Sequence)new ASN1InputStream(x.getExtensionValue("1.3.6.1.5.5.7.1.14")).readObject();
                if(pci.size() > 0 && pci.getObjectAt(0) instanceof ASN1Integer) {
                    int pcpathlen = ((ASN1Integer)pci.getObjectAt(0)).getValue().intValue();
                    if(i > pcpathlen) {
                        error = X509Utils.V_ERR_PROXY_PATH_LENGTH_EXCEEDED;
                        error_depth = i;
                        current_cert = x;
                        ok = verifyCallback.call(this, ZERO);
                        if ( ok == 0 ) return ok;
                    }
                }
                proxy_path_length++;
                must_be_ca = 0;
            } else {
                must_be_ca = 1;
            }
        }
        return 1;
    }

    /*
     * Check EE or CA certificate purpose.  For trusted certificates explicit local
     * auxiliary trust can be used to override EKU-restrictions.
     *
     * x509_vfy.c: static int check_purpose(X509_STORE_CTX *ctx, X509 *x, int purpose, int depth, int must_be_ca)
     */
    private int check_purpose(X509AuxCertificate x, int purpose, int depth, byte must_be_ca) throws Exception {
        int tr_ok = X509_TRUST_UNTRUSTED;

        /*
         * For trusted certificates we want to see whether any auxiliary trust
         * settings trump the purpose constraints.
         *
         * This is complicated by the fact that the trust ordinals in
         * ctx->param->trust are entirely independent of the purpose ordinals in
         * ctx->param->purpose!
         *
         * What connects them is their mutual initialization via calls from
         * X509_STORE_CTX_set_default() into X509_VERIFY_PARAM_lookup() which sets
         * related values of both param->trust and param->purpose.  It is however
         * typically possible to infer associated trust values from a purpose value
         * via the X509_PURPOSE API.
         *
         * Therefore, we can only check for trust overrides when the purpose we're
         * checking is the same as ctx->param->purpose and ctx->param->trust is
         * also set.
         */
        if (depth >= num_untrusted && purpose == getParam().purpose) {
            // TODO JOSSL auxiliary settings aren't properly implemented ...
            //tr_ok = Trust.checkTrust(x, getParam().trust, X509_TRUST_NO_SS_COMPAT); // X509_check_trust
        }

        switch (tr_ok) {
            case X509_TRUST_TRUSTED:
                return 1;
            case X509_TRUST_REJECTED:
                break;
            default:
                switch (Purpose.checkPurpose(x, getParam().purpose, must_be_ca > 0 ? 1 : 0)) { // X509_check_purpose(x, purpose, must_be_ca)
                    case 1:
                        return 1;
                    case 0:
                        break;
                    default:
                        if ((getParam().flags & V_FLAG_X509_STRICT) == 0) return 1;
                }
                break;
        }

        return verify_cb_cert(x, depth, V_ERR_INVALID_PURPOSE);
    }

    /*
     * Check a certificate chains extensions for consistency with the supplied purpose
     *
     * static int check_chain_extensions(X509_STORE_CTX *ctx)
     */
    private int check_chain_extensions() throws Exception {
        byte must_be_ca; int plen = 0;
        X509AuxCertificate x;
        int proxy_path_length = 0;
        int purpose;
        boolean allow_proxy_certs;
        int num = chain.size();

        /*-
         *  must_be_ca can have 1 of 3 values:
         * -1: we accept both CA and non-CA certificates, to allow direct
         *     use of self-signed certificates (which are marked as CA).
         * 0:  we only accept non-CA certificates.  This is currently not
         *     used, but the possibility is present for future extensions.
         * 1:  we only accept CA certificates.  This is currently used for
         *     all certificates in the chain except the leaf certificate.
         */
        must_be_ca = -1;

        /* CRL path validation */
        if (parent != null) { // NOT IMPLEMENTED: always null
            allow_proxy_certs = false;
            purpose = X509_PURPOSE_CRL_SIGN;
        } else {
            allow_proxy_certs = (getParam().flags & V_FLAG_ALLOW_PROXY_CERTS) != 0;
            purpose = getParam().purpose;
        }

        for (int i = 0; i < num; i++) {
            int ret;
            x = chain.get(i);
            if ((getParam().flags & V_FLAG_IGNORE_CRITICAL) == 0 && unhandledCritical(x)) {
                if (verify_cb_cert(x, i, V_ERR_UNHANDLED_CRITICAL_EXTENSION) == 0)
                    return 0;
            }
            if (allow_proxy_certs == false && (x.getExFlags() & EXFLAG_PROXY) != 0) {
                if (verify_cb_cert(x, i, V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED) == 0)
                    return 0;
            }
            ret = Purpose.checkCA(x); // X509_check_ca(x)
            switch (must_be_ca) {
                case -1:
                    if ((getParam().flags & V_FLAG_X509_STRICT) != 0 && ret != 1 && ret != 0) {
                        ret = 0;
                        this.error = V_ERR_INVALID_CA;
                    } else {
                        ret = 1;
                    }
                    break;
                case 0:
                    if (ret != 0) {
                        ret = 0;
                        this.error = V_ERR_INVALID_NON_CA;
                    } else {
                        ret = 1;
                    }
                    break;
                default:
                    /* X509_V_FLAG_X509_STRICT is implicit for intermediate CAs */
                    if ((ret == 0) || ((i + 1 < num || (getParam().flags & V_FLAG_X509_STRICT) != 0)
                            && (ret != 1))) {
                        ret = 0;
                        this.error = V_ERR_INVALID_CA;
                    } else
                        ret = 1;
                    break;
            }

            if (ret == 0 && verify_cb_cert(x, i, V_OK) == 0)
                return 0;
            /* check_purpose() makes the callback as needed */
            if (purpose > 0 && check_purpose(x, purpose, i, must_be_ca) == 0)
                return 0;
            /* Check pathlen if not self issued */
            final int ex_pathlen = x.getBasicConstraints();
            if ((i > 1) && (x.getExFlags() & EXFLAG_SI) == 0
                    && ex_pathlen != Integer.MAX_VALUE
                    && ex_pathlen != -1
                    && (plen > (ex_pathlen + proxy_path_length + 1))) {
                if (verify_cb_cert(x, i, V_ERR_PATH_LENGTH_EXCEEDED) == 0)
                    return 0;
            }

            /* Increment path length if not self issued */
            if ((x.getExFlags() & EXFLAG_SI) == 0) plen++;

            /*
             * If this certificate is a proxy certificate, the next certificate
             * must be another proxy certificate or a EE certificate.  If not,
             * the next certificate must be a CA certificate.
             */
            final byte[] ex_proxyCertInfo = x.getExtensionValue("1.3.6.1.5.5.7.1.14"); // id-pe-proxyCertInfo(14)
            if (ex_proxyCertInfo != null) { // x->ex_flags & EXFLAG_PROXY
                ASN1Sequence pci = (ASN1Sequence) new ASN1InputStream(ex_proxyCertInfo).readObject();
                if (pci.size() > 0 && pci.getObjectAt(0) instanceof ASN1Integer) {
                    int ex_pcpathlen = ((ASN1Integer) pci.getObjectAt(0)).getValue().intValue();
                    /*
                     * RFC3820, 4.1.3 (b)(1) stipulates that if pCPathLengthConstraint
                     * is less than max_path_length, the former should be copied to
                     * the latter, and 4.1.4 (a) stipulates that max_path_length
                     * should be verified to be larger than zero and decrement it.
                     *
                     * Because we're checking the certs in the reverse order, we start
                     * with verifying that proxy_path_length isn't larger than pcPLC,
                     * and copy the latter to the former if it is, and finally,
                     * increment proxy_path_length.
                     */
                    if (ex_pcpathlen != -1) {
                        if (proxy_path_length > ex_pcpathlen) {
                            if (verify_cb_cert(x, i, V_ERR_PROXY_PATH_LENGTH_EXCEEDED) == 0)
                                return 0;
                        }
                        proxy_path_length = ex_pcpathlen;
                    }
                }
                proxy_path_length++;
                must_be_ca = 0;
            } else {
                must_be_ca = 1;
            }
        }
        return 1;
    }

    /* Return 1 is a certificate is self signed */
    private boolean cert_self_signed(X509AuxCertificate x) throws CertificateException, IOException {
        // Purpose.checkPurpose(x, -1, 0);
        if ((x.getExFlags() & EXFLAG_SI) != 0) { // TODO EXFLAG_SS
            return true;
        }
        return false;
    }

    // NOTE: does not execute by default due: if ( verifyParameter.trust > 0 ) ...
    @Deprecated // legacy check_trust
    private int checkTrust() throws Exception {
        int i,ok;
        X509AuxCertificate x;
        i = chain.size()-1;
        x = chain.get(i);
        ok = Trust.checkTrust(x, verifyParameter.trust, 0);

        if ( ok == X509Utils.X509_TRUST_TRUSTED ) {
            return 1; // X509_TRUST_TRUSTED
        }
        error_depth = 1;
        current_cert = x;
        if ( ok == X509Utils.X509_TRUST_REJECTED ) {
            error = X509Utils.V_ERR_CERT_REJECTED;
        } else {
            error = X509Utils.V_ERR_CERT_UNTRUSTED;
        }
        return verifyCallback.call(this, ZERO);
    }

    /*
     * x509_vfy.c: check_trust(X509_STORE_CTX *ctx, int num_untrusted)
     */
    private int check_trust(final int num_untrusted) throws Exception {
        int i;
        final int num = chain.size();
        int trust;

        /*
         * Check trusted certificates in chain at depth num_untrusted and up.
         * Note, that depths 0..num_untrusted-1 may also contain trusted
         * certificates, but the caller is expected to have already checked those,
         * and wants to incrementally check just any added since.
         */
        for (i = num_untrusted; i < num; i++) {
            X509AuxCertificate x = chain.get(i);
            trust = Trust.checkTrust(x, getParam().trust, 0);
            /* If explicitly trusted return trusted */
            if (trust == X509_TRUST_TRUSTED)
                return X509_TRUST_TRUSTED; // goto trusted;
            if (trust == X509_TRUST_REJECTED)
                return check_trust_rejected(x, i); // goto rejected;
        }

        /*
         * If we are looking at a trusted certificate, and accept partial chains,
         * the chain is PKIX trusted.
         */
        if (num_untrusted < num) {
            if ((getParam().flags & V_FLAG_PARTIAL_CHAIN) != 0)
                return X509_TRUST_TRUSTED; // goto trusted;
            return X509_TRUST_UNTRUSTED;
        }

        if (num_untrusted == num && (getParam().flags & V_FLAG_PARTIAL_CHAIN) != 0) {
            /*
             * Last-resort call with no new trusted certificates, check the leaf
             * for a direct trust store match.
             */
            i = 0;
            X509AuxCertificate x = chain.get(i);
            X509AuxCertificate mx = lookup_cert_match(x);
            if (mx == null) return X509_TRUST_UNTRUSTED;

            /*
             * Check explicit auxiliary trust/reject settings.  If none are set,
             * we'll accept X509_TRUST_UNTRUSTED when not self-signed.
             */
            trust = Trust.checkTrust(mx, getParam().trust, 0);
            if (trust == X509_TRUST_REJECTED) {
                return check_trust_rejected(x, i); // goto rejected;
            }

            /* Replace leaf with trusted match */
            chain.set(0, mx);
            this.num_untrusted = 0;
            return X509_TRUST_TRUSTED; // goto trusted;
        }

        /*
         * If no trusted certs in chain at all return untrusted and allow
         * standard (no issuer cert) etc errors to be indicated.
         */
        return X509_TRUST_UNTRUSTED;
    }

    private int check_trust_rejected(X509AuxCertificate x, int i) throws Exception {
        if (verify_cb_cert(x, i, V_ERR_CERT_REJECTED) == 0) return X509_TRUST_REJECTED;
        return X509_TRUST_UNTRUSTED;
    }

    /*-
     * Check certificate validity times.
     * If depth >= 0, invoke verification callbacks on error, otherwise just return
     * the validation status.
     *
     * Return 1 on success, 0 otherwise.
     */
    boolean x509_check_cert_time(X509AuxCertificate x, final int depth) throws Exception {
        final Date pTime;
        if ((getParam().flags & V_FLAG_USE_CHECK_TIME) != 0) {
            pTime = getParam().checkTime;
        } else if ((getParam().flags & V_FLAG_NO_CHECK_TIME) != 0) {
            return true;
        } else {
            pTime = Calendar.getInstance().getTime();
        }

        int i = x.getNotBefore().compareTo(pTime);
        if (i >= 0 && depth < 0) {
            return false;
        }
        if (i == 0 && verify_cb_cert(x, depth, V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD) == 0) {
            return false;
        }
        if (i > 0 && verify_cb_cert(x, depth, V_ERR_CERT_NOT_YET_VALID) == 0) {
            return false;
        }

        i = x.getNotAfter().compareTo(pTime);
        if (i <= 0 && depth < 0) {
            return false;
        }
        if (i == 0 && verify_cb_cert(x, depth, V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD) == 0) {
            return false;
        }
        if (i < 0 && verify_cb_cert(x, depth, V_ERR_CERT_HAS_EXPIRED) == 0) {
            return false;
        }

        return true;
    }

    /**
     * c: check_cert
     */
    public int checkCertificate() throws Exception {
        final X509CRL[] crl = new X509CRL[1];
        X509AuxCertificate x;
        int ok, cnum;
        cnum = error_depth;
        x = chain.get(cnum);
        current_cert = x;
        current_issuer = null;

        if (x.getExtensionValue("1.3.6.1.5.5.7.1.14") != null) return 1; // (x.getExFlags() & EXFLAG_PROXY) != 0

        ok = getCRL.call(this, crl, x);
        if ( ok == 0 ) {
            error = X509Utils.V_ERR_UNABLE_TO_GET_CRL;
            ok = verifyCallback.call(this, ZERO);
            current_crl = null;
            return ok;
        }
        current_crl = crl[0];
        ok = checkCRL.call(this, crl[0]);
        if ( ok == 0 ) {
            current_crl = null;
            return ok;
        }
        ok = certificateCRL.call(this, crl[0], x);
        current_crl = null;
        return ok;
    }

    /* Check CRL times against values in X509_STORE_CTX */
    private boolean check_crl_time(X509CRL crl, final boolean notify) throws Exception {
        final Date pTime;

        if (notify) this.current_crl = crl;

        if ((getParam().flags & V_FLAG_USE_CHECK_TIME) != 0) {
            pTime = getParam().checkTime;
        } else if ((getParam().flags & V_FLAG_NO_CHECK_TIME) != 0) {
            return true;
        } else {
            pTime = Calendar.getInstance().getTime();
        }

        int i = crl.getThisUpdate().compareTo(pTime);
        if (i == 0) {
            if (!notify) return false;
            if (verify_cb_crl(V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD) == 0)
                return false;
        }

        if (i > 0) {
            if (!notify) return false;
            if (verify_cb_crl(V_ERR_CRL_NOT_YET_VALID) == 0)
                return false;
        }

        if (crl.getNextUpdate() != null) {
            i = crl.getNextUpdate().compareTo(pTime);

            if (i == 0) {
                if (!notify) return false;
                if (verify_cb_crl(V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD) == 0)
                    return false;
            }
            /* Ignore expiry of base CRL is delta is valid */
            if ((i < 0) /*&& !(ctx->current_crl_score & CRL_SCORE_TIME_DELTA)*/) {
                if (!notify) return false;
                if (verify_cb_crl(V_ERR_CRL_HAS_EXPIRED) == 0)
                    return false;
            }
        }

        if (notify) this.current_crl = null;

        return true;
    }

    @Deprecated // legacy check_crl_time
    private int checkCRLTime(X509CRL crl, int notify) throws Exception {
        current_crl = crl;
        final Date pTime;
        if ((getParam().flags & V_FLAG_USE_CHECK_TIME) != 0) {
            pTime = getParam().checkTime;
        } else {
            pTime = Calendar.getInstance().getTime();
        }

        if ( ! crl.getThisUpdate().before(pTime) ) {
            error = X509Utils.V_ERR_CRL_NOT_YET_VALID;
            if ( notify == 0 || verifyCallback.call(this, ZERO) == 0 ) {
                return 0;
            }
        }
        if ( crl.getNextUpdate() != null && !crl.getNextUpdate().after(pTime) ) {
            error = X509Utils.V_ERR_CRL_HAS_EXPIRED;
            if ( notify == 0 || verifyCallback.call(this, ZERO) == 0 ) {
                return 0;
            }
        }

        current_crl = null;
        return 1;
    }

    /**
     * c: get_crl_sk
     */
    public int getCRLStack(X509CRL[] pcrl, Name name, List<X509CRL> crls) throws Exception {
        X509CRL bestCrl = null;
        if ( crls != null ) {
            for ( final X509CRL crl : crls ) {
                if( ! name.equalTo( crl.getIssuerX500Principal() ) ) {
                    continue;
                }
                if ( checkCRLTime(crl, 0) != 0 ) {
                    pcrl[0] = crl;
                    return 1;
                }
                bestCrl = crl;
            }
        }
        if ( bestCrl != null ) {
            pcrl[0] = bestCrl;
        }
        return 0;
    }

    /* Given a certificate try and find an exact match in the store */

    private X509AuxCertificate lookup_cert_match(X509AuxCertificate x) throws Exception {
        /* Lookup all certs with matching subject name */
        List<X509AuxCertificate> certs = lookup_certs.call(this, new Name(x.getSubjectX500Principal()));
        if (certs == null) return null;
        /* Look for exact match */
        for (X509AuxCertificate xtmp : certs) {
            if (xtmp.equals(x)) return xtmp;
        }
        return null; // xtmp = null
    }

    /*
     * Inform the verify callback of an error.
     * If B<x> is not NULL it is the error cert, otherwise use the chain cert at
     * B<depth>.
     * If B<err> is not X509_V_OK, that's the error value, otherwise leave
     * unchanged (presumably set by the caller).
     *
     * Returns 0 to abort verification with an error, non-zero to continue.
     */
    private int verify_cb_cert(X509AuxCertificate x, int depth, int err) throws Exception {
        this.error_depth = depth;
        this.current_cert = x != null ? x : chain.get(depth);
        if (err != V_OK) this.error = err;
        return verifyCallback.call(this, 0); // ctx->verify_cb(0, ctx)
    }

    /*-
     * Inform the verify callback of an error, CRL-specific variant.  Here, the
     * error depth and certificate are already set, we just specify the error
     * number.
     *
     * Returns 0 to abort verification with an error, non-zero to continue.
     */
    private int verify_cb_crl(int err) throws Exception {
        this.error = err;
        return verifyCallback.call(this, 0); // ctx->verify_cb(0, ctx)
    }

    final static Store.GetIssuerFunction getFirstIssuer = new Store.GetIssuerFunction() {
        public int call(StoreContext context, X509AuxCertificate[] issuer, X509AuxCertificate cert) throws Exception {
            return context.getFirstIssuer(issuer, cert);
        }
    };

    /**
     * c: get_issuer_sk
     */
    final static Store.GetIssuerFunction getIssuerStack = new Store.GetIssuerFunction() {
        public int call(StoreContext context, X509AuxCertificate[] issuer, X509AuxCertificate x) throws Exception {
            issuer[0] = context.findIssuer(context.otherContext, x, false);
            if ( issuer[0] != null ) {
                return 1;
            } else {
                return 0;
            }
        }
    };

    /*
     * Given a possible certificate and issuer check them
     *
     * x509_vfy.c: static int check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)
     */
    final static Store.CheckIssuedFunction check_issued = new Store.CheckIssuedFunction() {
        public int call(StoreContext ctx, X509AuxCertificate x, X509AuxCertificate issuer) throws Exception {
            int ret;
            if (x.equals(issuer)) return ctx.cert_self_signed(x) ? 1 : 0;
            ret = checkIfIssuedBy(issuer, x);
            if (ret == V_OK) {
                /* Special case: single self signed certificate */
                if (ctx.cert_self_signed(x) && ctx.chain.size() == 1) return 1;

                //for (int i = 0; i < chain.size(); i++) {
                //    X509AuxCertificate ch = chain.get(i);
                //    if (ch == issuer || ch.equals(issuer)) {
                //        ret = V_ERR_PATH_LOOP;
                //        break;
                //    }
                //}
            }

            return (ret == V_OK) ? 1 : 0;
        }
    };

    final static Store.CheckIssuedFunction check_issued_legacy = new Store.CheckIssuedFunction() {
        public int call(StoreContext context, X509AuxCertificate cert, X509AuxCertificate issuer) throws Exception {
            int ret = X509Utils.checkIfIssuedBy(issuer, cert);
            if ( ret == X509Utils.V_OK ) return 1;

            if ( (context.verifyParameter.flags & X509Utils.V_FLAG_CB_ISSUER_CHECK) == 0 ) {
                return 0;
            }
            context.error = ret;
            context.current_cert = cert;
            context.current_issuer = issuer;

            return context.verifyCallback.call(context, ZERO);
        }
    };

    /**
     * c: null_callback
     */
    final static Store.VerifyCallbackFunction nullCallback = new Store.VerifyCallbackFunction() {
        public int call(StoreContext context, Integer outcome) {
            return outcome.intValue();
        }
    };

    /*
     * c: static int internal_verify(X509_STORE_CTX *ctx)
     */
    private int internal_verify() throws Exception {
        int n = chain.size() - 1;
        X509AuxCertificate xi = chain.get(n);
        X509AuxCertificate xs;

        if (checkIssued.call(this, xi, xi) != 0) {
            xs = xi;
        } else {
            if ((getParam().flags & V_FLAG_PARTIAL_CHAIN) != 0) {
                xs = xi;
                // goto check_cert;
                if (!internal_verify_check_cert(this, xi, xs, n)) {
                    return 0;
                }
                if (--n >= 0) {
                    xi = xs;
                    // xs = ctx.chain.get(n);
                }
                // goto end
            }
            if (n <= 0) {
                return verify_cb_cert(xi, 0, V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
            }

            n--;
            error_depth = n;
            xs = chain.get(n);
        }

        /*
         * Do not clear ctx->error=0, it must be "sticky", only the user's callback
         * is allowed to reset errors (at its own peril).
         */
        while ( n >= 0 ) {
            /*
             * Skip signature check for self signed certificates unless explicitly
             * asked for.  It doesn't add any security and just wastes time.  If
             * the issuer's public key is unusable, report the issuer certificate
             * and its depth (rather than the depth of the subject).
             */
            if (xs != xi || (getParam().flags & V_FLAG_CHECK_SS_SIGNATURE) != 0) {
                PublicKey pkey = xi.getPublicKey();
                if (pkey == null) {
                    if (verify_cb_cert(xi, xi != xs ? n+1 : n, V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY) == 0)
                        return 0;
                } else if (!X509_verify(xs, pkey)) {
                    if (verify_cb_cert(xs, n, V_ERR_CERT_SIGNATURE_FAILURE) == 0)
                        return 0;
                }
            }

            // check_cert :
            if (!internal_verify_check_cert(this, xi, xs, n)) {
                return 0;
            }
            if (--n >= 0) {
                xi = xs;
                xs = chain.get(n);
            }
            // end
        }
        return 1;
    }

    // goto check_cert:
    private static boolean internal_verify_check_cert(
            final StoreContext ctx, X509AuxCertificate xi, X509AuxCertificate xs, int n)
            throws Exception {
        /* Calls verify callback as needed */
        if (!ctx.x509_check_cert_time(xs, n))
            return false;

        /*
         * Signal success at this depth.  However, the previous error (if any)
         * is retained.
         */
        ctx.current_issuer = xi;
        ctx.current_cert = xs;
        ctx.error_depth = n;
        if (ctx.verifyCallback.call(ctx, 1) == 0)
            return false;

        return true; // do not halt yet but :
        //if (--n >= 0) {
        //    xi = xs;
        //    xs = ctx.chain.get(n);
        //}
    }

    private static boolean X509_verify(X509AuxCertificate xs, PublicKey pkey) {
        if (xs.verified) return true;

        try {
            xs.verify(pkey);
        } catch (Exception e) {
            return false;
        }
        return xs.verified = true;
    }

    @Deprecated // legacy internal_verify
    final static Store.VerifyFunction internalVerify = new Store.VerifyFunction() {
        public int call(final StoreContext context) throws Exception {
            Store.VerifyCallbackFunction verifyCallback = context.verifyCallback;

            int n = context.chain.size();
            context.error_depth = n - 1;
            n--;
            X509AuxCertificate xi = context.chain.get(n);
            X509AuxCertificate xs = null;
            int ok;

            if (context.checkIssued.call(context, xi, xi) != 0) {
                xs = xi;
            } else {
                if (n <= 0) {
                    context.error = X509Utils.V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
                    context.current_cert = xi;
                    ok = verifyCallback.call(context, ZERO);
                    return ok;
                } else {
                    n--;
                    context.error_depth = n;
                    xs = context.chain.get(n);
                }
            }

            while (n >= 0) {
                context.error_depth = n;
                if (!X509_verify(xs, xi.getPublicKey())) {
                    context.error = X509Utils.V_ERR_CERT_SIGNATURE_FAILURE;
                    context.current_cert = xs;
                    ok = verifyCallback.call(context, ZERO);
                    if (ok == 0) return ok;
                }

                if (!internal_verify_check_cert(context, xi, xs, n)) {
                    return 0;
                }

                n--;
                if (n >= 0) {
                    xi = xs;
                    xs = context.chain.get(n);
                }
            }
            ok = 1;
            return ok;
        }
    };

    /*
     * c: static int check_revocation(X509_STORE_CTX *ctx)
     */
    final static Store.CheckRevocationFunction check_revocation = new Store.CheckRevocationFunction() {
        public int call(final StoreContext ctx) throws Exception {
            if ( (ctx.getParam().flags & V_FLAG_CRL_CHECK) == 0 ) {
                return 1;
            }
            final int last;
            if ( (ctx.getParam().flags & V_FLAG_CRL_CHECK_ALL) != 0 ) {
                last = ctx.chain.size() - 1;
            } else {
                /* If checking CRL paths this isn't the EE certificate */
                if (ctx.parent != null) return 1; // NOT IMPLEMENTED: always null
                last = 0;
            }
            for ( int i=0; i<=last; i++ ) {
                ctx.error_depth = i;
                int ok = ctx.checkCertificate(); // check_cert(ctx);
                if (ok == 0) return 0;
            }
            return 1;
        }
    };

    /**
     * c: get_crl
     */
    final static Store.GetCRLFunction defaultGetCRL = new Store.GetCRLFunction() {
        public int call(final StoreContext context, final X509CRL[] crls, X509AuxCertificate x) throws Exception {
            final Name name = new Name( x.getIssuerX500Principal() );
            final X509CRL[] crl = new X509CRL[1];
            int ok = context.getCRLStack(crl, name, context.crls);
            if ( ok != 0 ) {
                crls[0] = crl[0];
                return 1;
            }
            final X509Object[] xobj = new X509Object[1];
            ok = context.getBySubject(X509Utils.X509_LU_CRL, name, xobj);
            if ( ok == 0 ) {
                if ( crl[0] != null ) {
                    crls[0] = crl[0];
                    return 1;
                }
                return 0;
            }
            crls[0] = (X509CRL) ( (CRL) xobj[0] ).crl;
            return 1;
        }
    };

    // TODO unused due incomplete - needs score support to pass test_x509store.rb tests?
    /* Check CRL validity */
    private int check_crl(X509CRL crl) throws Exception {
        final X509AuxCertificate issuer;
        int cnum = this.error_depth;
        int chnum = this.chain.size() - 1;

        /* if we have an alternative CRL issuer cert use that */
        if (this.current_issuer != null)
            issuer = this.current_issuer;
            /*
             * Else find CRL issuer: if not last certificate then issuer is next
             * certificate in chain.
             */
        else if (cnum < chnum)
            issuer = this.chain.get(cnum + 1);
        else {
            issuer = this.chain.get(chnum);
            /* If not self signed, can't check signature */
            if (this.checkIssued.call(this, issuer, issuer) == 0 &&
                    verify_cb_crl(V_ERR_UNABLE_TO_GET_CRL_ISSUER) == 0)
                return 0;
        }

        if (issuer == null) {
            return 1;
        }

        /*
         * Skip most tests for deltas because they have already been done
         */
        //if (!crl->base_crl_number) {
            /* Check for cRLSign bit if keyUsage present */
            if (issuer.getKeyUsage() != null && !issuer.getKeyUsage()[6]) {
                if (verify_cb_crl(V_ERR_KEYUSAGE_NO_CRL_SIGN) == 0) return 0;
            }

            //if (!(ctx->current_crl_score & CRL_SCORE_SCOPE) &&
            //        !verify_cb_crl(ctx, X509_V_ERR_DIFFERENT_CRL_SCOPE))
            //    return 0;
            //
            //if (!(ctx->current_crl_score & CRL_SCORE_SAME_PATH) &&
            //        check_crl_path(ctx, ctx->current_issuer) <= 0 &&
            //        !verify_cb_crl(ctx, X509_V_ERR_CRL_PATH_VALIDATION_ERROR))
            //    return 0;
            //
            //if ((crl->idp_flags & IDP_INVALID) &&
            //        !verify_cb_crl(ctx, X509_V_ERR_INVALID_EXTENSION))
            //    return 0;
        //}

        //if (!(ctx->current_crl_score & CRL_SCORE_TIME) &&
        //        !check_crl_time(ctx, crl, 1))
        //    return 0;
        if (!check_crl_time(crl, true)) return 0;

        /* Attempt to get issuer certificate public key */
        final PublicKey ikey = issuer.getPublicKey(); // X509_get0_pubkey(issuer)

        if (ikey == null && verify_cb_crl(V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY) == 0) {
            return 0;
        }

        if (ikey != null) {
            //int rv = X509_CRL_check_suiteb(crl, ikey, ctx->param->flags);
            //
            //if (rv != V_OK && verify_cb_crl(rv) == 0) {
            //    return 0;
            //}
            /* Verify CRL signature */
            try {
                SecurityHelper.verify(crl, ikey); // X509_CRL_verify
            }
            catch (GeneralSecurityException ex) {
                if (verify_cb_crl(V_ERR_CRL_SIGNATURE_FAILURE) == 0) return 0;
            }
        }
        return 1;
    }

    /* Check CRL validity */
    final static Store.CheckCRLFunction check_crl = new Store.CheckCRLFunction() {
        public int call(final StoreContext ctx, final X509CRL crl) throws Exception {
            return ctx.check_crl(crl);
        }
    };

    final static Store.CheckCRLFunction check_crl_legacy = new Store.CheckCRLFunction() {
        public int call(final StoreContext context, final X509CRL crl) throws Exception {
            final int errorDepth = context.error_depth;
            final int lastInChain = context.chain.size() - 1;

            int ok;
            final X509AuxCertificate issuer;
            if ( errorDepth < lastInChain ) {
                issuer = context.chain.get(errorDepth + 1);
            }
            else {
                issuer = context.chain.get(lastInChain);
                if ( context.checkIssued.call(context,issuer,issuer) == 0 ) {
                    context.error = X509Utils.V_ERR_UNABLE_TO_GET_CRL_ISSUER;
                    ok = context.verifyCallback.call(context, ZERO);
                    if ( ok == 0 ) return ok;
                }
            }

            if ( issuer != null ) {
                if ( issuer.getKeyUsage() != null && ! issuer.getKeyUsage()[6] ) {
                    context.error = X509Utils.V_ERR_KEYUSAGE_NO_CRL_SIGN;
                    ok = context.verifyCallback.call(context, ZERO);
                    if ( ok == 0 ) return ok;
                }
                final PublicKey ikey = issuer.getPublicKey();
                if ( ikey == null ) {
                    context.error = X509Utils.V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
                    ok = context.verifyCallback.call(context, ZERO);
                    if ( ok == 0 ) return ok;
                }
                else {
                    try {
                        SecurityHelper.verify(crl, ikey);
                    }
                    catch (GeneralSecurityException ex) {
                        context.error = X509Utils.V_ERR_CRL_SIGNATURE_FAILURE;
                        ok = context.verifyCallback.call(context, ZERO);
                        if ( ok == 0 ) return ok;
                    }
                }
            }

            //ok = context.checkCRLTime(crl, 1);
            //if ( ok == 0 ) return ok;
            if (!context.check_crl_time(crl, true)) return 0;

            return 1;
        }
    };

    /**
     * c: cert_crl
     */
    final static Store.CertificateCRLFunction defaultCertificateCRL = new Store.CertificateCRLFunction() {
        public int call(final StoreContext context, final X509CRL crl, X509AuxCertificate x) throws Exception {
            int ok;
            if ( crl.getRevokedCertificate( x.getSerialNumber() ) != null ) {
                context.error = X509Utils.V_ERR_CERT_REVOKED;
                ok = context.verifyCallback.call(context, ZERO);
                if ( ok == 0 ) return 0;
            }
            if ( (context.verifyParameter.flags & X509Utils.V_FLAG_IGNORE_CRITICAL) != 0 ) {
                return 1;
            }
            if ( crl.getCriticalExtensionOIDs() != null && crl.getCriticalExtensionOIDs().size() > 0 ) {
                context.error = X509Utils.V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION;
                ok = context.verifyCallback.call(context, ZERO);
                if ( ok == 0 ) return 0;
            }
            return 1;
        }
    };

    /*
     * c: static int check_policy(X509_STORE_CTX *ctx)
     */
    final static CheckPolicyFunction check_policy = new CheckPolicyFunction() {
        public int call(StoreContext context) throws Exception {
            // NOTE: NOT IMPLEMENTED
            return 1;
        }
    };

}// X509_STORE_CTX
