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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyString;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.RubyProc;
import org.jruby.anno.JRubyMethod;
import org.jruby.common.IRubyWarnings.ID;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.BlockCallback;
import org.jruby.runtime.CallBlock;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.x509store.Certificate;
import org.jruby.ext.openssl.x509store.Name;
import org.jruby.ext.openssl.x509store.Store;
import org.jruby.ext.openssl.x509store.StoreContext;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.X509Object;
import org.jruby.ext.openssl.x509store.X509Utils;

import static org.jruby.ext.openssl.CipherStrings.SuiteToOSSL;
import static org.jruby.ext.openssl.StringHelper.*;
import static org.jruby.ext.openssl.SSL.*;
import static org.jruby.ext.openssl.X509Cert._Certificate;
import static org.jruby.ext.openssl.x509store.StoreContext.ossl_ssl_ex_vcb_idx;
import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;
import static org.jruby.ext.openssl.OpenSSL.warn;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSLContext extends RubyObject {

    private static final long serialVersionUID = -6955774230685920773L;

    // Mapping table for OpenSSL's SSL_METHOD -> JSSE's SSLContext algorithm.
    private static final HashMap<String, String> SSL_VERSION_OSSL2JSSE;
    // Mapping table for JSEE's enabled protocols for the algorithm.
    private static final Map<String, String[]> ENABLED_PROTOCOLS;
    // Mapping table from CRuby parse_proto_version(VALUE str)
    private static final Map<String, Integer> PROTO_VERSION_MAP;

    private static final Map<String, Integer> JSSE_TO_VERSION;

    static {
        SSL_VERSION_OSSL2JSSE = new LinkedHashMap<>(32, 1);
        ENABLED_PROTOCOLS = new HashMap<>(16, 1);

        SSL_VERSION_OSSL2JSSE.put("TLSv1", "TLSv1");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_server", "TLSv1");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_client", "TLSv1");
        ENABLED_PROTOCOLS.put("TLSv1", new String[] { "TLSv1" });

        SSL_VERSION_OSSL2JSSE.put("SSLv2", "SSLv2");
        SSL_VERSION_OSSL2JSSE.put("SSLv2_server", "SSLv2");
        SSL_VERSION_OSSL2JSSE.put("SSLv2_client", "SSLv2");
        ENABLED_PROTOCOLS.put("SSLv2", new String[] { "SSLv2" });

        SSL_VERSION_OSSL2JSSE.put("SSLv3", "SSLv3");
        SSL_VERSION_OSSL2JSSE.put("SSLv3_server", "SSLv3");
        SSL_VERSION_OSSL2JSSE.put("SSLv3_client", "SSLv3");
        ENABLED_PROTOCOLS.put("SSLv3", new String[] { "SSLv3" });

        SSL_VERSION_OSSL2JSSE.put("SSLv23", "SSL");
        SSL_VERSION_OSSL2JSSE.put("SSLv23_server", "SSL");
        SSL_VERSION_OSSL2JSSE.put("SSLv23_client", "SSL");

        ENABLED_PROTOCOLS.put("SSL", new String[] { "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" });

        // Historically we were ahead of MRI to support TLS
        // ... thus the non-standard names version names :

        SSL_VERSION_OSSL2JSSE.put("TLS", "TLS");
        ENABLED_PROTOCOLS.put("TLS", new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" });

        SSL_VERSION_OSSL2JSSE.put("TLSv1.1", "TLSv1.1");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_1_server", "TLSv1.1");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_1_client", "TLSv1.1");
        ENABLED_PROTOCOLS.put("TLSv1.1", new String[] { "TLSv1.1" });

        SSL_VERSION_OSSL2JSSE.put("TLSv1_1", "TLSv1.1"); // supported on MRI 2.x
        SSL_VERSION_OSSL2JSSE.put("TLSv1_2", "TLSv1.2"); // supported on MRI 2.x
        ENABLED_PROTOCOLS.put("TLSv1.2", new String[] { "TLSv1.2" });

        SSL_VERSION_OSSL2JSSE.put("TLSv1.2", "TLSv1.2");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_2_server", "TLSv1.2");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_2_client", "TLSv1.2");

        SSL_VERSION_OSSL2JSSE.put("TLSv1.3", "TLSv1.3");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_3_server", "TLSv1.3");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_3_client", "TLSv1.3");
        SSL_VERSION_OSSL2JSSE.put("TLSv1_3", "TLSv1.3");
        ENABLED_PROTOCOLS.put("TLSv1.3", new String[] { "TLSv1.3" });

        PROTO_VERSION_MAP = new HashMap<>(8, 1);
        PROTO_VERSION_MAP.put("SSL2", SSL.SSL2_VERSION);
        PROTO_VERSION_MAP.put("SSL3", SSL.SSL3_VERSION);
        PROTO_VERSION_MAP.put("TLS1", SSL.TLS1_VERSION);
        PROTO_VERSION_MAP.put("TLS1_1", SSL.TLS1_1_VERSION);
        PROTO_VERSION_MAP.put("TLS1_2", SSL.TLS1_2_VERSION);
        PROTO_VERSION_MAP.put("TLS1_3", SSL.TLS1_3_VERSION);

        JSSE_TO_VERSION = new HashMap<>(8, 1);
        JSSE_TO_VERSION.put("SSLv2", SSL.SSL2_VERSION);
        JSSE_TO_VERSION.put("SSLv3", SSL.SSL3_VERSION);
        JSSE_TO_VERSION.put("TLSv1", SSL.TLS1_VERSION);
        JSSE_TO_VERSION.put("TLSv1.1", SSL.TLS1_1_VERSION);
        JSSE_TO_VERSION.put("TLSv1.2", SSL.TLS1_2_VERSION);
        JSSE_TO_VERSION.put("TLSv1.3", SSL.TLS1_3_VERSION);
    }

    private static final String[] EMPTY_STRING_ARRAY = new String[0];

    private static ObjectAllocator SSLCONTEXT_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new SSLContext(runtime, klass);
        }
    };

    public static void createSSLContext(final Ruby runtime, final RubyModule SSL) { // OpenSSL::SSL
        RubyClass SSLContext = SSL.defineClassUnder("SSLContext", runtime.getObject(), SSLCONTEXT_ALLOCATOR);

        final ThreadContext context = runtime.getCurrentContext();
        SSLContext.addReadWriteAttribute(context, "cert");
        SSLContext.addReadWriteAttribute(context, "key");
        /*
         * A certificate or Array of certificates that will be sent to the client.
         */
        SSLContext.addReadWriteAttribute(context, "client_ca");
        /*
         * The path to a file containing a PEM-format CA certificate
         */
        SSLContext.addReadWriteAttribute(context, "ca_file");
        /*
         * The path to a directory containing CA certificates in PEM format.
         *
         * Files are looked up by subject's X509 name's hash value.
         */
        SSLContext.addReadWriteAttribute(context, "ca_path");
        SSLContext.addReadWriteAttribute(context, "timeout");
        SSLContext.addReadWriteAttribute(context, "verify_mode");
        /*
         * Number of CA certificates to walk when verifying a certificate chain.
         */
        SSLContext.addReadWriteAttribute(context, "verify_depth");
        /*
         * A callback for additional certificate verification.  The callback is
         * invoked for each certificate in the chain.
         *
         * The callback is invoked with two values.  _preverify_ok_ indicates
         * indicates if the verification was passed (+true+) or not (+false+).
         * _store_context_ is an OpenSSL::X509::StoreContext containing the
         * context used for certificate verification.
         *
         * If the callback returns +false+, the chain verification is immediately
         * stopped and a bad_certificate alert is then sent.
         */
        SSLContext.addReadWriteAttribute(context, "verify_callback");
        /*
         * Whether to check the server certificate is valid for the hostname.
         *
         * In order to make this work, verify_mode must be set to VERIFY_PEER and
         * the server hostname must be given by OpenSSL::SSL::SSLSocket#hostname=.
         */
        SSLContext.addReadWriteAttribute(context, "verify_hostname");
        /*
         * An OpenSSL::X509::Store used for certificate verification.
         */
        SSLContext.addReadWriteAttribute(context, "cert_store");
        /*
         * An Array of extra X509 certificates to be added to the certificate
         * chain.
         *
         * The _cert_, _key_, and _extra_chain_cert_ attributes are deprecated.
         * It is recommended to use #add_certificate instead.
         */
        SSLContext.addReadWriteAttribute(context, "extra_chain_cert");
        SSLContext.addReadWriteAttribute(context, "client_cert_cb");
        SSLContext.addReadWriteAttribute(context, "session_id_context");
        SSLContext.addReadWriteAttribute(context, "tmp_dh_callback");
        SSLContext.addReadWriteAttribute(context, "servername_cb");
        SSLContext.addReadWriteAttribute(context, "renegotiation_cb");
        SSLContext.addReadWriteAttribute(context, "alpn_protocols");
        SSLContext.addReadWriteAttribute(context, "alpn_select_cb");

        SSLContext.defineAlias("ssl_timeout", "timeout");
        SSLContext.defineAlias("ssl_timeout=", "timeout=");

        SSLContext.defineAnnotatedMethods(SSLContext.class);

        final Set<String> methodKeys = SSL_VERSION_OSSL2JSSE.keySet();
        final RubyArray methods = runtime.newArray( methodKeys.size() );
        for ( final String method : methodKeys ) {
            if ( method.indexOf('.') == -1 ) {
                // do not "officially" report TLSv1.1 and TLSv1.2
                methods.append( runtime.newSymbol(method) );
            }
        }
        SSLContext.defineConstant("METHODS", methods);
        SSLContext.deprecateConstant(runtime, "METHODS");

        SSLContext.setConstant("SESSION_CACHE_OFF", runtime.newFixnum(SESSION_CACHE_OFF));
        SSLContext.setConstant("SESSION_CACHE_CLIENT", runtime.newFixnum(SESSION_CACHE_CLIENT));
        SSLContext.setConstant("SESSION_CACHE_SERVER", runtime.newFixnum(SESSION_CACHE_SERVER));
        SSLContext.setConstant("SESSION_CACHE_BOTH", runtime.newFixnum(SESSION_CACHE_BOTH));
        SSLContext.setConstant("SESSION_CACHE_NO_AUTO_CLEAR", runtime.newFixnum(SESSION_CACHE_NO_AUTO_CLEAR));
        SSLContext.setConstant("SESSION_CACHE_NO_INTERNAL_LOOKUP", runtime.newFixnum(SESSION_CACHE_NO_INTERNAL_LOOKUP));
        SSLContext.setConstant("SESSION_CACHE_NO_INTERNAL_STORE", runtime.newFixnum(SESSION_CACHE_NO_INTERNAL_STORE));
        SSLContext.setConstant("SESSION_CACHE_NO_INTERNAL", runtime.newFixnum(SESSION_CACHE_NO_INTERNAL));
    }

    static final int SESSION_CACHE_OFF = 0;
    static final int SESSION_CACHE_CLIENT = 1;
    static final int SESSION_CACHE_SERVER = 2;
    static final int SESSION_CACHE_BOTH = 3; // 1 | 2

    static final int SESSION_CACHE_NO_AUTO_CLEAR = 128;
    static final int SESSION_CACHE_NO_INTERNAL_LOOKUP = 256;
    static final int SESSION_CACHE_NO_INTERNAL_STORE = 512;
    static final int SESSION_CACHE_NO_INTERNAL = 768;

    public SSLContext(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    SSLContext(Ruby runtime) {
        super(runtime, _SSLContext(runtime));
    }

    private long options = OP_ALL;

    //private transient CipherStrings.Def cipher_list;
    /* same as above but sorted for lookup */
    //private transient CipherStrings.Def cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    //private transient CipherStrings.Def tls13_ciphersuites;

    private String ciphers = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
    private String protocol = "SSL"; // ctx->method
    private boolean protocolForServer = true;
    private boolean protocolForClient = true;
    private int minProtocolVersion = 0;
    private int maxProtocolVersion = 0;
    private PKey t_key;
    private X509Cert t_cert;

    private int verifyResult = 1; /* avoid 0 (= X509_V_OK) just in case */

    //private int sessionCacheMode; // 2 default on MRI
    private int sessionCacheSize; // 20480

    private volatile InternalContext internalContext;

    @JRubyMethod(required = 0, optional = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(IRubyObject[] args) {
        assert this.options == OP_ALL; // self.options |= OpenSSL::SSL::OP_ALL
        if ( args.length > 0 ) set_ssl_version(args[0]); // self.ssl_version = version if version
        return initializeImpl();
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    @Override // NOTE: instance variables (no internal state) on #dup
    public IRubyObject initialize_copy(IRubyObject original) {
        SSLContext copy = (SSLContext) super.initialize_copy(original);
        copy.options = ((SSLContext) original).options;
        return copy;
    }

    final SSLContext initializeImpl() { return this; }

    @JRubyMethod
    public IRubyObject setup(final ThreadContext context) {
        if (isFrozen()) return context.nil;
        return doSetup(context);
    }

    private synchronized IRubyObject doSetup(final ThreadContext context) {
        if (isFrozen()) return context.nil;

        final Ruby runtime = context.runtime;

        final X509Store certStore = getCertStore();

        // TODO: handle tmp_dh_callback :

        // #if !defined(OPENSSL_NO_DH)
        //   if (RTEST(ossl_sslctx_get_tmp_dh_cb(self))){
        //     SSL_CTX_set_tmp_dh_callback(ctx, ossl_tmp_dh_callback);
        //   }
        //   else{
        //     SSL_CTX_set_tmp_dh_callback(ctx, ossl_default_tmp_dh_callback);
        //   }
        // #endif

        IRubyObject value;

        value = getInstanceVariable("@key");
        final PKey key;
        if ( value != null && ! value.isNil() ) {
            if ( ! ( value instanceof PKey ) ) {
                throw runtime.newTypeError("OpenSSL::PKey::PKey expected but got @key = " + value.inspect());
            }
            key = (PKey) value;
        } else {
            key = getCallbackKey(context);
        }

        value = getInstanceVariable("@cert");
        final X509Cert cert;
        if ( value != null && ! value.isNil() ) {
            if ( ! ( value instanceof X509Cert ) ) {
                throw runtime.newTypeError("OpenSSL::X509::Certificate expected but got @cert = " + value.inspect());
            }
            cert = (X509Cert) value;
        } else {
            cert = getCallbackCert(context);
        }

        value = getInstanceVariable("@client_ca");
        final List<X509AuxCertificate> clientCert;
        if ( value != null && ! value.isNil() ) {
            if ( value.respondsTo("each") ) {
                clientCert = convertToAuxCerts(context, value);
            } else {
                if ( ! ( value instanceof X509Cert ) ) {
                    throw runtime.newTypeError("OpenSSL::X509::Certificate expected but got @client_ca = " + value.inspect());
                }
                clientCert = Collections.singletonList( ((X509Cert) value).getAuxCert() );
            }
        }
        else clientCert = Collections.emptyList();

        value = getInstanceVariable("@extra_chain_cert");
        final List<X509AuxCertificate> extraChainCert;
        if ( value != null && ! value.isNil() ) {
            extraChainCert = convertToAuxCerts(context, value);
        }
        else {
            extraChainCert = null;
        }

        value = getInstanceVariable("@verify_mode");
        final int verifyMode;
        if ( value != null && ! value.isNil() ) {
            verifyMode = RubyNumeric.fix2int(value);
        }
        else {
            verifyMode = SSL.VERIFY_NONE; // 0x00
        }

        value = getInstanceVariable("@timeout");
        final int timeout;
        if ( value != null && ! value.isNil() ) {
            timeout = RubyNumeric.fix2int(value);
        }
        else {
            timeout = 0;
        }

        final Store store = certStore != null ? certStore.getStore() : new Store();

        final String caFile = getCaFile();
        final String caPath = getCaPath();
        if (caFile != null || caPath != null) {
            try {
                if (store.loadLocations(runtime, caFile, caPath) == 0) {
                    runtime.getWarnings().warn(ID.MISCELLANEOUS, "can't set verify locations");
                }
            }
            catch (Exception e) {
                if ( e instanceof RuntimeException ) debugStackTrace(runtime, e);
                throw newSSLError(runtime, e);
            }
        }

        value = getInstanceVariable("@verify_callback");
        if ( value != null && ! value.isNil() ) {
            store.setExtraData(ossl_ssl_ex_vcb_idx, value);
        } else {
            store.setExtraData(ossl_ssl_ex_vcb_idx, null);
        }

        value = getInstanceVariable("@verify_depth");
        if ( value != null && ! value.isNil() ) {
            store.setDepth(RubyNumeric.fix2int(value));
        } else {
            store.setDepth(-1);
        }

        value = getInstanceVariable("@servername_cb");
        if ( value != null && ! value.isNil() ) {
            // SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        }

        final String[] alpnProtocols;

        value = getInstanceVariable("@alpn_protocols");
        if ( value != null && ! value.isNil() ) {
            IRubyObject[] alpn_protocols = ((RubyArray) value).toJavaArrayMaybeUnsafe();
            String[] protocols = new String[alpn_protocols.length];
            for(int i = 0; i < protocols.length; i++) {
                protocols[i] = alpn_protocols[i].convertToString().asJavaString();
            }
            alpnProtocols = protocols;
        } else {
            alpnProtocols = null;
        }

        final RubyProc alpnSelectCb;
        value = getInstanceVariable("@alpn_select_cb");
        if ( value != null && ! value.isNil() ) {
            alpnSelectCb = (RubyProc) value;
        } else {
            alpnSelectCb = null;
        }


        // NOTE: no API under javax.net to support session get/new/remove callbacks
        /*
        val = ossl_sslctx_get_sess_id_ctx(self);
        if (!NIL_P(val)){
            StringValue(val);
            if (!SSL_CTX_set_session_id_context(ctx, (unsigned char *)RSTRING_PTR(val),
                                                RSTRING_LEN(val))){
                ossl_raise(eSSLError, "SSL_CTX_set_session_id_context:");
            }
        }

        if (RTEST(rb_iv_get(self, "@session_get_cb"))) {
            SSL_CTX_sess_set_get_cb(ctx, ossl_sslctx_session_get_cb);
            OSSL_Debug("SSL SESSION get callback added");
        }
        if (RTEST(rb_iv_get(self, "@session_new_cb"))) {
            SSL_CTX_sess_set_new_cb(ctx, ossl_sslctx_session_new_cb);
            OSSL_Debug("SSL SESSION new callback added");
        }
        if (RTEST(rb_iv_get(self, "@session_remove_cb"))) {
            SSL_CTX_sess_set_remove_cb(ctx, ossl_sslctx_session_remove_cb);
            OSSL_Debug("SSL SESSION remove callback added");
        }
        */

        try {
            internalContext = createInternalContext(context, cert, key, store, clientCert, extraChainCert,
                                                    verifyMode, timeout, alpnProtocols, alpnSelectCb);
        }
        catch (GeneralSecurityException e) {
            throw newSSLError(runtime, e);
        }

        this.freeze(context);

        return runtime.getTrue();
    }

    @JRubyMethod
    public RubyArray ciphers(final ThreadContext context) { // SSL_CTX_get_ciphers
        return matchedCiphersWithCache(context, this.ciphers);
    }

    private RubyArray matchedCiphersWithCache(final ThreadContext context, final String ciphers) {
        final CipherListCache cache = cipherListCache;
        if ( protocol.equals(cache.protocol) && ciphers.equals(cache.ciphers) ) {
            return newSharedArray(cache.cipherList);
        }

        final RubyArray match = matchedCiphers(context, ciphers);
        cipherListCache = new CipherListCache(protocol, ciphers, match);
        return newSharedArray(match);
    }

    private RubyArray matchedCiphers(final ThreadContext context, final String ciphers) {
        final Ruby runtime = context.runtime;
        try {
            final String[] supported = getSupportedCipherSuites(context, protocol);
            final Collection<CipherStrings.Def> cipherDefs =
                    CipherStrings.matchingCiphers(ciphers, supported, false);

            final IRubyObject[] cipherList = new IRubyObject[ cipherDefs.size() ];

            int i = 0; for ( CipherStrings.Def def : cipherDefs ) {
                cipherList[i++] = runtime.newArrayNoCopy(
                    newUTF8String(runtime, def.name).freeze(context), // 0
                    newUTF8String(runtime, sslVersionString(def.algorithms)).freeze(context), // 1
                    runtime.newFixnum(def.algStrengthBits), // 2
                    runtime.newFixnum(def.algBits) // 3
                ).freeze(context);
            }
            return runtime.newArrayNoCopy(cipherList);
        }
        catch (GeneralSecurityException gse) {
            throw newSSLError(runtime, gse.getMessage());
        }
    }

    private static RubyArray newSharedArray(RubyArray array) {
        return (RubyArray) array.dup(); // shares underlying IRubyObject[] values
    }

    @JRubyMethod(name = "ciphers=")
    public IRubyObject set_ciphers(final ThreadContext context, final IRubyObject ciphers) {
        String cipherString;
        if ( ciphers.isNil() ) {
            cipherString = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
        }
        else if ( ciphers instanceof RubyArray ) {
            final RubyArray ciphs = (RubyArray) ciphers;
            StringBuilder cipherStr = new StringBuilder();
            String sep = "";
            for ( int i = 0; i < ciphs.size(); i++ ) {
                Object elem = ciphs.eltInternal(i);
                if (elem instanceof RubyArray) {
                    elem = ((RubyArray) elem).eltInternal(0);
                } else if (elem instanceof RubyString) {
                    // NOTE: JOSSL allows to pass in Java cipher names (in an array)
                    String osslName = SuiteToOSSL.get(((RubyString) elem).asJavaString());
                    if (osslName != null) elem = osslName;
                }
                cipherStr.append(sep).append( elem.toString() );
                sep = ":";
            }
            cipherString = cipherStr.toString();
        }
        else {
            cipherString = ciphers.asString().toString();
        }

        if (cipherString.equals(CipherStrings.SSL_DEFAULT_CIPHER_LIST)) {
            cipherString = CipherStrings.SSL_DEFAULT_CIPHER_LIST; // due caching
        }

        if ( matchedCiphersWithCache(context, cipherString).isEmpty() ) {
            throw newSSLError(context.runtime, "no cipher match");
        }

        this.ciphers = cipherString;
        return ciphers;
    }

    @JRubyMethod(name = "ssl_version=")
    public IRubyObject set_ssl_version(IRubyObject method) {
        final String version;
        if ( method instanceof RubySymbol ) {
            version = method.toString();
        } else {
            version = method.convertToString().toString();
        }
        final String protocol = SSL_VERSION_OSSL2JSSE.get(version);
        if ( protocol == null ) {
            throw getRuntime().newArgumentError("unknown SSL method `"+ version +"'");
        }
        this.protocol = protocol;
        protocolForServer = ! version.endsWith("_client");
        protocolForClient = ! version.endsWith("_server");
        return method;
    }

    @JRubyMethod(name = "set_minmax_proto_version", visibility = Visibility.PRIVATE)
    public IRubyObject set_minmax_proto_version(ThreadContext context, IRubyObject minVersion, IRubyObject maxVersion) {
        minProtocolVersion = parseProtoVersion(minVersion);
        maxProtocolVersion = parseProtoVersion(maxVersion);

        return context.nil;
    }

    private int parseProtoVersion(IRubyObject version) {
        if (version.isNil())
            return 0;
        if (version instanceof RubyFixnum) {
            return RubyFixnum.fix2int(version);
        }

        String string = version.asString().asJavaString();
        Integer sslVersion = PROTO_VERSION_MAP.get(string);

        if (sslVersion == null) {
            throw getRuntime().newArgumentError("unrecognized version \"" + string + "\"");
        }

        return sslVersion;
    }

    final String getProtocol() { return this.protocol; }

    @JRubyMethod(name = "session_cache_mode")
    public IRubyObject session_cache_mode() {
        return getRuntime().getNil();
        //return getRuntime().newFixnum(sessionCacheMode);
    }

    @JRubyMethod(name = "session_cache_mode=")
    public IRubyObject set_session_cache_mode(IRubyObject mode) {
        //this.sessionCacheMode = RubyInteger.fix2int(mode);
        //return mode;
        warn(getRuntime().getCurrentContext(), "OpenSSL::SSL::SSLContext#session_cache_mode= has no effect under JRuby");
        return session_cache_mode();
    }

    @JRubyMethod(name = "session_cache_size")
    public IRubyObject session_cache_size() {
        return getRuntime().newFixnum(sessionCacheSize);
    }

    @JRubyMethod(name = "session_cache_size=")
    public IRubyObject set_session_cache_size(IRubyObject size) {
        this.sessionCacheSize = RubyInteger.fix2int(size);
        return size;
    }

    @JRubyMethod(name = "session_cache_stats")
    public RubyHash session_cache_stats(final ThreadContext context) {
        // NOTE: session cache NOT IMPLEMENTED

        // { :connect_renegotiate=>0, :cache_full=>0, :accept_good=>0,
        //   :connect=>0, :timeouts=>0, :accept_renegotiate=>0, :accept=>0,
        //   :cache_hits=>0, :cache_num=>0, :cb_hits=>0, :connect_good=>0,
        //   :cache_misses=>0 }

        return RubyHash.newHash(context.runtime);
    }

    @JRubyMethod(name = "security_level")
    public IRubyObject security_level(ThreadContext context) {
        return context.runtime.newFixnum(0);
    }

    @JRubyMethod(name = "security_level=")
    public IRubyObject set_security_level(ThreadContext context, IRubyObject level) {
        warn(context, "OpenSSL::SSL::SSLContext#security_level= has no effect under JRuby");
        return context.nil;
    }

    boolean isProtocolForServer() {
        return protocolForServer;
    }

    boolean isProtocolForClient() {
        return protocolForClient;
    }

    int getLastVerifyResult() {
        return verifyResult;
    }

    void setLastVerifyResult(int verifyResult) {
        this.verifyResult = verifyResult;
    }

    private static CipherListCache cipherListCache = new CipherListCache(null, null, null);

    private static class CipherListCache {
        final String protocol;
        final String ciphers;

        final RubyArray cipherList;

        CipherListCache(String protocol, String ciphers, RubyArray cipherList) {
            this.protocol = protocol;
            this.ciphers = ciphers;
            this.cipherList = cipherList;
        }
    }

    void setApplicationProtocolsOrSelector(final SSLEngine engine) {
        setApplicationProtocolSelector(engine);
        setApplicationProtocols(engine);
    }

    private void setApplicationProtocolSelector(final SSLEngine engine) {
        final RubyProc alpn_select_cb = internalContext.alpnSelectCallback;
        if (alpn_select_cb != null) {
            engine.setHandshakeApplicationProtocolSelector((_engine, protocols) -> {
                final Ruby runtime = getRuntime();
                IRubyObject[] rubyProtocols = new IRubyObject[protocols.size()];
                int i = 0; for (String protocol : protocols) {
                    rubyProtocols[i++] = runtime.newString(protocol);
                }

                IRubyObject[] args = new IRubyObject[] { RubyArray.newArray(runtime, rubyProtocols) };
                IRubyObject selected_protocol = alpn_select_cb.call(runtime.getCurrentContext(), args);
                if (selected_protocol != null && !selected_protocol.isNil()) {
                    return ((RubyString) selected_protocol).asJavaString();
                }
                return null; // callback returned nil - none of the advertised names are acceptable
            });
        }
    }

    private void setApplicationProtocols(final SSLEngine engine) {
        final String[] alpn_protocols = internalContext.alpnProtocols;
        if (alpn_protocols != null) {
            SSLParameters params = engine.getSSLParameters();
            params.setApplicationProtocols(alpn_protocols);
            engine.setSSLParameters(params);
        }
    }

    private static String[] getSupportedCipherSuites(ThreadContext context, final String protocol)
        throws GeneralSecurityException {
        return dummySSLEngine(context, protocol).getSupportedCipherSuites();
    }

    private static SSLEngine dummySSLEngine(ThreadContext context, final String protocol) throws GeneralSecurityException {
        javax.net.ssl.SSLContext sslContext = SecurityHelper.getSSLContext(protocol);
        sslContext.init(null, null, OpenSSL.getSecureRandom(context));
        return sslContext.createSSLEngine();
    }

    final SSLEngine createSSLEngine(String peerHost, int peerPort) {
        final SSLEngine engine;
        // an empty peerHost implies no SNI (RFC 3546) support requested
        if ( peerHost == null || peerHost.length() == 0 ) {
            // no hints for an internal session reuse strategy
            engine = internalContext.getSSLContext().createSSLEngine();
        }
        // SNI is attempted for valid peerHost hostname on Java >= 7
        // if peerHost is set to an IP address Java does not use SNI
        else {
            engine = internalContext.getSSLContext().createSSLEngine(peerHost, peerPort);
        }
        final String[] protocols = getEnabledProtocols(engine);
        engine.setEnabledProtocols(protocols);
        engine.setEnabledCipherSuites( getEnabledCipherSuites(engine, protocols) );

        return engine;
    }

    private String[] getEnabledCipherSuites(final SSLEngine engine, final String[] protocols) {
        final String[] supported = engine.getSupportedCipherSuites();
        Collection<CipherStrings.Def> cipherDefs = CipherStrings.matchingCiphers(this.ciphers, supported, true);
        final String[] result = new String[ cipherDefs.size() ]; int i = 0;
        for ( CipherStrings.Def def : cipherDefs ) result[ i++ ] = def.getCipherSuite();
        return result;
    }

    private String[] getEnabledProtocols(final SSLEngine engine) {
        final String[] enabledProtocols = ENABLED_PROTOCOLS.get(protocol);
        if ( enabledProtocols != null ) {
            final long options = getOptions();
            final String[] engineProtocols = engine.getEnabledProtocols();
            final List<String> protocols = new ArrayList<>(enabledProtocols.length);
            for ( final String enabled : enabledProtocols ) {
                int protocolVersion = JSSE_TO_VERSION.get(enabled);
                if (minProtocolVersion != 0 && protocolVersion < minProtocolVersion) continue;
                if (maxProtocolVersion != 0 && protocolVersion > maxProtocolVersion) continue;

                if (((options & OP_NO_SSLv2) != 0) && enabled.equals("SSLv2")) continue;
                if (((options & OP_NO_SSLv3) != 0) && enabled.equals("SSLv3")) continue;
                if (((options & OP_NO_TLSv1) != 0) && enabled.equals("TLSv1")) continue;
                if (((options & OP_NO_TLSv1_1) != 0) && enabled.equals("TLSv1.1")) continue;
                if (((options & OP_NO_TLSv1_2) != 0) && enabled.equals("TLSv1.2")) continue;
                if (((options & OP_NO_TLSv1_3) != 0) && enabled.equals("TLSv1.3")) continue;

                if (arrayContains(engineProtocols, enabled)) protocols.add(enabled);
            }

            return protocols.toArray(EMPTY_STRING_ARRAY);
        }
        return EMPTY_STRING_ARRAY;
    }

    private static boolean arrayContains(final String[] array, final String value) {
        for (final String elem : array) {
            if (elem.equals(value)) return true;
        }
        return false;
    }

    private static final byte[] TLSv1 = { 'T','L','S','v','1' };
    private static final byte[] SSLv2 = { 'S','S','L','v','2' };
    private static final byte[] SSLv3 = { 'S','S','L','v','3' };

    private ByteList sslVersionString(long bits) {
        final ByteList str = new ByteList(18);
        boolean first = true;
        if ( ( bits & CipherStrings.SSL_SSLV3 ) != 0 ) {
            if ( ! first ) str.append('/'); first = false;
            str.append( TLSv1 ); str.append('/'); str.append( SSLv3 );
        }
        if ( ( bits & CipherStrings.SSL_SSLV2 ) != 0 ) {
            if ( ! first ) str.append('/'); // first = false;
            str.append( SSLv2 );
        }
        return str;
    }

    private PKey getCallbackKey(final ThreadContext context) {
        if ( t_key != null ) return t_key;
        initFromCallback(context);
        return t_key;
    }

    private X509Cert getCallbackCert(final ThreadContext context) {
        if ( t_cert != null ) return t_cert;
        initFromCallback(context);
        return t_cert;
    }

    private void initFromCallback(final ThreadContext context) {
        final IRubyObject callback = getInstanceVariable("@client_cert_cb");
        if ( callback != null && ! callback.isNil() ) {
            IRubyObject arr = callback.callMethod(context, "call", this);
            if ( ! ( arr instanceof RubyArray ) ) {
                throw context.runtime.newTypeError("expected @client_cert_cb.call to return an Array but got: " + arr.getMetaClass().getName());
            }
            final IRubyObject cert = ((RubyArray) arr).entry(0);
            final IRubyObject key = ((RubyArray) arr).entry(1);
            if ( ! ( cert instanceof X509Cert ) ) {
                throw context.runtime.newTypeError(cert.inspect() + " is not an instance of OpenSSL::X509::Certificate");
            }
            if ( ! ( key instanceof PKey ) ) {
                throw context.runtime.newTypeError(key.inspect() + " is not an instance of OpenSSL::PKey::PKey");
            }
            t_cert = (X509Cert) cert;
            t_key = (PKey) key;
        }
    }

    private X509Store getCertStore() {
        IRubyObject cert_store = getInstanceVariable("@cert_store");
        if ( cert_store instanceof X509Store ) {
            return (X509Store) cert_store;
        }
        return null;
    }

    private String getCaFile() {
        IRubyObject ca_file = getInstanceVariable("@ca_file");
        if ( ca_file != null && ! ca_file.isNil() ) {
            return ca_file.asString().toString();
        }
        return null;
    }

    private String getCaPath() {
        IRubyObject ca_path = getInstanceVariable("@ca_path");
        if ( ca_path != null && ! ca_path.isNil() ) {
            return ca_path.asString().toString();
        }
        return null;
    }

    private long getOptions() {
        return options;
    }

    @JRubyMethod
    public RubyInteger options(ThreadContext context) {
        return context.runtime.newFixnum(getOptions());
    }

    @JRubyMethod(name = "options=")
    public IRubyObject options_set(final IRubyObject options) {
        if (options.isNil()) {
            this.options = OP_ALL;
        } else {
            this.options = RubyNumeric.num2long(options);
        }

        return this;
    }

    private static List<X509AuxCertificate> convertToAuxCerts(final ThreadContext context, IRubyObject value) {
        final RubyModule SSLContext = _SSLContext(context.runtime);
        final RubyModule Certificate = _Certificate(context.runtime);
        if ( value instanceof RubyArray ) {
            final RubyArray val = (RubyArray) value;
            final int size = val.size();
            final ArrayList<X509AuxCertificate> result = new ArrayList<X509AuxCertificate>(size);
            for ( int i=0; i<size; i++ ) result.add( assureCertificate(context, Certificate, val.eltInternal(i)).getAuxCert() );
            return result;
        }
        if ( value instanceof List ) {
            final List<X509Cert> val = (List) value;
            final int size = val.size();
            final ArrayList<X509AuxCertificate> result = new ArrayList<X509AuxCertificate>(size);
            for ( int i=0; i<size; i++ ) result.add( assureCertificate(context, Certificate, val.get(i)).getAuxCert() );
            return result;
        }
        // else :
        final ArrayList<X509AuxCertificate> result = new ArrayList<X509AuxCertificate>();
        Utils.invoke(context, value, "each",
            CallBlock.newCallClosure(value, SSLContext, Arity.NO_ARGUMENTS, new BlockCallback() {

                public IRubyObject call(ThreadContext context, IRubyObject[] args, Block block) {
                    result.add( assureCertificate(context, Certificate, args[0]).getAuxCert() );
                    return context.nil;
                }

            }, context)
        );
        return result;
    }

    private static X509Cert assureCertificate(final ThreadContext context, final RubyModule Certificate, final IRubyObject cert) {
        if ( ! ( Certificate.isInstance(cert) ) ) {
            throw context.runtime.newTypeError("wrong argument : " + cert.inspect() + " is not a " + Certificate.getName());
        }
        return (X509Cert) cert;
    }

    static RubyClass _SSLContext(final Ruby runtime) {
        return (RubyClass) _SSL(runtime).getConstantAt("SSLContext");
    }

    private InternalContext createInternalContext(ThreadContext context,
        final X509Cert xCert, final PKey pKey, final Store store,
        final List<X509AuxCertificate> clientCert, final List<X509AuxCertificate> extraChainCert,
        final int verifyMode, final int timeout,
        final String[] alpnProtocols, final RubyProc alpnSelectCb) throws NoSuchAlgorithmException, KeyManagementException {
        InternalContext internalContext = new InternalContext(xCert, pKey, store, clientCert, extraChainCert, verifyMode, timeout, alpnProtocols, alpnSelectCb);
        internalContext.initSSLContext(context);
        return internalContext;
    }

    /**
     * c: SSL_CTX
     */
    private class InternalContext {

        InternalContext(
            final X509Cert xCert,
            final PKey pKey,
            final Store store,
            final List<X509AuxCertificate> clientCert,
            final List<X509AuxCertificate> extraChainCert,
            final int verifyMode,
            final int timeout,
            final String[] alpnProtocols,
            final RubyProc alpnSelectCallback) throws NoSuchAlgorithmException {

            if ( pKey != null && xCert != null ) {
                this.privateKey = pKey.getPrivateKey();
                this.keyType = pKey.getKeyType();
                this.cert = xCert.getAuxCert();
            }
            else {
                this.privateKey = null;
                this.keyType = null;
                this.cert = null;
            }

            this.store = store;
            this.clientCert = clientCert;
            this.extraChainCert = extraChainCert;
            this.verifyMode = verifyMode;
            this.timeout = timeout;
            this.alpnProtocols = alpnProtocols;
            this.alpnSelectCallback = alpnSelectCallback;

            // initialize SSL context :

            final javax.net.ssl.SSLContext sslContext = SecurityHelper.getSSLContext(protocol);

            this.sslContext = sslContext;
        }

        void initSSLContext(final ThreadContext context) throws KeyManagementException {
            final KeyManager[] keyManager = new KeyManager[] { new KeyManagerImpl(this) };
            final TrustManager[] trustManager = new TrustManager[] { new TrustManagerImpl(this) };
            // SSLContext (internals) on Sun JDK :
            // private final java.security.Provider provider; "SunJSSE"
            // private final javax.net.ssl.SSLContextSpi; sun.security.ssl.SSLContextImpl
            sslContext.init(keyManager, trustManager, OpenSSL.getSecureRandom(context));
            // if secureRandom == null JSSE will try :
            // - new SecureRandom();
            // - SecureRandom.getInstance("PKCS11", cryptoProvider);

            if ( protocolForClient ) {
                final SSLSessionContext clientContext = sslContext.getClientSessionContext();
                clientContext.setSessionTimeout(timeout);
                if ( sessionCacheSize >= 0 ) {
                    clientContext.setSessionCacheSize(sessionCacheSize);
                }
            }
            if ( protocolForServer ) {
                final SSLSessionContext serverContext = sslContext.getServerSessionContext();
                serverContext.setSessionTimeout(timeout);
                if ( sessionCacheSize >= 0 ) {
                    serverContext.setSessionCacheSize(sessionCacheSize);
                }
            }
        }

        final Store store;
        final X509AuxCertificate cert;
        final String keyType;
        final PrivateKey privateKey;

        final int verifyMode;

        final List<X509AuxCertificate> clientCert; // assumed always != null
        final List<X509AuxCertificate> extraChainCert; // empty assumed == null

        private final int timeout;

        private final String[] alpnProtocols;
        private final RubyProc alpnSelectCallback;

        private final javax.net.ssl.SSLContext sslContext;

        // part of ssl_verify_cert_chain
        StoreContext createStoreContext(final String purpose) {
            if ( store == null ) return null;

            final StoreContext storeContext = new StoreContext(store);
            if ( storeContext.init(null, null) == 0 ) return null;

            // for verify_cb
            storeContext.setExtraData(ossl_ssl_ex_vcb_idx, store.getExtraData(ossl_ssl_ex_vcb_idx));
            if ( purpose != null ) storeContext.setDefault(purpose);
            storeContext.getParam().inherit(store.getParam());
            return storeContext;
        }

        final javax.net.ssl.SSLContext getSSLContext() { return sslContext; }

        void setLastVerifyResult(int lastVerifyResult) {
            SSLContext.this.setLastVerifyResult(lastVerifyResult);
        }

    }

    private static class KeyManagerImpl extends X509ExtendedKeyManager {

        final InternalContext internalContext;

        KeyManagerImpl(InternalContext internalContext) {
            super();
            this.internalContext = internalContext;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            if (internalContext.privateKey == null) return null;

            for (int i = 0; i < keyType.length; i++) {
                if (keyType[i].equalsIgnoreCase(internalContext.keyType)) {
                    return keyType[i];
                }
            }
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            if (internalContext.privateKey == null) return null;

            if (keyType.equalsIgnoreCase(internalContext.keyType)) {
                return keyType;
            }
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return null;
        }

        @Override // c: ssl3_output_cert_chain
        public java.security.cert.X509Certificate[] getCertificateChain(String alias) {
            final List<java.security.cert.X509Certificate> chain;

            if ( internalContext.extraChainCert != null ) {
                chain = (List) internalContext.extraChainCert;
            }
            else if ( internalContext.cert != null ) {
                chain = new ArrayList<>(8);

                StoreContext storeCtx = internalContext.createStoreContext(null);
                X509AuxCertificate x = internalContext.cert;
                while (true) {

                    chain.add(x);

                    if ( x.getIssuerDN().equals(x.getSubjectDN()) ) break;

                    try {
                        final Name name = new Name(x.getIssuerX500Principal());
                        X509Object[] s_obj = new X509Object[1];
                        if (storeCtx.getBySubject(X509Utils.X509_LU_X509, name, s_obj) <= 0) {
                            break;
                        }
                        x = ((Certificate) s_obj[0]).cert;
                    }
                    catch (RuntimeException e) {
                        debugStackTrace(e);
                        break;
                    }
                    catch (Exception e) {
                        debug("KeyManagerImpl bySubject failed", e);
                        break;
                    }
                }
            }
            else {
                chain = Collections.EMPTY_LIST;
            }
            return chain.toArray( new java.security.cert.X509Certificate[chain.size()] );
        }

        @Override
        public String[] getClientAliases(String keyType, java.security.Principal[] issuers) {
            return null;
        }

        @Override
        public java.security.PrivateKey getPrivateKey(String alias) {
            return internalContext.privateKey; // might be null
        }

        @Override
        public String[] getServerAliases(String keyType, java.security.Principal[] issuers) {
            return null;
        }

    }

    private static class TrustManagerImpl implements X509TrustManager {

        final InternalContext internalContext;

        TrustManagerImpl(InternalContext internalContext) {
            super();
            this.internalContext = internalContext;
        }

        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            checkTrusted("ssl_client", chain);
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
            checkTrusted("ssl_server", chain);
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            final int size = internalContext.clientCert.size();
            return internalContext.clientCert.toArray( new java.security.cert.X509Certificate[size] );
        }

        // c: ssl_verify_cert_chain
        private void checkTrusted(final String purpose, final X509Certificate[] chain) throws CertificateException {
            if ( chain != null && chain.length > 0 ) {
                if ( (internalContext.verifyMode & SSL.VERIFY_PEER) != 0 ) {
                    // verify_peer
                    final StoreContext storeContext = internalContext.createStoreContext(purpose);
                    if ( storeContext == null ) {
                        throw new CertificateException("couldn't initialize store");
                    }
                    storeContext.setCertificate(chain[0]);
                    storeContext.setChain(chain);
                    verifyChain(storeContext);
                }
            } else {
                if ( (internalContext.verifyMode & SSL.VERIFY_FAIL_IF_NO_PEER_CERT) != 0 ) {
                    // fail if no peer cert
                    throw new CertificateException("no peer certificate");
                }
            }
        }

        private void verifyChain(final StoreContext storeContext) throws CertificateException {
            final int ok;
            try {
                ok = storeContext.verifyCertificate();
            }
            catch (Exception e) {
                internalContext.setLastVerifyResult(storeContext.getError());
                if ( storeContext.getError() == X509Utils.V_OK ) {
                    internalContext.setLastVerifyResult(X509Utils.V_ERR_CERT_REJECTED);
                }
                throw new CertificateException("certificate verify failed", e);
            }

            internalContext.setLastVerifyResult(storeContext.getError());
            if ( ok == 0 ) {
                throw new CertificateException("certificate verify failed");
            }
        }
    }

}// SSLContext
