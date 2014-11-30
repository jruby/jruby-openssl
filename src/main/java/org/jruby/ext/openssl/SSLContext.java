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

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
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

import static org.jruby.ext.openssl.StringHelper.*;
import static org.jruby.ext.openssl.SSL.*;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.X509Cert._Certificate;
import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;
import static org.jruby.ext.openssl.Utils.hasNonNilInstanceVariable;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSLContext extends RubyObject {

    private static final long serialVersionUID = -6955774230685920773L;

    // Mapping table for OpenSSL's SSL_METHOD -> JSSE's SSLContext algorithm.
    private static final HashMap<String, String> SSL_VERSION_OSSL2JSSE;
    // Mapping table for JSEE's enabled protocols for the algorithm.
    private static final Map<String, String[]> ENABLED_PROTOCOLS;

    static {
        SSL_VERSION_OSSL2JSSE = new LinkedHashMap<String, String>(16);
        ENABLED_PROTOCOLS = new HashMap<String, String[]>(8, 1);

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
        ENABLED_PROTOCOLS.put("SSL", new String[] { "SSLv2", "SSLv3", "TLSv1" });

        // Followings(TLS, TLSv1.1) are JSSE only methods at present. Let's allow user to use it.

        SSL_VERSION_OSSL2JSSE.put("TLS", "TLS");
        ENABLED_PROTOCOLS.put("TLS", new String[] { "TLSv1", "TLSv1.1" });

        SSL_VERSION_OSSL2JSSE.put("TLSv1.1", "TLSv1.1");
        ENABLED_PROTOCOLS.put("TLSv1.1", new String[] { "TLSv1.1" });
    }

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
        SSLContext.addReadWriteAttribute(context, "client_ca");
        SSLContext.addReadWriteAttribute(context, "ca_file");
        SSLContext.addReadWriteAttribute(context, "ca_path");
        SSLContext.addReadWriteAttribute(context, "timeout");
        SSLContext.addReadWriteAttribute(context, "verify_mode");
        SSLContext.addReadWriteAttribute(context, "verify_depth");
        SSLContext.addReadWriteAttribute(context, "verify_callback");
        SSLContext.addReadWriteAttribute(context, "options");
        SSLContext.addReadWriteAttribute(context, "cert_store");
        SSLContext.addReadWriteAttribute(context, "extra_chain_cert");
        SSLContext.addReadWriteAttribute(context, "client_cert_cb");
        SSLContext.addReadWriteAttribute(context, "session_id_context");
        SSLContext.addReadWriteAttribute(context, "tmp_dh_callback");
        SSLContext.addReadWriteAttribute(context, "servername_cb");

        SSLContext.defineAlias("ssl_timeout", "timeout");
        SSLContext.defineAlias("ssl_timeout=", "timeout=");

        SSLContext.defineAnnotatedMethods(SSLContext.class);

        final Set<String> methodKeys = SSL_VERSION_OSSL2JSSE.keySet();
        final RubyArray methods = runtime.newArray( methodKeys.size() );
        for ( String method : methodKeys ) {
            methods.append( runtime.newSymbol(method) );
        }
        SSLContext.defineConstant("METHODS", methods);
        // in 1.8.7 as well as 1.9.3 :
        // [:TLSv1, :TLSv1_server, :TLSv1_client, :SSLv3, :SSLv3_server, :SSLv3_client, :SSLv23, :SSLv23_server, :SSLv23_client]

        SSLContext.setConstant("SESSION_CACHE_OFF", runtime.newFixnum(SESSION_CACHE_OFF));
        SSLContext.setConstant("SESSION_CACHE_CLIENT", runtime.newFixnum(SESSION_CACHE_CLIENT));
        SSLContext.setConstant("SESSION_CACHE_SERVER", runtime.newFixnum(SESSION_CACHE_SERVER));
        SSLContext.setConstant("SESSION_CACHE_BOTH", runtime.newFixnum(SESSION_CACHE_BOTH));
        SSLContext.setConstant("SESSION_CACHE_NO_AUTO_CLEAR", runtime.newFixnum(SESSION_CACHE_NO_AUTO_CLEAR));
        SSLContext.setConstant("SESSION_CACHE_NO_INTERNAL_LOOKUP", runtime.newFixnum(SESSION_CACHE_NO_INTERNAL_LOOKUP));
        SSLContext.setConstant("SESSION_CACHE_NO_INTERNAL_STORE", runtime.newFixnum(SESSION_CACHE_NO_INTERNAL_STORE));
        SSLContext.setConstant("SESSION_CACHE_NO_INTERNAL", runtime.newFixnum(SESSION_CACHE_NO_INTERNAL));

        // DEFAULT_CERT_STORE = OpenSSL::X509::Store.new
        // DEFAULT_CERT_STORE.set_default_paths
        // if defined?(OpenSSL::X509::V_FLAG_CRL_CHECK_ALL)
        //   DEFAULT_CERT_STORE.flags = OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
        // end
        final X509Store DEFAULT_CERT_STORE = X509Store.newStore(runtime);
        DEFAULT_CERT_STORE.set_default_paths(context);
        final IRubyObject V_FLAG_CRL_CHECK_ALL = _X509(runtime).getConstantAt("V_FLAG_CRL_CHECK_ALL");
        if ( V_FLAG_CRL_CHECK_ALL != null ) DEFAULT_CERT_STORE.set_flags(V_FLAG_CRL_CHECK_ALL);

        SSLContext.setConstant("DEFAULT_CERT_STORE", DEFAULT_CERT_STORE);

        // DEFAULT_PARAMS = {
        //   :ssl_version => "SSLv23",
        //   :verify_mode => OpenSSL::SSL::VERIFY_PEER,
        //   :ciphers => "ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW",
        //   :options => OpenSSL::SSL::OP_ALL,
        // }
        // on MRI 2.1 (should not matter for us) :
        //  :options => defined?(OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS) ?
        //    OpenSSL::SSL::OP_ALL & ~OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS :
        //    OpenSSL::SSL::OP_ALL
        final RubyHash DEFAULT_PARAMS = new RubyHash(runtime);
        IRubyObject ssl_version = StringHelper.newString(runtime, new byte[] { 'S','S','L','v','2','3' });
        DEFAULT_PARAMS.op_aset(context, runtime.newSymbol("ssl_version"), ssl_version);
        IRubyObject verify_mode = runtime.newFixnum(VERIFY_PEER);
        DEFAULT_PARAMS.op_aset(context, runtime.newSymbol("verify_mode"), verify_mode);
        IRubyObject ciphers = StringHelper.newString(runtime, new byte[] {
            'A','L','L',':',
            '!','A','D','H',':',
            '!','E','X','P','O','R','T',':',
            '!','S','S','L','v','2',':',
            'R','C','4','+','R','S','A',':',
            '+','H','I','G','H',':',
            '+','M','E','D','I','U','M',':',
            '+','L','O','W'
        });
        DEFAULT_PARAMS.op_aset(context, runtime.newSymbol("ciphers"), ciphers);
        IRubyObject options = runtime.newFixnum(OP_ALL);
        DEFAULT_PARAMS.op_aset(context, runtime.newSymbol("options"), options);

        SSLContext.setConstant("DEFAULT_PARAMS", DEFAULT_PARAMS);
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

    private String ciphers = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
    private String protocol = "SSL"; // SSLv23 in OpenSSL by default
    private boolean protocolForServer = true;
    private boolean protocolForClient = true;
    private PKey t_key;
    private X509Cert t_cert;

    /* TODO: should move to SSLSession after implemented */
    private int verifyResult = 1; /* avoid 0 (= X509_V_OK) just in case */

    private int sessionCacheMode; // 2
    private int sessionCacheSize; // 20480

    private InternalContext internalContext;

    @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(IRubyObject[] args) {
        return this;
    }

    @JRubyMethod
    public IRubyObject setup(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        if ( isFrozen() ) return runtime.getNil();

        this.freeze(context);

        internalContext = new InternalContext();

        // TODO: handle tmp_dh_callback :
        
        // #if !defined(OPENSSL_NO_DH)
        //   if (RTEST(ossl_sslctx_get_tmp_dh_cb(self))){
        //     SSL_CTX_set_tmp_dh_callback(ctx, ossl_tmp_dh_callback);
        //   }
        //   else{
        //     SSL_CTX_set_tmp_dh_callback(ctx, ossl_default_tmp_dh_callback);
        //   }
        // #endif

        final X509Store certStore = getCertStore();
        internalContext.store = certStore != null ? certStore.getStore() : new Store();

        IRubyObject value = getInstanceVariable("@extra_chain_cert");
        if ( value != null && ! value.isNil() ) {
            final List<X509Cert> extraCerts = convertToX509Certs(context, value);
            final ArrayList<X509AuxCertificate> extraChainCert = new ArrayList<X509AuxCertificate>(extraCerts.size());
            for ( X509Cert x : extraCerts ) extraChainCert.add( x.getAuxCert() );
            internalContext.extraChainCert = extraChainCert;
        }

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

        if ( key != null && cert != null ) {
            internalContext.keyAlgorithm = key.getAlgorithm();
            internalContext.privateKey = key.getPrivateKey();
            internalContext.cert = cert.getAuxCert();
        }

        value = getInstanceVariable("@client_ca");
        if ( value != null && ! value.isNil() ) {
            if ( value.respondsTo("each") ) {
                for ( X509Cert x : convertToX509Certs(context, value) ) {
                    internalContext.clientCert.add( x.getAuxCert() );
                }
            } else {
                if ( ! ( value instanceof X509Cert ) ) {
                    throw runtime.newTypeError("OpenSSL::X509::Certificate expected but got @client_ca = " + value.inspect());
                }
                internalContext.clientCert.add( ((X509Cert) value).getAuxCert() );
            }
        }

        String caFile = getCaFile();
        String caPath = getCaPath();
        if (caFile != null || caPath != null) {
            try {
                if (internalContext.store.loadLocations(runtime, caFile, caPath) == 0) {
                    runtime.getWarnings().warn(ID.MISCELLANEOUS, "can't set verify locations");
                }
            }
            catch (Exception e) {
                if ( e instanceof RuntimeException ) debugStackTrace(runtime, e);
                throw newSSLError(runtime, e);
            }
        }

        value = getInstanceVariable("@timeout");
        if ( value != null && ! value.isNil() ) {
            internalContext.timeout = RubyNumeric.fix2int(value);
        }

        value = getInstanceVariable("@verify_mode");
        if ( value != null && ! value.isNil() ) {
            internalContext.verifyMode = RubyNumeric.fix2int(value);
        }

        value = getInstanceVariable("@verify_callback");
        if ( value != null && ! value.isNil() ) {
            internalContext.store.setExtraData(1, value);
        } else {
            internalContext.store.setExtraData(1, null);
        }

        value = getInstanceVariable("@verify_depth");
        if ( value != null && ! value.isNil() ) {
            internalContext.store.setDepth(RubyNumeric.fix2int(value));
        } else {
            internalContext.store.setDepth(-1);
        }

        value = getInstanceVariable("@servername_cb");
        if ( value != null && ! value.isNil() ) {
            // SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        }

        /* TODO: should be implemented for SSLSession
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
            internalContext.init();
        }
        catch (GeneralSecurityException e) {
            throw newSSLError(runtime, e);
        }
        return runtime.getTrue();
    }

    @JRubyMethod
    public IRubyObject ciphers(final ThreadContext context) {
        return matchedCiphers(context);
    }

    private RubyArray matchedCiphers(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        try {
            final String[] supported = getSupportedCipherSuites(this.protocol);
            final Collection<CipherStrings.Def> cipherDefs =
                    CipherStrings.matchingCiphers(this.ciphers, supported, false);

            final RubyArray cipherList = runtime.newArray(cipherDefs.size());

            for ( CipherStrings.Def def : cipherDefs ) {
                final RubyArray cipher = runtime.newArray(4);
                cipher.store(0, newUTF8String(runtime, def.name));
                cipher.store(1, newUTF8String(runtime, sslVersionString(def.algorithms)));
                cipher.store(2, runtime.newFixnum(def.strength_bits));
                cipher.store(3, runtime.newFixnum(def.alg_bits));

                cipherList.append(cipher);
            }
            return cipherList;
        }
        catch (GeneralSecurityException gse) {
            throw newSSLError(runtime, gse.getMessage());
        }
    }

    @JRubyMethod(name = "ciphers=")
    public IRubyObject set_ciphers(final ThreadContext context, final IRubyObject ciphers) {
        if ( ciphers.isNil() ) {
            this.ciphers = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
        }
        else if ( ciphers instanceof RubyArray ) {
            StringBuilder builder = new StringBuilder();
            String sep = "";
            for (IRubyObject obj : ((RubyArray) ciphers).toJavaArray()) {
                builder.append(sep).append(obj.toString());
                sep = ":";
            }
            this.ciphers = builder.toString();
        }
        else {
            this.ciphers = ciphers.asString().toString();
            if ( "DEFAULT".equals( this.ciphers ) ) {
                this.ciphers = CipherStrings.SSL_DEFAULT_CIPHER_LIST;
            }
        }
        if ( matchedCiphers(context).isEmpty() ) {
            throw newSSLError(context.runtime, "no cipher match");
        }
        return ciphers;
    }

    @JRubyMethod(name = "ssl_version=")
    public IRubyObject set_ssl_version(IRubyObject version) {
        final String versionStr;
        if ( version instanceof RubyString ) {
            versionStr = version.asString().toString();
        } else {
            versionStr = version.toString();
        }
        final String mapped = SSL_VERSION_OSSL2JSSE.get(versionStr);
        if ( mapped == null ) {
            throw newSSLError(getRuntime(), String.format("unknown SSL method `%s'.", versionStr));
        }
        protocol = mapped;
        protocolForServer = ! versionStr.endsWith("_client");
        protocolForClient = ! versionStr.endsWith("_server");
        return version;
    }

    // ##
    // # Sets the parameters for this SSL context to the values in +params+.
    // # The keys in +params+ must be assignment methods on SSLContext.
    // #
    // # If the verify_mode is not VERIFY_NONE and ca_file, ca_path and
    // # cert_store are not set then the system default certificate store is
    // # used.
    //
    //  def set_params(params={})
    //    params = DEFAULT_PARAMS.merge(params)
    //    params.each{|name, value| self.__send__("#{name}=", value) }
    //    if self.verify_mode != OpenSSL::SSL::VERIFY_NONE
    //      unless self.ca_file or self.ca_path or self.cert_store
    //        self.cert_store = DEFAULT_CERT_STORE
    //      end
    //    end
    //    return params
    //  end

    @JRubyMethod(optional = 1)
    public IRubyObject set_params(final ThreadContext context, final IRubyObject[] args) {
        final RubyHash params;
        final RubyClass SSLContext = _SSLContext(context.runtime);
        RubyHash DEFAULT_PARAMS = (RubyHash) SSLContext.getConstantAt("DEFAULT_PARAMS");
        if ( args.length == 0 ) params = DEFAULT_PARAMS;
        else {
            params = (RubyHash) DEFAULT_PARAMS.callMethod(context, "merge", args[0]);
        }
        final SSLContext self = this;
        params.visitAll(new RubyHash.Visitor() {
            @Override
            public void visit(IRubyObject name, IRubyObject value) {
                self.callMethod(context, name.toString() + '=', value);
            }
        });
        IRubyObject verify_mode = self.getInstanceVariable("@verify_mode");
        if ( verify_mode != null && ! verify_mode.isNil()
          && RubyNumeric.fix2int(verify_mode) != SSL.VERIFY_NONE ) {
          if ( ! hasNonNilInstanceVariable(self, "@ca_file")
            && ! hasNonNilInstanceVariable(self, "@ca_path")
            && ! hasNonNilInstanceVariable(self, "@cert_store") ) {
            IRubyObject DEFAULT_CERT_STORE = SSLContext.getConstantAt("DEFAULT_CERT_STORE");
            self.setInstanceVariable("@cert_store", DEFAULT_CERT_STORE);
          }
        }
        return params;
    }

    // NOTE: mostly stubs since SSL session (cache) not yet implemented :

    @JRubyMethod(name = "session_cache_mode")
    public IRubyObject session_cache_mode() {
        return getRuntime().newFixnum(sessionCacheMode);
    }

    @JRubyMethod(name = "session_cache_mode=")
    public IRubyObject set_session_cache_mode(IRubyObject mode) {
        this.sessionCacheMode = RubyInteger.fix2int(mode);
        return mode;
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
        // TODO: session cache NOT IMPLEMENTED

        // { :connect_renegotiate=>0, :cache_full=>0, :accept_good=>0,
        //   :connect=>0, :timeouts=>0, :accept_renegotiate=>0, :accept=>0,
        //   :cache_hits=>0, :cache_num=>0, :cb_hits=>0, :connect_good=>0,
        //   :cache_misses=>0 }

        return RubyHash.newHash(context.runtime);
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

    private static String cachedProtocol = null;
    private static String[] cachedSupportedCipherSuites;

    private static String[] getSupportedCipherSuites(final String protocol)
        throws GeneralSecurityException {
        if ( cachedProtocol == null ) {
            synchronized(SSLContext.class) {
                if ( cachedProtocol == null ) {
                    cachedSupportedCipherSuites = dummySSLEngine(protocol).getSupportedCipherSuites();
                    cachedProtocol = protocol;
                    return cachedSupportedCipherSuites;
                }
            }
        }

        if ( protocol.equals(cachedProtocol) ) return cachedSupportedCipherSuites;

        return dummySSLEngine(protocol).getSupportedCipherSuites();
    }

    private static SSLEngine dummySSLEngine(final String protocol) throws GeneralSecurityException {
        javax.net.ssl.SSLContext sslContext = SecurityHelper.getSSLContext(protocol);
        sslContext.init(null, null, null);
        return sslContext.createSSLEngine();
    }

    // should keep SSLContext as a member for introducin SSLSession. later...
    SSLEngine createSSLEngine(String peerHost, int peerPort) throws NoSuchAlgorithmException, KeyManagementException {
        final SSLEngine engine;
        // an empty peerHost implies no SNI (RFC 3546) support requested
        if (peerHost == null || peerHost.length() == 0) {
            engine = internalContext.getSSLContext().createSSLEngine();
        }
        // SNI is attempted for valid peerHost hostname on Java >= 7
        // if peerHost is set to an IP address Java does not use SNI
        else {
            engine = internalContext.getSSLContext().createSSLEngine(peerHost, peerPort);
        }
        engine.setEnabledCipherSuites( getCipherSuites(engine.getSupportedCipherSuites()) );
        engine.setEnabledProtocols( getEnabledProtocols(engine) );
        return engine;
    }

    private String[] getCipherSuites(final String[] supported) {
        Collection<CipherStrings.Def> cipherDefs =
                CipherStrings.matchingCiphers(this.ciphers, supported, true);
        final String[] result = new String[ cipherDefs.size() ]; int i = 0;
        for ( CipherStrings.Def def : cipherDefs ) {
            result[ i++ ] = def.getCipherSuite();
        }
        return result;
    }

    private String[] getEnabledProtocols(final SSLEngine engine) {
        final String[] enabledProtocols = ENABLED_PROTOCOLS.get(protocol);
        if ( enabledProtocols != null ) {
            final long options = getOptions();
            final String[] engineProtocols = engine.getEnabledProtocols();
            final List<String> protocols = new ArrayList<String>(enabledProtocols.length);
            for ( final String enabled : enabledProtocols ) {
                if (((options & SSL.OP_NO_SSLv2) != 0) && enabled.equals("SSLv2")) {
                    continue;
                }
                if (((options & SSL.OP_NO_SSLv3) != 0) && enabled.equals("SSLv3")) {
                    continue;
                }
                if (((options & SSL.OP_NO_TLSv1) != 0) && enabled.equals("TLSv1")) {
                    continue;
                }
                for ( final String allowed : engineProtocols ) {
                    if ( allowed.equals(enabled) ) protocols.add(allowed);
                }
            }
            return protocols.toArray( new String[ protocols.size() ] );
        }
        return new String[0];
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
        IRubyObject options = getInstanceVariable("@options");
        if ( options != null && ! options.isNil() ) {
            return RubyNumeric.fix2long(options);
        }
        return 0;
    }

    private List<X509Cert> convertToX509Certs(final ThreadContext context, IRubyObject value) {
        final ArrayList<X509Cert> result = new ArrayList<X509Cert>();
        final RubyModule SSLContext = _SSLContext(context.runtime);
        final RubyModule Certificate = _Certificate(context.runtime);
        Utils.invoke(context, value, "each",
            CallBlock.newCallClosure(value, SSLContext, Arity.NO_ARGUMENTS, new BlockCallback() {

                public IRubyObject call(ThreadContext context, IRubyObject[] args, Block block) {
                    final IRubyObject cert = args[0];
                    if ( ! ( Certificate.isInstance(cert) ) ) {
                        throw context.runtime.newTypeError("wrong argument : " + cert.inspect() + " is not a " + Certificate.getName());
                    }
                    result.add( (X509Cert) cert );
                    return context.nil;
                }

            }, context)
        );
        return result;
    }

    static RubyClass _SSLContext(final Ruby runtime) {
        return (RubyClass) _SSL(runtime).getConstantAt("SSLContext");
    }

    /**
     * c: SSL_CTX
     */
    private class InternalContext {

        Store store;
        int verifyMode = SSL.VERIFY_NONE; // 0x00
        X509AuxCertificate cert; String keyAlgorithm; PrivateKey privateKey;

        final List<X509AuxCertificate> clientCert = new ArrayList<X509AuxCertificate>();
        List<X509AuxCertificate> extraChainCert;

        int timeout = 0;

        private javax.net.ssl.SSLContext sslContext;

        void init() throws GeneralSecurityException {
            this.sslContext = SecurityHelper.getSSLContext(protocol);
            if (protocolForClient) {
                sslContext.getClientSessionContext().setSessionTimeout(timeout);
            }
            if (protocolForServer) {
                sslContext.getServerSessionContext().setSessionTimeout(timeout);
            }
            sslContext.init(
                new KeyManager[] { new KeyManagerImpl(this) },
                new TrustManager[] { new TrustManagerImpl(this) },
                null
            );
        }

        // part of ssl_verify_cert_chain
        StoreContext createStoreContext(final String purpose) {
            if ( store == null ) return null;

            final StoreContext storeContext = new StoreContext();
            if ( storeContext.init(store, null, null) == 0 ) {
                return null;
            }
            // for verify_cb
            storeContext.setExtraData(1, store.getExtraData(1));
            if ( purpose != null ) {
                storeContext.setDefault(purpose);
            }
            storeContext.verifyParameter.inherit(store.verifyParameter);
            return storeContext;
        }

        javax.net.ssl.SSLContext getSSLContext() {
            return sslContext;
        }

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
            if (internalContext == null) {
                return null;
            }
            if (internalContext.privateKey == null) {
                return null;
            }
            for (int i = 0; i < keyType.length; i++) {
                if (keyType[i].equalsIgnoreCase(internalContext.keyAlgorithm)) {
                    return keyType[i];
                }
            }
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            if (internalContext == null || internalContext.privateKey == null) {
                return null;
            }
            if (keyType.equalsIgnoreCase(internalContext.keyAlgorithm)) {
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
            if ( internalContext == null ) return null;

            final ArrayList<java.security.cert.X509Certificate> chain =
                    new ArrayList<java.security.cert.X509Certificate>();
            if ( internalContext.extraChainCert != null ) {
                chain.addAll(internalContext.extraChainCert);
            }
            else if ( internalContext.cert != null ) {
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
                        x = ((Certificate) s_obj[0]).x509;
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
            return chain.toArray( new java.security.cert.X509Certificate[chain.size()] );
        }

        @Override
        public String[] getClientAliases(String keyType, java.security.Principal[] issuers) {
            return null;
        }

        @Override
        public java.security.PrivateKey getPrivateKey(String alias) {
            if (internalContext == null || internalContext.privateKey == null) {
                return null;
            }
            return internalContext.privateKey;
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
            if ( internalContext == null ) return null;

            final int size = internalContext.clientCert.size();
            return internalContext.clientCert.toArray( new java.security.cert.X509Certificate[size] );
        }

        // c: ssl_verify_cert_chain
        private void checkTrusted(final String purpose, final X509Certificate[] chain) throws CertificateException {
            if ( internalContext == null ) throw new CertificateException("uninitialized trust manager");

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
                internalContext.setLastVerifyResult(storeContext.error);
                if ( storeContext.error == X509Utils.V_OK ) {
                    internalContext.setLastVerifyResult(X509Utils.V_ERR_CERT_REJECTED);
                }
                throw new CertificateException("certificate verify failed", e);
            }

            internalContext.setLastVerifyResult(storeContext.error);
            if ( ok == 0 ) {
                throw new CertificateException("certificate verify failed");
            }
        }
    }

}// SSLContext
