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
 * Copyright (C) 2006, 2007 Ola Bini <ola@ologix.com>
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

import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.*;
import org.jruby.runtime.builtin.IRubyObject;

import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.StoreContext;

import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;
import static org.jruby.ext.openssl.OpenSSL.warn;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.X509CRL._CRL;
import static org.jruby.ext.openssl.X509Cert._Certificate;
import static org.jruby.ext.openssl.x509store.X509Utils.verifyCertificateErrorString;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509StoreContext extends RubyObject {
    private static final long serialVersionUID = -4165247923898746888L;

    private static ObjectAllocator X509STORECTX_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509StoreContext(runtime, klass);
        }
    };

    public static void createX509StoreContext(final Ruby runtime, final RubyModule X509) {
        RubyClass StoreContext = X509.defineClassUnder("StoreContext", runtime.getObject(), X509STORECTX_ALLOCATOR);
        StoreContext.defineAnnotatedMethods(X509StoreContext.class);
        StoreContext.undefineMethod("dup");
    }

    private static RubyClass _StoreContext(final Ruby runtime) {
        return _X509(runtime).getClass("StoreContext");
    }

    private StoreContext storeContext;

    public X509StoreContext(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    // constructor for creating callback parameter object of verify_cb
    private X509StoreContext(Ruby runtime, RubyClass type, StoreContext storeContext) {
        super(runtime, type);
        this.storeContext = storeContext;
    }

    static X509StoreContext newStoreContext(final Ruby runtime, final StoreContext storeContext) {
        return new X509StoreContext(runtime, _StoreContext(runtime), storeContext);
    }

    static X509StoreContext newStoreContext(final ThreadContext context, final X509Store store,
        final IRubyObject cert, final IRubyObject chain) {
        final Ruby runtime = context.runtime;
        X509StoreContext instance = new X509StoreContext(runtime, _StoreContext(runtime));
        instance.initialize(context, new IRubyObject[] { store, cert, chain } );
        return instance;
    }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        X509Store store; IRubyObject cert, chain; cert = chain = context.nil;

        store = (X509Store) args[0];

        if ( Arity.checkArgumentCount(context.runtime, args, 1, 3) > 1 ) {
            cert = args[1];
            if ( args.length > 2) chain = args[2];
        }

        final X509AuxCertificate _cert;
        if (cert.isNil()) {
            _cert = null;
        }
        else {
            if ( ! (cert instanceof X509Cert) ) {
                throw context.runtime.newTypeError(cert, "OpenSSL::X509::Certificate");
            }
            _cert = ((X509Cert) cert).getAuxCert();
        }
        final List<X509AuxCertificate> _chain;
        if ( ! chain.isNil() ) {
            @SuppressWarnings("unchecked")
            final RubyArray certs = (RubyArray) chain;
            _chain = new ArrayList<X509AuxCertificate>( certs.size() );

            for (int i = 0; i < certs.size(); i++) {
                // NOTE: if we use the normal java syntax for iterating over this
                // RubyArray, the `toJava` method of the X509Cert class will be
                // implicitly called, and that will return the BC certificate object
                // rather than the JRuby one.
                X509Cert c = (X509Cert) certs.eltOk(i);
                _chain.add(c.getAuxCert());
            }
        }
        else {
            _chain = new ArrayList<X509AuxCertificate>(4);
        }

        this.storeContext = new StoreContext(store.getStore());
        if ( storeContext.init(_cert, _chain) != 1 ) {
            throw newStoreError(context.runtime, null);
        }

        IRubyObject time = store.getInstanceVariables().getInstanceVariable("@time");
        if ( ! time.isNil() ) set_time(time);
        this.setInstanceVariable("@verify_callback", store.verify_callback());
        this.setInstanceVariable("@cert", cert);
        return this;
    }

    @JRubyMethod
    public IRubyObject verify(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        storeContext.setExtraData(1, getInstanceVariable("@verify_callback"));
        try {
            final int result = storeContext.verifyCertificate();
            return result != 0 ? runtime.getTrue() : runtime.getFalse();
        }
        catch (Exception e) {
            debugStackTrace(runtime, e);
            // TODO: define suitable exception for jopenssl and catch it.
            throw newStoreError(runtime, e.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject chain(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final List<X509AuxCertificate> chain = storeContext.getChain();
        if ( chain == null ) return runtime.getNil();

        final RubyArray result = runtime.newArray(chain.size());
        final RubyClass _Certificate = _Certificate(runtime);
        try {
            for (X509AuxCertificate x509 : chain) {
                RubyString encoded = StringHelper.newString(runtime, x509.getEncoded());
                result.append( _Certificate.newInstance( context, encoded, Block.NULL_BLOCK ) );
            }
        }
        catch (CertificateEncodingException e) {
            throw newStoreError(runtime, e.getMessage());
        }
        return result;
    }

    @JRubyMethod
    public IRubyObject error(final ThreadContext context) {
        return context.runtime.newFixnum( storeContext.getError() );
    }

    @JRubyMethod(name="error=")
    public IRubyObject set_error(final IRubyObject error) {
        storeContext.setError( RubyNumeric.fix2int(error) );
        return error;
    }

    @JRubyMethod
    public IRubyObject error_string(final ThreadContext context) {
        final int error = storeContext.getError();
        return context.runtime.newString( verifyCertificateErrorString(error) );
    }

    @JRubyMethod
    public IRubyObject error_depth(final ThreadContext context) {
        final int depth = storeContext.getErrorDepth();
        return context.runtime.newFixnum( depth );
    }

    @JRubyMethod
    public IRubyObject current_cert(final ThreadContext context) {
        final X509AuxCertificate x509 = storeContext.getCurrentCertificate();
        try {
            return X509Cert.wrap(context, x509.getEncoded());
        }
        catch (CertificateEncodingException e) {
            throw newStoreError(context.runtime, e.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject current_crl(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final RubyClass _CRL = _CRL(runtime);
        try {
            final java.security.cert.X509CRL crl = storeContext.getCurrentCRL();
            return _CRL.newInstance(context, StringHelper.newString(runtime, crl.getEncoded()), Block.NULL_BLOCK);
        }
        catch (CRLException e) {
            throw newStoreError(runtime, e.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject cleanup(final ThreadContext context) {
        try {
            storeContext.cleanup();
        }
        catch (RuntimeException e) {
            throw e;
        }
        catch (Exception e) {
            debugStackTrace(context.runtime, e);
            throw newStoreError(context.runtime, e.getMessage());
        }
        return context.runtime.getNil();
    }

    @JRubyMethod(name = "flags=")
    public IRubyObject set_flags(final ThreadContext context, final IRubyObject arg) {
        storeContext.setFlags(RubyFixnum.fix2long((RubyFixnum)arg));
        return arg;
    }

    @JRubyMethod(name = "purpose=")
    public IRubyObject set_purpose(final ThreadContext context, final IRubyObject arg) {
        storeContext.setPurpose(RubyFixnum.fix2int((RubyFixnum)arg));
        return arg;
    }

    @JRubyMethod(name = "trust=")
    public IRubyObject set_trust(final ThreadContext context, final IRubyObject arg) {
        storeContext.setTrust(RubyFixnum.fix2int((RubyFixnum)arg));
        return arg;
    }

    @JRubyMethod(name = "time=")
    public IRubyObject set_time(IRubyObject arg) {
        storeContext.setTime( 0, ( (RubyTime) arg ).getJavaDate() );
        return arg;
    }

    private static RaiseException newStoreError(Ruby runtime, String message) {
        return Utils.newError(runtime, _X509(runtime).getClass("StoreError"), message);
    }

}// X509StoreContext
