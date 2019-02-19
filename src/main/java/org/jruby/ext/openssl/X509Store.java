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

import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;
import static org.jruby.ext.openssl.OpenSSL.warn;
import static org.jruby.ext.openssl.X509._X509;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.Store;
import org.jruby.ext.openssl.x509store.StoreContext;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.X509Error;
import org.jruby.ext.openssl.x509store.X509Utils;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Store extends RubyObject {

    private static final long serialVersionUID = -2969708892287379665L;

    private static ObjectAllocator X509STORE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509Store(runtime, klass);
        }
    };

    static void createX509Store(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass Store = X509.defineClassUnder("Store", runtime.getObject(), X509STORE_ALLOCATOR);
        X509.defineClassUnder("StoreError", OpenSSLError, OpenSSLError.getAllocator());

        final ThreadContext context = runtime.getCurrentContext();

        Store.addReadWriteAttribute(context, "error");
        Store.addReadWriteAttribute(context, "error_string");
        Store.addReadWriteAttribute(context, "chain");
        Store.defineAnnotatedMethods(X509Store.class);
        Store.undefineMethod("dup");

        X509StoreContext.createX509StoreContext(runtime, X509);
    }

    public X509Store(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    private X509Store(Ruby runtime) {
        super(runtime, _X509(runtime).getClass("Store"));
    }

    static X509Store newStore(final Ruby runtime) {
        final X509Store store = new X509Store(runtime);
        store.initialize(runtime.getCurrentContext(), NULL_ARRAY);
        return store;
    }

    private final Store store = new Store();

    final Store getStore() { return store; }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        final IRubyObject nil = runtime.getNil();
        final IRubyObject zero = RubyFixnum.zero(runtime);

        store.setVerifyCallbackFunction(verifyCallback);

        this.set_verify_callback(nil);
        this.setInstanceVariable("@flags", zero);
        this.setInstanceVariable("@purpose", zero);
        this.setInstanceVariable("@trust", zero);

        this.setInstanceVariable("@error", nil);
        this.setInstanceVariable("@error_string", nil);
        this.setInstanceVariable("@chain", nil);
        this.setInstanceVariable("@time", nil);
        return this;
    }

    @JRubyMethod
    public IRubyObject verify_callback() {
        return this.getInstanceVariable("@verify_callback");
    }

    @JRubyMethod(name = "verify_callback=")
    public IRubyObject set_verify_callback(final IRubyObject callback) {
        store.setExtraData(1, callback);
        this.setInstanceVariable("@verify_callback", callback);
        return callback;
    }

    @JRubyMethod(name = "flags=")
    public IRubyObject set_flags(final IRubyObject arg) {
        store.setFlags(RubyNumeric.fix2long(arg));
        return arg;
    }

    @JRubyMethod(name = "purpose=")
    public IRubyObject set_purpose(final IRubyObject arg) {
        store.setPurpose(RubyNumeric.fix2int(arg));
        return arg;
    }

    @JRubyMethod(name = "trust=")
    public IRubyObject set_trust(final IRubyObject arg) {
        store.setTrust(RubyNumeric.fix2int(arg));
        return arg;
    }

    @JRubyMethod(name = "time=")
    public IRubyObject set_time(final IRubyObject arg) {
        setInstanceVariable("@time", arg);
        return arg;
    }

    @JRubyMethod
    public IRubyObject add_path(final ThreadContext context, final IRubyObject arg) {
        warn(context, "WARNING: unimplemented method called: OpenSSL::X509::Store#add_path");
        return context.nil;
    }

    @JRubyMethod
    public IRubyObject add_file(final IRubyObject arg) {
        String file = arg.toString();
        final Ruby runtime = getRuntime();
        try {
            store.loadLocations(runtime, file, null);
        }
        catch (Exception e) {
            debugStackTrace(runtime, e);
            throw newStoreError(runtime, "loading file failed: ", e);
        }
        return this;
    }

    @JRubyMethod
    public IRubyObject set_default_paths(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        try {
            store.setDefaultPaths(runtime);
        }
        catch (Exception e) {
            debugStackTrace(runtime, e);
            throw newStoreError(runtime, "setting default path failed: ", e);
        }
        return runtime.getNil();
    }

    @JRubyMethod
    public X509Store add_cert(final IRubyObject cert) {
        X509AuxCertificate auxCert = cert instanceof X509Cert ? ((X509Cert) cert).getAuxCert() : null;
        if ( store.addCertificate(auxCert) != 1 ) {
            throw newStoreError(getRuntime(), X509Error.getLastErrorMessage());
        }
        return this;
    }

    @JRubyMethod
    public X509Store add_crl(final IRubyObject crl) {
        java.security.cert.X509CRL jCRL = (crl instanceof X509CRL) ? ((X509CRL) crl).getCRL() : null;
        if ( store.addCRL(jCRL) != 1 ) {
            throw newStoreError(getRuntime(), X509Error.getLastErrorMessage());
        }
        return this;
    }

    @JRubyMethod(rest = true)
    public IRubyObject verify(final ThreadContext context, final IRubyObject[] args, final Block block) {
        final Ruby runtime = context.runtime;
        final IRubyObject cert = args[0], chain;
        if ( Arity.checkArgumentCount(runtime, args, 1, 2) == 2 ) {
            chain = args[1];
        } else {
            chain = runtime.getNil();
        }

        final IRubyObject verify_callback;
        if (block.isGiven()) {
            verify_callback = runtime.newProc(Block.Type.PROC, block);
        } else {
            verify_callback = getInstanceVariable("@verify_callback");
        }

        final X509StoreContext store_context = X509StoreContext.newStoreContext(context, this, cert, chain);
        store_context.setInstanceVariable("@verify_callback", verify_callback);

        IRubyObject result = store_context.callMethod(context, "verify");
        this.setInstanceVariable("@error", store_context.error(context));
        this.setInstanceVariable("@error_string", store_context.error_string(context));
        this.setInstanceVariable("@chain", store_context.chain(context));
        return result;
    }

    private static Store.VerifyCallbackFunction verifyCallback = new Store.VerifyCallbackFunction() {

        public int call(final StoreContext context, final Integer outcome) {
            int ok = outcome.intValue();
            IRubyObject proc = (IRubyObject) context.getExtraData(1);
            if (proc == null) {
                proc = (IRubyObject) context.getStore().getExtraData(0);
            }

            if ( proc == null ) return ok;

            if ( ! proc.isNil() ) {
                final Ruby runtime = proc.getRuntime();
                X509StoreContext store_context = X509StoreContext.newStoreContext(runtime, context);
                IRubyObject ret = proc.callMethod(runtime.getCurrentContext(), "call",
                    new IRubyObject[] { runtime.newBoolean(ok != 0), store_context }
                );
                if (ret.isTrue()) {
                    context.setError(X509Utils.V_OK);
                    ok = 1;
                }
                else {
                    if (context.getError() == X509Utils.V_OK) {
                        context.setError(X509Utils.V_ERR_CERT_REJECTED);
                    }
                    ok = 0;
                }
            }
            return ok;
        }
    };

    private static RubyClass _StoreError(final Ruby runtime) {
        return _X509(runtime).getClass("StoreError");
    }

    private static RaiseException newStoreError(final Ruby runtime, final String message) {
        return Utils.newError(runtime, _StoreError(runtime), message);
    }

    private static RaiseException newStoreError(final Ruby runtime, final String message, final Exception e) {
    	return newStoreError(runtime, message + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
    }
}// X509Store
