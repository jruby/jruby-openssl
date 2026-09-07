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

import java.math.BigInteger;
import java.security.cert.X509CRLEntry;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Time;
import org.joda.time.DateTime;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;

import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.X509Extension.newExtension;
import static org.jruby.ext.openssl.X509Extension.newExtensionError;
import static org.jruby.ext.openssl.util.RubySupport.newError;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Revoked extends RubyObject {

    private static final long serialVersionUID = -6238325248555061878L;

    static void createX509Revoked(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass Revoked = X509.defineClassUnder("Revoked", runtime.getObject(), (r, klass) -> new X509Revoked(r, klass));
        X509.defineClassUnder("RevokedError", OpenSSLError, OpenSSLError.getAllocator());
        Revoked.defineAnnotatedMethods(X509Revoked.class);
    }

    static RubyClass _Revoked(final Ruby runtime) {
        return _X509(runtime).getClass("Revoked");
    }

    static RaiseException newRevokedError(final Ruby runtime, final String message) {
        return newError(runtime, _X509(runtime).getClass("RevokedError"), message);
    }

    static X509Revoked newInstance(final ThreadContext context, final X509CRLEntry entry) {
        final Ruby runtime = context.runtime;

        final X509Revoked revoked = new X509Revoked(runtime, _Revoked(runtime));
        revoked.serial = BN.newInstance(runtime, entry.getSerialNumber());
        revoked.time = RubyTime.newTime(runtime, entry.getRevocationDate().getTime());

        if ( entry.hasExtensions() ) {
            final Set<String> criticalExtOIDs = entry.getCriticalExtensionOIDs();
            if ( criticalExtOIDs != null ) {
                for ( final String extOID : criticalExtOIDs ) {
                    revoked.addExtension(context, entry, extOID, true);
                }
            }
            final Set<String> nonCriticalExtOIDs = entry.getNonCriticalExtensionOIDs();
            if ( nonCriticalExtOIDs != null ) {
                for ( final String extOID : nonCriticalExtOIDs ) {
                    revoked.addExtension(context, entry, extOID, false);
                }
            }
        }
        return revoked;
    }

    private void addExtension(final ThreadContext context,
        final X509CRLEntry entry, final String extOID, final boolean critical) {
        try {
            final IRubyObject extension = newExtension(context, extOID, entry, critical);
            if ( extension != null ) add_extension(context, extension);
        }
        catch (IOException e) { throw newExtensionError(context.runtime, e); }
    }

    private BN serial;
    private RubyArray extensions;
    private RubyTime time;

    public X509Revoked(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        serial = BN.newInstance(context.runtime, BigInteger.ZERO);
        return this;
    }

    BN getSerial() {
        return serial;
    }

    @JRubyMethod
    public IRubyObject serial() {
        return this.serial;
    }

    @JRubyMethod(name = "serial=")
    public IRubyObject set_serial(ThreadContext context, final IRubyObject serial) {
        if (serial instanceof BN) {
            return this.serial = (BN) serial;
        }
        if (serial instanceof RubyInteger) {
            BigInteger value = ((RubyInteger) serial).getBigIntegerValue();
            return this.serial = BN.newInstance(context.runtime, value);
        }
        throw context.runtime.newTypeError(serial, context.runtime.getInteger());
    }

    DateTime getTime() {
        if ( time == null ) return null;
        return time.getDateTime();
    }

    @JRubyMethod
    public IRubyObject time() {
        return time == null ? getRuntime().getNil() : time;
    }

    @JRubyMethod(name = "time=")
    public IRubyObject set_time(ThreadContext context, final IRubyObject time) {
        return this.time = X509Cert.toUtcTime(context, time);
    }

    boolean hasExtensions() {
        return extensions != null && extensions.size() > 0;
    }

    @JRubyMethod
    public RubyArray extensions() {
        return extensions == null ? extensions = RubyArray.newArray(getRuntime(), 4) : extensions;
    }

    @JRubyMethod(name = "extensions=")
    public IRubyObject set_extensions(final IRubyObject extensions) {
        if (!(extensions instanceof RubyArray)) {
            throw getRuntime().newTypeError(extensions, getRuntime().getArray());
        }
        return this.extensions = (RubyArray) extensions;
    }

    @JRubyMethod
    public IRubyObject add_extension(final ThreadContext context, final IRubyObject ext) {
        if (!(ext instanceof X509Extension)) {
            throw context.runtime.newTypeError(ext, X509Extension._Extension(context.runtime));
        }
        return extensions().append(ext);
    }

    @Override
    @SuppressWarnings("unchecked")
    @JRubyMethod
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this, Collections.EMPTY_LIST);
    }

    ASN1Sequence toASN1Sequence() throws IOException {
        final DateTime revokedTime = getTime();
        if (revokedTime == null) throw newRevokedError(getRuntime(), "revocation time not set");

        final ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(getSerial().getValue()));
        vec.add(new Time(revokedTime.toDate()));
        if (hasExtensions()) {
            final RubyArray extensions = this.extensions();
            final ASN1Encodable[] entries = new ASN1Encodable[extensions.size()];
            for (int i = 0; i < extensions.size(); i++) {
                entries[i] = ((X509Extension) extensions.eltInternal(i)).toASN1Sequence();
            }
            vec.add(new DERSequence(entries));
        }
        return new DLSequence(vec);
    }

}// X509Revoked
