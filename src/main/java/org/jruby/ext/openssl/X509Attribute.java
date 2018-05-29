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

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DERSet;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;

import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.ASN1._ASN1;
import static org.jruby.ext.openssl.Utils.*;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Attribute extends RubyObject {
    private static final long serialVersionUID = 5569940260019783275L;

    private static ObjectAllocator ATTRIBUTE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509Attribute(runtime, klass);
        }
    };

    static void createAttribute(Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass Attribute = X509.defineClassUnder("Attribute", runtime.getObject(), ATTRIBUTE_ALLOCATOR);

        X509.defineClassUnder("AttributeError", OpenSSLError, OpenSSLError.getAllocator());

        Attribute.defineAnnotatedMethods(X509Attribute.class);
    }


    static RubyClass _Attribute(final Ruby runtime) {
        RubyModule _X509 = (RubyModule) runtime.getModule("OpenSSL").getConstant("X509");
        return _X509.getClass("Attribute");
    }

    public X509Attribute(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private IRubyObject oid; // attribute type
    private IRubyObject value;

    private transient ASN1ObjectIdentifier objectId;

    static X509Attribute newAttribute(final Ruby runtime, final ASN1ObjectIdentifier type, final ASN1Set values)
        throws IOException {
        X509Attribute attribute = new X509Attribute(runtime, _Attribute(runtime));
        attribute.objectId = type;
        final ThreadContext context = runtime.getCurrentContext();
        attribute.value = ASN1.decodeObject(context, _ASN1(runtime), values);
        return attribute;
    }

    private ASN1ObjectIdentifier getTypeID() {
        if ( objectId != null ) return objectId;
        return objectId = ASN1.getObjectID(getRuntime(), oid.toString());
    }

    ASN1Primitive toASN1(final ThreadContext context) {
        ASN1EncodableVector v1 = new ASN1EncodableVector();
        v1.add( getTypeID() );
        if ( value instanceof ASN1.Constructive ) {
            v1.add( ((ASN1.Constructive) value).toASN1(context) );
        }
        else {
            ASN1EncodableVector v2 = new ASN1EncodableVector();
            v2.add( ((ASN1.ASN1Data) value).toASN1(context) );
            v1.add( new DERSet(v2) );
        }
        return new DLSequence(v1);
    }

    @JRubyMethod(name="initialize", required = 1, optional = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 1 ) {
            set_oid( to_der_if_possible(context, args[0]) );
            return this;
        }
        set_oid(args[0]);
        set_value(context, args[1]);
        return this;
    }

    @Override
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final X509Attribute that = (X509Attribute) original;
        this.value = that.value == null ? null : that.value.dup();
        this.oid = that.oid;
        this.objectId = that.objectId;
        return this;
    }

    @JRubyMethod
    public IRubyObject to_der(final ThreadContext context) {
        try { // NOTE: likely won't work due Constructive !
            return StringHelper.newString(context.runtime, toDER(context));
        }
        catch (IOException e) {
            throw newIOError(context.runtime, e);
        }
    }

    final byte[] toDER(ThreadContext context) throws IOException {
        return toASN1(context).getEncoded(ASN1Encoding.DER);
    }

    @JRubyMethod
    public IRubyObject oid() {
        if ( this.oid == null ) {
            final Ruby runtime = getRuntime();
            oid = runtime.newString( ASN1.oid2Sym(runtime, objectId) );
        }
        return this.oid;
    }

    @JRubyMethod(name="oid=")
    public IRubyObject set_oid(final IRubyObject oid) {
        this.objectId = null; return this.oid = oid;
    }

    @JRubyMethod
    public IRubyObject value() {
        return value;
    }

    @JRubyMethod(name="value=")
    public IRubyObject set_value(final ThreadContext context, final IRubyObject value) {
        try {
            //if ( value instanceof ASN1.ASN1Data ) {
            //    return this.value = value;
            //}
            return this.value = ASN1.decodeImpl(context, value);
        }
        catch (IOException e) {
            throw newIOError(context.runtime, e);
        }
        catch (IllegalArgumentException e) {
            throw newArgumentError(context.runtime, e);
        }
    }

    @Override
    @JRubyMethod(name = "==")
    public IRubyObject op_equal(ThreadContext context, IRubyObject obj) {
        if (this == obj) return context.runtime.getTrue();
        if (obj instanceof X509Attribute) {
            boolean equal;
            try {
                equal = Arrays.equals(toDER(context), ((X509Attribute) obj).toDER(context));
            }
            catch (IOException e) {
                throw newIOError(context.runtime, e);
            }
            return context.runtime.newBoolean(equal);
        }
        return context.runtime.getFalse();
    }

}// X509Attribute
