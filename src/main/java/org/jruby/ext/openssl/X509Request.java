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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;

import org.jruby.ext.openssl.impl.PKCS10Request;

import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.PKey._PKey;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.PKey.supportedSignatureAlgorithm;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newIOError;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Request extends RubyObject {
    private static final long serialVersionUID = -2886532636278901502L;
    private static final Logger LOG = Logger.getLogger(X509Request.class);

    public static void createRequest(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass _Request = X509.defineClassUnder("Request", runtime.getObject(), (r, klass) -> new X509Request(r, klass));
        X509.defineClassUnder("RequestError", OpenSSLError, OpenSSLError.getAllocator());
        _Request.defineAnnotatedMethods(X509Request.class);
    }

    static RubyClass _RequestError(final Ruby runtime) {
        return (RubyClass) _X509(runtime).getConstantAt("RequestError");
    }

    private IRubyObject subject;
    private PKey public_key;
    private IRubyObject version;
    private final List<X509Attribute> attributes;

    private transient PKCS10Request request;

    public X509Request(Ruby runtime, RubyClass type) {
        super(runtime, type);
        attributes = new ArrayList<>(4);
    }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;

        try {
            request = new PKCS10Request( StringHelper.readX509PEM(context, args[0]) );
        }
        catch (RuntimeException e) {
            LOG.debugStack(runtime, null, e);
            throw newRequestError(runtime, "invalid certificate request data", e);
        }

        final PublicKey publicKey;
        try {
            publicKey = request.generatePublicKey();
        }
        catch (IOException|GeneralSecurityException e) {
            throw newRequestError(runtime, e);
        }
        this.public_key = PKey.newInstance(runtime, publicKey);

        this.subject = newName( context, request.getSubject() );

        final Attribute[] attrs = request.getAttributes();
        try { // final RubyModule _ASN1 = _ASN1(runtime);
            if ( attrs != null ) {
                for ( final Attribute attr : attrs ) {
                    final ASN1ObjectIdentifier type = attr.getAttrType();
                    final ASN1Set values = attr.getAttrValues();
                    attributes.add( newAttribute( context, type, values ) );
                }
            }
        }
        catch (IOException e) {
            throw newRequestError(runtime, e);
        }

        return this;
    }

    private static X509Attribute newAttribute(final ThreadContext context,
        final ASN1ObjectIdentifier type, final ASN1Set values) throws IOException {
        return X509Attribute.newAttribute(context.runtime, type, values);
    }

    private static IRubyObject newName(final ThreadContext context, X500Name name) {
        if ( name == null ) return context.nil;
        return X509Name.newName(context.runtime, name);
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();

        final X509Request that = (X509Request) obj;
        final ThreadContext context = getRuntime().getCurrentContext();

        this.subject = that.subject == null ? null : newName(context, getX500Name(that.subject));
        this.public_key = that.public_key == null ? null : (PKey) that.public_key.dup();
        this.version = that.version;

        this.attributes.clear();
        for ( X509Attribute attribute : that.attributes ) {
            this.attributes.add( (X509Attribute) attribute.dup() );
        }

        final PKCS10Request request = that.request;
        if ( request != null ) {
            final ASN1Sequence requestSequence = request.toASN1Structure();
            this.request = requestSequence.size() == 0 ? null : new PKCS10Request(requestSequence);
        }
        else {
            this.request = null;
        }

        return this;
    }

    private PKCS10Request getRequest() {
        if ( request != null ) return request;

        PublicKey publicKey = null;
        if ( public_key != null && ! public_key.isNil() ) {
            publicKey = public_key.getPublicKey();
        }
        X500Name subjectName = subject != null ? getX500Name(subject) : null;
        final ThreadContext context = getRuntime().getCurrentContext();
        return request = new PKCS10Request( subjectName, publicKey, newAttributesImpl(context) );
    }

    private static X500Name getX500Name(final IRubyObject name) {
        if ( name.isNil() ) return null;
        return ((X509Name) name).getX500Name();
    }

    @JRubyMethod(name = { "to_pem", "to_s" })
    public RubyString to_pem() {
        StringWriter writer = new StringWriter();
        try {
            PEMInputOutput.writeX509Request(writer, getRequest());
            return getRuntime().newString( writer.toString() );
        }
        catch (IOException e) {
            throw newIOError(getRuntime(), e);
        }
    }

    @JRubyMethod
    public RubyString to_der() {
        try {
            return newString(getRuntime(), toDER());
        }
        catch (IOException ex) {
            throw getRuntime().newIOErrorFromException(ex);
        }
    }

    final byte[] toDER() throws IOException {
        return getRequest().toASN1Structure().getEncoded(ASN1Encoding.DER);
    }

    @Override
    @JRubyMethod(name = "==")
    public IRubyObject op_equal(ThreadContext context, IRubyObject obj) {
        return equalImpl(context.runtime, obj);
    }

    private IRubyObject equalImpl(final Ruby runtime, IRubyObject obj) {
        if (this == obj) return runtime.getTrue();
        if (obj instanceof X509Request) {
            boolean equal;
            try {
                equal = Arrays.equals(toDER(), ((X509Request) obj).toDER());
            }
            catch (IOException e) {
                throw getRuntime().newIOErrorFromException(e);
            }
            return runtime.newBoolean(equal);
        }
        return runtime.getFalse();
    }

    @Override
    public IRubyObject eql_p(IRubyObject obj) {
        return equalImpl(getRuntime(), obj);
    }

    @JRubyMethod
    public IRubyObject to_text(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        final char[] S20 = StringHelper.S20;
        final StringBuilder text = new StringBuilder(512);

        text.append("Certificate Request:\n");
        text.append(S20, 0, 4).append("Data:\n");

        final int version;
        if (request != null && request.getVersion() != null) {
            version = request.getVersion().intValue();
        } else {
            version = this.version == null ? 0 : RubyNumeric.fix2int(this.version);
        }
        text.append(S20, 0, 8)
                .append("Version: ").append(version + 1)
                .append(" (0x").append(Integer.toString(version, 16)).append(")\n");

        text.append(S20, 0, 8).append("Subject: ").append(subject()).append('\n');

        text.append(S20, 0, 8).append("Subject Public Key Info:\n");
        final PublicKey publicKey = public_key == null ? null : public_key.getPublicKey();
        if (publicKey != null) {
            text.append(S20, 0, 12).append("Public Key Algorithm: ").append(publicKey.getAlgorithm()).append('\n');
            if (public_key != null) {
                try {
                    final RubyString keyText = public_key.to_text();
                    for (CharSequence line : StringHelper.split(keyText, '\n')) {
                        text.append(S20, 0, 16).append(line).append('\n');
                    }
                } catch (Exception e) {
                    text.append(S20, 0, 16).append("Unable to print public key\n");
                }
            }
        }

        text.append(S20, 0, 8).append("Attributes:\n");
        if (attributes.isEmpty()) {
            text.append(S20, 0, 12).append("(none)\n");
        } else {
            for (final X509Attribute attr : attributes) {
                text.append(S20, 0, 12).append(attr.oid());
                // pad to column 25 after indent, then value
                text.append(S20, 0, 4).append(':');
                final IRubyObject val = attr.value();
                if (!val.isNil()) text.append(val);
                text.append('\n');
            }
        }

        text.append(S20, 0, 4).append("Signature Algorithm: ").append(getSignatureAlgorithm()).append('\n');

        if (request != null) {
            final byte[] sig = request.getSignatureBytes();
            if (sig != null) { // signature hex dump
                StringHelper.appendLowerHexValue(text, sig, 9, 54);
            }
        }

        return newString(runtime, text);
    }

    @JRubyMethod
    public IRubyObject version() {
        final PKCS10Request request = getRequest(); // (false)
        if ( request != null ) {
            BigInteger certVersion = request.getVersion();
            if ( certVersion != null ) {
                return getRuntime().newFixnum( certVersion.intValue() );
            }
        }
        return version == null ? getRuntime().newFixnum(-1) : version;
    }

    @JRubyMethod(name="version=")
    public IRubyObject set_version(final ThreadContext context, IRubyObject version) {
        LOG.warnWithCaller(context.runtime, "version= has no effect on certification request");
        return this.version = version;
    }

    @JRubyMethod
    public IRubyObject subject() {
        return subject == null ? subject = getRuntime().getNil() : subject;
    }

    @JRubyMethod(name="subject=")
    public IRubyObject set_subject(final IRubyObject val) {
        if ( val != this.subject ) {
            if (request != null) {
                request.setSubject( getX500Name(val) );
            }
            this.subject = val;
        }
        return val;
    }

    @JRubyMethod
    public IRubyObject signature_algorithm(final ThreadContext context) {
        return context.runtime.newString(getSignatureAlgorithm());
    }

    private String getSignatureAlgorithm() {
        AlgorithmIdentifier signatureAlgId = request == null ? null : request.getSignatureAlgorithm();
        if (signatureAlgId == null) return "NULL";
        String name = ASN1Registry.o2a(signatureAlgId.getAlgorithm());
        if (name == null) name = ASN1.o2a(getRuntime(), signatureAlgId.getAlgorithm(), true);
        return name == null ? "" : name;
    }

    @JRubyMethod
    public IRubyObject public_key() {
        return public_key == null ? getRuntime().getNil() : public_key;
    }

    @JRubyMethod(name="public_key=")
    public IRubyObject set_public_key(final IRubyObject pkey) {
        if ( pkey != this.public_key ) {
            if (request != null) {
                request.setPublicKey( ((PKey) pkey).getPublicKey() );
            }
            this.public_key = (PKey) pkey;
        }
        return pkey;
    }

    @JRubyMethod
    public IRubyObject sign(final ThreadContext context, final IRubyObject key, final IRubyObject _digest) {
        final PKey pkey = (PKey) key;
        final Ruby runtime = context.runtime;

        try {
            request = null;
            if (_digest.isNil() && (PKeyEdDSA.isEdDSAAlgorithm(pkey.getAlgorithm()) ||
                                   PKeyMLDSA.isMLDSAAlgorithm(pkey.getAlgorithm()))) {
                // Pure signatures take the algorithm identifier directly.
                final String keyAlg = pkey.getAlgorithm();
                AlgorithmIdentifier algId = new DefaultSignatureAlgorithmIdentifierFinder().find(keyAlg);
                getRequest().sign( pkey.getPrivateKey(), algId );
            }
            else {
                if (PKeyMLDSA.isMLDSAAlgorithm(pkey.getAlgorithm())) {
                    throw newRequestError(runtime, new IllegalArgumentException("ML-DSA does not support digests"));
                }
                Digest digest = Digest.getDigest(context, _digest);
                supportedSignatureAlgorithm(runtime, _RequestError(runtime), public_key, digest);
                getRequest().sign( pkey.getPrivateKey(), digest.getShortAlgorithm() );
            }
        }
        catch (InvalidKeyException e) {
            LOG.debug(runtime, "sign invalid key", e);
            throw newRequestError(runtime, e);
        }
        catch (Exception e) {
            LOG.debugStack(runtime, "sign", e);
            throw newRequestError(runtime, e);
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
        return this;
    }

    private List<Attribute> newAttributesImpl(final ThreadContext context) {
        ArrayList<Attribute> attrs = new ArrayList<>(attributes.size());
        for ( X509Attribute attribute : attributes ) {
            attrs.add( newAttributeImpl(context, attribute) );
        }
        return attrs;
    }

    private static Attribute newAttributeImpl(final ThreadContext context, final X509Attribute attribute) {
        return Attribute.getInstance( attribute.toASN1( context ) );
    }

    @JRubyMethod
    public IRubyObject verify(final ThreadContext context, IRubyObject key) {
        final Ruby runtime = context.runtime;
        try {
            if (!(key instanceof PKey)) { // due PKeyEC
                key = key.callMethod(context, "public_key");
                if (!(key instanceof PKey)) {
                    throw context.runtime.newTypeError(key, _PKey(runtime));
                }
            }
            boolean signatureValid = getRequest().verify( ((PKey) key).getPublicKey() );
            return runtime.newBoolean(signatureValid);
        }
        catch (InvalidKeyException e) {
            LOG.debug(runtime, "verify invalid key", e);
            throw newRequestError(runtime, "invalid key supplied", e);
        }
        catch (RuntimeException e) {
            LOG.debugStack(runtime, "verify", e);
            return context.nil;
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
    }

    @JRubyMethod
    public IRubyObject attributes() {
        @SuppressWarnings("unchecked")
        List<IRubyObject> attributes = (List) this.attributes;
        return getRuntime().newArray(attributes);
    }

    @JRubyMethod(name = "attributes=")
    public IRubyObject set_attributes(final ThreadContext context,final IRubyObject attributes) {
        this.attributes.clear();
        final RubyArray attrs = (RubyArray) attributes;
        for ( int i = 0; i < attrs.size(); i++ ) {
            this.attributes.add( (X509Attribute) attrs.entry(i) );
        }
        if (request != null) {
            request.setAttributes( newAttributesImpl(context) );
        }
        return attributes;
    }

    @JRubyMethod
    public IRubyObject add_attribute(final ThreadContext context,final IRubyObject attribute) {
        attributes.add( (X509Attribute) attribute );
        if (request != null) {
            request.addAttribute( newAttributeImpl( context, (X509Attribute) attribute ) );
        }
        return attribute;
    }

    private static RaiseException newRequestError(Ruby runtime, Exception e) {
        return newError(runtime, _X509(runtime).getClass("RequestError"), e);
    }

    private static RaiseException newRequestError(Ruby runtime, String message, Exception cause) {
        return newError(runtime, _X509(runtime).getClass("RequestError"), message, cause);
    }

}// X509Request
