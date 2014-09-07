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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLEntry;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.x509.X509V2CRLGenerator;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.Variable;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.OpenSSLReal.debugStackTrace;
import static org.jruby.ext.openssl.OpenSSLReal.warn;
import static org.jruby.ext.openssl.ASN1._ASN1;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.X509Extensions.newExtension;
import static org.jruby.ext.openssl.X509Extensions.Extension;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509CRL extends RubyObject {
    private static final long serialVersionUID = -2463300006179688577L;

    private static ObjectAllocator X509CRL_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509CRL(runtime, klass);
        }
    };

    public static void createX509CRL(final Ruby runtime, final RubyModule _X509) {
        RubyClass _CRL = _X509.defineClassUnder("CRL", runtime.getObject(), X509CRL_ALLOCATOR);
        RubyClass _OpenSSLError = runtime.getModule("OpenSSL").getClass("OpenSSLError");
        _X509.defineClassUnder("CRLError", _OpenSSLError, _OpenSSLError.getAllocator());
        _CRL.defineAnnotatedMethods(X509CRL.class);
    }

    private IRubyObject version;
    private IRubyObject issuer;
    private RubyTime last_update;
    private RubyTime next_update;
    private RubyArray revoked;
    private RubyArray extensions;

    private IRubyObject signature_algorithm;

    private boolean changed = true;

    private final X509V2CRLGenerator generator = new X509V2CRLGenerator();
    private java.security.cert.X509CRL crl;

    private ASN1Primitive crlValue;

    static RubyClass _CRL(final Ruby runtime) {
        return _X509(runtime).getClass("CRL");
    }

    public X509CRL(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    java.security.cert.X509CRL getCRL() { return crl; }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context,
        final IRubyObject[] args, final Block block) {
        final Ruby runtime = context.runtime;

        this.version = runtime.newFixnum(0);
        //this.issuer = new X509Name(runtime, X509Name._Name(runtime));
        this.extensions = runtime.newArray(4);

        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;

        final ByteList bytes = args[0].asString().getByteList();
        final int offset = bytes.getBegin(); final int length = bytes.getRealSize();
        try {
            CertificateFactory factory = SecurityHelper.getCertificateFactory("X.509");
            crl = (java.security.cert.X509CRL) factory.generateCRL(
                new ByteArrayInputStream(bytes.unsafeBytes(), offset, length)
            );
        }
        catch (GeneralSecurityException e) {
            throw newCRLError(runtime, e.getMessage());
        }

        try {
            byte[] crl_bytes = OpenSSLImpl.readX509PEM(bytes.unsafeBytes(), offset, length);
            crlValue = new ASN1InputStream(new ByteArrayInputStream(crl_bytes)).readObject();
        }
        catch (IOException e) {
            throw newCRLError(runtime, e);
        }

        final ASN1Sequence seq = (ASN1Sequence) crlValue;
        final ASN1Sequence seq0 = (ASN1Sequence) seq.getObjectAt(0);
        final ASN1Encodable v0 = seq0.getObjectAt(0);
        if ( v0 instanceof ASN1Integer ) {
            set_version( runtime.newFixnum( ((ASN1Integer) v0).getValue().intValue() ) );
        }
        else {
            set_version( runtime.newFixnum(2) );
        }

        set_last_update( context, RubyTime.newTime(runtime, crl.getThisUpdate().getTime()) );
        set_next_update( context, RubyTime.newTime(runtime, crl.getNextUpdate().getTime()) );
        set_issuer( X509Name.newName(runtime, crl.getIssuerX500Principal()) );

        final ASN1Primitive maybe_ext = (ASN1Primitive) seq0.getObjectAt( seq0.size() - 1 );
        if ( maybe_ext instanceof ASN1TaggedObject && ( (ASN1TaggedObject) maybe_ext ).getTagNo() == 0 ) {
            final RubyModule _ASN1 = _ASN1(runtime);

            ASN1Sequence exts = (ASN1Sequence) ( (ASN1TaggedObject) maybe_ext ).getObject();
            for ( int i = 0; i < exts.size(); i++ ) {
                ASN1Sequence extSeq = (ASN1Sequence) exts.getObjectAt(i);
                boolean critical = false;
                if ( extSeq.getObjectAt(1) == DERBoolean.TRUE ) critical = true;

                String oid = ( (ASN1ObjectIdentifier) extSeq.getObjectAt(0) ).getId();
                IRubyObject realValue; final byte[] valueBytes = crl.getExtensionValue(oid);
                try {
                    IRubyObject value = RubyString.newString(runtime, valueBytes);
                    value = ASN1.decodeImpl(context, _ASN1, value).callMethod(context, "value");
                    realValue = ASN1.decodeImpl(context, _ASN1, value);
                }
                catch (Exception e) {
                    debugStackTrace(e);
                    realValue = StringHelper.newString(runtime, valueBytes);
                }

                ASN1ObjectIdentifier objectId = ASN1.getObjectIdentifier(context.runtime, oid);
                this.extensions.append( newExtension(runtime, objectId, realValue, critical) );
            }
        }

        Set<? extends X509CRLEntry> revokedCRLs = crl.getRevokedCertificates();
        if ( revokedCRLs != null ) {
            for ( X509CRLEntry entry : revokedCRLs ) {
                revoked().append( X509Revoked.newInstance(context, entry) );
            }
        }

        this.changed = false;
        return this;
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject obj) {
        final ThreadContext context = getRuntime().getCurrentContext();
        warn(context, "WARNING: unimplemented method called: CRL#init_copy");
        if ( this == obj ) return this;
        checkFrozen(); return this;
    }

    @JRubyMethod(name = {"to_pem", "to_s"})
    public IRubyObject to_pem(final ThreadContext context) {
        StringWriter writer = new StringWriter();
        try {
            PEMInputOutput.writeX509CRL(writer, crl);
            return context.runtime.newString(writer.toString());
        }
        catch (IOException e) {
            throw newCRLError(context.runtime, e);
        }
    }

    @JRubyMethod
    public IRubyObject to_der(final ThreadContext context) {
        try {
            return StringHelper.newString(context.runtime, crlValue.getEncoded());
        }
        catch (IOException e) {
            throw newCRLError(context.runtime, e);
        }
    }

    private static final char[] S16 = new char[] {
        ' ',' ',' ',' ',  ' ',' ',' ',' ',
        ' ',' ',' ',' ',  ' ',' ',' ',' ',
    };

    @JRubyMethod
    public IRubyObject to_text(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final StringBuilder text = new StringBuilder(160);

        text.append("Certificate Revocation List (CRL):\n");
        text.append(S16,0,8).append("Version ").append( RubyNumeric.fix2int(version) + 1 ).append(" (0x");
        text.append( Integer.toString( RubyNumeric.fix2int(version), 16 ) ).append(")\n");
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) ( (ASN1Sequence) ((ASN1Sequence) crlValue).getObjectAt(1) ).getObjectAt(0);
        text.append(S16,0,4).append("Signature Algorithm: ").append( ASN1.nid2ln(runtime, ASN1.obj2nid(runtime, oid)) ).append('\n');
        text.append(S16,0,8).append("Issuer: ").append( issuer() ).append('\n');
        text.append(S16,0,8).append("Last Update: ");
        appendGMTDateTime( text, getLastUpdate() ).append('\n');

        if ( ! next_update().isNil() ) {
            text.append(S16,0,8).append("Next Update: ");
            appendGMTDateTime( text, getNextUpdate() ).append('\n');
        } else {
            text.append(S16,0,8).append("Next Update: NONE\n");
        }

        if ( extensions != null && extensions.size() > 0 ) {
            text.append(S16,0,8).append("CRL extensions\n");
            extensions_to_text(context, extensions, text, 12);
        }

        if ( revoked != null && revoked.size() > 0 ) {
            text.append("\nRevoked Certificates:\n");
            for ( int i = 0; i < revoked.size(); i++ ) {
                final X509Revoked rev = (X509Revoked) revoked.entry(i);
                final String serial = rev.getSerial().toString(16).toUpperCase();
                text.append(S16,0,4).append("Serial Number: ");
                if ( serial.length() % 2 == 0 ) text.append(serial).append('\n');
                else text.append('0').append(serial).append('\n');
                text.append(S16,0,8).append("Revocation Date: ");
                appendGMTDateTime( text, rev.getTime() ).append('\n');
                if ( rev.hasExtensions() ) {
                    text.append(S16,0,8).append("CRL entry extensions\n");
                    extensions_to_text(context, extensions, text, 12);
                }
            }
        }
        else {
            text.append("No Revoked Certificates.\n");
        }

        // TODO - X509_signature_print(out, x->sig_alg, x->signature);

        return RubyString.newString( runtime, text );
    }

    private static final DateTimeFormatter ASN_DATE_NO_ZONE =
        DateTimeFormat.forPattern("MMM dd HH:mm:ss yyyy") // + " zzz"
                      .withZone(DateTimeZone.UTC);

    private static StringBuilder appendGMTDateTime(final StringBuilder text, final DateTime time) {
        final String date = ASN_DATE_NO_ZONE.print( time.getMillis() );
        return text.append(date).append(' ').append("GMT");
    }

    private static void extensions_to_text(final ThreadContext context,
        final RubyArray exts, final StringBuilder text, final int indent) {
        for ( int i = 0; i < exts.size(); i++ ) {
            final Extension ext = (Extension) exts.entry(i);
            final ASN1ObjectIdentifier oid = ext.getRealOid();
            final String no = ASN1.o2a(context.runtime, oid);
            text.append(S16,0,indent).append( no ).append(": ");
            if ( ext.isRealCritical() ) text.append("critical");
            text.append('\n');
            text.append(S16).append( ext.value(context) ).append('\n');
        }
    }

    @Override
    @JRubyMethod
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this, getInstanceVariableList());
    }

    @Override // FAKE'em to include "instance" variables in inspect
    public List<Variable<IRubyObject>> getInstanceVariableList() {
        final ArrayList<Variable<IRubyObject>> list = new ArrayList<Variable<IRubyObject>>(6);
        return list;
    }

    @JRubyMethod
    public IRubyObject version() {
        return this.version;
    }

    @JRubyMethod(name="version=")
    public IRubyObject set_version(IRubyObject version) {
        if ( ! version.equals(this.version) ) this.changed = true;
        return this.version = version;
    }

    @JRubyMethod
    public IRubyObject signature_algorithm() {
        return signature_algorithm == null ? signature_algorithm = getRuntime().newString("itu-t") : signature_algorithm;
    }

    @JRubyMethod
    public IRubyObject issuer() {
        return this.issuer == null ? this.issuer = X509Name.newName(getRuntime()) : this.issuer;
    }

    @JRubyMethod(name="issuer=")
    public IRubyObject set_issuer(final IRubyObject issuer) {
        if ( ! issuer.equals(this.issuer) ) this.changed = true;
        generator.setIssuerDN(((X509Name) issuer).getRealName());
        return this.issuer = issuer;
    }

    DateTime getLastUpdate() {
        if ( last_update == null ) return null;
        return last_update.getDateTime();
    }

    @JRubyMethod
    public IRubyObject last_update() {
        return last_update == null ? getRuntime().getNil() : last_update;
    }

    @JRubyMethod(name="last_update=")
    public IRubyObject set_last_update(final ThreadContext context, IRubyObject val) {
        this.changed = true;
        final RubyTime value = (RubyTime) val.callMethod(context, "getutc");
        value.setMicroseconds(0);
        generator.setThisUpdate( value.getJavaDate() );
        return this.last_update = value;
    }

    DateTime getNextUpdate() {
        if ( next_update == null ) return null;
        return next_update.getDateTime();
    }

    @JRubyMethod
    public IRubyObject next_update() {
        return next_update == null ? getRuntime().getNil() : next_update;
    }

    @JRubyMethod(name="next_update=")
    public IRubyObject set_next_update(final ThreadContext context, IRubyObject val) {
        this.changed = true;
        final RubyTime value = (RubyTime) val.callMethod(context, "getutc");
        value.setMicroseconds(0);
        generator.setNextUpdate( value.getJavaDate() );
        return this.next_update = value;
    }

    @JRubyMethod
    public RubyArray revoked() {
        return revoked == null ? revoked = getRuntime().newArray(4) : revoked;
    }

    @JRubyMethod(name="revoked=")
    public IRubyObject set_revoked(final IRubyObject revoked) {
        this.changed = true;
        return this.revoked = (RubyArray) revoked;
    }

    @JRubyMethod
    public IRubyObject add_revoked(final ThreadContext context, IRubyObject val) {
        this.changed = true;
        revoked().callMethod(context, "<<", val); return val;
    }

    @JRubyMethod
    public RubyArray extensions() {
        return this.extensions;
    }

    @SuppressWarnings("unchecked")
    @JRubyMethod(name="extensions=")
    public IRubyObject set_extensions(final IRubyObject extensions) {
        return this.extensions = (RubyArray) extensions;
    }

    @JRubyMethod
    public IRubyObject add_extension(final IRubyObject extension) {
        extensions().append(extension); return extension;
    }

    @JRubyMethod
    public IRubyObject sign(final ThreadContext context, final IRubyObject key, IRubyObject digest) {
        final Ruby runtime = context.runtime;
        // Have to obey some artificial constraints of the OpenSSL implementation. Stupid.
        final String keyAlg = ((PKey) key).getAlgorithm();
        final String digAlg = ((Digest) digest).getShortAlgorithm();

        if ( ( "DSA".equalsIgnoreCase(keyAlg) && "MD5".equalsIgnoreCase(digAlg) ) ||
             ( "RSA".equalsIgnoreCase(keyAlg) && "DSS1".equals(((Digest)digest).name().toString()) ) ||
             ( "DSA".equalsIgnoreCase(keyAlg) && "SHA1".equals(((Digest)digest).name().toString()) ) ) {
            throw newCRLError(runtime, "unsupported key / digest algorithm ("+ key +" / "+ digAlg +")");
        }

        signature_algorithm = runtime.newString(digAlg);
        generator.setSignatureAlgorithm(digAlg + "WITH" + keyAlg);

        if ( revoked != null ) {
            for ( int i = 0; i < revoked.size(); i++ ) {
                final X509Revoked rev = (X509Revoked) revoked.entry(i);
                BigInteger serial = new BigInteger( rev.callMethod(context, "serial").toString() );
                RubyTime t1 = (RubyTime) rev.callMethod(context, "time").callMethod(context, "getutc");
                t1.setMicroseconds(0);

                final org.bouncycastle.asn1.x509.X509Extensions revExts;
                if ( rev.hasExtensions() ) {
                    final RubyArray exts = rev.extensions();
                    final Vector<ASN1Sequence> vec = new Vector<ASN1Sequence>(exts.size());
                    for ( int j = 0; j < exts.size(); j++ ) {
                        final Extension ext = (Extension) exts.entry(j);
                        try {
                            vec.add( ext.toASN1Sequence() );
                        }
                        catch (IOException e) { throw newCRLError(runtime, e); }
                    }
                    revExts = new org.bouncycastle.asn1.x509.X509Extensions(vec, new Hashtable());
                }
                else {
                    revExts = new org.bouncycastle.asn1.x509.X509Extensions(new Hashtable());
                }

                generator.addCRLEntry( serial, t1.getJavaDate(), revExts );
            }
        }

        try {
            for ( int i = 0; i < extensions.size(); i++ ) {
                Extension ext = (Extension) extensions.entry(i);
                generator.addExtension(ext.getRealOid(), ext.isRealCritical(), ext.getRealValueBytes());
            }
        }
        catch (IOException e) { throw newCRLError(runtime, e); }

        final PrivateKey privateKey = ((PKey) key).getPrivateKey();
        try {
            crl = generator.generate(privateKey);
        }
        catch (IllegalStateException e) {
            debugStackTrace(e); throw newCRLError(runtime, e);
        }
        catch (GeneralSecurityException e) {
            debugStackTrace(e); throw newCRLError(runtime, e.getMessage());
        }

        try {
            crlValue = new ASN1InputStream(new ByteArrayInputStream(crl.getEncoded())).readObject();
        }
        catch (CRLException e) { throw newCRLError(runtime, e); }
        catch (IOException e) { throw newCRLError(runtime, e); }

        ASN1Sequence v1 = (ASN1Sequence) ( ((ASN1Sequence) crlValue).getObjectAt(0) );
        final ASN1EncodableVector build1 = new ASN1EncodableVector();
        int copyIndex = 0;
        if ( v1.getObjectAt(0) instanceof ASN1Integer ) copyIndex++;
        build1.add( new ASN1Integer( new BigInteger(version.toString()) ) );
        while ( copyIndex < v1.size() ) {
            build1.add( v1.getObjectAt(copyIndex++) );
        }
        final ASN1EncodableVector build2 = new ASN1EncodableVector();
        build2.add( new DLSequence(build1) );
        build2.add( ((ASN1Sequence) crlValue).getObjectAt(1) );
        build2.add( ((ASN1Sequence) crlValue).getObjectAt(2) );
        crlValue = new DLSequence(build2);
        changed = false;
        return this;
    }

    @JRubyMethod
    public IRubyObject verify(final ThreadContext context, final IRubyObject key) {
        if ( changed ) return context.runtime.getFalse();
        final PublicKey publicKey = ((PKey) key).getPublicKey();
        try {
            boolean valid = SecurityHelper.verify(crl, publicKey, true);
            return context.runtime.newBoolean(valid);
        }
        catch (CRLException e) {
            return context.runtime.getFalse();
        }
        catch (InvalidKeyException e) {
            return context.runtime.getFalse();
        }
        catch (SignatureException e) {
            return context.runtime.getFalse();
        }
        catch (NoSuchAlgorithmException e) {
            return context.runtime.getFalse();
        }
    }

    private static RubyClass _CRLError(final Ruby runtime) {
        return _X509(runtime).getClass("CRLError");
    }

    static RaiseException newCRLError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _CRLError(runtime), e);
    }

    private static RaiseException newCRLError(Ruby runtime, String message) {
        return Utils.newError(runtime, _CRLError(runtime), message);
    }

}// X509CRL
