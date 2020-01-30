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
import java.util.List;
import java.util.Set;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyInteger;
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

import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.X509Extension.newExtension;
import static org.jruby.ext.openssl.StringHelper.appendGMTDateTime;
import static org.jruby.ext.openssl.StringHelper.appendLowerHexValue;

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

    static void createX509CRL(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass CRL = X509.defineClassUnder("CRL", runtime.getObject(), X509CRL_ALLOCATOR);
        X509.defineClassUnder("CRLError", OpenSSLError, OpenSSLError.getAllocator());
        CRL.defineAnnotatedMethods(X509CRL.class);
    }

    private RubyInteger version;
    private IRubyObject issuer;
    private RubyTime last_update;
    private RubyTime next_update;
    private RubyArray revoked;
    private RubyArray extensions;

    private IRubyObject signature_algorithm;

    private boolean changed = true;

    private java.security.cert.X509CRL crl = null;
    private transient X509CRLHolder crlHolder;
    private transient ASN1Primitive crlValue;

    static RubyClass _CRL(final Ruby runtime) {
        return _X509(runtime).getClass("CRL");
    }

    public X509CRL(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    java.security.cert.X509CRL getCRL() {
        return getCRL(false);
    }

    private java.security.cert.X509CRL getCRL(boolean allowNull) {
        if ( crl != null ) return crl;
        try {
            if ( crlHolder == null ) {
                if ( allowNull ) return null;
                throw new IllegalStateException("no crl holder");
            }
            final byte[] encoded = crlHolder.getEncoded();
            return crl = generateCRL(encoded, 0, encoded.length);
        }
        catch (IOException ex) {
            throw newCRLError(getRuntime(), ex);
        }
        catch (GeneralSecurityException ex) {
            throw newCRLError(getRuntime(), ex);
        }
    }

    private X509CRLHolder getCRLHolder(boolean allowNull) {
        if ( crlHolder != null ) return crlHolder;
        try {
            if ( crl == null ) {
                if ( allowNull ) return null;
                throw new IllegalStateException("no crl");
            }
            return crlHolder = new X509CRLHolder(crl.getEncoded());
        }
        catch (IOException ex) {
            throw newCRLError(getRuntime(), ex);
        }
        catch (CRLException ex) {
            throw newCRLError(getRuntime(), ex);
        }
    }

    final byte[] getEncoded() throws IOException, CRLException {
        if ( crlHolder != null ) return crlHolder.getEncoded();
        java.security.cert.X509CRL crl = getCRL(true);
        return crl == null ? new byte[0] : crl.getEncoded(); // TODO CRL.new isn't like MRI
    }

    private byte[] getSignature() {
        return getCRL().getSignature();
    }

    private static final boolean avoidJavaSecurity = false; // true NOT SUPPORTED

    private static java.security.cert.X509CRL generateCRL(final byte[] bytes, final int offset, final int length)
        throws GeneralSecurityException {
        CertificateFactory factory = SecurityHelper.getCertificateFactory("X.509");
        return (java.security.cert.X509CRL) factory.generateCRL(new ByteArrayInputStream(bytes, offset, length));
    }

    private static X509CRLHolder parseCRLHolder(final byte[] bytes, final int offset, final int length)
        throws IOException {
        return new X509CRLHolder(new ByteArrayInputStream(bytes, offset, length));
    }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args, final Block block) {
        final Ruby runtime = context.runtime;

        this.extensions = runtime.newArray(8);

        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;

        final ByteList strList = args[0].asString().getByteList();
        final byte[] bytes = strList.unsafeBytes();
        final int offset = strList.getBegin(); final int length = strList.getRealSize();
        try {
            if ( avoidJavaSecurity ) {
                this.crlHolder = parseCRLHolder(bytes, offset, length);
            }
            else {
                this.crl = generateCRL(bytes, offset, length);
            }
        }
        catch (IOException e) {
            debugStackTrace(runtime, e);
            throw newCRLError(runtime, e);
        }
        catch (GeneralSecurityException e) {
            debugStackTrace(runtime, e);
            throw newCRLError(runtime, e);
        }

        if (this.crl == null) {
            throw newCRLError(runtime, ""); // MRI: "header too long" for OpenSSL::X509::CRL.new('')
        }

        set_last_update( context, RubyTime.newTime(runtime, crl.getThisUpdate().getTime()) );
        set_next_update( context, RubyTime.newTime(runtime, crl.getNextUpdate().getTime()) );
        set_issuer( X509Name.newName(runtime, crl.getIssuerX500Principal()) );

        final int version = crl.getVersion();
        this.version = runtime.newFixnum( version > 0 ? version - 1 : 2 );

        extractExtensions(context);

        Set<? extends X509CRLEntry> revokedCRLs = crl.getRevokedCertificates();
        if ( revokedCRLs != null && ! revokedCRLs.isEmpty() ) {
            final X509CRLEntry[] revokedSorted =
                    revokedCRLs.toArray(new X509CRLEntry[ revokedCRLs.size() ]);
            Arrays.sort(revokedSorted, 0, revokedSorted.length, new Comparator<X509CRLEntry>() {
                public int compare(X509CRLEntry o1, X509CRLEntry o2) {
                    return o1.getRevocationDate().compareTo( o2.getRevocationDate() );
                }
            });
            for ( X509CRLEntry entry : revokedSorted ) {
                revoked().append( X509Revoked.newInstance(context, entry) );
            }
        }

        this.changed = false;
        return this;
    }

    private void extractExtensions(final ThreadContext context) {
        if ( crlHolder != null ) extractExtensions(context, crlHolder);
        else extractExtensionsCRL(context, getCRL());
    }

    @SuppressWarnings("unchecked")
    private void extractExtensions(final ThreadContext context, final X509CRLHolder crl) {
        if ( ! crlHolder.hasExtensions() ) return;
        for ( ASN1ObjectIdentifier oid : (Collection<ASN1ObjectIdentifier>) crl.getExtensionOIDs() ) {
            addExtension(context, oid, crl);
        }
    }

    private void addExtension(final ThreadContext context,
        final ASN1ObjectIdentifier extOID, final X509CRLHolder crl) {
        final Extension ext = crl.getExtension(extOID);
        final IRubyObject extension = newExtension(context.runtime, extOID, ext);
        this.extensions.append(extension);
    }

    private void extractExtensionsCRL(final ThreadContext context,
        final java.security.cert.X509Extension crl) {
        //final RubyClass _Extension = _Extension(context.runtime);

        final Set<String> criticalExtOIDs = crl.getCriticalExtensionOIDs();
        if ( criticalExtOIDs != null ) {
            for ( final String extOID : criticalExtOIDs ) {
                addExtensionCRL(context, extOID, crl, true);
            }
        }

        final Set<String> nonCriticalExtOIDs = crl.getNonCriticalExtensionOIDs();
        if ( nonCriticalExtOIDs != null ) {
            for ( final String extOID : nonCriticalExtOIDs ) {
                addExtensionCRL(context, extOID, crl, false);
            }
        }
    }

    private void addExtensionCRL(final ThreadContext context,
        final String extOID, final java.security.cert.X509Extension crl,
        final boolean critical) {
        try {
            final IRubyObject extension = newExtension(context, extOID, crl, critical);
            if ( extension != null ) this.extensions.append(extension);
        }
        catch (IOException e) { throw newCRLError(context.runtime, e); }
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject obj) {
        if ( this == obj ) return this;
        return super.initialize_copy(obj);
    }

    @JRubyMethod(name = {"to_pem", "to_s"})
    public IRubyObject to_pem(final ThreadContext context) {
        StringWriter writer = new StringWriter();
        try {
            PEMInputOutput.writeX509CRL(writer, crl);
            return RubyString.newString(context.runtime, writer.getBuffer());
        }
        catch (IOException e) {
            throw newCRLError(context.runtime, e);
        }
    }

    @JRubyMethod
    public IRubyObject to_der(final ThreadContext context) {
        try {
            return StringHelper.newString(context.runtime, getEncoded());
        }
        catch (IOException|CRLException e) {
            throw newCRLError(context.runtime, e);
        }
    }

    @JRubyMethod
    @SuppressWarnings("unchecked")
    public IRubyObject to_text(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final char[] S16 = StringHelper.S20;
        final StringBuilder text = new StringBuilder(160);

        text.append("Certificate Revocation List (CRL):\n");
        final int version = RubyNumeric.fix2int(this.version);
        text.append(S16,0,8).append("Version ").append( version + 1 ).
             append(" (0x").append( Integer.toString( version, 16 ) ).append(")\n");
        text.append(S16,0,4).append("Signature Algorithm: ").append( signature_algorithm() ).append('\n');
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
            text.append(S16,0,8).append("CRL extensions:\n");
            extensions_to_text(context, extensions, text, 12);
        }

        if ( revoked != null && revoked.size() > 0 ) {
            text.append("\nRevoked Certificates:\n");
            for ( int i = 0; i < revoked.size(); i++ ) {
                final X509Revoked rev = (X509Revoked) revoked.entry(i);
                final String serial = rev.serial.toString(16);
                text.append(S16,0,4).append("Serial Number: ");
                if ( serial.length() % 2 == 0 ) text.append(serial).append('\n');
                else text.append('0').append(serial).append('\n');
                text.append(S16,0,8).append("Revocation Date: ");
                appendGMTDateTime( text, rev.getTime() ).append('\n');
                if ( rev.hasExtensions() ) {
                    text.append(S16,0,8).append("CRL entry extensions:\n");
                    extensions_to_text(context, extensions, text, 12);
                }
            }
        }
        else {
            text.append("No Revoked Certificates.\n");
        }

        // TODO we shall parse / use crlValue when != null :
        text.append(S16,0,4).append("Signature Algorithm: ").append( signature_algorithm() ).append('\n');

        appendLowerHexValue(text, getSignature(), 9, 54);

        return RubyString.newString( runtime, text );
    }

    static void extensions_to_text(final ThreadContext context,
        final List<X509Extension> exts, final StringBuilder text, final int indent) {
        final char[] S20 = StringHelper.S20;
        for ( int i = 0; i < exts.size(); i++ ) {
            final X509Extension ext = exts.get(i);
            final ASN1ObjectIdentifier oid = ext.getRealObjectID();
            String no = ASN1.o2a(context.runtime, oid, true);
            if (no == null) { // MRI here just appends the OID string
                no = ASN1.oid2Sym(context.runtime, oid, true);
                if (no == null) no = oid.toString();
            }
            text.append(S20,0,indent).append( no ).append(": ");
            if ( ext.isRealCritical() ) text.append("critical");
            text.append('\n');
            final String value = ext.value(context).toString();
            for ( String val : value.split("\n") ) {
                text.append(S20,0,16).append( val ).append('\n');
            }
        }
    }

    @Override
    @JRubyMethod
    @SuppressWarnings("unchecked")
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this, (List) getInstanceVariableList());
    }

    @Override // FAKE'em to include "instance" variables in inspect
    public List<Variable<IRubyObject>> getInstanceVariableList() {
        final ArrayList<Variable<IRubyObject>> list = new ArrayList<Variable<IRubyObject>>(6);
        return list;
    }

    @JRubyMethod
    public IRubyObject version() {
        return version == null ? version = getRuntime().newFixnum(0) : version;
    }

    @JRubyMethod(name="version=")
    public IRubyObject set_version(IRubyObject version) {
        if ( ! version.equals(this.version) ) this.changed = true;
        return this.version = version.convertToInteger("to_i");
    }

    @JRubyMethod
    public IRubyObject signature_algorithm() {
        return signature_algorithm == null ?
            signature_algorithm = signature_algorithm(getRuntime()) :
                signature_algorithm;
    }

    private RubyString signature_algorithm(final Ruby runtime) {
        return RubyString.newString(runtime, getSignatureAlgorithm(runtime, "NULL"));
    }

    private String getSignatureAlgorithm(final Ruby runtime, final String def) {
        final X509CRLHolder crlHolder = getCRLHolder(true);
        if ( crlHolder == null ) return def;

        ASN1ObjectIdentifier algId =
            crlHolder.toASN1Structure().getSignatureAlgorithm().getAlgorithm();
        //ASN1ObjectIdentifier algId = ASN1.toObjectID( getCRL().getSigAlgOID(), true );
        String algName;
        if ( algId != null ) {
            algName = ASN1.o2a(runtime, algId, true);
        }
        else algName = null;
        //else {
        //    algName = getCRL().getSigAlgName();
        //    algId = ASN1.toObjectID( algName, true );
        //    if ( algId != null ) {
        //        algName = ASN1.o2a(runtime, algId, true);
        //    }
        //}
        return algName == null ? def : algName;
    }

    @JRubyMethod
    public IRubyObject issuer() {
        return this.issuer == null ? this.issuer = X509Name.newName(getRuntime()) : this.issuer;
    }

    @JRubyMethod(name="issuer=")
    public IRubyObject set_issuer(final IRubyObject issuer) {
        if ( ! issuer.equals(this.issuer) ) this.changed = true;
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
        final String signatureAlgorithm = getSignatureAlgorithm(runtime, (PKey) key, (Digest) digest);

        final X500Name issuerName = ((X509Name) issuer).getX500Name();
        final java.util.Date thisUpdate = getLastUpdate().toDate();
        final X509v2CRLBuilder generator = new X509v2CRLBuilder(issuerName, thisUpdate);
        final java.util.Date nextUpdate = getNextUpdate().toDate();
        generator.setNextUpdate(nextUpdate);

        //signature_algorithm = RubyString.newString(runtime, digAlg);
        //generator.setSignatureAlgorithm( signatureAlgorithm );

        if ( revoked != null ) {
            for ( int i = 0; i < revoked.size(); i++ ) {
                final X509Revoked rev = (X509Revoked) revoked.entry(i);
                BigInteger serial = new BigInteger( rev.callMethod(context, "serial").toString() );
                RubyTime t1 = (RubyTime) rev.callMethod(context, "time").callMethod(context, "getutc");
                t1.setMicroseconds(0);

                final Extensions revExts;
                if ( rev.hasExtensions() ) {
                    final RubyArray exts = rev.extensions();
                    final ASN1Encodable[] array = new ASN1Encodable[ exts.size() ];
                    for ( int j = 0; j < exts.size(); j++ ) {
                        final X509Extension ext = (X509Extension) exts.entry(j);
                        try { array[j] = ext.toASN1Sequence(); }
                        catch (IOException e) { throw newCRLError(runtime, e); }
                    }
                    revExts = Extensions.getInstance( new DERSequence(array) );
                }
                else {
                    revExts = null;
                }

                generator.addCRLEntry( serial, t1.getJavaDate(), revExts );
            }
        }

        try {
            for ( int i = 0; i < extensions.size(); i++ ) {
                X509Extension ext = (X509Extension) extensions.entry(i);
                ASN1Encodable value = ext.getRealValue();
                generator.addExtension(ext.getRealObjectID(), ext.isRealCritical(), value);
            }
        }
        catch (IOException e) { throw newCRLError(runtime, e); }

        final PrivateKey privateKey = ((PKey) key).getPrivateKey();
        try {
            if ( avoidJavaSecurity ) {
                // NOT IMPLEMENTED
            }
            else {
                //crl = generator.generate(((PKey) key).getPrivateKey());
            }
            /*
            AlgorithmIdentifier keyAldID = new AlgorithmIdentifier(new ASN1ObjectIdentifier(keyAlg));
            AlgorithmIdentifier digAldID = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digAlg));
            final BcContentSignerBuilder signerBuilder;
            final AsymmetricKeyParameter signerPrivateKey;
            if ( isDSA ) {
                signerBuilder = new BcDSAContentSignerBuilder(keyAldID, digAldID);
                DSAPrivateKey privateKey = (DSAPrivateKey) ((PKey) key).getPrivateKey();
                DSAParameters params = new DSAParameters(
                        privateKey.getParams().getP(),
                        privateKey.getParams().getQ(),
                        privateKey.getParams().getG()
                );
                signerPrivateKey = new DSAPrivateKeyParameters(privateKey.getX(), params);
            }
            */

            ContentSigner signer = new JcaContentSignerBuilder( signatureAlgorithm ).build(privateKey);
            this.crlHolder = generator.build( signer ); this.crl = null;
        }
        catch (IllegalStateException e) {
            debugStackTrace(e); throw newCRLError(runtime, e);
        }
        catch (Exception e) {
            debugStackTrace(e); throw newCRLError(runtime, e.getMessage());
        }

        final ASN1Primitive crlVal = getCRLValue(runtime);

        ASN1Sequence v1 = (ASN1Sequence) ( ((ASN1Sequence) crlVal).getObjectAt(0) );
        final ASN1EncodableVector build1 = new ASN1EncodableVector();
        int copyIndex = 0;
        if ( v1.getObjectAt(0) instanceof ASN1Integer ) copyIndex++;
        build1.add( new ASN1Integer( new BigInteger(version.toString()) ) );
        while ( copyIndex < v1.size() ) {
            build1.add( v1.getObjectAt(copyIndex++) );
        }
        final ASN1EncodableVector build2 = new ASN1EncodableVector();
        build2.add( new DLSequence(build1) );
        build2.add( ((ASN1Sequence) crlVal).getObjectAt(1) );
        build2.add( ((ASN1Sequence) crlVal).getObjectAt(2) );

        this.crlValue = new DLSequence(build2);
        changed = false;
        return this;
    }

    private String getSignatureAlgorithm(final Ruby runtime, final PKey key, final Digest digest) {
        // Have to obey some artificial constraints of the OpenSSL implementation. Stupid.
        final String keyAlg = key.getAlgorithm();
        final String digAlg = digest.getShortAlgorithm();

        if ( "DSA".equalsIgnoreCase(keyAlg) ) {
            if ( ( "MD5".equalsIgnoreCase( digAlg ) ) ) { // ||
                // ( "SHA1".equals( digest.name().toString() ) ) ) {
                throw newCRLError(runtime, "unsupported key / digest algorithm ("+ key +" / "+ digAlg +")");
            }
        }
        else if ( "RSA".equalsIgnoreCase(keyAlg) ) {
            if ( "DSS1".equals( digest.name().toString() ) ) {
                throw newCRLError(runtime, "unsupported key / digest algorithm ("+ key +" / "+ digAlg +")");
            }
        }

        return digAlg + "WITH" + keyAlg;
    }

    private ASN1Primitive getCRLValue(final Ruby runtime) {
        if ( this.crlValue != null ) return this.crlValue;
        return this.crlValue = readCRL( runtime );
    }

    private ASN1Primitive readCRL(final Ruby runtime) {
        try {
            return ASN1.readObject( getEncoded() );
        }
        catch (CRLException e) { throw newCRLError(runtime, e); }
        catch (IOException e) { throw newCRLError(runtime, e); }
    }

    @JRubyMethod
    public IRubyObject verify(final ThreadContext context, final IRubyObject key) {
        if ( changed ) return context.runtime.getFalse();
        final PublicKey publicKey = ((PKey) key).getPublicKey();
        try {
            boolean valid = SecurityHelper.verify(getCRL(), publicKey, true);
            return context.runtime.newBoolean(valid);
        }
        catch (GeneralSecurityException e) {
            debug("CRL#verify() failed:", e);
            return context.runtime.getFalse();
        }
    }

    @Override
    @JRubyMethod(name = "==")
    public IRubyObject op_equal(ThreadContext context, IRubyObject obj) {
        if (this == obj) return context.runtime.getTrue();
        if (obj instanceof X509CRL) {
            boolean equal;
            try {
                equal = Arrays.equals(getEncoded(), ((X509CRL) obj).getEncoded());
            }
            catch (IOException|CRLException e) {
                throw newCRLError(context.runtime, e);
            }
            return context.runtime.newBoolean(equal);
        }
        return context.runtime.getFalse();
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
