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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import org.joda.time.DateTime;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.builtin.Variable;
import org.jruby.runtime.component.VariableEntry;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.X509Extension.newExtension;
import static org.jruby.ext.openssl.X509CRL.extensions_to_text;
import static org.jruby.ext.openssl.StringHelper.appendGMTDateTime;
import static org.jruby.ext.openssl.StringHelper.appendLowerHexValue;
import static org.jruby.ext.openssl.StringHelper.lowerHexBytes;
import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Cert extends RubyObject {
    private static final long serialVersionUID = -6524431607032364369L;

    private static ObjectAllocator X509CERT_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509Cert(runtime, klass);
        }
    };

    static void createX509Cert(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass Certificate = X509.defineClassUnder("Certificate", runtime.getObject(), X509CERT_ALLOCATOR);
        X509.defineClassUnder("CertificateError", OpenSSLError, OpenSSLError.getAllocator());
        Certificate.defineAnnotatedMethods(X509Cert.class);
    }

    public X509Cert(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    private X509Cert(Ruby runtime) {
        super(runtime, _Certificate(runtime));
    }

    private IRubyObject subject;
    private IRubyObject issuer;
    private BigInteger serial = BigInteger.ZERO;
    private RubyTime not_before;
    private RubyTime not_after;

    private IRubyObject sig_alg;
    private IRubyObject version;

    private X509Certificate cert;

    private transient PKey public_key; // lazy initialized

    private final List<X509Extension> extensions = new ArrayList<X509Extension>();

    private boolean changed = true;

    final X509AuxCertificate getAuxCert() {
        if ( cert == null ) return null;
        if ( cert instanceof X509AuxCertificate ) {
            return (X509AuxCertificate) cert;
        }
        return new X509AuxCertificate(cert);
    }

    public static IRubyObject wrap(Ruby runtime, Certificate cert)
        throws CertificateEncodingException {
        return wrap(runtime.getCurrentContext(), cert.getEncoded());
    }

    static X509Cert wrap(ThreadContext context, Certificate cert)
        throws CertificateEncodingException {
        return wrap(context, cert.getEncoded());
    }

    // this is the javax.security counterpart of the previous wrap method
    public static IRubyObject wrap(Ruby runtime, javax.security.cert.Certificate cert)
        throws javax.security.cert.CertificateEncodingException {
        return wrap(runtime.getCurrentContext(), cert.getEncoded());
    }

    static X509Cert wrap(ThreadContext context, javax.security.cert.Certificate cert)
        throws javax.security.cert.CertificateEncodingException {
        return wrap(context, cert.getEncoded());
    }

    static X509Cert wrap(final ThreadContext context, final byte[] encoded) {
        //final Ruby runtime = context.runtime;
        //final RubyString enc = StringHelper.newString(runtime, encoded);
        //return _Certificate(runtime).callMethod(context, "new", enc);
        final X509Cert cert = new X509Cert(context.runtime);
        cert.initialize(context, encoded);
        return cert;
    }

    @JRubyMethod(name="initialize", optional = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context,
        final IRubyObject[] args, final Block unusedBlock) {

        if ( args.length == 0 ) {
            this.subject = X509Name.newName(context.runtime);
            this.issuer = X509Name.newName(context.runtime);
            return this;
        }

        final RubyString str = StringHelper.readPossibleDERInput(context, args[0]);
        final ByteList bytes = str.getByteList();
        initialize(context, bytes.unsafeBytes(), bytes.getBegin(), bytes.getRealSize());

        return this;
    }

    private void initialize(final ThreadContext context, final byte[] encoded) {
        initialize(context, encoded, 0, encoded.length);
    }

    private void initialize(final ThreadContext context, final byte[] encoded, final int offset, final int length) {
        final Ruby runtime = context.runtime;

        byte[] bytes = StringHelper.readX509PEM(encoded, offset, length);

        try {
            final ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            cert = (X509Certificate) SecurityHelper.getCertificateFactory("X.509").generateCertificate(bis);
        }
        catch (CertificateException e) {
            throw newCertificateError(runtime, e);
        }

        if ( cert == null ) {
            throw newCertificateError(runtime, (String) null);
        }

        set_serial( RubyNumeric.str2inum(runtime, runtime.newString(cert.getSerialNumber().toString()), 10) );
        set_not_before( context, RubyTime.newTime( runtime, cert.getNotBefore().getTime() ) );
        set_not_after( context, RubyTime.newTime( runtime, cert.getNotAfter().getTime() ) );
        this.subject = X509Name.newName(runtime, cert.getSubjectX500Principal());
        this.issuer = X509Name.newName(runtime, cert.getIssuerX500Principal());
        this.version = RubyFixnum.newFixnum(runtime, cert.getVersion() - 1);
        String sigAlgorithm = cert.getSigAlgOID();

        if ( sigAlgorithm == null ) sigAlgorithm = cert.getSigAlgName(); // e.g. SHA256withRSA
        else {
            sigAlgorithm = ASN1.oid2name(runtime, new ASN1ObjectIdentifier(sigAlgorithm), true);
            if (sigAlgorithm == null) {
                sigAlgorithm = "0.0"; // "NULL";
                // for some certificates that MRI parses,
                // we get getSigAlgOID() == getSigAlgName() == "0.0"

                if ( cert.getSigAlgName() != null && ! cert.getSigAlgOID().equals(cert.getSigAlgName()) ) {
                    sigAlgorithm = cert.getSigAlgName(); // not sure if it makes any sense
                }
            }

        } // "hot" path e.g. sha256WithRSAEncryption
        this.sig_alg = RubyString.newString(runtime, sigAlgorithm);

        final Set<String> criticalExtOIDs = cert.getCriticalExtensionOIDs();
        if ( criticalExtOIDs != null ) {
            for ( final String extOID : criticalExtOIDs ) {
                addExtension(context, extOID, true);
            }
        }

        final Set<String> nonCriticalExtOIDs = cert.getNonCriticalExtensionOIDs();
        if ( nonCriticalExtOIDs != null ) {
            for ( final String extOID : nonCriticalExtOIDs ) {
                addExtension(context, extOID, false);
            }
        }
        changed = false;
    }

    private void addExtension(final ThreadContext context,
        final String extOID, final boolean critical) {
        try {
            final byte[] extValue = cert.getExtensionValue(extOID);
            if ( extValue == null ) return;
            final X509Extension[] extension = newExtension(context, extOID, extValue, critical);
            for ( int i = 0; i < extension.length; i++ ) this.extensions.add( extension[i] );
        }
        catch (IOException e) { throw newCertificateError(context.runtime, e); }
    }

    private static RubyClass _CertificateError(final Ruby runtime) {
        return _X509(runtime).getClass("CertificateError");
    }

    static RubyClass _Certificate(final Ruby runtime) {
        return _X509(runtime).getClass("Certificate");
    }

    public static RaiseException newCertificateError(final Ruby runtime, Exception e) {
        return Utils.newError(runtime, _CertificateError(runtime), e);
    }

    static RaiseException newCertificateError(final Ruby runtime, String msg) {
        return Utils.newError(runtime, _CertificateError(runtime), msg);
    }

    static RaiseException newCertificateError(final Ruby runtime, String msg, Exception e) {
        return Utils.newError(runtime, _CertificateError(runtime), msg, e);
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();
        return this;
    }

    @JRubyMethod
    public IRubyObject to_der() {
        try {
            return StringHelper.newString(getRuntime(), cert.getEncoded());
        }
        catch (CertificateEncodingException ex) {
            throw newCertificateError(getRuntime(), ex);
        }
    }

    @JRubyMethod(name = {"to_pem", "to_s"})
    public IRubyObject to_pem() {
        final StringWriter str = new StringWriter();
        try {
            PEMInputOutput.writeX509Certificate(str, getAuxCert());
            return getRuntime().newString( str.toString() );
        }
        catch (IOException ex) {
            throw getRuntime().newIOErrorFromException(ex);
        }
    }

    @JRubyMethod
    public IRubyObject to_text(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final char[] S20 = StringHelper.S20;
        final StringBuilder text = new StringBuilder(240);

        text.append("Certificate:\n");
        text.append(S20,0,4).append("Data:\n");
        final int version = this.version == null ? 0 : RubyNumeric.fix2int(this.version);
        text.append(S20,0,8).append("Version: ").append( version + 1 ).
             append(" (0x").append( Integer.toString( version, 16 ) ).append(")\n");
        // <= 0x1122334455667788 printed on same line as :
        // Serial Number: 1234605616436508552 (0x1122334455667788)
        // but 0x112233445566778899 ends up :
        // Serial Number:
        //      11:22:33:44:55:66:77:88:99
        text.append(S20,0,8).append("Serial Number:");
        if ( serial.compareTo( new BigInteger("FFFFFFFFFFFFFFFF", 16) ) > 0 ) {
            text.append('\n');
            text.append(S20,0,12).append( lowerHexBytes(serial.toByteArray(), 1) ).append('\n');
        }
        else {
            text.append(' ').append(serial.toString(10)).append(' ');
            text.append('(').append("0x").append(serial.toString(16)).append(')').append('\n');
        }

        text.append(S20,0,4).append("Signature Algorithm: ").append( signature_algorithm() ).append('\n');
        //final RubyString issuer = issuer().asString(); ByteList bytes = issuer.getByteList();
        //StringHelper.gsub(runtime, bytes, (byte) '/', (byte) ' ');
        //if ( bytes.charAt(0) == ' ' ) bytes.setBegin(bytes.getBegin() + 1);
        text.append(S20,0,8).append("Issuer: ").append( issuer ).append('\n');
        text.append(S20,0,8).append("Validity\n");
        text.append(S20,0,12).append("Not Before: ");
        appendGMTDateTime( text, getNotBefore() ).append('\n');
        text.append(S20,0,12).append("Not After : ");
        appendGMTDateTime( text, getNotAfter() ).append('\n');

        text.append(S20,0,8).append("Subject: ").append( subject() ).append('\n');
        text.append(S20,0,8).append("Subject Public Key Info:\n");

        final PublicKey publicKey = getPublicKey();
        text.append(S20,0,12).append("Public Key Algorithm: ").append(publicKey.getAlgorithm()).append('\n');

        if ( "RSA".equals( publicKey.getAlgorithm() ) ) {
            final RSAPublicKey rsaKey = ((RSAPublicKey) publicKey);
            text.append(S20,0,16).append("Public-Key: (").append( rsaKey.getModulus().bitLength() ).append(" bit)\n");

            text.append(S20,0,16).append("Modulus:\n");
            appendLowerHexValue(text, rsaKey.getModulus().toByteArray(), 20, 45);

            final BigInteger exponent = rsaKey.getPublicExponent();
            text.append(S20,0,16).append("Exponent: ").append(exponent).
                 append(" (0x").append( exponent.toString(16) ).append(")\n");
        }
        else if ( "DSA".equals( publicKey.getAlgorithm() ) ) {
            final DSAPublicKey dsaKey = ((DSAPublicKey) publicKey);
            text.append(S20,0,16).append("Public-Key: (").append( dsaKey.getY().bitLength() ).append(" bit)\n");

            text.append(S20,0,16).append("TODO: not-implemented (PR HOME-WORK)").append('\n'); // left-TODO
        }
        else {
            text.append(S20,0,16).append("TODO: not-implemented (PRs WELCOME!)").append('\n'); // left-TODO
        }

        if ( extensions != null && extensions.size() > 0 ) {
            text.append(S20,0,8).append("X509v3 extensions:\n");
            extensions_to_text(context, extensions, text, 12);
        }

        text.append(S20,0,4).append("Signature Algorithm: ").append( signature_algorithm() ).append('\n');

        appendLowerHexValue(text, getSignature(), 9, 54);

        return RubyString.newString( runtime, text );
    }

    @Override
    @JRubyMethod
    @SuppressWarnings("unchecked")
    public IRubyObject inspect() {
        final ArrayList<Variable<String>> varList = new ArrayList<Variable<String>>(5);
        varList.add(new VariableEntry<String>( "subject", subject().isNil() ? "nil" : subject().asString().toString() ));
        varList.add(new VariableEntry<String>( "issuer", issuer().isNil() ? "nil" : issuer().asString().toString() ));
        varList.add(new VariableEntry<String>( "serial", serial().isNil() ? "nil" : serial().asString().toString() ));
        varList.add(new VariableEntry<String>( "not_before", not_before().isNil() ? "nil" : not_before().toString() ));
        varList.add(new VariableEntry<String>( "not_after", not_after().isNil() ? "nil" : not_after().toString() ));

        return ObjectSupport.inspect(this, (List) varList);
    }

    @JRubyMethod
    public IRubyObject version() {
        return version != null ? version : ( version = getRuntime().newFixnum(0) );
    }

    @JRubyMethod(name = "version=")
    public IRubyObject set_version(final IRubyObject version) {
        if ( ! version().equals(version) ) {
            this.changed = true;
        }
        return this.version = version;
    }

    @JRubyMethod
    public IRubyObject signature_algorithm() {
        return sig_alg;
    }

    private byte[] getSignature() {
        return cert.getSignature();
    }

    BigInteger getSerial() { return serial; }

    @JRubyMethod
    public IRubyObject serial() {
        return BN.newBN(getRuntime(), serial);
    }

    @JRubyMethod(name = "serial=")
    public IRubyObject set_serial(final IRubyObject serial) {
        final String serialStr = serial.asString().toString();
        final BigInteger serialInt;
        if ( serialStr.equals("0") ) { // MRI compatibility: allow 0 serial number
            serialInt = BigInteger.ONE;
        } else {
            serialInt = new BigInteger(serialStr);
        }
        this.changed = ! serialInt.equals(this.serial);
        //generator.setSerialNumber( serialInt.abs() );
        this.serial = serialInt; return serial;
    }

    X509Name getSubject() { return ((X509Name) subject); }

    @JRubyMethod
    public IRubyObject subject() {
        return subject;
    }

    @JRubyMethod(name = "subject=")
    public IRubyObject set_subject(final IRubyObject subject) {
        if ( ! subject.equals(this.subject) ) this.changed = true;
        return this.subject = subject;
    }

    X509Name getIssuer() { return ((X509Name) issuer); }

    @JRubyMethod
    public IRubyObject issuer() {
        return issuer;
    }

    @JRubyMethod(name = "issuer=")
    public IRubyObject set_issuer(final IRubyObject issuer) {
        if ( ! issuer.equals(this.issuer) ) this.changed = true;
        return this.issuer = issuer;
    }

    @JRubyMethod
    public IRubyObject not_before() {
        return not_before == null ? getRuntime().getNil() : not_before;
    }

    @JRubyMethod(name = "not_before=")
    public IRubyObject set_not_before(final ThreadContext context, final IRubyObject time) {
        changed = true;
        not_before = (RubyTime) time.callMethod(context, "getutc");
        not_before.setMicroseconds(0);
        return time;
    }

    DateTime getNotBefore() {
        return not_before == null ? null : not_before.getDateTime();
    }

    @JRubyMethod
    public IRubyObject not_after() {
        return not_after == null ? getRuntime().getNil() : not_after;
    }

    @JRubyMethod(name = "not_after=")
    public IRubyObject set_not_after(final ThreadContext context, final IRubyObject time) {
        changed = true;
        not_after = (RubyTime) time.callMethod(context, "getutc");
        not_after.setMicroseconds(0);
        return time;
    }

    DateTime getNotAfter() {
        return not_after == null ? null : not_after.getDateTime();
    }

    @JRubyMethod
    public IRubyObject public_key(final ThreadContext context) {
        if ( public_key == null ) initializePublicKey();
        return public_key.callMethod(context, "public_key");
    }

    @JRubyMethod(name = "public_key=")
    public IRubyObject set_public_key(IRubyObject public_key) {
        if ( ! ( public_key instanceof PKey ) ) {
            throw getRuntime().newTypeError("OpenSSL::PKey::PKey expected but got " + public_key.getMetaClass().getName());
        }
        if ( ! public_key.equals(this.public_key) ) {
            this.changed = true;
        }
        return this.public_key = (PKey) public_key;
    }

    private PublicKey getPublicKey() {
        if ( public_key == null ) initializePublicKey();
        return public_key.getPublicKey();
    }

    private void initializePublicKey() throws RaiseException {
        final Ruby runtime = getRuntime();

        final boolean changed = this.changed;

        if ( cert == null ) {
            throw newCertificateError(runtime, "no certificate");
        }

        final PublicKey publicKey = cert.getPublicKey();

        final String algorithm = publicKey.getAlgorithm();

        if ( "RSA".equalsIgnoreCase(algorithm) ) {
            //if ( public_key == null ) {
            //    throw new IllegalStateException("no public key encoded data");
            //}
            set_public_key( PKeyRSA.newInstance(runtime, publicKey) );
        }
        else if ( "DSA".equalsIgnoreCase(algorithm) ) {
            //if ( public_key == null ) {
            //    throw new IllegalStateException("no public key encoded data");
            //}
            set_public_key( PKeyDSA.newInstance(runtime, publicKey) );
        }
        else {
            String message = "unsupported algorithm";
            if ( algorithm != null ) message += " '" + algorithm + "'";
            throw newCertificateError(runtime, message);
        }

        this.changed = changed;
    }

    @JRubyMethod
    public IRubyObject sign(final ThreadContext context, final IRubyObject key, final IRubyObject digest) {
        final Ruby runtime = context.runtime;

        if (!(key instanceof PKey)) { // MRI: NoMethodError: undefined method `private?' for nil:NilClass
            throw runtime.newTypeError(key, PKey._PKey(runtime).getClass("PKey"));
        }

        // Have to obey some artificial constraints of the OpenSSL implementation. Stupid.
        final String keyAlg = ((PKey) key).getAlgorithm();
        final String digAlg; final String digName;
        if (digest instanceof Digest) {
            digAlg = ((Digest) digest).getShortAlgorithm();
            digName = ((Digest) digest).getName();
        }
        else if (digest instanceof RubyString) {
            digAlg = digest.asJavaString(); digName = null;
        }
        else { // MRI: TypeError: wrong argument type nil (expected OpenSSL/Digest)
            throw runtime.newTypeError(digest, Digest._Digest(runtime));
        }

        if( ( "DSA".equalsIgnoreCase(keyAlg) && "MD5".equalsIgnoreCase(digAlg) ) ||
            ( "RSA".equalsIgnoreCase(keyAlg) && "DSS1".equals(digName) ) ) {
            throw newCertificateError(runtime, "signature_algorithm not supported");
        }

        org.bouncycastle.x509.X509V3CertificateGenerator builder = getCertificateBuilder();

        for ( X509Extension ext : uniqueExtensions() ) {
            try {
                final byte[] bytes = ext.getRealValueEncoded();
                builder.addExtension(ext.getRealObjectID().getId(), ext.isRealCritical(), bytes);
            }
            catch (IOException ioe) {
                throw runtime.newIOErrorFromException(ioe);
            }
        }

        builder.setSignatureAlgorithm(digAlg + "WITH" + keyAlg); // "SHA1WITHRSA"

        try {
            cert = builder.generate( ((PKey) key).getPrivateKey() );
        }
        catch (GeneralSecurityException e) {
            throw newCertificateError(runtime, e);
        }
        catch (IllegalStateException e) {
            // e.g. "not all mandatory fields set in V3 TBScertificate generator"
            throw newCertificateError(runtime, "could not generate certificate", e);
        }

        if (cert == null) throw newCertificateError(runtime, (String) null);

        String name = ASN1Registry.o2a(cert.getSigAlgOID());
        if ( name == null ) name = cert.getSigAlgOID();
        this.sig_alg = runtime.newString(name);
        this.changed = false;
        return this;
    }

    private org.bouncycastle.x509.X509V3CertificateGenerator getCertificateBuilder() {
        org.bouncycastle.x509.X509V3CertificateGenerator generator =
            new org.bouncycastle.x509.X509V3CertificateGenerator();
        if ( serial.equals(BigInteger.ZERO) ) { // NOTE: diversion from MRI (OpenSSL allows not setting serial)
            throw newCertificateError(getRuntime(), "Certificate#serial needs to be set (to > 0)");
        }
        generator.setSerialNumber( serial.abs() );

        if ( subject != null ) generator.setSubjectDN( ((X509Name) subject).getRealName() );
        if ( issuer != null ) generator.setIssuerDN( ((X509Name) issuer).getRealName() );

        generator.setNotBefore( not_before.getJavaDate() );
        generator.setNotAfter( not_after.getJavaDate() );
        generator.setPublicKey( getPublicKey() );

        return generator;
    }

    //private transient org.bouncycastle.x509.X509V3CertificateGenerator generator;

    @JRubyMethod
    public RubyBoolean verify(final IRubyObject key) {
        final Ruby runtime = getRuntime();

        if ( changed ) return runtime.getFalse();

        try {
            cert.verify(((PKey) key).getPublicKey());
            return runtime.getTrue();
        }
        catch (CertificateException e) {
            debug(runtime, "Certificate#verify failed: ", e);
            throw newCertificateError(runtime, e);
        }
        catch (NoSuchAlgorithmException e) {
            debugStackTrace(runtime, e);
            throw newCertificateError(runtime, e);
        }
        catch (NoSuchProviderException e) {
            debugStackTrace(runtime, e);
            throw newCertificateError(runtime, e);
        }
        catch (SignatureException e) {
            debug(runtime, "Certificate#verify failed: ", e);
            return runtime.getFalse();
        }
        catch (InvalidKeyException e) {
            debug(runtime, "Certificate#verify failed: ", e);
            return runtime.getFalse();
        }
    }

    @JRubyMethod
    public RubyBoolean check_private_key(final IRubyObject key) {
        final PublicKey certPublicKey = cert.getPublicKey();
        if ( certPublicKey.equals( ((PKey) key).getPublicKey() ) ) {
            return getRuntime().getTrue();
        }
        return getRuntime().getFalse();
    }

    @JRubyMethod
    public RubyArray extensions() {
        @SuppressWarnings("unchecked")
        final List<IRubyObject> extensions = (List) this.extensions;
        return getRuntime().newArray( extensions );
    }

    @SuppressWarnings("unchecked")
    @JRubyMethod(name = "extensions=")
    public IRubyObject set_extensions(final IRubyObject array) {
        extensions.clear(); // RubyArray is a List :
        extensions.addAll( (List<X509Extension>) array );
        return array;
    }

    @JRubyMethod
    public IRubyObject add_extension(final IRubyObject ext) {
        changed = true;
        extensions.add((X509Extension) ext);
        return ext;
    }

    private Collection<X509Extension> uniqueExtensions() {
        final Map<ASN1ObjectIdentifier, X509Extension> unique =
            new LinkedHashMap<ASN1ObjectIdentifier, X509Extension>();

        for ( X509Extension current : this.extensions ) {

            final ASN1ObjectIdentifier oid = current.getRealObjectID();
            final X509Extension existing = unique.get( oid );
            if ( existing == null ) {
                unique.put( oid, current ); continue;
            }

            // NOTE: dealing with Java API limits here since it does not
            // handle multiple OID mappings to a sequence out of the box

            // commonly used e.g. with subjectAltName || issuserAltName :
            if ( "2.5.29.17".equals( oid.getId() ) || "2.5.29.18".equals( oid.getId() ) ) {
                final ASN1EncodableVector vec = new ASN1EncodableVector();
                try {
                    GeneralName[] n1 = extRealNames(existing);
                    for ( int i = 0; i < n1.length; i++ ) vec.add( n1[i] );
                    GeneralName[] n2 = extRealNames(current);
                    for ( int i = 0; i < n2.length; i++ ) vec.add( n2[i] );

                    GeneralNames nn = GeneralNames.getInstance(new DLSequence(vec));
                    final X509Extension existingDup = existing.clone();
                    existingDup.setRealValue( nn );
                    unique.put( oid, existingDup );
                }
                catch (IOException ex) { throw getRuntime().newIOErrorFromException(ex); }
                continue;
            }

            // TODO do we need special care for any others here ?!?

            final ASN1EncodableVector vec = new ASN1EncodableVector();
            try {
                final ASN1Encodable existingValue = existing.getRealValue();
                if ( existingValue instanceof ASN1Sequence ) {
                    final ASN1Sequence seq = (ASN1Sequence) existingValue;
                    for ( int i = 0; i < seq.size(); i++ ) {
                        vec.add( seq.getObjectAt(i) );
                    }
                }
                else {
                    vec.add(existingValue);
                }
                vec.add( current.getRealValue() );

                // existing.setRealValue( new DLSequence(vec) );
                final X509Extension existingDup = existing.clone();
                existingDup.setRealValue( new DLSequence(vec) );
                unique.put( oid, existingDup );
            }
            catch (IOException ex) { throw getRuntime().newIOErrorFromException(ex); }

        }
        return unique.values();
    }

    private static GeneralName[] extRealNames(final X509Extension extension) throws IOException {
        final ASN1Encodable value = extension.getRealValue();
        if ( value instanceof GeneralName ) {
            return new GeneralName[] { (GeneralName) value };
        }
        return GeneralNames.getInstance( value ).getNames();
    }

    @Override
    public Object toJava(Class target) {
        if ( target.isAssignableFrom(X509Certificate.class) ) {
            if ( target == X509AuxCertificate.class ) return getAuxCert();
            return cert;
        }
        return super.toJava(target);
    }

}// X509Cert
