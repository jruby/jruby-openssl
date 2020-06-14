/*
 * Copyright (c) 2016 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.crypto.KeyAgreement;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DLSequence;

import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.component.VariableEntry;

import org.jruby.ext.openssl.impl.CipherSpec;
import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;
import static org.jruby.ext.openssl.PKey._PKey;
import org.jruby.ext.openssl.impl.ECPrivateKeyWithName;
import static org.jruby.ext.openssl.impl.PKey.readECPrivateKey;
import org.jruby.ext.openssl.util.ByteArrayOutputStream;
import org.jruby.ext.openssl.x509store.PEMInputOutput;

/**
 * OpenSSL::PKey::EC implementation.
 *
 * @author kares
 */
public final class PKeyEC extends PKey {

    private static final long serialVersionUID = 1L;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public PKeyEC allocate(Ruby runtime, RubyClass klass) { return new PKeyEC(runtime, klass); }
    };

    static void createPKeyEC(final Ruby runtime, final RubyModule PKey, final RubyClass PKeyPKey, final RubyClass OpenSSLError) {
        RubyClass EC = PKey.defineClassUnder("EC", PKeyPKey, ALLOCATOR);

        RubyClass PKeyError = PKey.getClass("PKeyError");
        PKey.defineClassUnder("ECError", PKeyError, PKeyError.getAllocator());

        EC.defineAnnotatedMethods(PKeyEC.class);
        EC.setConstant("NAMED_CURVE", runtime.newFixnum(1));

        Point.createPoint(runtime, EC, OpenSSLError);
        Group.createGroup(runtime, EC, OpenSSLError);
    }

    static RubyClass _EC(final Ruby runtime) {
        return _PKey(runtime).getClass("EC");
    }

    public static RaiseException newECError(Ruby runtime, String message) {
        return Utils.newError(runtime, _PKey(runtime).getClass("ECError"), message);
    }

    @JRubyMethod(meta = true)
    public static RubyArray builtin_curves(ThreadContext context, IRubyObject self) {
        final Ruby runtime = context.runtime;
        final RubyArray curves = runtime.newArray();

        Enumeration names;

        names = org.bouncycastle.asn1.x9.X962NamedCurves.getNames();
        while ( names.hasMoreElements() ) {
            final String name = (String) names.nextElement();
            RubyString desc;
            if ( name.startsWith("prime") ) {
                desc = RubyString.newString(runtime, "X9.62 curve over a xxx bit prime field");
            }
            else {
                desc = RubyString.newString(runtime, "X9.62 curve over a xxx bit binary field");
            }
            curves.append(RubyArray.newArrayNoCopy(runtime, new IRubyObject[] { RubyString.newString(runtime, name), desc }));
        }

        names = org.bouncycastle.asn1.sec.SECNamedCurves.getNames();
        while ( names.hasMoreElements() ) {
            RubyString name = RubyString.newString(runtime, (String) names.nextElement());
            RubyString desc = RubyString.newString(runtime, "SECG curve over a xxx bit binary field");
            curves.append(RubyArray.newArrayNoCopy(runtime, new IRubyObject[] { name, desc }));
        }

        names = org.bouncycastle.asn1.nist.NISTNamedCurves.getNames();
        while ( names.hasMoreElements() ) {
            RubyString name = RubyString.newString(runtime, (String) names.nextElement());
            IRubyObject[] nameAndDesc = new IRubyObject[] { name, RubyString.newEmptyString(runtime) };
            curves.append(RubyArray.newArrayNoCopy(runtime, nameAndDesc));
        }

        names = org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves.getNames();
        while ( names.hasMoreElements() ) {
            RubyString name = RubyString.newString(runtime, (String) names.nextElement());
            RubyString desc = RubyString.newString(runtime, "RFC 5639 curve over a xxx bit prime field");
            curves.append(RubyArray.newArrayNoCopy(runtime, new IRubyObject[] { name, desc }));
        }

        return curves;
    }

    private static ASN1ObjectIdentifier getCurveOID(final String curveName) {
        ASN1ObjectIdentifier id;
        id = org.bouncycastle.asn1.sec.SECNamedCurves.getOID(curveName);
        if ( id != null ) return id;
        id = org.bouncycastle.asn1.x9.X962NamedCurves.getOID(curveName);
        if ( id != null ) return id;
        id = org.bouncycastle.asn1.nist.NISTNamedCurves.getOID(curveName);
        if ( id != null ) return id;
        id = org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves.getOID(curveName);
        if ( id != null ) return id;
        throw new IllegalStateException("could not identify curve name: " + curveName);
    }

    private static boolean isCurveName(final String curveName) {
        try {
            return getCurveOID(curveName) != null;
        }
        catch (IllegalStateException ex) { return false; }
    }

    private static String getCurveName(final ASN1ObjectIdentifier oid) {
        String name;
        name = org.bouncycastle.asn1.sec.SECNamedCurves.getName(oid);
        if ( name != null ) return name;
        name = org.bouncycastle.asn1.x9.X962NamedCurves.getName(oid);
        if ( name != null ) return name;
        name = org.bouncycastle.asn1.nist.NISTNamedCurves.getName(oid);
        if ( name != null ) return name;
        name = org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves.getName(oid);
        if ( name != null ) return name;
        throw new IllegalStateException("could not identify curve name from: " + oid);
    }

    public PKeyEC(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    PKeyEC(Ruby runtime, PublicKey pubKey) {
        this(runtime, _EC(runtime), null, pubKey);
    }

    PKeyEC(Ruby runtime, RubyClass type, PrivateKey privKey, PublicKey pubKey) {
        super(runtime, type);
        this.privateKey = privKey;
        this.publicKey = (ECPublicKey) pubKey;
    }

    private transient Group group;

    private ECPublicKey publicKey;
    private transient PrivateKey privateKey;

    private String curveName;

    private String getCurveName() { return curveName; }

//    private ECNamedCurveParameterSpec getParameterSpec() {
//        return ECNamedCurveTable.getParameterSpec( getCurveName() );
//    }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String getAlgorithm() { return "ECDSA"; }

    @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args, Block block) {
        final Ruby runtime = context.runtime;

        privateKey = null; publicKey = null;

        if ( Arity.checkArgumentCount(runtime, args, 0, 2) == 0 ) {
            return this;
        }

        IRubyObject arg = args[0];

        if ( arg instanceof Group ) {
            this.group = (Group) arg;
            this.curveName = this.group.getCurveName();
            return this;
        }

        IRubyObject pass = null;
        if ( args.length > 1 ) pass = args[1];
        final char[] passwd = password(context, pass, block);
        final RubyString str = readInitArg(context, arg);
        final String strJava = str.toString();

        if ( isCurveName(strJava) ) {
            this.curveName = strJava;
            return this;
        }

        Object key = null;
        final KeyFactory ecdsaFactory;
        try {
            ecdsaFactory = SecurityHelper.getKeyFactory("ECDSA");
        }
        catch (NoSuchAlgorithmException e) {
            throw runtime.newRuntimeError("unsupported key algorithm (ECDSA)");
        }
        catch (RuntimeException e) {
            throw runtime.newRuntimeError("unsupported key algorithm (ECDSA) " + e);
        }
        // TODO: ugly NoClassDefFoundError catching for no BC env. How can we remove this?
        boolean noClassDef = false;
        if ( key == null && ! noClassDef ) { // PEM_read_bio_DSAPrivateKey
            try {
                key = readPrivateKey(strJava, passwd);
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (PEMInputOutput.PasswordRequiredException retry) {
                if ( ttySTDIN(context) ) {
                    try { key = readPrivateKey(str, passwordPrompt(context)); }
                    catch (Exception e) { debugStackTrace(runtime, e); }
                }
            }
            catch (Exception e) { debugStackTrace(runtime, e); }
        }
        if ( key == null && ! noClassDef ) {
            try {
                key = PEMInputOutput.readECPublicKey(new StringReader(strJava), passwd);
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (Exception e) { debugStackTrace(runtime, e); }
        }
        if ( key == null && ! noClassDef ) {
            try {
                key = PEMInputOutput.readECPubKey(new StringReader(strJava));
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (Exception e) { debugStackTrace(runtime, e); }
        }
        if ( key == null && ! noClassDef ) {
            try {
                key = readECPrivateKey(ecdsaFactory, str.getBytes());
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (InvalidKeySpecException e) { debug(runtime, "PKeyEC could not read private key", e); }
            catch (IOException e) { debug(runtime, "PKeyEC could not read private key", e); }
            catch (RuntimeException e) {
                if ( isKeyGenerationFailure(e) ) debug(runtime, "PKeyEC could not read private key", e);
                else debugStackTrace(runtime, e);
            }
        }
//        if ( key == null && ! noClassDef ) {
//            try { // readECParameters
//                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(str.getBytes());
//                ECNamedCurveParameterSpec paramSpec = ECNamedCurveTable.getParameterSpec(oid.getId());
//
//                // ecdsaFactory.generatePublic(keySpec)
//
//            }
//            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
//            catch (InvalidKeySpecException e) { debug(runtime, "PKeyEC could not read public key", e); }
//            catch (IOException e) { debug(runtime, "PKeyEC could not read public key", e); }
//            catch (RuntimeException e) {
//                if ( isKeyGenerationFailure(e) ) debug(runtime, "PKeyEC could not read public key", e);
//                else debugStackTrace(runtime, e);
//            }
//        }

        if ( key == null ) key = tryPKCS8EncodedKey(runtime, ecdsaFactory, str.getBytes());
        if ( key == null ) key = tryX509EncodedKey(runtime, ecdsaFactory, str.getBytes());

        if ( key == null ) throw newECError(runtime, "Neither PUB key nor PRIV key:");

        if ( key instanceof KeyPair ) {
            final PublicKey pubKey = ((KeyPair) key).getPublic();
            final PrivateKey privKey = ((KeyPair) key).getPrivate();
            if ( ! ( privKey instanceof ECPrivateKey ) ) {
                if ( privKey == null ) {
                    throw newECError(runtime, "Neither PUB key nor PRIV key: (private key is null)");
                }
                throw newECError(runtime, "Neither PUB key nor PRIV key: (invalid key type " + privKey.getClass().getName() + ")");
            }
            this.publicKey = (ECPublicKey) pubKey;
            this.privateKey = (ECPrivateKey) privKey;
            unwrapPrivateKeyWithName();
        }
        else if ( key instanceof ECPrivateKey ) {
            this.privateKey = (ECPrivateKey) key;
            unwrapPrivateKeyWithName();
        }
        else if ( key instanceof ECPublicKey ) {
            this.publicKey = (ECPublicKey) key; this.privateKey = null;
        }
        else {
            throw newECError(runtime, "Neither PUB key nor PRIV key: "  + key.getClass().getName());
        }

        if ( publicKey != null ) {
            publicKey.getParams().getCurve();
        }
        // TODO set curveName ?!?!?!?!?!?!?!

        return this;
    }

    private void unwrapPrivateKeyWithName() {
        final ECPrivateKey privKey = (ECPrivateKey) this.privateKey;
        if ( privKey instanceof ECPrivateKeyWithName ) {
            this.privateKey = ((ECPrivateKeyWithName) privKey).unwrap();
            this.curveName = getCurveName( ((ECPrivateKeyWithName) privKey).getCurveNameOID() );
        }
    }

    //private static ECNamedCurveParameterSpec readECParameters(final byte[] input) throws IOException {
    //    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(input);
    //    return ECNamedCurveTable.getParameterSpec(oid.getId());
    //}

    @JRubyMethod
    public IRubyObject check_key(final ThreadContext context) {
        return context.runtime.getTrue(); // TODO not implemented stub
    }

    @JRubyMethod(name = "generate_key")
    public PKeyEC generate_key(final ThreadContext context) {
        // final ECDomainParameters params = getDomainParameters();
        try {
            ECGenParameterSpec genSpec = new ECGenParameterSpec(getCurveName());
            KeyPairGenerator gen = SecurityHelper.getKeyPairGenerator("ECDSA"); // "BC"
            gen.initialize(genSpec, new SecureRandom());
            KeyPair pair = gen.generateKeyPair();
            this.publicKey = (ECPublicKey) pair.getPublic();
            this.privateKey = pair.getPrivate();
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.toString());
        }
        return this;
    }

    @JRubyMethod(name = "dsa_sign_asn1")
    public IRubyObject dsa_sign_asn1(final ThreadContext context, final IRubyObject data) {
        try {
            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(getCurveName());
            ASN1ObjectIdentifier oid = getCurveOID(getCurveName());
            ECNamedDomainParameters domainParams = new ECNamedDomainParameters(oid,
                params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed()
            );

            final ECDSASigner signer = new ECDSASigner();
            final ECPrivateKey privKey = (ECPrivateKey) this.privateKey;
            signer.init(true, new ECPrivateKeyParameters(privKey.getS(), domainParams));

            final byte[] message = data.convertToString().getBytes();
            BigInteger[] signature = signer.generateSignature(message); // [r, s]

//            final byte[] r = signature[0].toByteArray();
//            final byte[] s = signature[1].toByteArray();
//            // ASN.1 encode as: 0x30 len 0x02 rlen (r) 0x02 slen (s)
//            final int len = 1 + (1 + r.length) + 1 + (1 + s.length);
//
//            final byte[] encoded = new byte[1 + 1 + len]; int i;
//            encoded[0] = 0x30;
//            encoded[1] = (byte) len;
//            encoded[2] = 0x20;
//            encoded[3] = (byte) r.length;
//            System.arraycopy(r, 0, encoded, i = 4, r.length); i += r.length;
//            encoded[i++] = 0x20;
//            encoded[i++] = (byte) s.length;
//            System.arraycopy(s, 0, encoded, i, s.length);

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            ASN1OutputStream asn1 = new ASN1OutputStream(bytes);

            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(signature[0])); // r
            v.add(new ASN1Integer(signature[1])); // s

            asn1.writeObject(new DLSequence(v));

            return StringHelper.newString(context.runtime, bytes.buffer(), bytes.size());
        }
        catch (IOException ex) {
            throw newECError(context.runtime, ex.toString());
        }
        catch (RuntimeException ex) {
            throw newECError(context.runtime, ex.toString());
        }
    }


    @JRubyMethod(name = "dh_compute_key")
    public IRubyObject dh_compute_key(final ThreadContext context, final IRubyObject point) {
        try {
            KeyAgreement agreement = SecurityHelper.getKeyAgreement("ECDH"); // "BC"
            agreement.init(getPrivateKey());
            if ( point.isNil() ) {
                agreement.doPhase(getPublicKey(), true);
            }
            else {
                final ECPoint ecPoint = ((Point) point).asECPoint();
                final String name = getCurveName();

                KeyFactory keyFactory = KeyFactory.getInstance("EC"); // "BC"
                ECParameterSpec spec = getParamSpec(name);
                ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, spec));
                agreement.doPhase(ecPublicKey, true);
            }
            final byte[] secret = agreement.generateSecret();
            return StringHelper.newString(context.runtime, secret);
        }
        catch (NoSuchAlgorithmException ex) {
            throw newECError(context.runtime, ex.toString());
        }
        catch (InvalidKeyException ex) {
            throw newECError(context.runtime, ex.toString());
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.toString());
        }
    }

    private Group getGroup(boolean required) {
        if (group == null) {
            if (publicKey != null) {
                return group = new Group(getRuntime(), this);
            }
            if (required) throw new IllegalStateException("no group (without public key)");
        }
        return group;
    }

    /**
     * @return OpenSSL::PKey::EC::Group
     */
    @JRubyMethod
    public IRubyObject group() {
        final Group group = getGroup(false);
        return group == null ? getRuntime().getNil() : group;
    }

    @JRubyMethod(name = "group=")
    public IRubyObject set_group(IRubyObject group) {
        this.group = group.isNil() ? null : (Group) group;
        return group;
    }

    /**
     * @return OpenSSL::PKey::EC::Point
     */
    @JRubyMethod
    public IRubyObject public_key(final ThreadContext context) {
        if ( publicKey == null ) return context.nil;

        return new Point(context.runtime, publicKey, getGroup(true));
    }

    @JRubyMethod(name = "public_key=")
    public IRubyObject set_public_key(final ThreadContext context, final IRubyObject arg) {
        if ( ! ( arg instanceof Point )  ) {
            throw context.runtime.newTypeError(arg, _EC(context.runtime).getClass("Point"));
        }
        final Point point = (Point) arg;
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point.asECPoint(), getParamSpec());
        try {
            this.publicKey = (ECPublicKey) SecurityHelper.getKeyFactory("ECDSA").generatePublic(keySpec);
            return arg;
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
    }

    private static ECParameterSpec getParamSpec(final String curveName) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        return new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    private ECParameterSpec getParamSpec() {
        return getParamSpec(getCurveName());
    }

    /**
     * @return OpenSSL::BN
     */
    @JRubyMethod
    public IRubyObject private_key(final ThreadContext context) {
        if ( privateKey == null ) return context.nil;

        return BN.newBN(context.runtime, ((ECPrivateKey) privateKey).getS());
    }

    @JRubyMethod(name = "private_key=")
    public IRubyObject set_private_key(final ThreadContext context, final IRubyObject arg) {
        final BigInteger s;
        if ( arg instanceof BN ) {
            s = ((BN) (arg)).getValue();
        }
        else {
            s = (BigInteger) arg;
        }
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, getParamSpec());
        try {
            this.privateKey = SecurityHelper.getKeyFactory("ECDSA").generatePrivate(keySpec);
            return arg;
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
    }

    @JRubyMethod(name = "public_key?")
    public RubyBoolean public_p() {
        return publicKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @JRubyMethod(name = "private_key?")
    public RubyBoolean private_p() {
        return privateKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @Override
    @JRubyMethod(name = "to_der")
    public RubyString to_der() {
        final byte[] bytes;
        try {
            bytes = toDER();
        }
        catch (IOException e) {
            throw newECError(getRuntime(), e.getMessage());
        }
        return StringHelper.newString(getRuntime(), bytes);
    }

    private byte[] toDER() throws IOException {
        if ( publicKey != null && privateKey == null ) {
            return publicKey.getEncoded();
        }
        if ( privateKey == null ) {
            throw new IllegalStateException("private key as well as public key are null");
        }
        return privateKey.getEncoded();
    }

    @Override
    @JRubyMethod(name = "to_pem", alias = "export", rest = true)
    public RubyString to_pem(ThreadContext context, final IRubyObject[] args) {
        Arity.checkArgumentCount(context.runtime, args, 0, 2);

        CipherSpec spec = null; char[] passwd = null;
        if ( args.length > 0 ) {
            spec = cipherSpec( args[0] );
            if ( args.length > 1 ) passwd = password(context, args[1], null);
        }

        try {
            final StringWriter writer = new StringWriter();
            if ( privateKey != null ) {
                PEMInputOutput.writeECPrivateKey(writer, (ECPrivateKey) privateKey, spec, passwd);
            }
            else {
                PEMInputOutput.writeECPublicKey(writer, publicKey);
            }
            return RubyString.newString(context.runtime, writer.getBuffer());
        }
        catch (IOException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
    }

    @JRubyClass(name = "OpenSSL::PKey::EC::Group")
    public static final class Group extends RubyObject {

        private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            public Group allocate(Ruby runtime, RubyClass klass) { return new Group(runtime, klass); }
        };

        static void createGroup(final Ruby runtime, final RubyClass EC, final RubyClass OpenSSLError) {
            RubyClass Group = EC.defineClassUnder("Group", runtime.getObject(), ALLOCATOR);

            // OpenSSL::PKey::EC::Group::Error
            Group.defineClassUnder("Error", OpenSSLError, OpenSSLError.getAllocator());

            Group.defineAnnotatedMethods(Group.class);
        }

        private transient PKeyEC key;
        private ECParameterSpec paramSpec;
        private RubyString curve_name;

        public Group(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        Group(Ruby runtime, PKeyEC key) {
            this(runtime, _EC(runtime).getClass("Group"));
            this.key = key;
            this.paramSpec = key.publicKey.getParams();
        }

        private String getCurveName() {
            if (key != null) return key.getCurveName();
            return curve_name.toString();
        }

        @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final Ruby runtime = context.runtime;

            if ( Arity.checkArgumentCount(runtime, args, 1, 4) == 1 ) {
                IRubyObject arg = args[0];

                if ( arg instanceof Group ) {
                    IRubyObject curve_name = ((Group) arg).curve_name(context);
                    this.curve_name = curve_name.isNil() ? null : (RubyString) curve_name;
                    return this;
                }

                this.curve_name = ((RubyString) arg);

                // TODO PEM/DER parsing not implemented
            }
            return this;
        }

        @Override
        @JRubyMethod(name = { "==", "eql?" })
        public IRubyObject op_equal(final ThreadContext context, final IRubyObject obj) {
            if ( paramSpec == null ) return context.nil;
            if ( obj instanceof Group ) {
                final Group that = (Group) obj;
                boolean equals = this.paramSpec.equals(that.paramSpec);
                return context.runtime.newBoolean(equals);
            }
            return context.runtime.getFalse();
        }

        @JRubyMethod
        public IRubyObject curve_name(final ThreadContext context) {
            if (curve_name == null) {
                String prefix, curveName = key.getCurveName();
                // BC 1.54: "brainpoolP512t1" 1.55: "brainpoolp512t1"
                if (curveName.startsWith(prefix = "brainpoolp")) {
                    curveName = "brainpoolP" + curveName.substring(prefix.length());
                }
                curve_name = RubyString.newString(context.runtime, curveName);
            }
            return curve_name.dup();
        }

        @JRubyMethod
        public IRubyObject order(final ThreadContext context) {
            if ( paramSpec == null ) return context.nil;
            return BN.newBN(context.runtime, paramSpec.getOrder());
        }

        @JRubyMethod
        public IRubyObject cofactor(final ThreadContext context) {
            if ( paramSpec == null ) return context.nil;
            return context.runtime.newFixnum(paramSpec.getCofactor());
        }

        @JRubyMethod
        public IRubyObject seed(final ThreadContext context) {
            if ( paramSpec == null ) return context.nil;
            final byte[] seed = paramSpec.getCurve().getSeed();
            return seed == null ? context.nil : StringHelper.newString(context.runtime, seed);
        }

        @JRubyMethod
        public IRubyObject degree(final ThreadContext context) {
            if ( paramSpec == null ) return context.nil;
            final int fieldSize = paramSpec.getCurve().getField().getFieldSize();
            return context.runtime.newFixnum(fieldSize);
        }

        @JRubyMethod
        public IRubyObject generator(final ThreadContext context) {
            if ( paramSpec == null ) return context.nil;
            final ECPoint generator = paramSpec.getGenerator();
            //final int bitLength = paramSpec.getOrder().bitLength();
            return new Point(context.runtime, generator, this);
        }

        @JRubyMethod(name = { "to_pem" }, alias = "export", rest = true)
        public RubyString to_pem(final ThreadContext context, final IRubyObject[] args) {
            Arity.checkArgumentCount(context.runtime, args, 0, 2);

            CipherSpec spec = null; char[] passwd = null;
            if ( args.length > 0 ) {
                spec = cipherSpec( args[0] );
                if ( args.length > 1 ) passwd = password(context, args[1], null);
            }

            try {
                final StringWriter writer = new StringWriter();
                PEMInputOutput.writeECParameters(writer, getCurveOID(getCurveName()), spec, passwd);
                return RubyString.newString(context.runtime, writer.getBuffer());
            }
            catch (IOException ex) {
                throw newECError(context.runtime, ex.getMessage());
            }
        }

        final EllipticCurve getCurve() {
            if (paramSpec == null) {
                paramSpec = getParamSpec(getCurveName());
            }
            return paramSpec.getCurve();
        }

//        @Override
//        @JRubyMethod
//        @SuppressWarnings("unchecked")
//        public IRubyObject inspect() {
//            final EllipticCurve curve = getCurve();
//            final StringBuilder part = new StringBuilder();
//            String cname = getMetaClass().getRealClass().getName();
//            part.append("#<").append(cname).append(":0x");
//            part.append(Integer.toHexString(System.identityHashCode(this)));
//            // part.append(' ');
//            part.append(" a:").append(curve.getA()).append(" b:").append(curve.getA());
//            return RubyString.newString(getRuntime(), part.append('>'));
//        }

    }

    @JRubyClass(name = "OpenSSL::PKey::EC::Point")
    public static final class Point extends RubyObject {

        private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            public Point allocate(Ruby runtime, RubyClass klass) { return new Point(runtime, klass); }
        };

        static void createPoint(final Ruby runtime, final RubyClass EC, final RubyClass OpenSSLError) {
            RubyClass Point = EC.defineClassUnder("Point", runtime.getObject(), ALLOCATOR);

            // OpenSSL::PKey::EC::Point::Error
            Point.defineClassUnder("Error", OpenSSLError, OpenSSLError.getAllocator());

            Point.defineAnnotatedMethods(Point.class);
        }

        public Point(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        // private transient ECPublicKey publicKey;
        private ECPoint point;
        //private int bitLength;
        private Group group;

        Point(Ruby runtime, ECPublicKey publicKey, Group group) {
            this(runtime, _EC(runtime).getClass("Point"));
            //this.publicKey = publicKey;
            this.point = publicKey.getW();
            this.group = group;
        }

        Point(Ruby runtime, ECPoint point, Group group) {
            this(runtime, _EC(runtime).getClass("Point"));
            this.point = point;
            this.group = group;
        }

        private static RaiseException newError(final Ruby runtime, final String message) {
            final RubyClass Error = _EC(runtime).getClass("Point").getClass("Error");
            return Utils.newError(runtime, Error, message);
        }

        @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final Ruby runtime = context.runtime;

            final int argc = Arity.checkArgumentCount(runtime, args, 1, 2);
            final IRubyObject arg = args[0];

            if ( arg instanceof Point ) {
                this.group = ((Point) arg).group;
                this.point = ((Point) arg).point;
                return this;
            }

            if ( arg instanceof Group ) {
                this.group = (Group) arg;
            }
            if ( argc == 2 ) { // (group, bn)
                final byte[] encoded = ((BN) args[1]).getValue().abs().toByteArray();
                try {
                    this.point = ECPointUtil.decodePoint(group.getCurve(), encoded);
                }
                catch (IllegalArgumentException ex) {
                    // MRI: OpenSSL::PKey::EC::Point::Error: invalid encoding
                    throw newError(context.runtime, ex.getMessage());
                }
            }

            return this;
        }

        @Override
        @JRubyMethod(name = { "==", "eql?" })
        public IRubyObject op_equal(final ThreadContext context, final IRubyObject obj) {
            if (obj instanceof Point) {
                final Point that = (Point) obj;
                boolean equals = this.point.equals(that.point);
                return context.runtime.newBoolean(equals);
            }
            return context.runtime.getFalse();
        }

        /**
         * @return OpenSSL::PKey::EC::Group
         */
        @JRubyMethod
        public IRubyObject group() {
            return group == null ? getRuntime().getNil() : group;
        }

        private ECPoint asECPoint() {
            return point; // return publicKey.getW();
        }

        private int bitLength() {
            return group.paramSpec.getOrder().bitLength();
        }

        @JRubyMethod
        public BN to_bn(final ThreadContext context) {
            final byte[] encoded = encode(bitLength(), point);
            return BN.newBN(context.runtime, new BigInteger(1, encoded));
        }

        private boolean isInfinity() {
            return point == ECPoint.POINT_INFINITY;
        }

        @JRubyMethod(name = "infinity?")
        public RubyBoolean infinity_p() {
            return getRuntime().newBoolean( isInfinity() );
        }

        @JRubyMethod(name = "set_to_infinity!")
        public IRubyObject set_to_infinity_b() {
            this.point = ECPoint.POINT_INFINITY;
            return this;
        }

        @Override
        @JRubyMethod
        @SuppressWarnings("unchecked")
        public IRubyObject inspect() {
            VariableEntry entry = new VariableEntry( "group", group == null ? (Object) "nil" : group );
            return ObjectSupport.inspect(this, (List) Collections.singletonList(entry));
        }

    }

    static byte[] encode(final ECPublicKey pubKey) {
        return encode(pubKey.getParams().getOrder().bitLength(), pubKey.getW());
    }

    private static byte[] encode(final int bitLength, final ECPoint point) {
        if ( point == ECPoint.POINT_INFINITY )  return new byte[1];

        final int bytesLength = (bitLength + 7) / 8;
        byte[] encoded = new byte[1 + bytesLength + bytesLength];

        encoded[0] = 0x04;

        addIntBytes(point.getAffineX(), bytesLength, encoded, 1);
        addIntBytes(point.getAffineY(), bytesLength, encoded, 1 + bytesLength);

        return encoded;
    }

    private static void addIntBytes(BigInteger i, final int length, final byte[] dest, final int destOffset) {
       final byte[] bytes = i.toByteArray();

       if (length < bytes.length) {
           System.arraycopy(bytes, bytes.length - length, dest, destOffset, length);
        }
        else if (length > bytes.length) {
            System.arraycopy(bytes, 0, dest, destOffset + (length - bytes.length), bytes.length);
        }
        else {
            System.arraycopy(bytes, 0, dest, destOffset, length);
        }
    }

}