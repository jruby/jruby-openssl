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
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.crypto.KeyAgreement;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
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
import org.jruby.RubySymbol;
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

    static PKeyEC newInstance(final Ruby runtime, final PublicKey publicKey) {
        return new PKeyEC(runtime, publicKey);
    }

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

    private static RaiseException newECError(Ruby runtime, String message) {
        return Utils.newError(runtime, _PKey(runtime).getClass("ECError"), message);
    }

    private static RaiseException newECError(Ruby runtime, String message, Exception cause) {
        return Utils.newError(runtime, _PKey(runtime).getClass("ECError"), message, cause);
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

    private static Optional<ASN1ObjectIdentifier> getCurveOID(final String curveName) {
        return Optional.ofNullable(ECUtil.getNamedCurveOid(curveName));
    }

    private static boolean isCurveName(final String curveName) {
        return getCurveOID(curveName).isPresent();
    }

    private static String getCurveName(final ASN1ObjectIdentifier oid) {
        final String name = ECUtil.getCurveName(oid);
        if (name == null) {
            throw new IllegalStateException("could not identify curve name from: " + oid);
        }
        return name;
    }

    public PKeyEC(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    PKeyEC(Ruby runtime, PublicKey pubKey) {
        this(runtime, _EC(runtime), null, pubKey);
    }

    PKeyEC(Ruby runtime, RubyClass type, PrivateKey privKey, PublicKey pubKey) {
        super(runtime, type);
        this.publicKey = (ECPublicKey) pubKey;
        if (privKey instanceof ECPrivateKey) {
            setPrivateKey((ECPrivateKey) privKey);
        } else {
            this.privateKey = privKey;
        }
    }

    private transient Group group;

    private ECPublicKey publicKey;
    private transient PrivateKey privateKey;

    private String curveName;

    private String getCurveName() { return curveName; }

    private ECNamedCurveParameterSpec getParameterSpec() {
        assert curveName != null;
        return ECNamedCurveTable.getParameterSpec(getCurveName());
    }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String getAlgorithm() { return "ECDSA"; }

    @Override
    public String getKeyType() { return "EC"; }

    @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args, Block block) {
        final Ruby runtime = context.runtime;

        privateKey = null; publicKey = null;

        if ( Arity.checkArgumentCount(runtime, args, 0, 2) == 0 ) {
            return this;
        }

        IRubyObject arg = args[0];

        if ( arg instanceof Group ) {
            setGroup((Group) arg);
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
            ecdsaFactory = SecurityHelper.getKeyFactory("EC");
        }
        catch (NoSuchAlgorithmException e) {
            throw runtime.newRuntimeError("unsupported key algorithm (EC)");
        }
        catch (RuntimeException e) {
            throw runtime.newRuntimeError("unsupported key algorithm (EC) " + e);
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
            catch (IOException e) { debugStackTrace(runtime, "PKeyEC could not read private key", e); }
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
            setPrivateKey((ECPrivateKey) privKey);
        }
        else if ( key instanceof ECPrivateKey ) {
            setPrivateKey((ECPrivateKey) key);
        }
        else if ( key instanceof ECPublicKey ) {
            this.publicKey = (ECPublicKey) key;
            this.privateKey = null;
        }
        else {
            throw newECError(runtime, "Neither PUB key nor PRIV key: "  + key.getClass().getName());
        }

        if ( curveName == null && publicKey != null ) {
            final String oid = getCurveNameObjectIdFromKey(context, publicKey);
            if (isCurveName(oid)) {
                this.curveName = getCurveName(new ASN1ObjectIdentifier(oid));
            }
        }

        return this;
    }

    void setPrivateKey(final ECPrivateKey key) {
        this.privateKey = key;
        unwrapPrivateKeyWithName();
    }

    private void unwrapPrivateKeyWithName() {
        final ECPrivateKey privKey = (ECPrivateKey) this.privateKey;
        if ( privKey instanceof ECPrivateKeyWithName ) {
            this.privateKey = ((ECPrivateKeyWithName) privKey).unwrap();
            this.curveName = getCurveName( ((ECPrivateKeyWithName) privKey).getCurveNameOID() );
        }
    }

    private static String getCurveNameObjectIdFromKey(final ThreadContext context, final ECPublicKey key) {
        try {
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC");
            algParams.init(key.getParams());
            return algParams.getParameterSpec(ECGenParameterSpec.class).getName();
        }
        catch (NoSuchAlgorithmException|InvalidParameterSpecException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
        catch (Exception ex) {
            throw (RaiseException) newECError(context.runtime, ex.toString()).initCause(ex);
        }
    }

    private void setGroup(final Group group) {
        this.group = group;
        this.curveName = this.group.getCurveName();
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
        try {
            ECGenParameterSpec genSpec = new ECGenParameterSpec(getCurveName());
            KeyPairGenerator gen = SecurityHelper.getKeyPairGenerator("EC"); // "BC"
            gen.initialize(genSpec, OpenSSL.getSecureRandom(context));
            KeyPair pair = gen.generateKeyPair();
            this.publicKey = (ECPublicKey) pair.getPublic();
            this.privateKey = pair.getPrivate();
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.toString());
        }
        return this;
    }

    @JRubyMethod(meta = true)
    public static IRubyObject generate(final ThreadContext context, final IRubyObject self, final IRubyObject group) {
        PKeyEC randomKey = new PKeyEC(context.runtime, (RubyClass) self);

        if (group instanceof Group) {
            randomKey.setGroup((Group) group);
        } else {
            randomKey.curveName = group.convertToString().toString();
        }

        return randomKey.generate_key(context);
    }

    @JRubyMethod(name = "dsa_sign_asn1")
    public IRubyObject dsa_sign_asn1(final ThreadContext context, final IRubyObject data) {
        if (privateKey == null) {
            throw newECError(context.runtime, "Private EC key needed!");
        }
        try {
            final ECNamedCurveParameterSpec params = getParameterSpec();

            final ECDSASigner signer = new ECDSASigner();
            signer.init(true, new ECPrivateKeyParameters(
                    ((ECPrivateKey) this.privateKey).getS(),
                    new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH())
            ));

            BigInteger[] signature = signer.generateSignature(data.convertToString().getBytes()); // [r, s]

            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            ASN1OutputStream asn1 = ASN1OutputStream.create(bytes, ASN1Encoding.DER);

            ASN1EncodableVector v = new ASN1EncodableVector(2);
            v.add(new ASN1Integer(signature[0])); // r
            v.add(new ASN1Integer(signature[1])); // s

            asn1.writeObject(new DERSequence(v));
            asn1.close();

            return StringHelper.newString(context.runtime, bytes.buffer(), bytes.size());
        }
        catch (IOException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
        catch (Exception ex) {
            throw newECError(context.runtime, ex.toString(), ex);
        }
    }

    @JRubyMethod(name = "dsa_verify_asn1")
    public IRubyObject dsa_verify_asn1(final ThreadContext context, final IRubyObject data, final IRubyObject sign) {
        final Ruby runtime = context.runtime;
        try {
            final ECNamedCurveParameterSpec params = getParameterSpec();

            final ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(
                    EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()),
                    new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH())
            ));

            ASN1Primitive vec = new ASN1InputStream(sign.convertToString().getBytes()).readObject();

            if (!(vec instanceof ASN1Sequence)) {
                throw newECError(runtime, "invalid signature (not a sequence)");
            }

            ASN1Sequence seq = (ASN1Sequence) vec;
            ASN1Integer r = ASN1Integer.getInstance(seq.getObjectAt(0));
            ASN1Integer s = ASN1Integer.getInstance(seq.getObjectAt(1));

            boolean verify = signer.verifySignature(data.convertToString().getBytes(), r.getPositiveValue(), s.getPositiveValue());
            return runtime.newBoolean(verify);
        }
        catch (IOException|IllegalArgumentException|IllegalStateException ex) {
            throw newECError(runtime, "invalid signature: " + ex.getMessage(), ex);
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
        catch (InvalidKeyException ex) {
            throw newECError(context.runtime, "invalid key: " + ex.getMessage());
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.toString());
        }
    }

    @JRubyMethod
    public IRubyObject oid() {
        return getRuntime().newString("id-ecPublicKey");
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
            this.publicKey = (ECPublicKey) SecurityHelper.getKeyFactory("EC").generatePublic(keySpec);
            return arg;
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
    }

    /**
     * @see ECNamedCurveSpec
     */
    private static ECParameterSpec getParamSpec(final String curveName) {
        final ECNamedCurveParameterSpec ecCurveParamSpec = ECNamedCurveTable.getParameterSpec(curveName);
        final EllipticCurve curve = EC5Util.convertCurve(ecCurveParamSpec.getCurve(), ecCurveParamSpec.getSeed());
        return EC5Util.convertSpec(curve, ecCurveParamSpec);
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
            this.privateKey = SecurityHelper.getKeyFactory("EC").generatePrivate(keySpec);
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

    private enum PointConversion {
        COMPRESSED, UNCOMPRESSED, HYBRID;

        String toRubyString() {
            return super.toString().toLowerCase(Locale.ROOT);
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
        private transient ECParameterSpec paramSpec;

        private PointConversion conversionForm = PointConversion.UNCOMPRESSED;

        private RubyString curve_name;

        public Group(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        Group(Ruby runtime, PKeyEC key) {
            this(runtime, _EC(runtime).getClass("Group"));
            this.key = key;
            this.paramSpec = key.publicKey.getParams();
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

                this.curve_name = arg.convertToString();
            }
            return this;
        }

        private String getCurveName() {
            if (key != null) return key.getCurveName();
            return curve_name.toString();
        }

        @Override
        @JRubyMethod(name = { "==", "eql?" })
        public IRubyObject op_equal(final ThreadContext context, final IRubyObject obj) {
            final Ruby runtime = context.runtime;
            if ( obj instanceof Group ) {
                final Group that = (Group) obj;
                return context.runtime.newBoolean(this.implCurveName(runtime).equals(that.implCurveName(runtime)));
            }
            return context.runtime.getFalse();
        }

        @JRubyMethod
        public IRubyObject curve_name(final ThreadContext context) {
            return implCurveName(context.runtime).dup();
        }

        private RubyString implCurveName(final Ruby runtime) {
            if (curve_name == null) {
                String prefix, curveName = key.getCurveName();
                // BC 1.54: "brainpoolP512t1" 1.55: "brainpoolp512t1"
                if (curveName.startsWith(prefix = "brainpoolp")) {
                    curveName = "brainpoolP" + curveName.substring(prefix.length());
                }
                curve_name = RubyString.newString(runtime, curveName);
            }
            return curve_name;
        }

        @JRubyMethod
        public IRubyObject order(final ThreadContext context) {
            return BN.newBN(context.runtime, getParamSpec().getOrder());
        }

        @JRubyMethod
        public IRubyObject cofactor(final ThreadContext context) {
            return context.runtime.newFixnum(getParamSpec().getCofactor());
        }

        @JRubyMethod
        public IRubyObject seed(final ThreadContext context) {
            final byte[] seed = getCurve().getSeed();
            return seed == null ? context.nil : StringHelper.newString(context.runtime, seed);
        }

        @JRubyMethod
        public IRubyObject degree(final ThreadContext context) {
            final int fieldSize = getCurve().getField().getFieldSize();
            return context.runtime.newFixnum(fieldSize);
        }

        @JRubyMethod
        public IRubyObject generator(final ThreadContext context) {
            final ECPoint generator = getParamSpec().getGenerator();
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
                final ASN1ObjectIdentifier oid = getCurveOID(getCurveName())
                        .orElseThrow(() -> newECError(context.runtime, "invalid curve name: " + getCurveName()));
                PEMInputOutput.writeECParameters(writer, oid, spec, passwd);
                return RubyString.newString(context.runtime, writer.getBuffer());
            }
            catch (IOException ex) {
                throw newECError(context.runtime, ex.getMessage());
            }
        }

        private ECParameterSpec getParamSpec() {
            if (paramSpec == null) {
                paramSpec = PKeyEC.getParamSpec(getCurveName());
            }
            return paramSpec;
        }

        EllipticCurve getCurve() {
            return getParamSpec().getCurve();
        }

        @JRubyMethod
        public RubySymbol point_conversion_form(final ThreadContext context) {
            return context.runtime.newSymbol(this.conversionForm.toRubyString());
        }

        @JRubyMethod(name = "point_conversion_form=")
        public IRubyObject set_point_conversion_form(final ThreadContext context, final IRubyObject form) {
            this.conversionForm = parse_point_conversion_form(context.runtime, form);
            return form;
        }

        static PointConversion parse_point_conversion_form(final Ruby runtime, final IRubyObject form) {
            if (form instanceof RubySymbol) {
                final String pointConversionForm = ((RubySymbol) form).asJavaString();
                if ("uncompressed".equals(pointConversionForm)) return PointConversion.UNCOMPRESSED;
                if ("compressed".equals(pointConversionForm)) return PointConversion.COMPRESSED;
                if ("hybrid".equals(pointConversionForm)) return PointConversion.HYBRID;
            }
            throw runtime.newArgumentError("unsupported point conversion form: " + form.inspect());
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

        private ECPoint point;
        //private int bitLength;
        private Group group;

        Point(Ruby runtime, ECPublicKey publicKey, Group group) {
            this(runtime, _EC(runtime).getClass("Point"));
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
                final byte[] encoded;
                if (args[1] instanceof BN) {
                    encoded = ((BN) args[1]).getValue().abs().toByteArray();
                } else {
                    encoded = args[1].convertToString().getBytes();
                }
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
            assert group != null;
            return group.getParamSpec().getOrder().bitLength();
        }

        private PointConversion getPointConversionForm() {
            if (group == null) return null;
            return group.conversionForm;
        }

        @JRubyMethod
        public BN to_bn(final ThreadContext context) {
            return toBN(context, getPointConversionForm()); // group.point_conversion_form
        }

        @JRubyMethod
        public BN to_bn(final ThreadContext context, final IRubyObject conversion_form) {
            return toBN(context, Group.parse_point_conversion_form(context.runtime, conversion_form));
        }

        private BN toBN(final ThreadContext context, final PointConversion conversionForm) {
            final byte[] encoded = encodePoint(conversionForm);
            return BN.newBN(context.runtime, new BigInteger(1, encoded));
        }

        private byte[] encodePoint(final PointConversion conversionForm) {
            final byte[] encoded;
            switch (conversionForm) {
                case UNCOMPRESSED:
                    encoded = encodeUncompressed(bitLength(), point);
                    break;
                case COMPRESSED:
                    encoded = encodeCompressed(point);
                    break;
                case HYBRID:
                    throw getRuntime().newNotImplementedError(":hybrid compression not implemented");
                default:
                    throw new AssertionError("unexpected conversion form: " + conversionForm);
            }
            return encoded;
        }

        @JRubyMethod
        public IRubyObject to_octet_string(final ThreadContext context, final IRubyObject conversion_form) {
            final PointConversion conversionForm = Group.parse_point_conversion_form(context.runtime, conversion_form);
            return StringHelper.newString(context.runtime, encodePoint(conversionForm));
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
        return encodeUncompressed(pubKey.getParams().getOrder().bitLength(), pubKey.getW());
    }

    private static byte[] encodeUncompressed(final int fieldSize, final ECPoint point) {
        if (point == ECPoint.POINT_INFINITY) return new byte[1];

        final int expLength = (fieldSize + 7) / 8;

        byte[] encoded = new byte[1 + expLength + expLength];

        encoded[0] = 0x04;

        addIntBytes(point.getAffineX(), expLength, encoded, 1);
        addIntBytes(point.getAffineY(), expLength, encoded, 1 + expLength);

        return encoded;
    }

    private static byte[] encodeCompressed(final ECPoint point) {
        if (point == ECPoint.POINT_INFINITY) return new byte[1];

        final int bytesLength = point.getAffineX().bitLength() / 8 + 1;

        byte[] encoded = new byte[1 + bytesLength];

        encoded[0] = (byte) (point.getAffineY().testBit(0) ? 0x03 : 0x02);

        addIntBytes(point.getAffineX(), bytesLength, encoded, 1);

        return encoded;
    }

    private static void addIntBytes(final BigInteger value, final int length, final byte[] dest, final int destOffset) {
        final byte[] in = value.toByteArray();

        if (length < in.length) {
           System.arraycopy(in, in.length - length, dest, destOffset, length);
        }
        else if (length > in.length) {
            System.arraycopy(in, 0, dest, destOffset + (length - in.length), in.length);
        }
        else {
            System.arraycopy(in, 0, dest, destOffset, length);
        }
    }

}
