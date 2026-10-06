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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Enumeration;
import java.security.spec.InvalidParameterSpecException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.math.field.PolynomialExtensionField;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
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
import org.jruby.ext.openssl.log.Logger;
import org.jruby.ext.openssl.shim.PKeyShim;

import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.ext.openssl.impl.ECPrivateKeyWithName;

import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.impl.PKey.readECPrivateKey;
import static org.jruby.ext.openssl.OpenSSL.handlePotentialOperationError;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * OpenSSL::PKey::EC implementation.
 *
 * @author kares
 */
public final class PKeyEC extends PKey {
    private static final Logger LOG = Logger.getLogger(PKeyEC.class);

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

    private static RaiseException newECError(Ruby runtime, String message) {
        return newError(runtime, _PKey(runtime).getClass("ECError"), message);
    }

    private static RaiseException newECError(Ruby runtime, String message, Exception cause) {
        return newError(runtime, _PKey(runtime).getClass("ECError"), message, cause);
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
        if (curveName == null) return Optional.empty();
        // work-around getNamedCurveOid not being able to handle "... " (assuming spacePos + 1 is valid index)
        if (curveName.indexOf(' ') == curveName.length() - 1) return Optional.empty();
        ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(curveName);
        if (oid == null) { // input might already be an OID string (e.g. "1.2.840.10045.3.1.7")
            try { oid = new ASN1ObjectIdentifier(curveName); }
            catch (IllegalArgumentException e) { /* not a valid OID string */ }
        }
        return Optional.ofNullable(oid);
    }

    private static boolean isCurveName(final String curveName) {
        return getCurveOID(curveName).isPresent();
    }

    private static String getCurveName(final ASN1ObjectIdentifier oid) {
        final String name = ECNamedCurveTable.getName(oid);
        if (name == null) throw new IllegalStateException("could not identify curve name from: " + oid);
        return name;
    }

    private static ASN1ObjectIdentifier findNamedCurveOID(final ECParameterSpec ecSpec) {
        final Enumeration<String> names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements()) {
            // resolve a ECParameterSpec by matching order+cofactor+field
            final String name = names.nextElement();
            final X9ECParameters x9 = ECNamedCurveTable.getByName(name);
            final BigInteger ecPrime = ((ECFieldFp) ecSpec.getCurve().getField()).getP();
            if (x9.getN().equals(ecSpec.getOrder()) && x9.getCurve().getField().getCharacteristic().equals(ecPrime)) {
                return ECNamedCurveTable.getOID(name);
            }
        }
        return null;
    }

    // based on BC's EC5Util/ECPointUtil; kept local so we do not depend on non-FIPS-only classes
    private static EllipticCurve convertCurve(final X9ECParameters ecParams) {
        final ECCurve curve = ecParams.getCurve();
        final BigInteger a = curve.getA().toBigInteger();
        final BigInteger b = curve.getB().toBigInteger();
        final byte[] seed = ecParams.hasSeed() ? ecParams.getSeed() : null;
        return new EllipticCurve(convertField(curve.getField()), a, b, seed);
    }

    private static ECPoint convertPoint(org.bouncycastle.math.ec.ECPoint point) {
        // the point at infinity has no affine coordinates (Point#infinity? compares identity)
        if (point.isInfinity()) return ECPoint.POINT_INFINITY;
        point = point.normalize();
        return new ECPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());
    }

    private static ECField convertField(final FiniteField field) {
        if (ECAlgorithms.isFpField(field)) {
            return new ECFieldFp(field.getCharacteristic());
        }

        final Polynomial poly = ((PolynomialExtensionField) field).getMinimalPolynomial();
        final int[] exponents = poly.getExponentsPresent();
        final int[] ks = Arrays.copyOfRange(exponents, 1, exponents.length - 1);
        org.bouncycastle.util.Arrays.reverseInPlace(ks);
        return new ECFieldF2m(poly.getDegree(), ks);
    }

    private static ECCurve toBCCurve(final EllipticCurve curve) throws IllegalArgumentException {
        return toBCCurve(curve, null, null);
    }

    // point arithmetic needs the order (bc-fips multiplies through the curve's order)
    private static ECCurve toBCCurve(final Group group) throws IllegalArgumentException {
        return toBCCurve(group.getCurve(), group.getOrder(), group.getCofactor());
    }

    // FIPS ECCurve Fp/F2m require a non-null order (BC works fine with null)
    // thus pass the real order/cofactor when known (e.g. from an ECParameterSpec)
    private static ECCurve toBCCurve(final EllipticCurve curve, final BigInteger order, final BigInteger cofactor)
        throws IllegalArgumentException {
        final ECField field = curve.getField();
        final BigInteger a = curve.getA();
        final BigInteger b = curve.getB();

        if (field instanceof ECFieldFp) {
            final BigInteger p = ((ECFieldFp) field).getP();
            //if (!p.isProbablePrime(100)) throw new IllegalArgumentException("Fp q value not prime");
            return new ECCurve.Fp(p, a, b, order, cofactor, true); // isInternal - doesn't validate prime
        }

        final ECFieldF2m fieldF2m = (ECFieldF2m) field;
        final int m = fieldF2m.getM();
        final int[] ks = convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
        return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b, order, cofactor);
    }

    private static org.bouncycastle.math.ec.ECPoint toBCPoint(final ECCurve curve, final ECPoint point) {
        return curve.createPoint(point.getAffineX(), point.getAffineY());
    }

    private static org.bouncycastle.math.ec.ECPoint toBCPoint(final ECParameterSpec spec, final ECPoint point) {
        return toBCPoint(toBCCurve(spec.getCurve()), point);
    }

    // copied from BC's ECUtil.convertMidTerms
    private static int[] convertMidTerms(final int[] k) {
        final int[] res = new int[3];

        if (k.length == 1) {
            res[0] = k[0];
            return res;
        }

        if (k.length != 3) throw new IllegalArgumentException("Only Trinomials and pentanomials supported");

        if (k[0] < k[1] && k[0] < k[2]) {
            res[0] = k[0];
            if (k[1] < k[2]) {
                res[1] = k[1];
                res[2] = k[2];
            }
            else {
                res[1] = k[2];
                res[2] = k[1];
            }
        }
        else if (k[1] < k[2]) {
            res[0] = k[1];
            if (k[0] < k[2]) {
                res[1] = k[0];
                res[2] = k[2];
            }
            else {
                res[1] = k[2];
                res[2] = k[0];
            }
        }
        else {
            res[0] = k[2];
            if (k[0] < k[1]) {
                res[1] = k[0];
                res[2] = k[1];
            }
            else {
                res[1] = k[1];
                res[2] = k[0];
            }
        }

        return res;
    }

    public PKeyEC(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    PKeyEC(Ruby runtime) {
        this(runtime, _EC(runtime));
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
            setCurveNameFromPublicKeyIfNeeded();
        }
    }

    private transient Group group;

    private ECPublicKey publicKey;
    private transient PrivateKey privateKey;

    private String curveName;

    private String getCurveName() {
        if (curveName == null && group != null) {
            curveName = group.getCurveName();
        }
        return curveName;
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

        if (isCurveName(strJava)) {
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
        if ( key == null && ! noClassDef ) {
            try {
                key = readPrivateKey(strJava, passwd);
            }
            catch (NoClassDefFoundError e) { noClassDef = true; LOG.debugStack(runtime, null, e); }
            catch (PEMInputOutput.PasswordRequiredException retry) {
                if ( ttySTDIN(context) ) {
                    try { key = readPrivateKey(str, passwordPrompt(context)); }
                    catch (Exception e) { LOG.debugStack(runtime, null, e); }
                }
            }
            catch (Exception e) { LOG.debugStack(runtime, null, e); }
        }
        if ( key == null && ! noClassDef ) {
            try {
                key = PEMInputOutput.readECPublicKey(new StringReader(strJava), passwd);
            }
            catch (NoClassDefFoundError e) { noClassDef = true; LOG.debugStack(runtime, null, e); }
            catch (Exception e) { LOG.debugStack(runtime, null, e); }
        }
        if ( key == null && ! noClassDef ) {
            try {
                key = PEMInputOutput.readECPubKey(new StringReader(strJava));
            }
            catch (NoClassDefFoundError e) { noClassDef = true; LOG.debugStack(runtime, null, e); }
            catch (Exception e) { LOG.debugStack(runtime, null, e); }
        }
        if ( key == null && ! noClassDef ) {
            try {
                key = readECPrivateKey(ecdsaFactory, str.getBytes());
            }
            catch (NoClassDefFoundError e) { noClassDef = true; LOG.debugStack(runtime, null, e); }
            catch (InvalidKeySpecException|IOException e) { LOG.debug(runtime, "could not read private key", e); }
            catch (RuntimeException e) {
                if ( isKeyGenerationFailure(e) ) LOG.debug(runtime, "could not read private key", e);
                else LOG.debugStack(runtime, null, e);
            }
        }

        if ( key == null ) key = tryPKCS8EncodedKey(runtime, ecdsaFactory, str.getBytes());
        if ( key == null ) key = tryX509EncodedKey(runtime, ecdsaFactory, str.getBytes());

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
            throw newECError(runtime, "Neither PUB key nor PRIV key: ");
        }

        setCurveNameFromPublicKeyIfNeeded();

        return this;
    }

    private void setCurveNameFromPublicKeyIfNeeded() {
        if (curveName == null && publicKey != null) {
            final String oid = getCurveNameObjectIdFromKey(getRuntime(), publicKey);
            final Optional<ASN1ObjectIdentifier> curveId = getCurveOID(oid);
            if (curveId.isPresent()) {
                this.curveName = getCurveName(curveId.get());
            }
        }
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

    private static String getCurveNameObjectIdFromKey(final Ruby runtime, final ECPublicKey key) {
        try {
            AlgorithmParameters algParams = SecurityHelper.getAlgorithmParameters("EC");
            algParams.init(key.getParams());
            return algParams.getParameterSpec(ECGenParameterSpec.class).getName();
        }
        catch (NoSuchAlgorithmException|InvalidParameterSpecException ex) {
            throw newECError(runtime, ex.getMessage());
        }
        catch (Exception ex) {
            throw (RaiseException) newECError(runtime, ex.toString()).initCause(ex);
        }
    }

    private void setGroup(final Group group) {
        this.group = group;
        this.curveName = this.group.getCurveName();
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    @Override
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final PKeyEC that = (PKeyEC) original;
        this.publicKey = that.publicKey;
        this.privateKey = that.privateKey;
        this.curveName = that.curveName;
        this.group = that.group;

        return this;
    }

    @JRubyMethod
    public IRubyObject check_key(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        if (publicKey == null) {
            throw newECError(runtime, "invalid key: no public key");
        }
        try {
            final ECParameterSpec spec = publicKey.getParams();
            final BigInteger order = spec.getOrder();
            final BigInteger cofactor = BigInteger.valueOf(spec.getCofactor());
            final ECCurve curve = toBCCurve(spec.getCurve(), order, cofactor);
            final org.bouncycastle.math.ec.ECPoint pub = toBCPoint(curve, publicKey.getW()).normalize();

            if (pub.isInfinity()) throw newECError(runtime, "point at infinity");
            if (!pub.isValid()) throw newECError(runtime, "point is not on curve");
            if (!pub.multiply(order).isInfinity()) throw newECError(runtime, "invalid point order");

            if (privateKey instanceof ECPrivateKey) {
                final BigInteger s = ((ECPrivateKey) privateKey).getS();
                if (s.signum() <= 0 || s.compareTo(order) >= 0) {
                    throw newECError(runtime, "invalid private key");
                }
                final org.bouncycastle.math.ec.ECPoint gen = toBCPoint(curve, spec.getGenerator());
                if (!gen.multiply(s).normalize().equals(pub)) {
                    throw newECError(runtime, "public key does not match private key");
                }
            }
        }
        catch (RaiseException e) { throw e; }
        catch (Exception e) {
            throw newECError(runtime, e.getMessage(), e);
        }
        return runtime.getTrue();
    }

    @JRubyMethod(name = "generate_key!", alias = "generate_key")
    public PKeyEC generate_key(final ThreadContext context) {
        try {
            ECGenParameterSpec genSpec = new ECGenParameterSpec(getCurveName());
            KeyPairGenerator gen = SecurityHelper.getKeyPairGenerator("EC"); // "BC"
            gen.initialize(genSpec, OpenSSL.getSecureRandom(context));
            KeyPair pair = gen.generateKeyPair();
            this.publicKey = (ECPublicKey) pair.getPublic();
            this.privateKey = pair.getPrivate();
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            throw newECError(context.runtime, ex.getMessage());
        }
        catch (GeneralSecurityException ex) {
            throw (RaiseException) newECError(context.runtime, ex.toString()).initCause(ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(context.runtime, ex);
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
            Signature signer = SecurityHelper.getSignature("NONEwithECDSA");
            signer.initSign(privateKey);
            signer.update(data.convertToString().getBytes());
            return newString(context.runtime, signer.sign());
        }
        catch (Exception ex) {
            throw newECError(context.runtime, ex.toString(), ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(context.runtime, ex);
        }
    }

    @JRubyMethod(name = "dsa_verify_asn1")
    public IRubyObject dsa_verify_asn1(final ThreadContext context, final IRubyObject data, final IRubyObject sign) {
        final Ruby runtime = context.runtime;
        final ByteList signature = sign.convertToString().getByteList();
        final ByteList dataBytes = data.convertToString().getByteList();
        try {
            return runtime.newBoolean(doVerifyECDSA(signature, dataBytes));
        }
        catch (SignatureException ex) {
            throw newECError(runtime, "invalid signature: " + ex.getMessage(), ex);
        }
        catch (GeneralSecurityException ex) {
            throw newECError(runtime, ex.getMessage(), ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(runtime, ex);
        }
    }

    // sign_raw(digest, data) -- signs pre-hashed (raw) bytes with the EC private key.
    // Produces a DER-encoded ASN.1 SEQUENCE [r, s], identical to dsa_sign_asn1.
    // The digest argument is accepted for API parity with RSA/DSA sign_raw but is unused;
    // ECDSASigner operates directly on the supplied bytes without additional hashing.
    @JRubyMethod(name = "sign_raw")
    public IRubyObject sign_raw(final ThreadContext context, final IRubyObject digest, final IRubyObject data) {
        return dsa_sign_asn1(context, data);
    }

    // verify_raw(digest, signature, data) -- verifies a DER-encoded ECDSA signature over raw bytes.
    // Returns true/false; returns false (rather than raising) for a malformed or invalid signature.
    // Argument order matches PKey#verify_raw convention: (digest, signature, data),
    // unlike dsa_verify_asn1 which takes (data, signature).
    @JRubyMethod(name = "verify_raw")
    public IRubyObject verify_raw(final ThreadContext context, final IRubyObject digest,
                                  final IRubyObject sign, final IRubyObject data) {
        final Ruby runtime = context.runtime;
        final ByteList signature = sign.convertToString().getByteList();
        final ByteList dataBytes = data.convertToString().getByteList();
        try {
            checkSignatureEncoding(signature);
            return runtime.newBoolean(doVerifyECDSA(signature, dataBytes));
        }
        catch (IOException | IllegalArgumentException ex) {
            throw newPKeyError(runtime, ex.getMessage()); // "EVP_PKEY_verify"
        }
        catch (GeneralSecurityException ex) {
            LOG.debugStack(runtime, "verify_raw", ex);
            return runtime.getFalse();
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(runtime, ex);
        }
    }

    private boolean doVerifyECDSA(final ByteList signature, final ByteList dataBytes)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature verifier = SecurityHelper.getSignature("NONEwithECDSA");
        verifier.initVerify(publicKey);
        verifier.update(dataBytes.unsafeBytes(), dataBytes.begin(), dataBytes.realSize());
        return verifier.verify(signature.unsafeBytes(), signature.begin(), signature.realSize());
    }

    private static void checkSignatureEncoding(final ByteList signature)
        throws IOException, IllegalArgumentException {
        final ASN1Sequence sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(signature.bytes()));
        if (sequence.size() != 2) throw new IOException("invalid ECDSA signature");
        ASN1Integer.getInstance(sequence.getObjectAt(0));
        ASN1Integer.getInstance(sequence.getObjectAt(1));
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

                KeyFactory keyFactory = SecurityHelper.getKeyFactory("EC");
                ECParameterSpec spec = getParamSpec(name);
                ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(new ECPublicKeySpec(ecPoint, spec));
                agreement.doPhase(ecPublicKey, true);
            }
            final byte[] secret = agreement.generateSecret();
            return newString(context.runtime, secret);
        }
        catch (InvalidKeyException ex) {
            throw newECError(context.runtime, "invalid key: " + ex.getMessage());
        }
        catch (GeneralSecurityException ex) {
            throw newECError(context.runtime, ex.toString());
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(context.runtime, ex);
        }
    }

    // derive(peer_key) -- computes the ECDH shared secret with a peer EC public key.
    // Equivalent to dh_compute_key(peer_key.public_key).
    @Override
    public IRubyObject derive(final ThreadContext context, final IRubyObject peer_pkey) {
        if (!(peer_pkey instanceof PKeyEC)) {
            throw context.runtime.newTypeError(peer_pkey, _EC(context.runtime));
        }
        final IRubyObject peerPublicKey = ((PKeyEC) peer_pkey).public_key(context);
        if (peerPublicKey.isNil()) {
            throw newECError(context.runtime, "no public key");
        }
        return dh_compute_key(context, peerPublicKey);
    }

    @Override
    public RubyString oid() {
        return getRuntime().newString("id-ecPublicKey");
    }

    private Group getGroup(boolean required) {
        if (group == null) {
            return group = new Group(getRuntime(), this);
        }
        return group;
    }

    /**
     * @return OpenSSL::PKey::EC::Group
     */
    @JRubyMethod
    public IRubyObject group(ThreadContext context) {
        Group group = this.group;
        if (group != null) return group;

        if (getCurveName() == null) {
            return context.nil; // PKey::EC.new with no args / no curve configured
        }
        group = getGroup(false);
        return group == null ? context.nil : group;
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

    // converts ASN1-layer named curve params to JCA ECParameterSpec
    private static ECParameterSpec getParamSpec(final String curveName) {
        final org.bouncycastle.asn1.x9.X9ECParameters x9 =
            org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(curveName);
        if (x9 == null) return null;

        final org.bouncycastle.math.ec.ECCurve bcCurve = x9.getCurve();
        final EllipticCurve curve = new EllipticCurve(
            new ECFieldFp(bcCurve.getField().getCharacteristic()),
            bcCurve.getA().toBigInteger(),
            bcCurve.getB().toBigInteger(),
            x9.getSeed()
        );
        final ECPoint generator = new ECPoint(
            x9.getG().getAffineXCoord().toBigInteger(),
            x9.getG().getAffineYCoord().toBigInteger()
        );
        return new ECParameterSpec(curve, generator, x9.getN(), x9.getH().intValue());
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

    @JRubyMethod(name = "public?", alias = "public_key?")
    public RubyBoolean public_p() {
        return publicKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @JRubyMethod(name = "private?", alias = "private_key?")
    public RubyBoolean private_p() {
        return privateKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @Override
    public RubyString public_to_der(ThreadContext context) {
        return public_to_der(context.runtime);
    }

    private RubyString public_to_der(final Ruby runtime) {
        final byte[] bytes;
        try {
            bytes = publicKey.getEncoded();
        } catch (Exception e) {
            throw newECError(runtime, e.getMessage(), e);
        }
        return newString(runtime, bytes);
    }

    @Override
    @JRubyMethod(name = "to_der")
    public RubyString to_der() {
        final Ruby runtime = getRuntime();
        if (publicKey != null && privateKey == null) {
            return public_to_der(runtime);
        }
        if (privateKey == null) {
            throw newECError(runtime, "can't export - no public key set");
        }

        try {
            byte[] encoded = toPrivateKeyStructure((ECPrivateKey) privateKey, publicKey, false).getEncoded(ASN1Encoding.DER);
            return newString(runtime, encoded);
        } catch (Exception e) {
            throw newECError(runtime, e.getMessage(), e);
        }
    }

    @Override
    public RubyString private_to_der(ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        if (args.length > 0) {
            throw newECError(runtime, "encryption not supported for EC private key export");
        }
        final byte[] encoded;
        if (privateKey instanceof ECPrivateKey) {
            try {
                encoded = toPrivateKeyInfo((ECPrivateKey) privateKey, publicKey).getEncoded(ASN1Encoding.DER);
            } catch (IOException e) {
                throw newECError(runtime, e.getMessage(), e);
            }
        } else {
            try {
                encoded = privateKey.getEncoded();
            } catch (Exception e) {
                throw newECError(runtime, e.getMessage(), e);
            }
        }
        return newString(runtime, encoded);
    }

    private static org.bouncycastle.asn1.sec.ECPrivateKey toPrivateKeyStructure(final ECPrivateKey privateKey,
                                                                                final ECPublicKey publicKey,
                                                                                final boolean compressed) throws IOException {
        final ECParameterSpec ecSpec = privateKey.getParams();
        final X962Parameters params = getDomainParametersFromName(ecSpec, compressed);

        // named curves always have an explicit order; implicitCA is not used
        int orderBitLength = ecSpec != null ? ecSpec.getOrder().bitLength() : privateKey.getS().bitLength();

        if (publicKey == null) {
            return new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, privateKey.getS(), params);
        }

        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(publicKey.getEncoded()));
        return PKeyShim.newECPrivateKey(orderBitLength, privateKey.getS(), info.getPublicKeyData(), params);
    }

    private static PrivateKeyInfo toPrivateKeyInfo(final ECPrivateKey privateKey,
                                                   final ECPublicKey publicKey) throws IOException {
        final ECParameterSpec ecSpec = privateKey.getParams();
        final X962Parameters params = getDomainParametersFromName(ecSpec, false);

        org.bouncycastle.asn1.sec.ECPrivateKey keyStructure = toPrivateKeyStructure(privateKey, publicKey, false);
        return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);
    }

    private static X962Parameters getDomainParametersFromName(ECParameterSpec ecSpec, boolean compressed) {
        if (ecSpec != null) {
            // try to resolve as a named curve by matching order against the ASN1 curve table
            ASN1ObjectIdentifier curveOid = findNamedCurveOID(ecSpec);
            if (curveOid != null) return new X962Parameters(curveOid);
        }

        if (ecSpec == null) return new X962Parameters(DERNull.INSTANCE);

        ECCurve curve = toBCCurve(ecSpec.getCurve());

        X9ECParameters ecParameters = new X9ECParameters(
                curve,
                new X9ECPoint(toBCPoint(curve, ecSpec.getGenerator()), compressed),
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());

        return new X962Parameters(ecParameters);
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

        if (privateKey == null) return public_to_pem(context);

        try {
            final StringWriter writer = new StringWriter();
            // Include curve OID and public-key point so the PEM can be decoded
            // stand-alone (SEC1 optional fields parameters[0] and publicKey[1]).
            final ASN1ObjectIdentifier curveOID = getCurveOID(getCurveName()).orElse(null);
            byte[] pubKeyBytes = null;
            if (publicKey != null) {
                pubKeyBytes = toBCPoint(publicKey.getParams(), publicKey.getW()).getEncoded(false);
            }
            PEMInputOutput.writeECPrivateKey(writer, (ECPrivateKey) privateKey,
                    curveOID, pubKeyBytes, spec, passwd);
            return RubyString.newString(context.runtime, writer.getBuffer());
        } catch (IOException ex) {
            throw newECError(context.runtime, ex.getMessage(), ex);
        }
    }

    @Override
    public RubyString public_to_pem(ThreadContext context) {
        try {
            final StringWriter writer = new StringWriter();
            PEMInputOutput.writePublicKey(writer, publicKey);
            return RubyString.newString(context.runtime, writer.getBuffer());
        } catch (IOException ex) {
            throw newECError(context.runtime, ex.getMessage(), ex);
        }
    }

    @Override
    @JRubyMethod
    public RubyString to_text() {
        StringBuilder result = new StringBuilder();
        final ECParameterSpec spec = getParamSpec();
        result.append("Private-Key: (").append(spec.getOrder().bitLength()).append(" bit)").append('\n');

        if (privateKey instanceof ECPrivateKey) {
            result.append("priv:");
            addSplittedAndFormatted(result, ((ECPrivateKey) privateKey).getS());
        }

        if (publicKey != null) {
            result.append("pub:");
            final byte[] pubBytes = encodeCompressed(publicKey.getW());
            final StringBuilder hexBytes = new StringBuilder(pubBytes.length * 2);
            for (byte b: pubBytes) hexBytes.append(Integer.toHexString(Byte.toUnsignedInt(b)));
            addSplittedAndFormatted(result, hexBytes);
        }
        result.append("ASN1 OID: ").append(getCurveName()).append('\n');

        return RubyString.newString(getRuntime(), result);
    }

    private enum PointConversion {
        COMPRESSED, UNCOMPRESSED, HYBRID;

        String toRubyString() {
            return super.toString().toLowerCase(Locale.ROOT);
        }
    }

    @JRubyClass(name = "OpenSSL::PKey::EC::Group")
    public static final class Group extends RubyObject {

        static void createGroup(final Ruby runtime, final RubyClass EC, final RubyClass OpenSSLError) {
            RubyClass Group = EC.defineClassUnder("Group", runtime.getObject(), Group::new);

            // OpenSSL::PKey::EC::Group::Error
            Group.defineClassUnder("Error", OpenSSLError, OpenSSLError.getAllocator());

            Group.defineAnnotatedMethods(Group.class);
        }

        static RaiseException newGroupError(final Ruby runtime, final String message) {
            return newError(runtime, _EC(runtime).getClass("Group").getClass("Error"), message);
        }

        private EllipticCurve curve;
        private ECPoint generator;
        private BigInteger order;
        private int cofactor;

        private transient ECParameterSpec paramSpec; // cached from above fields

        private PointConversion conversionForm = PointConversion.UNCOMPRESSED;

        private int asn1Flag = 1; // OPENSSL_EC_NAMED_CURVE

        private String curveName;
        private RubyString impl_curve_name;

        public Group(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        Group(Ruby runtime, PKeyEC key) {
            this(runtime, _EC(runtime).getClass("Group"));
            final String curveName = key.getCurveName();
            if (curveName != null) setCurveName(runtime, curveName);
        }

        @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final Ruby runtime = context.runtime;

            final int argc = Arity.checkArgumentCount(runtime, args, 1, 4);
            if ( argc == 1 ) {
                IRubyObject arg = args[0];

                if ( arg instanceof Group ) {
                    final Group src = (Group) arg;
                    this.curveName = src.curveName;
                    this.impl_curve_name = src.impl_curve_name;
                    this.paramSpec = src.paramSpec;
                    this.curve = src.curve;
                    this.generator = src.generator;
                    this.order = src.order;
                    this.cofactor = src.cofactor;
                    this.asn1Flag = src.asn1Flag;
                    this.conversionForm = src.conversionForm;
                    return this;
                }

                final RubyString strArg = arg.convertToString();
                final byte[] bytes = strArg.getBytes();
                // Detect DER input: OID tag (0x06) for named curve, SEQUENCE tag (0x30) for explicit params
                if (bytes.length > 0 && (bytes[0] == 0x06 || bytes[0] == 0x30)) {
                    try {
                        final ASN1Primitive primitive = ASN1Primitive.fromByteArray(bytes);
                        if (primitive instanceof ASN1ObjectIdentifier) {
                            // Named curve: DER-encoded OID  ->  look up curve name
                            setCurveName(runtime, PKeyEC.getCurveName((ASN1ObjectIdentifier) primitive));
                            this.asn1Flag = 1; // NAMED_CURVE
                            return this;
                        } else if (primitive instanceof ASN1Sequence) { // explicit X9.62 ECParameters SEQUENCE
                            final X9ECParameters ecParams = X9ECParameters.getInstance(primitive);
                            final EllipticCurve curve = convertCurve(ecParams);
                            this.curve = curve;
                            this.generator = convertPoint(ecParams.getG());
                            this.order = ecParams.getN();
                            this.cofactor = ecParams.getH().intValue();
                            this.asn1Flag = 0; // explicit
                            return this;
                        }
                    } catch (IOException e) {
                        // fall through to treat as curve name string
                    }
                }

                this.impl_curve_name = strArg;
            } else if (argc == 4) {
                if (!(args[0] instanceof RubySymbol)) {
                    throw runtime.newArgumentError("unknown argument, must be :GFp or :GF2m");
                }
                final String fieldType = ((RubySymbol) args[0]).asJavaString();
                if ("GFp".equals(fieldType)) {
                    this.curve = new EllipticCurve(
                            new ECFieldFp(getBigInteger(context, args[1])),
                            getBigInteger(context, args[2]),
                            getBigInteger(context, args[3]));
                    this.asn1Flag = 0;
                } else if ("GF2m".equals(fieldType)) {
                    throw newGroupError(runtime, "unsupported field");
                } else {
                    throw runtime.newArgumentError("unknown symbol, must be :GFp or :GF2m");
                }
            }
            return this;
        }

        @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
        public IRubyObject initialize_copy(final IRubyObject original) {
            if (original instanceof Group) {
                final Group src = (Group) original;
                this.curveName = src.curveName;
                this.impl_curve_name = src.impl_curve_name;
                this.curve = src.curve;
                this.generator = src.generator;
                this.order = src.order;
                this.cofactor = src.cofactor;
                this.asn1Flag = src.asn1Flag;
                this.conversionForm = src.conversionForm;
            }
            return this;
        }

        private String getCurveName() {
            if (curveName == null) {
                if (impl_curve_name == null) {
                    throw newGroupError(getRuntime(), "no curve name");
                }
                return impl_curve_name.asJavaString();
            }
            return curveName;
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
            if (impl_curve_name == null && curveName != null) {
                setCurveName(runtime, curveName);
            }
            return impl_curve_name;
        }

        private void setCurveName(final Ruby runtime, String curveName) {
            assert curveName != null;
            this.curveName = curveName;
            String prefix;
            // BC 1.54: "brainpoolP512t1" 1.55: "brainpoolp512t1"
            if (curveName.startsWith(prefix = "brainpoolp")) {
                curveName = "brainpoolP" + curveName.substring(prefix.length());
            }
            impl_curve_name = RubyString.newString(runtime, curveName);
        }

        @JRubyMethod
        public IRubyObject order(final ThreadContext context) {
            return BN.newBN(context.runtime, order != null ? order : getParamSpec().getOrder());
        }

        @JRubyMethod
        public IRubyObject cofactor(final ThreadContext context) {
            return context.runtime.newFixnum(order != null ? cofactor : getParamSpec().getCofactor());
        }

        @JRubyMethod
        public IRubyObject seed(final ThreadContext context) {
            final byte[] seed = getCurve().getSeed();
            return seed == null ? context.nil : newString(context.runtime, seed);
        }

        @JRubyMethod
        public IRubyObject degree(final ThreadContext context) {
            final int fieldSize = getCurve().getField().getFieldSize();
            return context.runtime.newFixnum(fieldSize);
        }

        @JRubyMethod
        public IRubyObject generator(final ThreadContext context) {
            final ECPoint generator = this.generator != null ? this.generator : getParamSpec().getGenerator();
            return new Point(context.runtime, generator, this);
        }

        @JRubyMethod(name = "set_generator")
        public IRubyObject set_generator(final ThreadContext context, final IRubyObject generator, final IRubyObject order, final IRubyObject cofactor) {
            if (!(generator instanceof Point)) throw context.runtime.newTypeError(generator, _EC(context.runtime).getClass("Point"));
            this.generator = ((Point) generator).asECPoint();
            this.order = getBigInteger(context, order);
            this.cofactor = getBigInteger(context, cofactor).intValue();
            this.paramSpec = null; // new ECParameterSpec(getCurve(), this.generator, this.order, this.cofactor)
            return this;
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

        @JRubyMethod(name = "asn1_flag")
        public IRubyObject asn1_flag(final ThreadContext context) {
            return context.runtime.newFixnum(asn1Flag);
        }

        @JRubyMethod(name = "asn1_flag=")
        public IRubyObject set_asn1_flag(final ThreadContext context, final IRubyObject flag_v) {
            this.asn1Flag = (int) RubyFixnum.num2long(flag_v);
            return flag_v;
        }

        /**
         * Serializes the group as DER. For named curves (NAMED_CURVE flag set) this is the
         * DER encoding of the curve OID. For explicit parameters it is the DER encoding of
         * the X9.62 ECParameters SEQUENCE – matching OpenSSL's i2d_ECPKParameters().
         */
        @JRubyMethod(name = "to_der")
        public RubyString to_der(final ThreadContext context) {
            final Ruby runtime = context.runtime;
            try {
                final byte[] encoded;
                if ((asn1Flag & 1) != 0) { // NAMED_CURVE: encode as DER OID
                    final ASN1ObjectIdentifier oid = getCurveOID(getCurveName())
                            .orElseThrow(() -> newGroupError(runtime, "invalid curve name: " + getCurveName()));
                    encoded = oid.getEncoded(ASN1Encoding.DER);
                } else { // explicit parameters: encode as X9.62 ECParameters SEQUENCE
                    final ECParameterSpec ps = getParamSpec();
                    final ECCurve bcCurve = toBCCurve(ps.getCurve());
                    final X9ECParameters ecParameters = new X9ECParameters(
                            bcCurve,
                            new X9ECPoint(toBCPoint(bcCurve, ps.getGenerator()), false),
                            ps.getOrder(),
                            BigInteger.valueOf(ps.getCofactor()),
                            ps.getCurve().getSeed());
                    encoded = ecParameters.getEncoded(ASN1Encoding.DER);
                }
                return newString(runtime, encoded);
            } catch (IOException e) {
                throw newGroupError(runtime, e.getMessage());
            }
        }

        private ECParameterSpec getParamSpec() {
            if (paramSpec == null) {
                if (curve != null && generator != null) {
                    paramSpec = new ECParameterSpec(curve, generator, order, cofactor);
                } else {
                    paramSpec = PKeyEC.getParamSpec(getCurveName());
                }
            }
            return paramSpec;
        }

        EllipticCurve getCurve() {
            return curve != null ? curve : getParamSpec().getCurve();
        }

        // order/cofactor are not part of EllipticCurve but bc-fips insists on having them
        BigInteger getOrder() {
            return order != null ? order : getParamSpec().getOrder();
        }

        BigInteger getCofactor() {
            return BigInteger.valueOf(order != null ? cofactor : getParamSpec().getCofactor());
        }

        int getBitLength() {
            return getCurve().getField().getFieldSize();
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
    }

    @JRubyClass(name = "OpenSSL::PKey::EC::Point")
    public static final class Point extends RubyObject {

        static void createPoint(final Ruby runtime, final RubyClass EC, final RubyClass OpenSSLError) {
            RubyClass Point = EC.defineClassUnder("Point", runtime.getObject(), Point::new);

            // OpenSSL::PKey::EC::Point::Error
            Point.defineClassUnder("Error", OpenSSLError, OpenSSLError.getAllocator());

            Point.defineAnnotatedMethods(Point.class);
        }

        public Point(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        private ECPoint point;
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

        private static RaiseException newPointError(final Ruby runtime, final String message) {
            return newError(runtime, _EC(runtime).getClass("Point").getClass("Error"), message);
        }

        @JRubyMethod(visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject groupOrPoint) {
            getPointAndGroup(context, groupOrPoint);

            return this;
        }

        @JRubyMethod(visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject groupOrPoint, final IRubyObject bn) {
            if (getPointAndGroup(context, groupOrPoint)) {
                return this;
            }

            final byte[] encoded;
            if (bn instanceof BN) {
                encoded = ((BN) bn).getValue().abs().toByteArray();
            } else {
                encoded = bn.convertToString().getBytes();
            }
            try {
                this.point = convertPoint(toBCCurve(group.getCurve()).decodePoint(encoded));
            }
            catch (IllegalArgumentException ex) {
                // MRI: OpenSSL::PKey::EC::Point::Error: invalid encoding
                throw newPointError(context.runtime, ex.getMessage());
            }

            return this;
        }

        private boolean getPointAndGroup(ThreadContext context, IRubyObject groupOrPoint) {
            final Ruby runtime = context.runtime;

            if ( groupOrPoint instanceof Point) {
                this.group = ((Point) groupOrPoint).group;
                this.point = ((Point) groupOrPoint).point;
                return true;
            }

            if ( groupOrPoint instanceof Group) {
                this.group = (Group) groupOrPoint;
            } else {
                throw runtime.newTypeError(groupOrPoint, _EC(runtime).getClass("Group"));
            }
            return false;
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
                    assert group != null;
                    encoded = encodeUncompressed(group.getBitLength(), point);
                    break;
                case COMPRESSED:
                    encoded = encodeCompressed(point);
                    break;
                case HYBRID:
                    assert group != null;
                    encoded = encodeHybrid(group.getBitLength(), point);
                    break;
                default:
                    throw new AssertionError("unexpected conversion form: " + conversionForm);
            }
            return encoded;
        }

        @JRubyMethod
        public IRubyObject to_octet_string(final ThreadContext context, final IRubyObject conversion_form) {
            final PointConversion conversionForm = Group.parse_point_conversion_form(context.runtime, conversion_form);
            return newString(context.runtime, encodePoint(conversionForm));
        }

        private boolean isInfinity() {
            return point == ECPoint.POINT_INFINITY;
        }

        @JRubyMethod(name = "infinity?")
        public RubyBoolean infinity_p() {
            return getRuntime().newBoolean( isInfinity() );
        }

        @JRubyMethod(name = "on_curve?")
        public RubyBoolean on_curve_p(ThreadContext context) {
            if (isInfinity()) return context.tru;
            try {
                return context.runtime.newBoolean(toBCPoint(toBCCurve(group.getCurve()), point).isValid());
            }
            catch (IllegalArgumentException ex) {
                return context.fals;
            }
        }

        @JRubyMethod(name = "set_to_infinity!")
        public IRubyObject set_to_infinity_b() {
            this.point = ECPoint.POINT_INFINITY;
            return this;
        }

        @JRubyMethod(name = "invert!")
        public IRubyObject invert_bang() {
            if (isInfinity()) return this;

            final ECCurve curve = toBCCurve(group.getCurve());
            this.point = convertPoint(toBCPoint(curve, point).negate());
            return this;
        }

        @Override
        @JRubyMethod
        @SuppressWarnings("unchecked")
        public IRubyObject inspect() {
            VariableEntry entry = new VariableEntry( "group", group == null ? (Object) "nil" : group );
            return ObjectSupport.inspect(this, (List) Collections.singletonList(entry));
        }

        @JRubyMethod(name = "add")
        public IRubyObject add(final ThreadContext context, final IRubyObject other) {
            Ruby runtime = context.runtime;
            if (!(other instanceof Point)) throw runtime.newTypeError(other, _EC(runtime).getClass("Point"));

            org.bouncycastle.math.ec.ECPoint pointSelf, pointOther, pointResult;

            Group groupV = this.group;
            Point result;

            ECCurve selfCurve = toBCCurve(groupV);
            pointSelf = toBCPoint(selfCurve, asECPoint());

            Point otherPoint = (Point) other;
            ECCurve otherCurve = toBCCurve(otherPoint.group);
            pointOther = toBCPoint(otherCurve, otherPoint.asECPoint());

            pointResult = pointSelf.add(pointOther);
            if (pointResult == null) {
                throw newECError(runtime, "EC_POINT_add");
            }

            result = new Point(runtime, convertPoint(pointResult), group);

            return result;
        }

        @JRubyMethod(name = "mul")
        public IRubyObject mul(final ThreadContext context, final IRubyObject bn1) {
            Ruby runtime = context.runtime;

            if (bn1 instanceof RubyArray) {
                throw runtime.newNotImplementedError("calling #mul with arrays is not supported by this OpenSSL version");
            }

            org.bouncycastle.math.ec.ECPoint pointSelf;

            Group groupV = this.group;

            ECCurve selfCurve = toBCCurve(groupV);
            pointSelf = toBCPoint(selfCurve, asECPoint());

            BigInteger bn = getBigInteger(context, bn1);

            org.bouncycastle.math.ec.ECPoint mulPoint = ECAlgorithms.referenceMultiply(pointSelf, bn);
            if (mulPoint == null) {
                throw newECError(runtime, "bad multiply result");
            }

            return new Point(runtime, convertPoint(mulPoint), groupV);
        }

        @JRubyMethod(name = "mul")
        public IRubyObject mul(final ThreadContext context, final IRubyObject bn1, final IRubyObject bn2) {
            Ruby runtime = context.runtime;

            if (bn1 instanceof RubyArray) {
                throw runtime.newNotImplementedError("calling #mul with arrays is not supported by this OpenSSL version");
            }

            org.bouncycastle.math.ec.ECPoint pointSelf, pointResult;

            Group groupV = this.group;

            ECCurve selfCurve = toBCCurve(groupV);
            pointSelf = toBCPoint(selfCurve, asECPoint());

            ECCurve resultCurve = toBCCurve(groupV);
            pointResult = toBCPoint(resultCurve, ((Point) groupV.generator(context)).asECPoint());

            BigInteger bn = getBigInteger(context, bn1);
            BigInteger bn_g = getBigInteger(context, bn2);

            org.bouncycastle.math.ec.ECPoint mulPoint = ECAlgorithms.sumOfTwoMultiplies(pointResult, bn_g, pointSelf, bn);

            if (mulPoint == null) {
                throw newECError(runtime, "bad multiply result");
            }

            return new Point(runtime, convertPoint(mulPoint), groupV);
        }

        @JRubyMethod(name = "mul")
        public IRubyObject mul(final ThreadContext context, final IRubyObject bns, final IRubyObject points, final IRubyObject bn2) {
            throw context.runtime.newNotImplementedError("calling #mul with arrays is not supported by this OpenSSL version");
        }

        @Deprecated
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final int argc = Arity.checkArgumentCount(context.runtime, args, 1, 2);

            switch (argc) {
                case 1:
                    return initialize(context, args[0]);
                case 2:
                    return initialize(context, args[0], args[1]);
                default:
                    throw context.runtime.newArgumentError(args.length, 1);
            }
        }

    }

    private static BigInteger getBigInteger(ThreadContext context, IRubyObject arg1) {
        BigInteger bn;
        if (arg1 instanceof RubyFixnum) {
            bn = BigInteger.valueOf(arg1.convertToInteger().getLongValue());
        } else if (arg1 instanceof RubyBignum) {
            bn = ((RubyBignum) arg1).getValue();
        } else if (arg1 instanceof BN) {
            bn = ((BN) arg1).getValue();
        } else {
            Ruby runtime = context.runtime;
            throw runtime.newTypeError(arg1, runtime.getInteger());
        }
        return bn;
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

    private static byte[] encodeHybrid(final int fieldSize, final ECPoint point) {
        final byte[] encoded = encodeUncompressed(fieldSize, point);
        if (encoded.length > 1) encoded[0] = (byte) (point.getAffineY().testBit(0) ? 0x07 : 0x06);
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
