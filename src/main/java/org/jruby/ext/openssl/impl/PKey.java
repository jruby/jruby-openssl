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
 * Copyright (C) 2010 Hiroshi Nakamura <nahi@ruby-lang.org>
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
package org.jruby.ext.openssl.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.openssl.PEMParser;

import org.jruby.ext.openssl.SecurityHelper;
import org.jruby.ext.openssl.shim.PKeyShim;

/**
 *
 * Handles PKey related ASN.1 handling.
 *
 * @author <a href="mailto:nahi@ruby-lang.org">Hiroshi Nakamura</a>
 */
public class PKey {

    public enum Type { RSA, DSA, EC, EdDSA, XDH, DH, MLDSA; }

    public static KeyPair readPrivateKey(final Type type, final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readPrivateKey(type, mockPrivateKeyInfo(type, input));
    }

    private static PrivateKeyInfo mockPrivateKeyInfo(final Type type, final byte[] input) throws IOException {
        assert type != null;
        return new PrivateKeyInfo(null, new ASN1InputStream(input).readObject());
    }

    public static KeyPair readPrivateKey(final Type type, final PrivateKeyInfo keyInfo)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec pubSpec; KeySpec privSpec; ASN1Sequence seq;
        switch (type) {
            case RSA:
                seq = (ASN1Sequence) keyInfo.parsePrivateKey();
                if (seq.size() < 9) {
                    throw new IOException("malformed RSA private key (expected 9 elements, got " + seq.size() + ")");
                }
                ASN1Integer mod = (ASN1Integer) seq.getObjectAt(1);
                ASN1Integer pubExp = (ASN1Integer) seq.getObjectAt(2);
                ASN1Integer privExp = (ASN1Integer) seq.getObjectAt(3);
                ASN1Integer p1 = (ASN1Integer) seq.getObjectAt(4);
                ASN1Integer p2 = (ASN1Integer) seq.getObjectAt(5);
                ASN1Integer exp1 = (ASN1Integer) seq.getObjectAt(6);
                ASN1Integer exp2 = (ASN1Integer) seq.getObjectAt(7);
                ASN1Integer crtCoef = (ASN1Integer) seq.getObjectAt(8);
                pubSpec = new RSAPublicKeySpec(mod.getValue(), pubExp.getValue());
                privSpec = new RSAPrivateCrtKeySpec(
                        mod.getValue(), pubExp.getValue(), privExp.getValue(),
                        p1.getValue(), p2.getValue(),
                        exp1.getValue(), exp2.getValue(), crtCoef.getValue());
                break;
            case DSA:
                final ASN1Encodable parsedDSAKey = keyInfo.parsePrivateKey();
                if (parsedDSAKey instanceof ASN1Integer) {
                    // PKCS#8 format: private key is just x (INTEGER), params in AlgorithmIdentifier
                    final BigInteger xVal = ((ASN1Integer) parsedDSAKey).getValue();
                    final DSAParameter dsaParam = DSAParameter.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters());
                    final BigInteger pVal = dsaParam.getP();
                    final BigInteger qVal = dsaParam.getQ();
                    final BigInteger gVal = dsaParam.getG();
                    final BigInteger yVal = gVal.modPow(xVal, pVal);
                    privSpec = new DSAPrivateKeySpec(xVal, pVal, qVal, gVal);
                    pubSpec = new DSAPublicKeySpec(yVal, pVal, qVal, gVal);
                } else {
                    // Traditional "DSA PRIVATE KEY" format: SEQUENCE { version, p, q, g, y, x }
                    seq = (ASN1Sequence) parsedDSAKey;
                    if (seq.size() < 6) {
                        throw new IOException("malformed DSA private key (expected 6 elements, got " + seq.size() + ")");
                    }
                    ASN1Integer p = (ASN1Integer) seq.getObjectAt(1);
                    ASN1Integer q = (ASN1Integer) seq.getObjectAt(2);
                    ASN1Integer g = (ASN1Integer) seq.getObjectAt(3);
                    ASN1Integer y = (ASN1Integer) seq.getObjectAt(4);
                    ASN1Integer x = (ASN1Integer) seq.getObjectAt(5);
                    privSpec = new DSAPrivateKeySpec(x.getValue(), p.getValue(), q.getValue(), g.getValue());
                    pubSpec = new DSAPublicKeySpec(y.getValue(), p.getValue(), q.getValue(), g.getValue());
                }
                break;
            case EC:
                return readECPrivateKey(SecurityHelper.getKeyFactory("EC"), keyInfo);
            case EdDSA:
                return readEdDSAPrivateKey(keyInfo);
            case XDH:
                return readXDHPrivateKey(keyInfo);
            case MLDSA:
                return readMLDSAPrivateKey(keyInfo);
            case DH:
                return readDHPrivateKey(keyInfo);
            default:
                throw new AssertionError("unexpected key type: " + type);
        }
        final KeyFactory keyFactory = SecurityHelper.getKeyFactory(type.name());
        return new KeyPair(keyFactory.generatePublic(pubSpec), keyFactory.generatePrivate(privSpec));
    }

    // d2i_PUBKEY_bio
    public static PublicKey readPublicKey(final byte[] input) throws IOException {
        // Try PEM first
        try (Reader in = new InputStreamReader(new ByteArrayInputStream(input))) {
            Object pemObject = new PEMParser(in).readObject();
            if (pemObject instanceof SubjectPublicKeyInfo) {
                return readPublicKey((SubjectPublicKeyInfo) pemObject);
            }
        } catch (Exception e) {
            if (e instanceof RuntimeException) throw (RuntimeException) e;
            throw new IOException("Could not parse public key: " + e.getMessage(), e);
        }
        // Fall back to DER-encoded SubjectPublicKeyInfo
        try {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(input));
            if (publicKeyInfo != null) return readPublicKey(publicKeyInfo);
        } catch (IllegalArgumentException e) {
            // BC signals a non SubjectPublicKeyInfo shape (input is not a public key)
            throw new IOException("Could not parse public key: " + e.getMessage(), e);
        } catch (Exception e) {
            if (e instanceof RuntimeException) throw (RuntimeException) e;
            throw new IOException("Could not parse public key: " + e.getMessage(), e);
        }
        return null;
    }

    private static PublicKey readPublicKey(final SubjectPublicKeyInfo publicKeyInfo)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Type type = matchPublicKeyType(publicKeyInfo.getAlgorithm());
        final KeyFactory keyFactory = SecurityHelper.getKeyFactory(type.name());
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
    }

    private static Type matchPublicKeyType(final AlgorithmIdentifier algId) throws IOException {
        final ASN1ObjectIdentifier algIdentifier = algId.getAlgorithm();

        if (X9ObjectIdentifiers.id_ecPublicKey.equals(algIdentifier)) return Type.EC;
        if (PKCSObjectIdentifiers.rsaEncryption.equals(algIdentifier)) return Type.RSA;
        if (X9ObjectIdentifiers.id_dsa.equals(algIdentifier)) return Type.DSA;
        if (EdECObjectIdentifiers.id_Ed25519.equals(algIdentifier)) return Type.EdDSA;
        if (EdECObjectIdentifiers.id_Ed448.equals(algIdentifier)) return Type.EdDSA;
        if (EdECObjectIdentifiers.id_X25519.equals(algIdentifier)) return Type.XDH;
        if (EdECObjectIdentifiers.id_X448.equals(algIdentifier)) return Type.XDH;
        if (NISTObjectIdentifiers.id_ml_dsa_44.equals(algIdentifier) ||
            NISTObjectIdentifiers.id_ml_dsa_65.equals(algIdentifier) ||
            NISTObjectIdentifiers.id_ml_dsa_87.equals(algIdentifier)) return Type.MLDSA;
        if (PKCSObjectIdentifiers.dhKeyAgreement.equals(algIdentifier)) return Type.DH;

        throw new IOException("unsupported public key algorithm: " + algIdentifier);
    }

    // d2i_RSAPrivateKey_bio
    public static KeyPair readRSAPrivateKey(final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readRSAPrivateKey(SecurityHelper.getKeyFactory("RSA"), input);
    }

    public static KeyPair readRSAPrivateKey(final KeyFactory rsaFactory, final byte[] input)
        throws IOException, InvalidKeySpecException {
        ASN1Sequence seq;
        ASN1Primitive obj = new ASN1InputStream(input).readObject();
        if (obj instanceof ASN1Sequence && (seq = (ASN1Sequence) obj).size() == 9) {
            BigInteger mod = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            BigInteger pubexp = ((ASN1Integer) seq.getObjectAt(2)).getValue();
            BigInteger privexp = ((ASN1Integer) seq.getObjectAt(3)).getValue();
            BigInteger primep = ((ASN1Integer) seq.getObjectAt(4)).getValue();
            BigInteger primeq = ((ASN1Integer) seq.getObjectAt(5)).getValue();
            BigInteger primeep = ((ASN1Integer) seq.getObjectAt(6)).getValue();
            BigInteger primeeq = ((ASN1Integer) seq.getObjectAt(7)).getValue();
            BigInteger crtcoeff = ((ASN1Integer) seq.getObjectAt(8)).getValue();
            PrivateKey priv = rsaFactory.generatePrivate(new RSAPrivateCrtKeySpec(mod, pubexp, privexp, primep, primeq, primeep, primeeq, crtcoeff));
            PublicKey pub = rsaFactory.generatePublic(new RSAPublicKeySpec(mod, pubexp));
            return new KeyPair(pub, priv);
        }
        return null;
    }

    // d2i_PrivateKey_bio - type specific DER encodings (PKCS#1 RSA, DSA, SEC1 EC)
    public static KeyPair readPrivateKeyDER(final byte[] input) throws IOException {
        try {
            // each reader matches on sequence shape so order does not matter
            KeyPair keyPair = readRSAPrivateKey(input);
            if (keyPair == null) keyPair = readDSAPrivateKey(input);
            if (keyPair == null) keyPair = readECPrivateKey(input);
            return keyPair;
        }
        catch (Exception e) { // the EC reader mocks up a PrivateKeyInfo and blows up in all sorts of ways
            throw new IOException("Could not parse private key: " + e.getMessage(), e);
        }
    }

    // d2i_RSAPublicKey_bio
    public static PublicKey readRSAPublicKey(final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readRSAPublicKey(SecurityHelper.getKeyFactory("RSA"), input);
    }

    public static PublicKey readRSAPublicKey(final KeyFactory rsaFactory, final byte[] input)
        throws IOException, InvalidKeySpecException {
        ASN1Sequence seq;
        ASN1Primitive obj = new ASN1InputStream(input).readObject();
        if (obj instanceof ASN1Sequence && (seq = (ASN1Sequence) obj).size() == 2) {
            BigInteger mod = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger pubexp = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            return rsaFactory.generatePublic(new RSAPublicKeySpec(mod, pubexp));
        }
        return null;
    }

    // d2i_DSAPrivateKey_bio
    public static KeyPair readDSAPrivateKey(final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readDSAPrivateKey(SecurityHelper.getKeyFactory("DSA"), input);
    }

    public static KeyPair readDSAPrivateKey(final KeyFactory dsaFactory, final byte[] input)
        throws IOException, InvalidKeySpecException {
        ASN1Sequence seq;
        ASN1Primitive obj = new ASN1InputStream(input).readObject();
        if (obj instanceof ASN1Sequence && (seq = (ASN1Sequence) obj).size() == 6) {
            BigInteger p = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            BigInteger q = ((ASN1Integer) seq.getObjectAt(2)).getValue();
            BigInteger g = ((ASN1Integer) seq.getObjectAt(3)).getValue();
            BigInteger y = ((ASN1Integer) seq.getObjectAt(4)).getValue();
            BigInteger x = ((ASN1Integer) seq.getObjectAt(5)).getValue();
            PrivateKey priv = dsaFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
            PublicKey pub = dsaFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
            return new KeyPair(pub, priv);
        }
        return null;
    }

    // d2i_DSA_PUBKEY_bio
    public static PublicKey readDSAPublicKey(final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readDSAPublicKey(SecurityHelper.getKeyFactory("DSA"), input);
    }

    public static PublicKey readDSAPublicKey(final KeyFactory dsaFactory, final byte[] input)
        throws IOException, InvalidKeySpecException {
        ASN1Sequence seq;
        ASN1Primitive obj = new ASN1InputStream(input).readObject();
        if (obj instanceof ASN1Sequence) {
            seq = (ASN1Sequence) obj;
            if (seq.size() == 4) {
                BigInteger y = ((ASN1Integer) seq.getObjectAt(0)).getValue();
                BigInteger p = ((ASN1Integer) seq.getObjectAt(1)).getValue();
                BigInteger q = ((ASN1Integer) seq.getObjectAt(2)).getValue();
                BigInteger g = ((ASN1Integer) seq.getObjectAt(3)).getValue();
                return dsaFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
            } else if (seq.size() == 2 && seq.getObjectAt(1) instanceof DERBitString) {
                ASN1Integer y = (ASN1Integer)
                        new ASN1InputStream(((DERBitString) seq.getObjectAt(1)).getBytes()).readObject();
                seq = (ASN1Sequence) ((ASN1Sequence) seq.getObjectAt(0)).getObjectAt(1);
                BigInteger p = ((ASN1Integer) seq.getObjectAt(0)).getValue();
                BigInteger q = ((ASN1Integer) seq.getObjectAt(1)).getValue();
                BigInteger g = ((ASN1Integer) seq.getObjectAt(2)).getValue();
                return dsaFactory.generatePublic(new DSAPublicKeySpec(y.getPositiveValue(), p, q, g));
            }
        }
        return null;
    }

    // d2i_DHparams_bio
    public static DHParameterSpec readDHParameter(final byte[] input) throws IOException {
        ASN1Primitive obj = new ASN1InputStream(input).readObject();
        // DHparameter ::= SEQUENCE { prime INTEGER, base INTEGER, privateValueLength INTEGER OPTIONAL }
        // the size bounds matter: an RSA (9) or DSA (6) private key also starts with two INTEGERs
        if (!(obj instanceof ASN1Sequence) || ((ASN1Sequence) obj).size() < 2 || ((ASN1Sequence) obj).size() > 3) {
            throw new IOException("malformed DH parameters (expected sequence of 2 or 3 elements)");
        }
        ASN1Sequence seq = (ASN1Sequence) obj;
        if (!(seq.getObjectAt(0) instanceof ASN1Integer) || !(seq.getObjectAt(1) instanceof ASN1Integer)) {
            throw new IOException("malformed DH parameters (expected p and g integers)");
        }
        BigInteger p = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger g = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        return new DHParameterSpec(p, g);
    }

    // PKCS#8 DH - only the private value is stored, the public one gets derived
    private static KeyPair readDHPrivateKey(final PrivateKeyInfo keyInfo)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = SecurityHelper.getKeyFactory("DH");
        DHPrivateKey privateKey = (DHPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyInfo.getEncoded()));
        DHParameterSpec params = privateKey.getParams();
        BigInteger y = params.getG().modPow(privateKey.getX(), params.getP());
        PublicKey publicKey = keyFactory.generatePublic(new DHPublicKeySpec(y, params.getP(), params.getG()));
        return new KeyPair(publicKey, privateKey);
    }

    private static KeyPair readMLDSAPrivateKey(final PrivateKeyInfo keyInfo)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final ASN1ObjectIdentifier oid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();
        final int parameter = NISTObjectIdentifiers.id_ml_dsa_44.equals(oid) ? 44 :
            NISTObjectIdentifiers.id_ml_dsa_65.equals(oid) ? 65 : 87;
        final int expandedLength = parameter == 44 ? 2560 : parameter == 65 ? 4032 : 4896;
        final ASN1Encodable encoded = keyInfo.parsePrivateKey();
        byte[] seed = null;
        byte[] expanded = null;
        if (encoded instanceof ASN1TaggedObject) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) encoded;
            if (!tagged.hasContextTag(0) || tagged.isExplicit()) throw new InvalidKeySpecException("invalid ML-DSA seed tag");
            seed = ASN1OctetString.getInstance(tagged, false).getOctets();
        }
        else if (encoded instanceof ASN1Sequence) {
            ASN1Sequence both = (ASN1Sequence) encoded;
            if (both.size() != 2) throw new InvalidKeySpecException("invalid ML-DSA private key sequence");
            seed = ASN1OctetString.getInstance(both.getObjectAt(0)).getOctets();
            expanded = ASN1OctetString.getInstance(both.getObjectAt(1)).getOctets();
        }
        else {
            expanded = ASN1OctetString.getInstance(encoded).getOctets();
        }
        if (expanded != null && expanded.length != expandedLength) {
            throw new InvalidKeySpecException("invalid ML-DSA expanded key length");
        }
        final MLDSAParameterSpec parameters = MLDSAParameterSpec.fromName("ML-DSA-" + parameter);
        // BC 1.80 misreads standardized seed encodings; its KeySpec works across supported BCs.
        final KeySpec spec = seed != null ? new MLDSAPrivateKeySpec(parameters, seed) :
            new MLDSAPrivateKeySpec(parameters, expanded, null);
        final PrivateKey privateKey = SecurityHelper.getKeyFactory("ML-DSA").generatePrivate(spec);
        if (!(privateKey instanceof MLDSAPrivateKey)) {
            throw new InvalidKeySpecException("ML-DSA public key derivation requires a BC private key");
        }
        final MLDSAPrivateKey key = (MLDSAPrivateKey) privateKey;
        if (expanded != null && !org.bouncycastle.util.Arrays.constantTimeAreEqual(expanded, key.getPrivateData())) {
            throw new InvalidKeySpecException("ML-DSA seed does not match expanded key");
        }
        if (keyInfo.hasPublicKey() && !org.bouncycastle.util.Arrays.constantTimeAreEqual(
                keyInfo.getPublicKeyData().getOctets(), key.getPublicKey().getPublicData())) {
            throw new InvalidKeySpecException("ML-DSA public key does not match private key");
        }
        return new KeyPair(key.getPublicKey(), privateKey);
    }

    // XDH (X25519 / X448)
    private static KeyPair readXDHPrivateKey(final PrivateKeyInfo keyInfo)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final String algorithm =
            EdECObjectIdentifiers.id_X448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()) ? "X448" : "X25519";
        KeyFactory keyFactory = SecurityHelper.getKeyFactory(algorithm);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyInfo.getEncoded()));
        PublicKey publicKey = null;
        if (privateKey instanceof XDHPrivateKey) { // assuming BC provider
            publicKey = ((XDHPrivateKey) privateKey).getPublicKey();
        }
        return new KeyPair(publicKey, privateKey);
    }

    // EdDSA (Ed25519 / Ed448)
    private static KeyPair readEdDSAPrivateKey(final PrivateKeyInfo keyInfo)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = SecurityHelper.getKeyFactory("EdDSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyInfo.getEncoded()));
        PublicKey publicKey;
        if (privateKey instanceof EdDSAPrivateKey) { // assuming BC provider
            publicKey = ((EdDSAPrivateKey) privateKey).getPublicKey();
        } else {
            publicKey = null;
        }
        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair readECPrivateKey(final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readECPrivateKey(SecurityHelper.getKeyFactory("EC"), input);
    }

    public static KeyPair readECPrivateKey(final KeyFactory keyFactory, final byte[] input)
        throws IOException, InvalidKeySpecException {
        return readECPrivateKey(keyFactory, mockPrivateKeyInfo(Type.EC, input));
    }

    public static KeyPair readECPrivateKey(final KeyFactory keyFactory, final PrivateKeyInfo keyInfo)
        throws IOException, InvalidKeySpecException {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(keyInfo.parsePrivateKey());

            org.bouncycastle.asn1.sec.ECPrivateKey key = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(seq);
            AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
            if (algId == null) { // mockPrivateKeyInfo
                algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, PKeyShim.getECParametersObject(key));
            }
            final PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, key);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privInfo.getEncoded()));
            if (algId.getParameters() instanceof ASN1ObjectIdentifier) {
                privateKey = ECPrivateKeyWithName.wrap(privateKey, (ASN1ObjectIdentifier) algId.getParameters());
            }

            // The publicKey field in ECPrivateKey DER is optional (RFC 5915).
            // Keys written by older JRuby-OpenSSL may omit it; handle gracefully.
            final org.bouncycastle.asn1.ASN1BitString pubKeyBits = PKeyShim.getECPublicKey(key);
            if (pubKeyBits == null) return new KeyPair(null, privateKey);
            final SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pubKeyBits.getBytes());
            return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(pubInfo.getEncoded())), privateKey);
        }
        catch (ClassCastException ex) {
            throw new IOException("wrong ASN.1 object found in stream", ex);
        }
        //catch (Exception ex) {
        //    throw new IOException("problem parsing EC private key: " + ex);
        //}
    }

    public static byte[] toDerRSAKey(RSAPublicKey pubKey, RSAPrivateCrtKey privKey) throws IOException {
        if ( pubKey != null && privKey == null ) {
            return toDerRSAPublicKey(pubKey);
        }
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(BigInteger.ZERO));
        vec.add(new ASN1Integer(privKey.getModulus()));
        vec.add(new ASN1Integer(privKey.getPublicExponent()));
        vec.add(new ASN1Integer(privKey.getPrivateExponent()));
        vec.add(new ASN1Integer(privKey.getPrimeP()));
        vec.add(new ASN1Integer(privKey.getPrimeQ()));
        vec.add(new ASN1Integer(privKey.getPrimeExponentP()));
        vec.add(new ASN1Integer(privKey.getPrimeExponentQ()));
        vec.add(new ASN1Integer(privKey.getCrtCoefficient()));
        return new DERSequence(vec).toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    public static byte[] toDerRSAPublicKey(final RSAPublicKey pubKey) throws IOException {
        AlgorithmIdentifier algIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        return new SubjectPublicKeyInfo(algIdentifier, toASN1Primitive(pubKey)).getEncoded(); // pubKey.getEncoded()
    }

    public static ASN1Sequence toASN1Primitive(final RSAPublicKey publicKey) {
        assert publicKey != null : "null public key";
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(publicKey.getModulus()));
        vec.add(new ASN1Integer(publicKey.getPublicExponent()));
        return new DERSequence(vec);
    }

    public static byte[] toDerDSAKey(DSAPublicKey pubKey, DSAPrivateKey privKey)
        throws IOException, IllegalArgumentException {
        if ( pubKey != null && privKey == null ) {
            return toDerDSAPublicKey(pubKey);
        }
        if ( privKey != null && pubKey != null ) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            final DSAParams params = privKey.getParams();
            vec.add(new ASN1Integer(BigInteger.ZERO));
            vec.add(new ASN1Integer(params.getP()));
            vec.add(new ASN1Integer(params.getQ()));
            vec.add(new ASN1Integer(params.getG()));
            vec.add(new ASN1Integer(pubKey.getY()));
            vec.add(new ASN1Integer(privKey.getX()));
            return new DERSequence(vec).toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }
        if ( privKey == null ) {
            throw new IllegalArgumentException("private key as well as public key are null");
        }
        final DSAParams params = privKey.getParams();
        return new PrivateKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
                        new DSAParameter(params.getP(), params.getQ(), params.getG())),
                new ASN1Integer(privKey.getX())
        ).getEncoded(ASN1Encoding.DER);
    }

    public static byte[] toDerDSAPublicKey(final DSAPublicKey pubKey) throws IOException {
        // pubKey.getEncoded() :
        final DSAParams params = pubKey.getParams();
        if (params == null) {
            return new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa),
                    toASN1Primitive(pubKey)
            ).getEncoded(ASN1Encoding.DER);
        }
        return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
                        new DSAParameter(params.getP(), params.getQ(), params.getG())
                ),
                toASN1Primitive(pubKey)
        ).getEncoded(ASN1Encoding.DER);
    }

    public static ASN1Primitive toASN1Primitive(DSAPublicKey pubKey) {
        return new ASN1Integer(pubKey.getY());
    }

    public static byte[] toDerDHKey(BigInteger p, BigInteger g) throws IOException {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if ( p != null ) vec.add( new ASN1Integer(p) );
        if ( g != null ) vec.add( new ASN1Integer(g) );
        return new DLSequence(vec).getEncoded();
    }
}
