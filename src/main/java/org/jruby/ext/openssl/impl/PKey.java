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

import java.io.IOException;
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
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

import org.jruby.ext.openssl.SecurityHelper;

/**
 *
 * Handles PKey related ASN.1 handling.
 *
 * @author <a href="mailto:nahi@ruby-lang.org">Hiroshi Nakamura</a>
 */
public class PKey {

    public static KeyPair readPrivateKey(final byte[] input, final String type)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec pubSpec; KeySpec privSpec;
        ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(input).readObject();
        if ( type.equals("RSA") ) {
            ASN1Integer mod = (ASN1Integer) seq.getObjectAt(1);
            ASN1Integer pubExp = (ASN1Integer) seq.getObjectAt(2);
            ASN1Integer privExp = (ASN1Integer) seq.getObjectAt(3);
            ASN1Integer p1 = (ASN1Integer) seq.getObjectAt(4);
            ASN1Integer p2 = (ASN1Integer) seq.getObjectAt(5);
            ASN1Integer exp1 = (ASN1Integer) seq.getObjectAt(6);
            ASN1Integer exp2 = (ASN1Integer) seq.getObjectAt(7);
            ASN1Integer crtCoef = (ASN1Integer) seq.getObjectAt(8);
            pubSpec = new RSAPublicKeySpec(mod.getValue(), pubExp.getValue());
            privSpec = new RSAPrivateCrtKeySpec(mod.getValue(), pubExp.getValue(), privExp.getValue(), p1.getValue(), p2.getValue(), exp1.getValue(),
                    exp2.getValue(), crtCoef.getValue());
        }
        else if ( type.equals("DSA") ) {
            ASN1Integer p = (ASN1Integer) seq.getObjectAt(1);
            ASN1Integer q = (ASN1Integer) seq.getObjectAt(2);
            ASN1Integer g = (ASN1Integer) seq.getObjectAt(3);
            ASN1Integer y = (ASN1Integer) seq.getObjectAt(4);
            ASN1Integer x = (ASN1Integer) seq.getObjectAt(5);
            privSpec = new DSAPrivateKeySpec(x.getValue(), p.getValue(), q.getValue(), g.getValue());
            pubSpec = new DSAPublicKeySpec(y.getValue(), p.getValue(), q.getValue(), g.getValue());
        }
        else if ( type.equals("ECDSA") ) {
            return readECPrivateKey(input);
        }
        else {
            throw new IllegalStateException("unsupported type: " + type);
        }
        KeyFactory fact = SecurityHelper.getKeyFactory(type);
        return new KeyPair(fact.generatePublic(pubSpec), fact.generatePrivate(privSpec));
    }

    // d2i_PrivateKey_bio
    public static KeyPair readPrivateKey(byte[] input) throws IOException,
        NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPair key = null;
        try {
            key = readRSAPrivateKey(input);
        }
        catch (NoSuchAlgorithmException e) { throw e; /* should not happen */ }
        catch (InvalidKeySpecException e) {
            // ignore
        }
        if (key == null) {
            try {
                key = readDSAPrivateKey(input);
            }
            catch (NoSuchAlgorithmException e) { throw e; /* should not happen */ }
            catch (InvalidKeySpecException e) {
                // ignore
            }
        }
        return key;
    }

    // d2i_PUBKEY_bio
    public static PublicKey readPublicKey(byte[] input) throws IOException,
        NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey key = null;
        try {
            key = readRSAPublicKey(input);
        }
        catch (NoSuchAlgorithmException e) { throw e; /* should not happen */ }
        catch (InvalidKeySpecException e) {
            // ignore
        }
        if (key == null) {
            try {
                key = readDSAPublicKey(input);
            }
            catch (NoSuchAlgorithmException e) { throw e; /* should not happen */ }
            catch (InvalidKeySpecException e) {
                // ignore
            }
        }
        return key;
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
        ASN1InputStream aIn = new ASN1InputStream(input);
        ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
        BigInteger p = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger g = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        return new DHParameterSpec(p, g);
    }

    public static KeyPair readECPrivateKey(final byte[] input)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return readECPrivateKey(SecurityHelper.getKeyFactory("ECDSA"), input);
    }

    public static KeyPair readECPrivateKey(final KeyFactory ecFactory, final byte[] input)
        throws IOException, InvalidKeySpecException {
        try {
            ECPrivateKeyStructure pKey = new ECPrivateKeyStructure((ASN1Sequence) ASN1Primitive.fromByteArray(input));
            AlgorithmIdentifier   algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
            PrivateKeyInfo        privInfo = new PrivateKeyInfo(algId, pKey.toASN1Primitive());
            SubjectPublicKeyInfo  pubInfo = new SubjectPublicKeyInfo(algId, pKey.getPublicKey().getBytes());
            PKCS8EncodedKeySpec   privSpec = new PKCS8EncodedKeySpec(privInfo.getEncoded());
            X509EncodedKeySpec    pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());
            //KeyFactory            fact = KeyFactory.getInstance("ECDSA", provider);

            ECPrivateKey privateKey = (ECPrivateKey) ecFactory.generatePrivate(privSpec);
            if ( algId.getParameters() instanceof ASN1ObjectIdentifier ) {
                privateKey = ECPrivateKeyWithName.wrap(privateKey, (ASN1ObjectIdentifier) algId.getParameters());
            }
            return new KeyPair(ecFactory.generatePublic(pubSpec), privateKey);
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
            // pubKey.getEncoded() :
            return KeyUtil.getEncodedSubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), toASN1Primitive(pubKey)
            );
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

    public static ASN1Sequence toASN1Primitive(RSAPublicKey pubKey) {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(pubKey.getModulus()));
        vec.add(new ASN1Integer(pubKey.getPublicExponent()));
        return new DERSequence(vec);
    }

    public static byte[] toDerDSAKey(DSAPublicKey pubKey, DSAPrivateKey privKey) throws IOException {
        if ( pubKey != null && privKey == null ) {
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


