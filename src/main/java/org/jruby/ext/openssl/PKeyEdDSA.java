/*
 * Copyright (c) 2026 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.ext.openssl.shim.PKeyShim;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.OpenSSL.throwOperationErrorOrOriginal;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * Wraps EdDSA keys (Ed25519, Ed448) using BouncyCastle's JCA EdDSA provider.
 *
 * Not exposed — instances appear as OpenSSL::PKey::PKey.
 */
public class PKeyEdDSA extends PKey {

    private static final Logger LOG = Logger.getLogger(PKeyEdDSA.class);

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private PKeyEdDSA(Ruby runtime, RubyClass type, PublicKey publicKey, PrivateKey privateKey) {
        super(runtime, type);
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    PKeyEdDSA(Ruby runtime, PublicKey publicKey, PrivateKey privateKey) {
        this(runtime, PKey._PKey(runtime).getClass("PKey"), publicKey, privateKey);
    }

    PKeyEdDSA(Ruby runtime, PublicKey publicKey) {
        this(runtime, convertNonBCPublicKey(runtime, publicKey), null);
    }

    // handle JDK (SunEC) keys e.g. from SunJSSE certificates
    private static PublicKey convertNonBCPublicKey(final Ruby runtime, final PublicKey publicKey) {
        if (publicKey instanceof EdDSAPublicKey) return publicKey;
        try {
            return SecurityHelper.getKeyFactory("EdDSA")
                    .generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw newPKeyError(runtime, e);
        }
    }

    static PKeyEdDSA newInstance(final Ruby runtime, final KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null && privateKey instanceof EdDSAPrivateKey) {
            // BC EdDSA private keys can derive their public key
            publicKey = ((EdDSAPrivateKey) privateKey).getPublicKey();
        }
        return new PKeyEdDSA(runtime, publicKey, privateKey);
    }

    static PKeyEdDSA generate(final ThreadContext context, final String algorithm) {
        try {
            KeyPairGenerator gen = SecurityHelper.getKeyPairGenerator(algorithm);
            gen.initialize(256, OpenSSL.getSecureRandom(context));
            return newInstance(context.runtime, gen.generateKeyPair());
        }
        catch (NoSuchAlgorithmException e) {
            throw newPKeyError(context.runtime, "unsupported algorithm: " + algorithm);
        }
        catch (Exception e) {
            LOG.debugStack(context.runtime, null, e);
            throw newPKeyError(context.runtime, e.getMessage());
        }
    }

    static PKeyEdDSA fromRawPrivateKey(final Ruby runtime, final String algorithm, final byte[] bytes) {
        try {
            final ASN1ObjectIdentifier oid = getEdObjectId(algorithm);
            if (oid == null) throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);

            // Build PKCS#8 PrivateKeyInfo wrapping the raw CurvePrivateKey octet string
            PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(oid), new DEROctetString(bytes));
            KeyFactory keyFactory = SecurityHelper.getKeyFactory("EdDSA");
            PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));

            // Derive public key from the private key
            PublicKey pubKey = null;
            if (privKey instanceof EdDSAPrivateKey) {
                pubKey = ((EdDSAPrivateKey) privKey).getPublicKey();
            }

            return new PKeyEdDSA(runtime, pubKey, privKey);
        }
        catch (IllegalArgumentException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
        catch (Exception e) {
            LOG.debugStack(runtime, null, e);
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    static PKeyEdDSA fromRawPublicKey(final Ruby runtime, final String algorithm, final byte[] bytes) {
        try {
            final ASN1ObjectIdentifier oid = getEdObjectId(algorithm);
            if (oid == null) throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);

            // Build SubjectPublicKeyInfo wrapping the raw key bytes
            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), bytes);
            KeyFactory keyFactory = SecurityHelper.getKeyFactory("EdDSA");
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubInfo.getEncoded()));

            return new PKeyEdDSA(runtime, pubKey);
        }
        catch (IllegalArgumentException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
        catch (Exception e) {
            LOG.debugStack(runtime, null, e);
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    private static ASN1ObjectIdentifier getEdObjectId(final String algorithm) {
        if ("Ed25519".equals(algorithm) || "ED25519".equals(algorithm)) {
            return EdECObjectIdentifiers.id_Ed25519;
        }
        if ("Ed448".equals(algorithm) || "ED448".equals(algorithm)) {
            return EdECObjectIdentifiers.id_Ed448;
        }
        return null;
    }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String getAlgorithm() { // BC returns "Ed25519" or "Ed448"
        if (privateKey != null) return privateKey.getAlgorithm();
        if (publicKey != null) return publicKey.getAlgorithm();
        return "EdDSA";
    }

    @Override
    public String getKeyType() { return "EdDSA"; }

    @Override
    public String getTypeName() { return getAlgorithm().toUpperCase(); }

    @Override
    public RubyString oid() { // MRI: OBJ_nid2sn returns "ED25519" or "ED448"
        return getRuntime().newString(getAlgorithm().toUpperCase());
    }

    @Override
    public IRubyObject sign(IRubyObject digest, IRubyObject data) {
        final Ruby runtime = getRuntime();
        if (!isPrivateKey()) throw runtime.newArgumentError("Private key is needed.");
        if (!digest.isNil()) {
            throw newPKeyError(runtime, "Ed25519 does not support digests");
        }

        try {
            final String sigAlg = getAlgorithm(); // "Ed25519" or "Ed448"
            Signature sig = SecurityHelper.getSignature(sigAlg);
            sig.initSign(privateKey);
            ByteList dataBytes = data.convertToString().getByteList();
            sig.update(dataBytes.getUnsafeBytes(), dataBytes.getBegin(), dataBytes.getRealSize());
            return RubyString.newString(runtime, new ByteList(sig.sign(), false));
        }
        catch (GeneralSecurityException ex) {
            throw newPKeyError(runtime, ex.getMessage());
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
    }

    @Override
    public IRubyObject verify(IRubyObject digest, IRubyObject sign, IRubyObject data) {
        final Ruby runtime = getRuntime();
        if (!digest.isNil()) {
            throw newPKeyError(runtime, "Ed25519 does not support digests");
        }

        try {
            final String sigAlg = getAlgorithm();
            Signature sig = SecurityHelper.getSignature(sigAlg);
            sig.initVerify(publicKey);
            ByteList dataBytes = data.convertToString().getByteList();
            sig.update(dataBytes.getUnsafeBytes(), dataBytes.getBegin(), dataBytes.getRealSize());
            ByteList sigBytes = sign.convertToString().getByteList();
            boolean verified = sig.verify(sigBytes.getUnsafeBytes(), sigBytes.getBegin(), sigBytes.getRealSize());
            return runtime.newBoolean(verified);
        }
        catch (SignatureException e) {
            return runtime.getFalse();
        }
        catch (InvalidKeyException e) {
            throw newPKeyError(runtime, "invalid key");
        }
        catch (NoSuchAlgorithmException e) {
            throw newPKeyError(runtime, "unsupported algorithm: " + getAlgorithm());
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
    }

    @Override
    @JRubyMethod(name = "derive")
    public IRubyObject derive(ThreadContext context, IRubyObject peer) {
        // EdDSA pkey type does not support key derivation
        throw newPKeyError(context.runtime, "EVP_PKEY_derive_init");
    }

    @Override
    @JRubyMethod(name = "raw_private_key")
    public IRubyObject raw_private_key(ThreadContext context) {
        final Ruby runtime = context.runtime;
        if (privateKey == null) throw newPKeyError(runtime, "private key not set");

        try {
            // Extract raw key bytes from PKCS#8 encoding:
            // PrivateKeyInfo -> parsePrivateKey -> OctetString -> getOctets
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            ASN1OctetString oct = ASN1OctetString.getInstance(info.parsePrivateKey());
            return RubyString.newString(runtime, oct.getOctets());
        }
        catch (IOException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    @Override
    @JRubyMethod(name = "raw_public_key")
    public IRubyObject raw_public_key(ThreadContext context) {
        final Ruby runtime = context.runtime;
        if (publicKey == null) throw newPKeyError(runtime, "public key not set");
        if (publicKey instanceof EdDSAPublicKey) {
            return RubyString.newString(runtime, PKeyShim.getEdDSAPointEncoding(publicKey));
        }
        throw newPKeyError(runtime, "cannot extract raw public key");
    }

    @Override
    public RubyString to_der() {
        final Ruby runtime = getRuntime();
        try {
            if (privateKey != null) {
                return newString(runtime, privateKey.getEncoded());
            }
            if (publicKey != null) {
                return newString(runtime, publicKey.getEncoded());
            }
            throw newPKeyError(runtime, "no key set");
        }
        catch (Exception e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    @Override
    public RubyString to_pem(ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        try {
            if (privateKey != null) {
                return private_to_pem(context, args);
            }
            if (publicKey != null) {
                return public_to_pem(context);
            }
            throw newPKeyError(runtime, "no key set");
        }
        catch (Exception e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    @Override
    public RubyString to_text() {
        final StringBuilder sb = new StringBuilder();
        sb.append(getAlgorithm().toUpperCase()).append(' ');
        if (privateKey != null) {
            sb.append("Private-Key:\n");
        }
        else {
            sb.append("Public-Key:\n");
        }
        if (publicKey instanceof EdDSAPublicKey) {
            sb.append("pub:\n");
            addSplittedAndFormatted(sb, bytesToHex(PKeyShim.getEdDSAPointEncoding(publicKey)));
        }
        return RubyString.newString(getRuntime(), sb);
    }

    private static StringBuilder bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb;
    }

    static boolean isEdDSAAlgorithm(final String alg) {
        return "EdDSA".equalsIgnoreCase(alg) || "Ed25519".equalsIgnoreCase(alg) || "Ed448".equalsIgnoreCase(alg);
    }

    static boolean isEdDSAKey(final PublicKey key) {
        return key instanceof EdDSAPublicKey || (key != null && isEdDSAAlgorithm(key.getAlgorithm()));
    }
}
