/*
 * Copyright (c) 2026 JRuby contributors.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.jruby.Ruby;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.OpenSSL.throwOperationErrorOrOriginal;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/** Pure ML-DSA keys, exposed as OpenSSL::PKey::PKey. */
public class PKeyMLDSA extends PKey {
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    PKeyMLDSA(Ruby runtime, PublicKey publicKey, PrivateKey privateKey) {
        super(runtime, PKey._PKey(runtime).getClass("PKey"));
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        final int length = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getOctets().length;
        final int expected = "ML-DSA-44".equals(publicKey.getAlgorithm()) ? 1312 :
            "ML-DSA-65".equals(publicKey.getAlgorithm()) ? 1952 : 2592;
        if (length != expected) throw newPKeyError(runtime, "invalid ML-DSA public key length");
    }

    static PKeyMLDSA generate(ThreadContext context, String algorithm) {
        try {
            KeyPairGenerator generator = SecurityHelper.getKeyPairGenerator("ML-DSA");
            generator.initialize(MLDSAParameterSpec.fromName(algorithm), OpenSSL.getSecureRandom(context));
            KeyPair pair = generator.generateKeyPair();
            return new PKeyMLDSA(context.runtime, pair.getPublic(), pair.getPrivate());
        }
        catch (GeneralSecurityException | IllegalArgumentException e) {
            throw newPKeyError(context.runtime, e);
        }
    }

    static boolean isMLDSAAlgorithm(String algorithm) {
        return "ML-DSA-44".equalsIgnoreCase(algorithm) ||
               "ML-DSA-65".equalsIgnoreCase(algorithm) ||
               "ML-DSA-87".equalsIgnoreCase(algorithm);
    }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String getAlgorithm() {
        return privateKey != null ? privateKey.getAlgorithm() : publicKey.getAlgorithm();
    }

    // BCJSSE requests the exact parameter set when selecting a TLS credential.
    @Override
    public String getKeyType() { return getAlgorithm(); }

    @Override
    public RubyString oid() {
        return getRuntime().newString("id-ml-dsa-" + getAlgorithm().substring(7));
    }

    @Override
    public IRubyObject sign(IRubyObject digest, IRubyObject data) {
        final Ruby runtime = getRuntime();
        if (!isPrivateKey()) throw runtime.newArgumentError("Private key is needed.");
        if (!digest.isNil()) throw newPKeyError(runtime, "ML-DSA does not support digests");
        try {
            return RubyString.newString(runtime, sign(getAlgorithm(), privateKey, data.convertToString().getByteList()));
        }
        catch (GeneralSecurityException e) {
            throw newPKeyError(runtime, e);
        }
        catch (Throwable e) {
            return throwOperationErrorOrOriginal(runtime, e);
        }
    }

    @Override
    public IRubyObject verify(IRubyObject digest, IRubyObject signature, IRubyObject data) {
        final Ruby runtime = getRuntime();
        if (!digest.isNil()) throw newPKeyError(runtime, "ML-DSA does not support digests");
        try {
            ByteList message = data.convertToString().getByteList();
            ByteList bytes = signature.convertToString().getByteList();
            return runtime.newBoolean(verify(getAlgorithm(), publicKey, message, bytes));
        }
        catch (SignatureException e) {
            return runtime.getFalse();
        }
        catch (GeneralSecurityException e) {
            throw newPKeyError(runtime, e);
        }
        catch (Throwable e) {
            return throwOperationErrorOrOriginal(runtime, e);
        }
    }

    @Override
    public RubyString to_der() {
        return privateKey != null ? private_to_der(getRuntime().getCurrentContext(), IRubyObject.NULL_ARRAY) :
            newString(getRuntime(), publicKey.getEncoded());
    }

    @Override
    public RubyString private_to_der(ThreadContext context, IRubyObject[] args) {
        if (privateKey == null || args.length > 0) return super.private_to_der(context, args);
        try {
            // Always emit standard expanded-only PKCS#8, including with BC 1.80's prestandard encoder.
            PrivateKeyInfo info = new PrivateKeyInfo(
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm(),
                new DEROctetString(((MLDSAPrivateKey) privateKey).getPrivateData()));
            return newString(context.runtime, info.getEncoded());
        }
        catch (IOException e) {
            throw newPKeyError(context.runtime, e);
        }
    }

    @Override
    public RubyString private_to_pem(ThreadContext context, IRubyObject[] args) {
        try {
            StringWriter writer = new StringWriter();
            PEMInputOutput.writePKCS8PrivateKey(writer, private_to_der(context, args).getBytes());
            return context.runtime.newString(writer.toString());
        }
        catch (IOException e) {
            throw newPKeyError(context.runtime, e);
        }
    }

    @Override
    public RubyString to_pem(ThreadContext context, IRubyObject[] args) {
        return privateKey != null ? private_to_pem(context, args) : public_to_pem(context);
    }

    @Override
    public RubyString to_text() {
        return getRuntime().newString(getAlgorithm() + (privateKey != null ? " Private-Key\n" : " Public-Key\n"));
    }
}
