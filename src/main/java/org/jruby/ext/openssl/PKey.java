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

import java.io.Console;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.ext.openssl.x509store.PEMInputOutput;

import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.Cipher._Cipher;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public abstract class PKey extends RubyObject {
    private static final long serialVersionUID = 6114668087816965720L;
    private static final Logger LOG = Logger.getLogger(PKey.class);

    static void createPKey(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule PKey = OpenSSL.defineModuleUnder("PKey");
        PKey.defineAnnotatedMethods(PKeyModule.class);

        // PKey is abstract
        RubyClass PKeyPKey = PKey.defineClassUnder("PKey", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);
        RubyClass PKeyError = PKey.defineClassUnder("PKeyError", OpenSSLError, OpenSSLError.getAllocator());

        PKeyPKey.defineAnnotatedMethods(PKey.class);

        PKeyRSA.createPKeyRSA(runtime, PKey, PKeyPKey, PKeyError);
        PKeyDSA.createPKeyDSA(runtime, PKey, PKeyPKey, PKeyError);
        PKeyDH.createPKeyDH(runtime, PKey, PKeyPKey, PKeyError);
        PKeyEC.createPKeyEC(runtime, PKey, PKeyPKey, OpenSSLError);
    }

    public static RaiseException newPKeyError(Ruby runtime, String message) {
        return newError(runtime, (RubyClass) _PKey(runtime).getConstantAt("PKeyError"), message);
    }

    static RaiseException newPKeyError(Ruby runtime, Exception cause) {
        return newError(runtime, (RubyClass) _PKey(runtime).getConstantAt("PKeyError"), cause);
    }

    public static PKey newInstance(final Ruby runtime, final PublicKey publicKey) {
        assert publicKey != null;
        if (publicKey instanceof RSAPublicKey) {
            return new PKeyRSA(runtime, (RSAPublicKey) publicKey);
        }
        if (publicKey instanceof DSAPublicKey) {
            return new PKeyDSA(runtime, (DSAPublicKey) publicKey);
        }
        if (publicKey instanceof ECPublicKey) {
            return new PKeyEC(runtime, publicKey);
        }
        if (PKeyEdDSA.isEdDSAKey(publicKey)) {
            return new PKeyEdDSA(runtime, publicKey);
        }
        if (PKeyXDH.isXDHKey(publicKey)) {
            return new PKeyXDH(runtime, publicKey);
        }
        if (publicKey instanceof DHPublicKey) {
            return new PKeyDH(runtime, (DHPublicKey) publicKey, null);
        }
        throw runtime.newNotImplementedError("public key algorithm: " + (publicKey != null ? publicKey.getAlgorithm() : "nil"));
    }

    static RubyModule _PKey(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstantAt("PKey");
    }

    public static class PKeyModule {

        @JRubyMethod(name = "read", meta = true, required = 1, optional = 1)
        public static IRubyObject read(final ThreadContext context, IRubyObject recv, IRubyObject... args) {
            final Ruby runtime = context.runtime;
            try {
                return readImpl(context, args);
            }
            catch (Throwable ex) {
                return throwOperationErrorOrOriginal(runtime, ex);
            }
        }

        private static IRubyObject readImpl(final ThreadContext context, IRubyObject... args) {
            final Ruby runtime = context.runtime;

            final IRubyObject data; final char[] pass;
            switch (args.length) {
            case 1:
                data = args[0];
                pass = null;
                break;
            default:
                data = args[0];
                pass = args[1].isNil() ? null : args[1].toString().toCharArray();
            }

            final RubyString str = readInitArg(context, data);
            KeyPair keyPair;
            // d2i_PrivateKey_bio (PEM formats: RSA PRIVATE KEY, DSA PRIVATE KEY, PRIVATE KEY, ENCRYPTED PRIVATE KEY)
            try {
                keyPair = readPrivateKey(str, pass);
            } catch (IOException e) {
                LOG.debugStack(runtime, "readPrivateKey", e); /* ignore */
                keyPair = null;
            }
            // DER-encoded PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo
            if (keyPair == null) {
                try {
                    final byte[] derInput = str.getBytes();
                    keyPair = PEMInputOutput.readPrivateKeyFromDER(derInput, pass);
                } catch (IOException e) {
                    LOG.debugStack(runtime, "readPrivateKeyFromDER", e); /* ignore */
                }
            }
            // d2i_PrivateKey_bio - PKCS#1 RSA, DSA and SEC1 EC keys (as written by #to_der)
            if (keyPair == null) {
                try {
                    keyPair = org.jruby.ext.openssl.impl.PKey.readPrivateKeyDER(str.getBytes());
                } catch (IOException e) {
                    LOG.debugStack(runtime, "readPrivateKeyDER", e); /* ignore */
                }
            }
            // PEM_read_bio_PrivateKey
            if (keyPair != null) {
                final String alg = getAlgorithm(keyPair);
                if ( "RSA".equals(alg) ) {
                    return new PKeyRSA(runtime, _PKey(runtime).getClass("RSA"), (RSAPrivateCrtKey) keyPair.getPrivate(), (RSAPublicKey) keyPair.getPublic());
                }
                if ( "DSA".equals(alg) ) {
                    return new PKeyDSA(runtime, _PKey(runtime).getClass("DSA"), (DSAPrivateKey) keyPair.getPrivate(), (DSAPublicKey) keyPair.getPublic());
                }
                if ( "EC".equals(alg) || "ECDSA".equals(alg) ) { // Sun vs BC provider naming
                    return new PKeyEC(runtime, _PKey(runtime).getClass("EC"), keyPair.getPrivate(), keyPair.getPublic());
                }
                if ( PKeyEdDSA.isEdDSAAlgorithm(alg) ) {
                    return PKeyEdDSA.newInstance(runtime, keyPair);
                }
                if ( PKeyXDH.isXDHAlgorithm(alg) ) {
                    return PKeyXDH.newInstance(runtime, keyPair);
                }
                if ( "DH".equals(alg) ) {
                    return new PKeyDH(runtime, (DHPublicKey) keyPair.getPublic(), (DHPrivateKey) keyPair.getPrivate());
                }
                LOG.debug(runtime, "readPrivateKey unexpected key pair algorithm: " + alg);
            }

            PublicKey pubKey = null;
            try {
                pubKey = PEMInputOutput.readRSAPublicKey(new StringReader(str.toString()), null);
                if (pubKey != null) return new PKeyRSA(runtime, (RSAPublicKey) pubKey);
            } catch (IOException e) {
                LOG.debugStack(runtime, "readRSAPublicKey", e); /* ignore */
            }
            try {
                pubKey = PEMInputOutput.readDSAPublicKey(new StringReader(str.toString()), null);
                if (pubKey != null) return new PKeyDSA(runtime, (DSAPublicKey) pubKey);
            } catch (IOException e) {
                LOG.debugStack(runtime, "readDSAPublicKey", e); /* ignore */
            }

            final byte[] input = StringHelper.readX509PEM(context, str);
            // d2i_PUBKEY_bio
            try {
                pubKey = org.jruby.ext.openssl.impl.PKey.readPublicKey(input);
            } catch (IOException e) {
                LOG.debugStack(runtime, "readPublicKey", e); /* ignore */
            }
            // PEM_read_bio_PUBKEY
            if (pubKey == null) {
                try {
                    pubKey = PEMInputOutput.readPubKey(new StringReader(str.toString()));
                } catch (IOException e) {
                    LOG.debugStack(runtime, "readPubKey", e); /* ignore */
                }
            }

            if (pubKey instanceof RSAPublicKey) {
                return new PKeyRSA(runtime, (RSAPublicKey) pubKey);
            }
            if (pubKey instanceof DSAPublicKey) {
                return new PKeyDSA(runtime, (DSAPublicKey) pubKey);
            }
            if (pubKey instanceof ECPublicKey) {
                return new PKeyEC(runtime, pubKey);
            }
            if (PKeyEdDSA.isEdDSAKey(pubKey)) {
                return new PKeyEdDSA(runtime, pubKey);
            }
            if (PKeyXDH.isXDHKey(pubKey)) {
                return new PKeyXDH(runtime, pubKey);
            }
            if (pubKey instanceof DHPublicKey) {
                return new PKeyDH(runtime, (DHPublicKey) pubKey, null);
            }

            // PEM_read_bio_DHparams / d2i_DHparams (last resort) - DH parameters carry no algorithm id
            try {
                DHParameterSpec spec = PEMInputOutput.readDHParameters(new StringReader(str.toString()));
                if (spec == null) {
                    spec = org.jruby.ext.openssl.impl.PKey.readDHParameter(str.getByteList().bytes());
                }
                if (spec != null) return new PKeyDH(runtime, spec);
            } catch (IOException e) {
                LOG.debugStack(runtime, "readDHParameters", e); /* ignore */
            }

            throw newPKeyError(runtime, "Could not parse PKey: unsupported");
        }

        @JRubyMethod(name = "generate_key", meta = true, required = 1, optional = 1)
        public static IRubyObject generate_key(final ThreadContext context, IRubyObject recv, IRubyObject[] args) {
            final Ruby runtime = context.runtime;
            final IRubyObject arg = args[0];
            final IRubyObject options = args.length > 1 ? args[1] : runtime.getNil();
            try {
                // a key acts as a template - generate a new key off its parameters
                if (arg instanceof PKey) return generateKeyFromParams(context, (PKey) arg, options);

                final String algorithm = arg.convertToString().asJavaString();
                if ( "HMAC".equalsIgnoreCase(algorithm) ) {
                    if (args.length < 2) throw newPKeyError(runtime, "missing key parameter");
                    final RubyString key = RubySupport.extractRubyStringOpt(context, args[1], "key", true);
                    if (key == null) throw newPKeyError(runtime, "missing key parameter");
                    return PKeyHMAC.newInstance(runtime, key);
                }
                if ( PKeyEdDSA.isEdDSAAlgorithm(algorithm) ) {
                    return PKeyEdDSA.generate(context, algorithm);
                }
                if ( PKeyXDH.isXDHAlgorithm(algorithm) ) {
                    return PKeyXDH.generate(context, algorithm);
                }
                if ( "RSA".equalsIgnoreCase(algorithm) ) {
                    return generateRSAKey(context, options);
                }
                if ( "EC".equalsIgnoreCase(algorithm) ) {
                    return generateECKey(context, options);
                }
                // like MRI, generate_key does not generate parameters - DSA/DH need them upfront
                if ( "DSA".equalsIgnoreCase(algorithm) || "DH".equalsIgnoreCase(algorithm) ) {
                    throw newPKeyError(runtime, algorithm.toUpperCase() +
                        " key generation requires parameters, generate them with PKey.generate_parameters");
                }
                throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);
            }
            catch (Throwable ex) {
                return throwOperationErrorOrOriginal(runtime, ex);
            }
        }

        private static IRubyObject generateKeyFromParams(final ThreadContext context, final PKey baseKey,
            final IRubyObject options) {
            final Ruby runtime = context.runtime;

            // RSA has no parameters to derive from - the key only selects the algorithm (like MRI)
            if (baseKey instanceof PKeyRSA) {
                return generateRSAKey(context, options);
            }

            if (baseKey instanceof PKeyEC) {
                final PKeyEC ec = (PKeyEC) baseKey.dup();
                return ec.generate_key(context);
            }

            if (baseKey instanceof PKeyDH) {
                final PKeyDH dh = (PKeyDH) baseKey.dup();
                dh.set_key(context, runtime.getNil(), runtime.getNil());
                return dh.generate_key(context);
            }

            if (baseKey instanceof PKeyDSA) {
                final PKeyDSA dsa = (PKeyDSA) baseKey.dup();
                dsa.set_key(context, runtime.getNil(), runtime.getNil());
                return dsa.generate_key(context);
            }

            throw newPKeyError(runtime, "unsupported parameter type for key generation: "
                    + baseKey.getMetaClass().getRealClass().getName());
        }

        @JRubyMethod(name = "generate_parameters", meta = true, required = 1, optional = 1)
        public static IRubyObject generate_parameters(final ThreadContext context, IRubyObject recv, IRubyObject[] args) {
            final Ruby runtime = context.runtime;
            final String algorithm = args[0].asJavaString();
            final IRubyObject options = args.length > 1 ? args[1] : runtime.getNil();

            if ("EC".equalsIgnoreCase(algorithm)) {
                return generateECParameters(context, options);
            }
            if ("DSA".equalsIgnoreCase(algorithm)) {
                return generateDSAParameters(context, options);
            }
            if ("DH".equalsIgnoreCase(algorithm)) {
                return generateDHParameters(context, options);
            }

            throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);
        }

        private static IRubyObject generateECParameters(final ThreadContext context, final IRubyObject options) {
            final String curve = RubySupport.extractStringOpt(context, options, "ec_paramgen_curve", true);

            final Ruby runtime = context.runtime;
            if (curve == null) throw newPKeyError(runtime, "missing ec_paramgen_curve parameter");
            return new PKeyEC(runtime).initialize(context, new IRubyObject[] { runtime.newString(curve) }, Block.NULL_BLOCK);
        }

        private static IRubyObject generateDSAParameters(final ThreadContext context, final IRubyObject options) {
            final int bits = RubySupport.extractIntOpt(context, options, "dsa_paramgen_bits", 2048, true);

            final Ruby runtime = context.runtime;
            final PKeyDSA generated;
            try {
                generated = PKeyDSA.generateImpl(context, new PKeyDSA(runtime), bits);
            }
            catch (NoSuchAlgorithmException e) {
                throw newPKeyError(runtime, e.getMessage());
            }

            final PKeyDSA params = new PKeyDSA(runtime);
            params.set_pqg(generated.get_p(), generated.get_q(), generated.get_g());
            return params;
        }

        private static IRubyObject generateDHParameters(final ThreadContext context, final IRubyObject options) {
            final int bits = RubySupport.extractIntOpt(context, options, "dh_paramgen_prime_len", 2048, true);
            final int generator = RubySupport.extractIntOpt(context, options, "dh_paramgen_generator", 2, true);

            final Ruby runtime = context.runtime;
            final PKeyDH params = new PKeyDH(runtime);
            try {
                params.set_p(BN.newBN(runtime, PKeyDH.generateP(bits, generator)));
            }
            catch (IllegalArgumentException e) {
                throw newPKeyError(runtime, e.getMessage());
            }
            params.set_g(BN.newBN(runtime, BigInteger.valueOf(generator)));
            return params;
        }

        private static IRubyObject generateRSAKey(final ThreadContext context, final IRubyObject options) {
            final int bits = RubySupport.extractIntOpt(context, options, "rsa_keygen_bits", 2048, true);
            final IRubyObject pubexp = RubySupport.extractOpt(context, options, "rsa_keygen_pubexp", true);

            final Ruby runtime = context.runtime;
            final BigInteger exponent = pubexp == null || pubexp.isNil() ? RSAKeyGenParameterSpec.F4 : BN.asBigInteger(pubexp);
            return PKeyRSA.rsaGenerate(context, new PKeyRSA(runtime, PKeyRSA._RSA(runtime)), bits, exponent);
        }

        private static IRubyObject generateECKey(final ThreadContext context, final IRubyObject options) {
            final RubyString curve = RubySupport.extractRubyStringOpt(context, options, "ec_paramgen_curve", true);

            final Ruby runtime = context.runtime;
            if (curve == null) throw newPKeyError(runtime, "missing ec_paramgen_curve parameter");
            return PKeyEC.generate(context, PKeyEC._EC(runtime), curve);
        }

        @JRubyMethod(name = "new_raw_private_key", meta = true)
        public static IRubyObject new_raw_private_key(final ThreadContext context, IRubyObject recv,
            IRubyObject type, IRubyObject key) {
            final Ruby runtime = context.runtime;
            final String algorithm = type.asJavaString();
            if ( "HMAC".equalsIgnoreCase(algorithm) ) {
                return PKeyHMAC.newInstance(runtime, key.convertToString());
            }
            if ( PKeyEdDSA.isEdDSAAlgorithm(algorithm) ) {
                final byte[] bytes = key.convertToString().getBytes();
                return PKeyEdDSA.fromRawPrivateKey(runtime, algorithm, bytes);
            }
            if ( PKeyXDH.isXDHAlgorithm(algorithm) ) {
                final byte[] bytes = key.convertToString().getBytes();
                return PKeyXDH.fromRawPrivateKey(runtime, algorithm, bytes);
            }
            throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);
        }

        @JRubyMethod(name = "new_raw_public_key", meta = true)
        public static IRubyObject new_raw_public_key(final ThreadContext context, IRubyObject recv,
            IRubyObject type, IRubyObject key) {
            final Ruby runtime = context.runtime;
            final String algorithm = type.asJavaString();
            final byte[] raw = key.convertToString().getBytes();
            if ( PKeyEdDSA.isEdDSAAlgorithm(algorithm) ) {
                return PKeyEdDSA.fromRawPublicKey(runtime, algorithm, raw);
            }
            if ( PKeyXDH.isXDHAlgorithm(algorithm) ) {
                return PKeyXDH.fromRawPublicKey(runtime, algorithm, raw);
            }
            throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);
        }

        private static String getAlgorithm(final KeyPair key) {
            if ( key.getPrivate() != null ) return key.getPrivate().getAlgorithm();
            if ( key.getPublic() != null ) return key.getPublic().getAlgorithm();
            return null;
        }
    }

    public PKey(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context) {
        return this;
    }

    public abstract PublicKey getPublicKey() ;

    public abstract PrivateKey getPrivateKey() ;

    public String getAlgorithm() { return "NONE"; }

    public String getKeyType() { return getAlgorithm(); }

    // EVP_PKEY_get0_type_name (key type as MRI reports in #inspect)
    public String getTypeName() { return getKeyType(); }

    @JRubyMethod
    public RubyString inspect(final ThreadContext context) {
        // MRI also prints provider=, there is no such notion behind a JCA provider
        return ObjectSupport.inspectAddr(this, "oid=" + oid().asJavaString() + " type_name=" + getTypeName());
    }

    public boolean isPrivateKey() { return getPrivateKey() != null; }

    @JRubyMethod(name = { "public?", "public_key?" })
    public IRubyObject public_p() {
        return getRuntime().newBoolean(getPublicKey() != null);
    }

    @JRubyMethod(name = { "private?", "private_key?" })
    public IRubyObject private_p() {
        return getRuntime().newBoolean(isPrivateKey());
    }

    public abstract RubyString to_der();

    public abstract RubyString to_pem(ThreadContext context, final IRubyObject[] args) ;

    @JRubyMethod
    public abstract IRubyObject oid();

    /**
     * Dumps key parameters, public key, and private key components contained in
     * the key into a human-readable text. This is intended for debugging purpose.
     */
    @JRubyMethod(name = "to_text")
    public abstract RubyString to_text();

    /**
     * Derives a shared secret from this key and the peer key.
     * Only supported for key types that support key agreement (e.g. EC, DH).
     */
    @JRubyMethod(name = "derive")
    public IRubyObject derive(ThreadContext context, IRubyObject peer) {
        throw newPKeyError(context.runtime, "EVP_PKEY_derive_init");
    }

    /**
     * Returns the raw private key data as a binary string.
     */
    @JRubyMethod(name = "raw_private_key")
    public IRubyObject raw_private_key(ThreadContext context) {
        throw newPKeyError(context.runtime, "EVP_PKEY_get_raw_private_key");
    }

    /**
     * Returns the raw public key data as a binary string.
     */
    @JRubyMethod(name = "raw_public_key")
    public IRubyObject raw_public_key(ThreadContext context) {
        throw newPKeyError(context.runtime, "EVP_PKEY_get_raw_public_key");
    }

    /**
     * Serializes the public key to DER-encoded X.509 SubjectPublicKeyInfo format
     */
    @JRubyMethod(name = "public_to_der")
    public RubyString public_to_der(ThreadContext context) {
        final Ruby runtime = context.runtime;
        final PublicKey publicKey = getPublicKey();
        if (publicKey == null) {
            throw newPKeyError(runtime, "public key not set");
        }
        return newString(runtime, publicKey.getEncoded());
    }

    /**
     * Serializes the public key to PEM-encoded X.509 SubjectPublicKeyInfo format
     */
    @JRubyMethod(name = "public_to_pem")
    public RubyString public_to_pem(ThreadContext context) {
        final Ruby runtime = context.runtime;
        final PublicKey publicKey = getPublicKey();
        if (publicKey == null) {
            throw newPKeyError(runtime, "public key not set");
        }
        try {
            StringWriter writer = new StringWriter();
            PEMInputOutput.writePublicKey(writer, publicKey);
            return RubyString.newString(runtime, writer.toString());
        }
        catch (IOException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    /**
     * Serializes the private key to DER-encoded PKCS#8 format
     */
    @JRubyMethod(name = "private_to_der", rest = true)
    public RubyString private_to_der(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final PrivateKey privateKey = getPrivateKey();
        if (privateKey == null) {
            throw newPKeyError(runtime, "private key not set");
        }
        if (args.length > 0) {
            throw newPKeyError(runtime, "encryption not supported for this key type");
        }
        return newString(runtime, privateKey.getEncoded());
    }

    /**
     * Serializes the private key to PEM-encoded PKCS#8 format
     */
    @JRubyMethod(name = "private_to_pem", rest = true)
    public RubyString private_to_pem(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final PrivateKey privateKey = getPrivateKey();
        if (privateKey == null) {
            throw newPKeyError(runtime, "private key not set");
        }
        if (args.length > 0) {
            throw newPKeyError(runtime, "encryption not supported for this key type");
        }
        try {
            StringWriter writer = new StringWriter();
            PEMInputOutput.writePKCS8PrivateKey(writer, privateKey.getEncoded());
            return RubyString.newString(runtime, writer.toString());
        }
        catch (IOException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    @JRubyMethod(name = "sign")
    public IRubyObject sign(IRubyObject digest, IRubyObject data) {
        final Ruby runtime = getRuntime();
        if ( ! isPrivateKey() ) throw runtime.newArgumentError("Private key is needed.");
        String digAlg = (digest instanceof Digest) ? ((Digest) digest).getShortAlgorithm() : digest.asJavaString();
        try {
            ByteList sign = sign(digAlg + "WITH" + getAlgorithm(), getPrivateKey(), data.convertToString().getByteList());
            return RubyString.newString(runtime, sign);
        }
        catch (GeneralSecurityException ex) {
            throw newPKeyError(runtime, ex.getMessage());
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
    }

    public ASN1Primitive toASN1PublicInfo() throws IOException {
        ASN1InputStream input = new ASN1InputStream(to_der().getBytes());

        ASN1Primitive data = input.readObject();
        if (data instanceof ASN1Sequence) {
            return ((ASN1Sequence) data).getObjectAt(1).toASN1Primitive();
        }
        return data;
    }

    @Override
    public Object toJava(final Class target) {
        if (target == KeyPair.class) {
            final PrivateKey privateKey = getPrivateKey();
            if (privateKey == null) {
                throw getRuntime().newRuntimeError("private key not available, to convert to " + target);
            }
            return new KeyPair(getPublicKey(), privateKey);
        }
        if (PrivateKey.class.isAssignableFrom(target)) {
            final PrivateKey key = getPrivateKey();
            if (key == null) {
                throw getRuntime().newRuntimeError("private key not available, to convert to " + target);
            }
            if (target.isInstance(key)) return key;
            throw getRuntime().newTypeError("cannot convert private key of type " + key.getClass() + " to " + target);
        }
        if (target.isAssignableFrom(PublicKey.class) || Key.class.isAssignableFrom(target)) {
            // default is public key, also want to_java() as well as to_java(java.lang.Object) to end up here
            final PublicKey key = getPublicKey();
            if (key == null) {
                throw getRuntime().newRuntimeError("public key not available, to convert to " + target);
            }
            if (target.isInstance(key)) return key;
            throw getRuntime().newTypeError("cannot convert public key of type " + key.getClass() + " to " + target);
        }
        return super.toJava(target);
    }

    static ByteList sign(final String signAlg, final PrivateKey privateKey, final ByteList data)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = SecurityHelper.getSignature(signAlg);
        signature.initSign( privateKey );
        signature.update( data.getUnsafeBytes(), data.getBegin(), data.getRealSize() );
        return new ByteList(signature.sign(), false);
    }

    @JRubyMethod(name = "verify")
    public IRubyObject verify(IRubyObject digest, IRubyObject sign, IRubyObject data) {
        final Ruby runtime = getRuntime();
        ByteList sigBytes = convertToString(runtime, sign, "OpenSSL::PKey::PKeyError", "invalid signature").getByteList();
        ByteList dataBytes = convertToString(runtime, data, "OpenSSL::PKey::PKeyError", "invalid data").getByteList();
        final String algorithm = getDigestAlgName(digest) + "WITH" + getAlgorithm();
        try {
            return runtime.newBoolean( verify(algorithm, getPublicKey(), dataBytes, sigBytes) );
        }
        catch (NoSuchAlgorithmException e) {
            throw newPKeyError(runtime, "unsupported algorithm: " + algorithm);
        }
        catch (SignatureException e) {
            throw newPKeyError(runtime, "invalid signature");
        }
        catch (InvalidKeyException e) {
            throw newPKeyError(runtime, "invalid key");
        }
        catch (Throwable ex) {
            return throwOperationErrorOrOriginal(runtime, ex);
        }
    }

    // Used primarily to check if an OpenSSL::X509::Certificate#public_key compares to its private key.
    @JRubyMethod(name = "compare?")
    public IRubyObject compare_p(ThreadContext context, IRubyObject arg) {
        final Ruby runtime = context.runtime;
        if (!(arg instanceof PKey)) {
            throw runtime.newTypeError("OpenSSL::PKey::PKey expected but got " + arg.getMetaClass().getRealClass().getName());
        }
        final PKey other = (PKey) arg;
        if (!getKeyType().equals(other.getKeyType())) {
            throw runtime.newTypeError("Cannot compare different key types");
        }
        final PublicKey myPub = getPublicKey();
        final PublicKey otherPub = other.getPublicKey();
        if (myPub == null || otherPub == null) {
            return runtime.getFalse();
        }
        return runtime.newBoolean(MessageDigest.isEqual(myPub.getEncoded(), otherPub.getEncoded()));
    }

    static String getDigestAlgName(IRubyObject digest) {
        if (digest.isNil()) return "SHA256";
        if (digest instanceof Digest) return ((Digest) digest).getShortAlgorithm();
        return digest.asJavaString();
    }

    static RubyString convertToString(final Ruby runtime, final IRubyObject str, final String errorType, final CharSequence errorMsg) {
        try {
            return str.convertToString();
        }
        catch (RaiseException ex) { // to_str conversion failed
            throw newError(runtime, (RubyClass) runtime.getClassFromPath(errorType), errorMsg == null ? null : errorMsg.toString());
        }
    }

    static boolean verify(final String signAlg, final PublicKey publicKey, final ByteList data, final ByteList sign)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = SecurityHelper.getSignature(signAlg);
        signature.initVerify(publicKey);
        signature.update(data.getUnsafeBytes(), data.getBegin(), data.getRealSize());
        return signature.verify(sign.getUnsafeBytes(), sign.getBegin(), sign.getRealSize());
    }

    static SecureRandom getSecureRandom(final ThreadContext context) {
        try {
            return OpenSSL.getSecureRandom(context);
        }
        catch (NoSuchAlgorithmException e) {
            throw newPKeyError(context.runtime, e.getMessage());
        }
    }

    // shared Helpers for PKeyRSA / PKeyDSA :

    protected PrivateKey tryPKCS8EncodedKey(final Ruby runtime, final KeyFactory keyFactory, final byte[] encodedKey) {
        try {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
        }
        catch (InvalidKeySpecException e) {
            if ( LOG.isDebug(runtime) ) {
                LOG.debug(runtime, "tryPKCS8EncodedKey could not generate private key", e);
            }
        }
        catch (RuntimeException e) {
            if ( isKeyGenerationFailure(e) ) {
                if( LOG.isDebug(runtime) ) {
                    LOG.debug(runtime, "tryPKCS8EncodedKey could not generate private key", e);
                }
            }
            else LOG.debugStack(runtime, null, e);
        }
        return null;
    }

    protected static boolean isKeyGenerationFailure(final RuntimeException e) {
        // NOTE handle "common-failure" more gently (no need for stack trace) :
        // java.lang.ClassCastException: org.bouncycastle.asn1.DLSequence cannot be cast to org.bouncycastle.asn1.ASN1Integer
        //   at org.bouncycastle.asn1.pkcs.PrivateKeyInfo.<init>(Unknown Source)
        //	 at org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(Unknown Source)
        //   at org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi.engineGeneratePrivate(Unknown Source)
        //   at org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyFactorySpi.engineGeneratePrivate(Unknown Source)
        //   at java.security.KeyFactory.generatePrivate(KeyFactory.java:366)
        if ( e instanceof ClassCastException ) {
            // RSA :
            final String msg = e.getMessage();
            if ( msg != null && msg.contains("DLSequence cannot be cast to") ) {
                return true;
            }
        }
        return false;
    }

    protected PublicKey tryX509EncodedKey(final Ruby runtime, final KeyFactory keyFactory, final byte[] encodedKey) {
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
        }
        catch (InvalidKeySpecException e) {
            if ( LOG.isDebug(runtime) ) {
                LOG.debug(runtime, "tryX509EncodedKey could not generate public key", e);
            }
        }
        catch (RuntimeException e) {
            if ( isKeyGenerationFailure(e) ) { // NOTE: not (yet) detected with X.509
                if( LOG.isDebug(runtime) ) {
                    LOG.debug(runtime, "tryX509EncodedKey could not generate public key", e);
                }
            }
            else LOG.debugStack(runtime, null, e);
        }
        return null;
    }

    protected static void addSplittedAndFormatted(StringBuilder result, BigInteger value) {
        addSplittedAndFormatted(result, value.toString(16));
    }

    static void addSplittedAndFormatted(StringBuilder result, CharSequence v) {
        if ((v.length() % 2) != 0) v = "0" + v;

        char sep = '\0';
        for (int i = 0; i < v.length(); i += 2) {
            result.append(sep);
            if ((i % 30) == 0) {
                result.append("\n    ");
            }
            result.append(v, i, i + 2);
            sep = ':';
        }
        result.append('\n');
    }

    protected static CipherSpec cipherSpec(final IRubyObject cipher) {
        Cipher obj = null;
        if (cipher instanceof RubyString) {
            final Ruby runtime = cipher.getRuntime();
            obj = new Cipher(runtime, _Cipher(runtime));
            obj.initializeImpl(runtime, cipher.asString().toString());
        } else if (cipher instanceof Cipher) {
            obj = (Cipher) cipher;
        }
        if (obj != null) {
            return new CipherSpec(obj.getCipherInstance(), obj.getName(), obj.getKeyLength() * 8);
        }
        return null;
    }

    protected static char[] password(final ThreadContext context, IRubyObject pass, final Block block) {
        if (pass != null && !pass.isNil()) { // argument takes precedence (instead of block)
            return pass.toString().toCharArray();
        }
        if (block != null && block.isGiven()) {
            return password(context, block.call(context), null);
        }
        return null;
    }

    protected static char[] passwordPrompt(final ThreadContext context) {
        return passwordPrompt(context, "Enter PEM pass phrase:");
    }

    protected static char[] passwordPrompt(final ThreadContext context, final String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }

        // fall back on simple IO, but may be broken (jruby/jruby#5588)
        final RubyModule Kernel = context.runtime.getKernel();
        // NOTE: just a fast and simple print && gets - hopefully better than nothing!
        Kernel.callMethod("print", context.runtime.newString(prompt));
        final RubyString gets = Kernel.callMethod(context, "gets").convertToString();
        gets.chomp_bang(context);
        return gets.decodeString().toCharArray();
    }

    protected static boolean ttySTDIN(final ThreadContext context) {
        final IRubyObject stdin = context.runtime.getGlobalVariables().get("$stdin");
        if ( stdin == null || stdin.isNil() ) return false;
        try {
            final IRubyObject tty = stdin.callMethod(context, "tty?");
            return ! tty.isNil() && ! ( tty == context.runtime.getFalse() );
        }
        catch (RaiseException ex) { return false; }
    }

    static KeyPair readPrivateKey(final String str, final char[] passwd)
        throws PEMInputOutput.PasswordRequiredException, IOException {
        return PEMInputOutput.readPrivateKey(new StringReader(str), passwd);
    }

    static KeyPair readPrivateKey(final RubyString str, final char[] passwd)
        throws PEMInputOutput.PasswordRequiredException, IOException {
        return readPrivateKey(str.toString(), passwd);
    }

    protected static RubyString readInitArg(final ThreadContext context, IRubyObject arg) {
        return StringHelper.readPossibleDERInput(context, arg);
    }

    static void supportedSignatureAlgorithm(final Ruby runtime, final RubyClass errorClass,
        final PKey key, final Digest digest) {
        // Have to obey some artificial constraints of the OpenSSL implementation. Stupid.
        final String keyAlg = key.getAlgorithm();
        final String digAlg = digest.getShortAlgorithm();
        if ( ( "DSA".equalsIgnoreCase(keyAlg) && "MD5".equalsIgnoreCase(digAlg)) ||
             ( "RSA".equalsIgnoreCase(keyAlg) && "DSS1".equals( digest.name().toString() ) ) ) {
            throw newError(runtime, errorClass, "unsupported key / digest algorithm ( "+ keyAlg +" / "+ digAlg +" )");
        }
    }

    static void supportedSignatureAlgorithm(final Ruby runtime, final PKey key, final Digest digest) {
        supportedSignatureAlgorithm(runtime, _OpenSSLError(runtime), key, digest);
    }

}// PKey
