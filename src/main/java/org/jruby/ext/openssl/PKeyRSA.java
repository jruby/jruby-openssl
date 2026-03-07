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

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static javax.crypto.Cipher.*;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyBignum;
import org.jruby.RubyBoolean;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.util.ByteArrayOutputStream;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;

import org.jruby.util.ByteList;

import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.impl.PKey.readRSAPrivateKey;
import static org.jruby.ext.openssl.impl.PKey.readRSAPublicKey;
import static org.jruby.ext.openssl.impl.PKey.toASN1Primitive;
import static org.jruby.ext.openssl.impl.PKey.toDerRSAKey;
import static org.jruby.ext.openssl.impl.PKey.toDerRSAPublicKey;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class PKeyRSA extends PKey {
    private static final long serialVersionUID = -2540383779256333197L;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public PKeyRSA allocate(Ruby runtime, RubyClass klass) { return new PKeyRSA(runtime, klass); }
    };

    static void createPKeyRSA(final Ruby runtime, final RubyModule PKey, final RubyClass PKeyPKey, final RubyClass PKeyError) {
        RubyClass RSA = PKey.defineClassUnder("RSA", PKeyPKey, ALLOCATOR);
        PKey.defineClassUnder("RSAError", PKeyError, PKeyError.getAllocator());

        RSA.defineAnnotatedMethods(PKeyRSA.class);

        RSA.setConstant("PKCS1_PADDING", runtime.newFixnum(1));
        RSA.setConstant("SSLV23_PADDING", runtime.newFixnum(2));
        RSA.setConstant("NO_PADDING", runtime.newFixnum(3));
        RSA.setConstant("PKCS1_OAEP_PADDING", runtime.newFixnum(4));
    }

    static RubyClass _RSA(final Ruby runtime) {
        return _PKey(runtime).getClass("RSA");
    }

    public static RaiseException newRSAError(Ruby runtime, String message) {
        return Utils.newError(runtime, _PKey(runtime).getClass("RSAError"), message);
    }

    static RaiseException newRSAError(Ruby runtime, Throwable cause) {
        return newRSAError(runtime, cause.getMessage(), cause);
    }

    static RaiseException newRSAError(Ruby runtime, String message, Throwable cause) {
        return Utils.newError(runtime, _PKey(runtime).getClass("RSAError"), message, cause);
    }

    public PKeyRSA(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    public PKeyRSA(Ruby runtime, RubyClass type, RSAPrivateCrtKey privKey, RSAPublicKey pubKey) {
        super(runtime, type);
        this.privateKey = privKey;
        this.publicKey = pubKey;
    }

    PKeyRSA(Ruby runtime, RSAPublicKey pubKey) {
        this(runtime, _RSA(runtime), null, pubKey);
    }

    private volatile RSAPublicKey publicKey;
    private volatile transient RSAPrivateKey privateKey;

    // fields to hold individual RSAPublicKeySpec components. this allows
    // a public key to be constructed incrementally, as required by the
    // current implementation of Net::SSH.
    // (see net-ssh-1.1.2/lib/net/ssh/transport/ossl/buffer.rb #read_keyblob)
    private transient volatile BigInteger rsa_e;
    private transient volatile BigInteger rsa_n;

    private transient volatile BigInteger rsa_d;
    private transient volatile BigInteger rsa_p;
    private transient volatile BigInteger rsa_q;
    private transient volatile BigInteger rsa_dmp1;
    private transient volatile BigInteger rsa_dmq1;
    private transient volatile BigInteger rsa_iqmp;

    @JRubyMethod(visibility = Visibility.PRIVATE)
    @Override
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final PKeyRSA that = (PKeyRSA) original;
        this.publicKey = that.publicKey;
        this.privateKey = that.privateKey;
        this.rsa_e = that.rsa_e;
        this.rsa_n = that.rsa_n;
        this.rsa_d = that.rsa_d;
        this.rsa_p = that.rsa_p;
        this.rsa_q = that.rsa_q;
        this.rsa_dmp1 = that.rsa_dmp1;
        this.rsa_dmq1 = that.rsa_dmq1;
        this.rsa_iqmp = that.rsa_iqmp;
        return this;
    }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public String getAlgorithm() { return "RSA"; }

    @JRubyMethod(name = "generate", meta = true, rest = true)
    public static IRubyObject generate(IRubyObject self, IRubyObject[] args) {
        final Ruby runtime = self.getRuntime();
        BigInteger exp = RSAKeyGenParameterSpec.F4;
        if ( Arity.checkArgumentCount(runtime, args, 1, 2) == 2 ) {
            if (args[1] instanceof RubyFixnum) {
                exp = BigInteger.valueOf(RubyNumeric.num2long(args[1]));
            } else {
                exp = ((RubyBignum) args[1]).getValue();
            }
        }
        final int keySize = RubyNumeric.fix2int(args[0]);
        return rsaGenerate(runtime, new PKeyRSA(runtime, (RubyClass) self), keySize, exp);
    }

    /*
     * c: rsa_generate
     */
    private static PKeyRSA rsaGenerate(final Ruby runtime,
        PKeyRSA rsa, int keySize, BigInteger exp) throws RaiseException {
        try {
            KeyPairGenerator gen = SecurityHelper.getKeyPairGenerator("RSA");
            if ( "IBMJCEFIPS".equals( gen.getProvider().getName() ) ) {
                gen.initialize(keySize); // IBMJCEFIPS does not support parameters
            } else {
                gen.initialize(new RSAKeyGenParameterSpec(keySize, exp), getSecureRandom(runtime));
            }
            KeyPair pair = gen.generateKeyPair();
            rsa.privateKey = (RSAPrivateCrtKey) pair.getPrivate();
            rsa.publicKey = (RSAPublicKey) pair.getPublic();
        }
        catch (NoSuchAlgorithmException e) {
            throw newRSAError(runtime, e.getMessage());
        }
        catch (InvalidAlgorithmParameterException e) {
            throw newRSAError(runtime, e.getMessage());
        }
        catch (RuntimeException e) {
            throw newRSAError(rsa.getRuntime(), e);
        }
        return rsa;
    }

    @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args, final Block block) {
        final Ruby runtime = context.runtime;

        if ( Arity.checkArgumentCount(runtime, args, 0, 2) == 0 ) {
            privateKey = null; publicKey = null; return this;
        }

        IRubyObject arg = args[0];
        IRubyObject arg1 = args.length > 1 ? args[1] : null; // exponent (Fixnum) or password (String)

        if ( arg instanceof RubyFixnum ) {
            int keySize = RubyNumeric.fix2int((RubyFixnum) arg);
            BigInteger exp = RSAKeyGenParameterSpec.F4;
            if (arg1 != null && !arg1.isNil()) {
                exp = BigInteger.valueOf(RubyNumeric.num2long(arg1));
            }
            return rsaGenerate(runtime, this, keySize, exp);
        }

        final char[] passwd = password(context, arg1, block);
        final RubyString str = readInitArg(context, arg);
        final String strJava = str.toString();

        Object key = null;
        final KeyFactory rsaFactory;
        try {
            rsaFactory = SecurityHelper.getKeyFactory("RSA");
        }
        catch (NoSuchAlgorithmException e) {
            throw runtime.newRuntimeError("unsupported key algorithm (RSA)");
        }
        catch (RuntimeException e) {
            throw runtime.newRuntimeError("unsupported key algorithm (RSA) " + e);
        }
        // TODO: ugly NoClassDefFoundError catching for no BC env. How can we remove this?
        boolean noClassDef = false;
        if ( key == null && ! noClassDef ) { // PEM_read_bio_RSAPrivateKey
            try {
                key = readPrivateKey(strJava, passwd);
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (PEMInputOutput.PasswordRequiredException retry) {
                if ( ttySTDIN(context) ) {
                    try { key = readPrivateKey(strJava, passwordPrompt(context)); }
                    catch (Exception e) { debugStackTrace(runtime, e); }
                }
            }
            catch (Exception e) { debugStackTrace(runtime, e); }
        }
        if ( key == null && ! noClassDef )  { // PEM_read_bio_RSAPublicKey
            try {
                key = PEMInputOutput.readRSAPublicKey(new StringReader(strJava), passwd);
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (Exception e) { debugStackTrace(runtime, e); }
        }
        if ( key == null && ! noClassDef ) { // PEM_read_bio_RSA_PUBKEY
            try {
                key = PEMInputOutput.readRSAPubKey(new StringReader(strJava));
            }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (Exception e) { debugStackTrace(runtime, e); }
        }
        if ( key == null && ! noClassDef ) { // d2i_RSAPrivateKey_bio
            try { key = readRSAPrivateKey(rsaFactory, str.getBytes()); }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (InvalidKeySpecException e) { debug(runtime, "PKeyRSA could not read private key", e); }
            catch (IOException e) { debugStackTrace(runtime, "PKeyRSA could not read private key", e); }
            catch (RuntimeException e) {
                if ( isKeyGenerationFailure(e) ) debug(runtime, "PKeyRSA could not read private key", e);
                else debugStackTrace(runtime, e);
            }
        }
        if ( key == null && ! noClassDef ) { // d2i_RSAPublicKey_bio
            try { key = readRSAPublicKey(rsaFactory, str.getBytes()); }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (InvalidKeySpecException e) { debug(runtime, "PKeyRSA could not read public key", e); }
            catch (IOException e) { debugStackTrace(runtime, "PKeyRSA could not read public key", e); }
            catch (RuntimeException e) {
                if ( isKeyGenerationFailure(e) ) debug(runtime, "PKeyRSA could not read public key", e);
                else debugStackTrace(runtime, e);
            }
        }

        if ( key == null ) key = tryPKCS8EncodedKey(runtime, rsaFactory, str.getBytes());
        if ( key == null ) key = tryX509EncodedKey(runtime, rsaFactory, str.getBytes());

        if ( key == null ) throw newPKeyError(runtime, "Neither PUB key nor PRIV key:");

        if ( key instanceof KeyPair ) {
            PublicKey publicKey = ((KeyPair) key).getPublic();
            PrivateKey privateKey = ((KeyPair) key).getPrivate();
            if ( ! ( privateKey instanceof RSAPrivateCrtKey ) ) {
                if ( privateKey == null ) {
                    throw newRSAError(runtime, "Neither PUB key nor PRIV key: (private key is null)");
                }
                throw newRSAError(runtime, "Neither PUB key nor PRIV key: (invalid key type " + privateKey.getClass().getName() + ")");
            }
            this.privateKey = (RSAPrivateCrtKey) privateKey;
            this.publicKey = (RSAPublicKey) publicKey;
        }
        else if ( key instanceof RSAPrivateCrtKey ) {
            this.privateKey = (RSAPrivateCrtKey) key;
            BigInteger exponent = ((RSAPrivateCrtKey) key).getPublicExponent();
            try {
                this.publicKey = (RSAPublicKey) rsaFactory.generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), exponent));
            } catch (GeneralSecurityException e) {
                throw newRSAError(runtime, e.getMessage());
            } catch (RuntimeException e) {
                debugStackTrace(runtime, e);
                throw newRSAError(runtime, e.toString());
            }
        }
        else if ( key instanceof RSAPublicKey ) {
            this.publicKey = (RSAPublicKey) key; this.privateKey = null;
        }
        else {
            throw newRSAError(runtime, "Neither PUB key nor PRIV key: " + key.getClass().getName());
        }
        return this;
    }

    @JRubyMethod(name = "public?")
    public RubyBoolean public_p() {
        return publicKey != null ? getRuntime().getTrue() : getRuntime().getFalse();
    }

    @Override
    public boolean isPrivateKey() {
        return privateKey != null;
    }

    @JRubyMethod(name = "private?")
    public RubyBoolean private_p() {
        return getRuntime().newBoolean(isPrivateKey());
    }

    @JRubyMethod(name = "public_to_der")
    public RubyString public_to_der(ThreadContext context) {
        final byte[] bytes;
        try {
            bytes = toDerRSAPublicKey(publicKey);
        }
        catch (NoClassDefFoundError e) {
            throw newRSAError(context.runtime, bcExceptionMessage(e));
        }
        catch (Exception e) {
            throw newRSAError(getRuntime(), e.getMessage(), e);
        }
        return StringHelper.newString(context.runtime, bytes);
    }

    @Override
    @JRubyMethod(name = "to_der")
    public RubyString to_der() {
        final byte[] bytes;
        try {
            bytes = toDerRSAKey(publicKey, privateKey instanceof RSAPrivateCrtKey ? (RSAPrivateCrtKey) privateKey : null);
        }
        catch (NoClassDefFoundError e) {
            throw newRSAError(getRuntime(), bcExceptionMessage(e));
        }
        catch (Exception e) {
            throw newRSAError(getRuntime(), e.getMessage(), e);
        }
        return StringHelper.newString(getRuntime(), bytes);
    }

    @Override
    public ASN1Primitive toASN1PublicInfo() {
        return toASN1Primitive(publicKey);
    }

    @JRubyMethod
    public PKeyRSA public_key() {
        return new PKeyRSA(getRuntime(), this.publicKey);
    }

    @JRubyMethod
    public IRubyObject params(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        RubyHash hash = RubyHash.newHash(runtime);
        if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) this.privateKey;
            hash.op_aset(context, runtime.newString("iqmp"), BN.newBN(runtime, privateKey.getCrtCoefficient()));
            hash.op_aset(context, runtime.newString("n"), BN.newBN(runtime, privateKey.getModulus()));
            hash.op_aset(context, runtime.newString("d"), BN.newBN(runtime, privateKey.getPrivateExponent()));
            hash.op_aset(context, runtime.newString("p"), BN.newBN(runtime, privateKey.getPrimeP()));
            hash.op_aset(context, runtime.newString("e"), BN.newBN(runtime, privateKey.getPublicExponent()));
            hash.op_aset(context, runtime.newString("q"), BN.newBN(runtime, privateKey.getPrimeQ()));
            hash.op_aset(context, runtime.newString("dmq1"), BN.newBN(runtime, privateKey.getPrimeExponentQ()));
            hash.op_aset(context, runtime.newString("dmp1"), BN.newBN(runtime, privateKey.getPrimeExponentP()));

        } else {
            hash.op_aset(context, runtime.newString("iqmp"), BN.newBN(runtime, BigInteger.ZERO));
            hash.op_aset(context, runtime.newString("n"), BN.newBN(runtime, publicKey.getModulus()));
            hash.op_aset(context, runtime.newString("d"), BN.newBN(runtime, BigInteger.ZERO));
            hash.op_aset(context, runtime.newString("p"), BN.newBN(runtime, BigInteger.ZERO));
            hash.op_aset(context, runtime.newString("e"), BN.newBN(runtime, publicKey.getPublicExponent()));
            hash.op_aset(context, runtime.newString("q"), BN.newBN(runtime, BigInteger.ZERO));
            hash.op_aset(context, runtime.newString("dmq1"), BN.newBN(runtime, BigInteger.ZERO));
            hash.op_aset(context, runtime.newString("dmp1"), BN.newBN(runtime, BigInteger.ZERO));
        }
        return hash;
    }

    @JRubyMethod
    public RubyString to_text() {
        StringBuilder result = new StringBuilder();
        if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) this.privateKey;
            int len = privateKey.getModulus().bitLength();
            result.append("Private-Key: (").append(len).append(" bit)").append('\n');
            result.append("modulus:");
            addSplittedAndFormatted(result, privateKey.getModulus());
            result.append("publicExponent: ").append(privateKey.getPublicExponent()).append(" (0x").append(privateKey.getPublicExponent().toString(16)).append(")\n");
            result.append("privateExponent:");
            addSplittedAndFormatted(result, privateKey.getPrivateExponent());
            result.append("prime1:");
            addSplittedAndFormatted(result, privateKey.getPrimeP());
            result.append("prime2:");
            addSplittedAndFormatted(result, privateKey.getPrimeQ());
            result.append("exponent1:");
            addSplittedAndFormatted(result, privateKey.getPrimeExponentP());
            result.append("exponent2:");
            addSplittedAndFormatted(result, privateKey.getPrimeExponentQ());
            result.append("coefficient:");
            addSplittedAndFormatted(result, privateKey.getCrtCoefficient());
        } else {
            int len = publicKey.getModulus().bitLength();
            result.append("Modulus (").append(len).append(" bit):");
            addSplittedAndFormatted(result, publicKey.getModulus());
            result.append("Exponent: ").append(publicKey.getPublicExponent()).append(" (0x").append(publicKey.getPublicExponent().toString(16)).append(")\n");
        }
        return RubyString.newString(getRuntime(), result);
    }

    @Override
    @JRubyMethod(name = { "to_pem", "to_s" }, alias = "export", rest = true)
    public RubyString to_pem(ThreadContext context, final IRubyObject[] args) {
        Arity.checkArgumentCount(context.runtime, args, 0, 2);

        CipherSpec spec = null; char[] passwd = null;
        if ( args.length > 0 ) {
            spec = cipherSpec( args[0] );
            if ( args.length > 1 ) passwd = password(context, args[1], null);
        }

        try {
            final StringWriter writer = new StringWriter();
            if (privateKey instanceof RSAPrivateCrtKey) {
                PEMInputOutput.writeRSAPrivateKey(writer, (RSAPrivateCrtKey) privateKey, spec, passwd);
            }
            else {
                PEMInputOutput.writeRSAPublicKey(writer, publicKey);
            }
            return RubyString.newString(context.runtime, writer.getBuffer());
        }
        catch (NoClassDefFoundError ncdfe) {
            throw newRSAError(context.runtime, bcExceptionMessage(ncdfe));
        }
        catch (IOException ioe) {
            throw newRSAError(context.runtime, ioe.getMessage());
        }
    }

    @JRubyMethod
    public RubyString public_to_pem(ThreadContext context) {
        try {
            final StringWriter writer = new StringWriter();
            PEMInputOutput.writeRSAPublicKey(writer, publicKey);
            return RubyString.newString(context.runtime, writer.getBuffer());
        }
        catch (NoClassDefFoundError ncdfe) {
            throw newRSAError(context.runtime, bcExceptionMessage(ncdfe));
        }
        catch (IOException ioe) {
            throw newRSAError(context.runtime, ioe.getMessage());
        }
    }

    @JRubyMethod(rest = true)
    public RubyString private_to_der(ThreadContext context, final IRubyObject[] args) {
        Arity.checkArgumentCount(context.runtime, args, 0, 2);
        if (privateKey == null) {
            throw newRSAError(context.runtime, "private key is not available");
        }
        CipherSpec spec = null; char[] passwd = null;
        if (args.length > 0) {
            spec = cipherSpec(args[0]);
            if (args.length > 1) passwd = password(context, args[1], null);
        }
        try {
            if (spec != null && passwd != null) {
                final ASN1ObjectIdentifier cipherOid = osslNameToCipherOid(spec.getOsslName());
                final OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(cipherOid)
                        .setProvider(SecurityHelper.getSecurityProvider()).build(passwd);
                final PKCS8EncryptedPrivateKeyInfo enc = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey).build(encryptor);
                return StringHelper.newString(context.runtime, enc.getEncoded());
            }
            return StringHelper.newString(context.runtime, privateKey.getEncoded());
        }
        catch (NoClassDefFoundError e) {
            throw newRSAError(context.runtime, bcExceptionMessage(e));
        }
        catch (OperatorCreationException | IOException e) {
            throw newRSAError(context.runtime, e.getMessage(), e);
        }
    }

    @JRubyMethod(rest = true)
    public RubyString private_to_pem(ThreadContext context, final IRubyObject[] args) {
        Arity.checkArgumentCount(context.runtime, args, 0, 2);
        if (privateKey == null) {
            throw newRSAError(context.runtime, "private key is not available");
        }
        CipherSpec spec = null; char[] passwd = null;
        if (args.length > 0) {
            spec = cipherSpec(args[0]);
            if (args.length > 1) passwd = password(context, args[1], null);
        }
        try {
            final StringWriter writer = new StringWriter();
            if (spec != null && passwd != null) {
                final ASN1ObjectIdentifier cipherOid = osslNameToCipherOid(spec.getOsslName());
                final OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(cipherOid)
                        .setProvider(SecurityHelper.getSecurityProvider()).build(passwd);
                final PKCS8EncryptedPrivateKeyInfo enc = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey).build(encryptor);
                PEMInputOutput.writeEncryptedPKCS8PrivateKey(writer, enc.getEncoded());
            } else {
                PEMInputOutput.writePKCS8PrivateKey(writer, privateKey.getEncoded());
            }
            return RubyString.newString(context.runtime, writer.getBuffer());
        }
        catch (NoClassDefFoundError e) {
            throw newRSAError(context.runtime, bcExceptionMessage(e));
        }
        catch (OperatorCreationException | IOException e) {
            throw newRSAError(context.runtime, e.getMessage(), e);
        }
    }

    private static ASN1ObjectIdentifier osslNameToCipherOid(final String osslName) {
        switch (osslName.toUpperCase()) {
            case "AES-128-CBC": return NISTObjectIdentifiers.id_aes128_CBC;
            case "AES-192-CBC": return NISTObjectIdentifiers.id_aes192_CBC;
            case "AES-256-CBC": return NISTObjectIdentifiers.id_aes256_CBC;
            case "AES-128-ECB": return NISTObjectIdentifiers.id_aes128_ECB;
            case "AES-192-ECB": return NISTObjectIdentifiers.id_aes192_ECB;
            case "AES-256-ECB": return NISTObjectIdentifiers.id_aes256_ECB;
            case "AES-128-OFB": return NISTObjectIdentifiers.id_aes128_OFB;
            case "AES-192-OFB": return NISTObjectIdentifiers.id_aes192_OFB;
            case "AES-256-OFB": return NISTObjectIdentifiers.id_aes256_OFB;
            case "AES-128-CFB": return NISTObjectIdentifiers.id_aes128_CFB;
            case "AES-192-CFB": return NISTObjectIdentifiers.id_aes192_CFB;
            case "AES-256-CFB": return NISTObjectIdentifiers.id_aes256_CFB;
            case "DES-EDE3-CBC":
            case "DES-EDE-CBC":
            case "DES3": return PKCSObjectIdentifiers.des_EDE3_CBC;
            default:
                throw new IllegalArgumentException("Unsupported cipher for PKCS8 encryption: " + osslName);
        }
    }

    private String getPadding(final int padding) {
        if ( padding < 1 || padding > 4 ) {
            throw newPKeyError(getRuntime(), "");
        }
        // BC accepts "/NONE/*" but SunJCE doesn't. use "/ECB/*"
        String p = "/ECB/PKCS1Padding";
        if ( padding == 3 ) {
            p = "/ECB/NoPadding";
        } else if ( padding == 4 ) {
            p = "/ECB/OAEPWithSHA1AndMGF1Padding";
        } else if ( padding == 2 ) {
            p = "/ECB/ISO9796-1Padding";
        }
        return p;
    }

    @JRubyMethod(rest = true)
    public IRubyObject private_encrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil() ) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( privateKey == null ) throw newPKeyError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, ENCRYPT_MODE, privateKey);
    }

    @JRubyMethod(rest = true)
    public IRubyObject private_decrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil())  {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( privateKey == null ) throw newPKeyError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, DECRYPT_MODE, privateKey);
    }

    @JRubyMethod(rest = true)
    public IRubyObject public_encrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil())  {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( publicKey == null ) throw newPKeyError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, ENCRYPT_MODE, publicKey);
    }

    @JRubyMethod(rest = true)
    public IRubyObject public_decrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil() ) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( publicKey == null ) throw newPKeyError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, DECRYPT_MODE, publicKey);
    }

    private RubyString doCipherRSA(final Ruby runtime,
        final IRubyObject content, final int padding,
        final int initMode, final Key initKey) {

        final String cipherPadding = getPadding(padding);
        final RubyString buffer = content.convertToString();
        try {
            javax.crypto.Cipher engine = SecurityHelper.getCipher("RSA" + cipherPadding);
            engine.init(initMode, initKey);
            byte[] output = engine.doFinal(buffer.getBytes());
            return StringHelper.newString(runtime, output);
        }
        catch (GeneralSecurityException gse) {
            throw newRSAError(runtime, gse.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject oid() {
        return getRuntime().newString("rsaEncryption");
    }

    // sign_raw(digest, data [, opts]) -- signs already-hashed data with this RSA private key.
    // With no opts (or opts without rsa_padding_mode: "pss"), uses PKCS#1 v1.5 padding:
    //   the hash is wrapped in a DigestInfo ASN.1 structure and signed with NONEwithRSA.
    // With opts containing rsa_padding_mode: "pss", uses RSA-PSS via BC's PSSSigner with
    //   NullDigest (so the pre-hashed bytes are fed directly without re-hashing).
    @JRubyMethod(name = "sign_raw", required = 2, optional = 1)
    public IRubyObject sign_raw(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        if (privateKey == null) throw newPKeyError(runtime, "Private RSA key needed!");

        final String digestAlg = getDigestAlgName(args[0]);
        final byte[] hashBytes = args[1].convertToString().getBytes();
        final IRubyObject opts = args.length > 2 ? args[2] : context.nil;

        if (!opts.isNil()) {
            String paddingMode = Utils.extractStringOpt(context, opts, "rsa_padding_mode", true);
            if ("pss".equalsIgnoreCase(paddingMode)) {
                int saltLen = Utils.extractIntOpt(context, opts, "rsa_pss_saltlen", -1, true);
                String mgf1Alg = Utils.extractStringOpt(context, opts, "rsa_mgf1_md", true);
                if (mgf1Alg == null) mgf1Alg = digestAlg;
                if (saltLen < 0) saltLen = getDigestLength(digestAlg);
                try {
                    return StringHelper.newString(runtime, signWithPSS(hashBytes, digestAlg, mgf1Alg, saltLen));
                } catch (IllegalArgumentException | CryptoException e) {
                    throw (RaiseException) newPKeyError(runtime, e.getMessage()).initCause(e);
                }
            }
        }

        // Default: PKCS#1 v1.5 — wrap hash in DigestInfo, then sign with NONEwithRSA
        try {
            byte[] digestInfoBytes = buildDigestInfo(digestAlg, hashBytes);
            ByteList signed = sign("NONEwithRSA", privateKey, new ByteList(digestInfoBytes, false));
            return RubyString.newString(runtime, signed);
        } catch (IOException e) {
            throw newPKeyError(runtime, "failed to encode DigestInfo: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw newPKeyError(runtime, "unsupported algorithm: NONEwithRSA");
        } catch (InvalidKeyException e) {
            throw newPKeyError(runtime, "invalid key");
        } catch (SignatureException e) {
            throw newPKeyError(runtime, e.getMessage());
        }
    }

    // verify_raw(digest, signature, data [, opts]) -- verifies signature over already-hashed data.
    @JRubyMethod(name = "verify_raw", required = 3, optional = 1)
    public IRubyObject verify_raw(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final String digestAlg = getDigestAlgName(args[0]);
        byte[] sigBytes = args[1].convertToString().getBytes();
        byte[] hashBytes = args[2].convertToString().getBytes();
        IRubyObject opts = args.length > 3 ? args[3] : runtime.getNil();

        if (!opts.isNil()) {
            String paddingMode = Utils.extractStringOpt(context, opts, "rsa_padding_mode", true);
            if ("pss".equalsIgnoreCase(paddingMode)) {
                int saltLen = Utils.extractIntOpt(context, opts, "rsa_pss_saltlen", -1, true);
                String mgf1Alg = Utils.extractStringOpt(context, opts, "rsa_mgf1_md", true);
                if (mgf1Alg == null) mgf1Alg = digestAlg;
                if (saltLen < 0) saltLen = getDigestLength(digestAlg);
                // verify_raw: input is already the hash → use PreHashedDigest (pass-through phase 1)
                return verifyPSS(runtime, true, hashBytes, digestAlg, mgf1Alg, saltLen, sigBytes);
            }
        }

        // Default: PKCS#1 v1.5 — verify against DigestInfo-wrapped hash bytes
        try {
            byte[] digestInfoBytes = buildDigestInfo(digestAlg, hashBytes);
            boolean ok = verify("NONEwithRSA", getPublicKey(),
                    new ByteList(digestInfoBytes, false),
                    new ByteList(sigBytes, false));
            return runtime.newBoolean(ok);
        } catch (IOException e) {
            throw newPKeyError(runtime, "failed to encode DigestInfo: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw newPKeyError(runtime, "unsupported algorithm: NONEwithRSA");
        } catch (InvalidKeyException e) {
            throw newPKeyError(runtime, "invalid key");
        } catch (SignatureException e) {
            return runtime.getFalse();
        }
    }

    // Override verify to support optional 4th opts argument for PSS.
    // Without opts (or with non-PSS opts), delegates to the base PKey#verify logic.
    @JRubyMethod(name = "verify", required = 3, optional = 1)
    public IRubyObject verify(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        IRubyObject digest = args[0];
        IRubyObject sign   = args[1];
        IRubyObject data   = args[2];
        IRubyObject opts   = args.length > 3 ? args[3] : runtime.getNil();

        if (!opts.isNil()) {
            String paddingMode = Utils.extractStringOpt(context, opts, "rsa_padding_mode", true);
            if ("pss".equalsIgnoreCase(paddingMode)) {
                final String digestAlg = getDigestAlgName(digest);
                int saltLen = Utils.extractIntOpt(context, opts, "rsa_pss_saltlen", -1, true);
                String mgf1Alg = Utils.extractStringOpt(context, opts, "rsa_mgf1_md", true);
                if (mgf1Alg == null) mgf1Alg = digestAlg;
                if (saltLen < 0) saltLen = getDigestLength(digestAlg);
                byte[] sigBytes = sign.convertToString().getBytes();
                byte[] dataBytes = data.convertToString().getBytes();

                // verify (non-raw): feed raw data; PSSSigner will hash it internally via SHA-NNN
                return verifyPSS(runtime, false, dataBytes, digestAlg, mgf1Alg, saltLen, sigBytes);
            }
        }

        // Fall back to standard PKey#verify (PKCS#1 v1.5)
        return super.verify(digest, sign, data);
    }

    // Override sign to support an optional 3rd opts argument.
    // When opts contains rsa_padding_mode: "pss", signs the raw data with RSA-PSS.
    // Otherwise delegates to PKey#sign (PKCS#1 v1.5).  Non-Hash opts raise TypeError.
    @JRubyMethod(name = "sign", required = 2, optional = 1)
    public IRubyObject sign(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final IRubyObject digest = args[0];
        final IRubyObject data   = args[1];
        final IRubyObject opts   = args.length > 2 ? args[2] : context.nil;

        if (!opts.isNil()) {
            if (!(opts instanceof RubyHash)) throw runtime.newTypeError("expected Hash");
            String paddingMode = Utils.extractStringOpt(context, opts, "rsa_padding_mode", true);
            if ("pss".equalsIgnoreCase(paddingMode)) {
                if (privateKey == null) throw newPKeyError(runtime, "Private RSA key needed!");
                final String digestAlg = getDigestAlgName(digest);
                int saltLen = Utils.extractIntOpt(context, opts, "rsa_pss_saltlen", -1, true);
                String mgf1Alg = Utils.extractStringOpt(context, opts, "rsa_mgf1_md", true);
                if (mgf1Alg == null) mgf1Alg = digestAlg;
                if (saltLen < 0) saltLen = maxPSSSaltLength(digestAlg, privateKey.getModulus().bitLength());

                final byte[] signedData;
                try {
                    signedData = signDataWithPSS(runtime, data.convertToString(), digestAlg, mgf1Alg, saltLen);
                } catch (IllegalArgumentException | DataLengthException | CryptoException e) {
                    throw (RaiseException) newPKeyError(runtime, e.getMessage()).initCause(e);
                }
                return StringHelper.newString(runtime, signedData);
            }
        }
        return super.sign(digest, data); // PKCS#1 v1.5 fallback
    }

    // sign_pss(digest, data, salt_length:, mgf1_hash:)
    // Signs data with RSA-PSS. salt_length accepts :digest, :max, :auto, or an integer.
    @JRubyMethod(name = "sign_pss", required = 2, optional = 1)
    public IRubyObject sign_pss(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        if (privateKey == null) throw newPKeyError(runtime, "Private RSA key needed!");
        final String digestAlg = getDigestAlgName(args[0]);
        final IRubyObject opts  = args.length > 2 ? args[2] : context.nil;
        final int maxSalt = maxPSSSaltLength(digestAlg, privateKey.getModulus().bitLength());

        String mgf1Alg = Utils.extractStringOpt(context, opts, "mgf1_hash");
        if (mgf1Alg == null) mgf1Alg = digestAlg;

        final IRubyObject saltLenArg = opts instanceof RubyHash ?
                ((RubyHash) opts).fastARef(runtime.newSymbol("salt_length")) : null;
        final int saltLen;
        if (saltLenArg instanceof RubySymbol) {
            String sym = saltLenArg.asJavaString();
            if ("digest".equals(sym)) saltLen = getDigestLength(digestAlg);
            else if ("max".equals(sym) || "auto".equals(sym)) saltLen = maxSalt;
            else throw runtime.newArgumentError("unknown salt_length: " + sym);
        } else if (saltLenArg != null && !saltLenArg.isNil()) {
            saltLen = RubyNumeric.fix2int(saltLenArg);
        } else {
            saltLen = maxSalt;
        }

        final byte[] signedData;
        try {
            signedData = signDataWithPSS(runtime, args[1].convertToString(), digestAlg, mgf1Alg, saltLen);
        } catch (IllegalArgumentException | DataLengthException | CryptoException e) {
            throw (RaiseException) newPKeyError(runtime, e.getMessage()).initCause(e);
        }
        return StringHelper.newString(runtime, signedData);
    }

    // verify_pss(digest, signature, data, salt_length:, mgf1_hash:)
    // Verifies a PSS signature. salt_length accepts :auto, :max, :digest, or an integer.
    @JRubyMethod(name = "verify_pss", required = 3, optional = 1)
    public IRubyObject verify_pss(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final String digestAlg = getDigestAlgName(args[0]);
        final byte[] sigBytes  = args[1].convertToString().getBytes();
        final byte[] dataBytes = args[2].convertToString().getBytes();
        final IRubyObject opts = args.length > 3 ? args[3] : context.nil;

        String mgf1Alg = Utils.extractStringOpt(context, opts, "mgf1_hash");
        if (mgf1Alg == null) mgf1Alg = digestAlg;

        IRubyObject saltLenArg = opts instanceof RubyHash
                ? ((RubyHash) opts).fastARef(runtime.newSymbol("salt_length")) : null;
        int saltLen;
        if (saltLenArg instanceof RubySymbol) {
            String sym = saltLenArg.asJavaString();
            if ("auto".equals(sym)) {
                saltLen = pssAutoSaltLength(publicKey, sigBytes, digestAlg, mgf1Alg);
                if (saltLen < 0) return runtime.getFalse();
            } else if ("max".equals(sym)) {
                saltLen = maxPSSSaltLength(digestAlg, publicKey.getModulus().bitLength());
            } else if ("digest".equals(sym)) {
                saltLen = getDigestLength(digestAlg);
            } else {
                throw runtime.newArgumentError("unknown salt_length: " + sym);
            }
        } else if (saltLenArg != null && !saltLenArg.isNil()) {
            saltLen = RubyNumeric.fix2int(saltLenArg);
        } else {
            saltLen = getDigestLength(digestAlg);
        }

        return verifyPSS(runtime, false, dataBytes, digestAlg, mgf1Alg, saltLen, sigBytes);
    }

    private IRubyObject verifyPSS(final Ruby runtime, final boolean rawVerify,
                                  final byte[] dataBytes, final String digestAlg,
                                  final String mgf1Alg, final int saltLen, final byte[] sigBytes) {
        boolean verified;
        try {
            verified = verifyWithPSS(rawVerify, publicKey, dataBytes, digestAlg, mgf1Alg, saltLen, sigBytes);
        } catch (IllegalArgumentException|IllegalStateException e) {
            verified = false;
        } catch (Exception e) {
            debugStackTrace(runtime, e);
            return runtime.getNil();
        }
        return runtime.newBoolean(verified);
    }

    private static byte[] buildDigestInfo(String digestAlg, byte[] hashBytes) throws IOException {
        AlgorithmIdentifier algId = getDigestAlgId(digestAlg);
        return new DigestInfo(algId, hashBytes).getEncoded("DER");
    }

    private static AlgorithmIdentifier getDigestAlgId(String digestAlg) {
        String upper = digestAlg.toUpperCase().replace("-", "");
        ASN1ObjectIdentifier oid;
        switch (upper) {
            case "SHA1": case "SHA":   oid = new ASN1ObjectIdentifier("1.3.14.3.2.26"); break;
            case "SHA224":             oid = NISTObjectIdentifiers.id_sha224; break;
            case "SHA256":             oid = NISTObjectIdentifiers.id_sha256; break;
            case "SHA384":             oid = NISTObjectIdentifiers.id_sha384; break;
            case "SHA512":             oid = NISTObjectIdentifiers.id_sha512; break;
            default:
                throw new IllegalArgumentException("Unsupported digest for DigestInfo: " + digestAlg);
        }
        return new AlgorithmIdentifier(oid, DERNull.INSTANCE);
    }

    private static org.bouncycastle.crypto.Digest createBCDigest(String digestAlg) {
        String upper = digestAlg.toUpperCase().replace("-", "");
        switch (upper) {
            case "SHA1": case "SHA": return new SHA1Digest();
            case "SHA256":           return new SHA256Digest();
            case "SHA384":           return new SHA384Digest();
            case "SHA512":           return new SHA512Digest();
            default:
                throw new IllegalArgumentException("Unsupported digest for PSS: " + digestAlg);
        }
    }

    private static int getDigestLength(String digestAlg) {
        String upper = digestAlg.toUpperCase().replace("-", "");
        switch (upper) {
            case "SHA1": case "SHA": return 20;
            case "SHA224":           return 28;
            case "SHA256":           return 32;
            case "SHA384":           return 48;
            case "SHA512":           return 64;
            default: return 32; // fallback
        }
    }

    // Signs pre-hashed bytes using RSA-PSS.  PSSSigner internally reuses the content digest for
    // BOTH hashing the message (phase 1) and hashing mDash (phase 2), so we use PreHashedDigest
    // which passes through pre-hashed bytes verbatim in phase 1 and runs a real SHA hash in phase 2.
    private byte[] signWithPSS(byte[] hashBytes, String digestAlg, String mgf1Alg, int saltLen)
        throws CryptoException {
        org.bouncycastle.crypto.Digest contentDigest = new PreHashedDigest(getDigestLength(digestAlg), digestAlg);
        org.bouncycastle.crypto.Digest mgf1Digest = createBCDigest(mgf1Alg);
        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), contentDigest, mgf1Digest, saltLen);
        RSAKeyParameters bcKey = toBCPrivateKeyParams(privateKey);
        signer.init(true, new ParametersWithRandom(bcKey, getSecureRandom(getRuntime())));
        signer.update(hashBytes, 0, hashBytes.length);
        return signer.generateSignature();
    }

    // Verifies an RSA-PSS signature.  When rawVerify=true the input is a pre-computed hash (verify_raw);
    // PreHashedDigest passes it through in phase 1 then uses a real SHA for hashing mDash in phase 2.
    // When rawVerify=false the input is raw data (verify with opts); a real SHA digest is used throughout.
    private static boolean verifyWithPSS(final boolean rawVerify, RSAPublicKey pubKey, byte[] inputBytes,
                                         String digestAlg, String mgf1Alg, int saltLen, byte[] sigBytes) {
        org.bouncycastle.crypto.Digest contentDigest = rawVerify
                ? new PreHashedDigest(getDigestLength(digestAlg), digestAlg)
                : createBCDigest(digestAlg);
        org.bouncycastle.crypto.Digest mgf1Digest = createBCDigest(mgf1Alg);
        PSSSigner verifier = new PSSSigner(new RSABlindedEngine(), contentDigest, mgf1Digest, saltLen);
        verifier.init(false, new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent()));
        verifier.update(inputBytes, 0, inputBytes.length);
        return verifier.verifySignature(sigBytes);
    }

    /**
     * Two-phase Digest for PSS raw-sign/verify.
     *
     * PSSSigner internally calls the content digest twice:
     *   Phase 1  - to hash the message content    → we pass pre-computed hash bytes through verbatim.
     *   Phase 2  - to hash mDash (needs a real hash) → we switch to the actual BC digest algorithm.
     *
     * getDigestSize() always returns the fixed hash length so PSSSigner can allocate its internal
     * buffers correctly even before any data has been accumulated.
     */
    private static class PreHashedDigest implements org.bouncycastle.crypto.Digest {
        private final int hashLen;
        private final String digestAlg; // algorithm name for the real phase-2 digest
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private org.bouncycastle.crypto.Digest realDigest; // non-null during phase 2

        PreHashedDigest(int hashLen, String digestAlg) {
            this.hashLen   = hashLen;
            this.digestAlg = digestAlg;
        }

        public String getAlgorithmName() { return "PRE-HASHED"; }
        public int getDigestSize()       { return hashLen; }

        public void update(byte in) {
            if (realDigest != null) realDigest.update(in);
            else buf.write(in);
        }

        public void update(byte[] in, int off, int len) {
            if (realDigest != null) realDigest.update(in, off, len);
            else buf.write(in, off, len);
        }

        public int doFinal(byte[] out, final int off) {
            if (realDigest == null) {
                // Phase 1: emit the pre-hashed bytes verbatim, then arm the real digest for phase 2
                final int len = buf.size();
                System.arraycopy(buf.buffer(), 0, out, off, len);
                buf.reset();
                realDigest = createBCDigest(digestAlg);
                return len;
            } else {
                // Phase 2: emit the real hash of the mDash bytes that PSSSigner fed us
                final int len = realDigest.doFinal(out, off);
                realDigest = null; // back to phase 1 for reuse
                return len;
            }
        }

        public void reset() {
            buf.reset();
            realDigest = null;
        }
    }

    private static RSAKeyParameters toBCPrivateKeyParams(RSAPrivateKey privKey) {
        if (privKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) privKey;
            return new RSAPrivateCrtKeyParameters(
                    crtKey.getModulus(), crtKey.getPublicExponent(), crtKey.getPrivateExponent(),
                    crtKey.getPrimeP(), crtKey.getPrimeQ(),
                    crtKey.getPrimeExponentP(), crtKey.getPrimeExponentQ(),
                    crtKey.getCrtCoefficient());
        }
        return new RSAKeyParameters(true, privKey.getModulus(), privKey.getPrivateExponent());
    }

    // Signs raw (unhashed) data with RSA-PSS; PSSSigner applies the hash internally.
    private byte[] signDataWithPSS(Ruby runtime, RubyString data, String digestAlg, String mgf1Alg, int saltLen)
        throws CryptoException {
        org.bouncycastle.crypto.Digest contentDigest = createBCDigest(digestAlg);
        org.bouncycastle.crypto.Digest mgf1Digest    = createBCDigest(mgf1Alg);
        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), contentDigest, mgf1Digest, saltLen);
        signer.init(true, new ParametersWithRandom(toBCPrivateKeyParams(privateKey), getSecureRandom(runtime)));
        final ByteList dataBytes = data.getByteList();
        signer.update(dataBytes.unsafeBytes(), dataBytes.getBegin(), dataBytes.getRealSize());
        return signer.generateSignature();
    }

    // Maximum PSS salt length per RFC 8017 §9.1.1:
    //   emLen = ceil((keyBits - 1) / 8),  maxSalt = emLen - 2 - hLen
    private static int maxPSSSaltLength(String digestAlg, int keyBits) {
        int emLen = (keyBits - 1 + 7) / 8;
        return emLen - 2 - getDigestLength(digestAlg);
    }

    // Extracts the actual PSS salt length from a signature by parsing the PSS-encoded message.
    // Returns -1 if the encoding is invalid (not a well-formed PSS block).
    // This is used to implement salt_length: :auto in verify_pss.
    private static int pssAutoSaltLength(RSAPublicKey pubKey, byte[] sigBytes, String digestAlg, String mgf1Alg) {
        // Step 1: RSA public-key operation → encoded message (EM)
        RSAKeyParameters bcPubKey = new RSAKeyParameters(false, pubKey.getModulus(), pubKey.getPublicExponent());
        RSABlindedEngine rsa = new RSABlindedEngine();
        rsa.init(false, bcPubKey);
        byte[] em = rsa.processBlock(sigBytes, 0, sigBytes.length);

        int hLen  = getDigestLength(digestAlg);
        int emLen = em.length;
        if (emLen < hLen + 2 || em[emLen - 1] != (byte) 0xBC) return -1;

        int dbLen = emLen - hLen - 1;
        byte[] H  = new byte[hLen];
        System.arraycopy(em, dbLen, H, 0, hLen);

        // Step 2: Recover DB = MGF1(H, dbLen) XOR maskedDB
        byte[] DB = new byte[dbLen];
        System.arraycopy(em, 0, DB, 0, dbLen);
        org.bouncycastle.crypto.Digest mgfDigest = createBCDigest(mgf1Alg);
        int mgfHLen  = mgfDigest.getDigestSize();
        byte[] hBuf  = new byte[mgfHLen];
        byte[] ctr   = new byte[4];
        for (int pos = 0, c = 0; pos < dbLen; c++) {
            ctr[0] = (byte)(c >> 24); ctr[1] = (byte)(c >> 16);
            ctr[2] = (byte)(c >>  8); ctr[3] = (byte) c;
            mgfDigest.update(H, 0, hLen);
            mgfDigest.update(ctr, 0, 4);
            mgfDigest.doFinal(hBuf, 0);
            int n = Math.min(mgfHLen, dbLen - pos);
            for (int i = 0; i < n; i++) DB[pos + i] ^= hBuf[i];
            pos += n;
        }

        // Step 3: Clear top bits per RFC 8017 §9.1.2
        int topBits = 8 * emLen - (pubKey.getModulus().bitLength() - 1);
        if (topBits > 0) DB[0] &= (byte)(0xFF >>> topBits);

        // Step 4: Find the 0x01 separator; salt follows it
        for (int i = 0; i < dbLen; i++) {
            if (DB[i] == 0x01) return dbLen - i - 1;
            if (DB[i] != 0x00) return -1;
        }
        return -1;
    }

    @JRubyMethod(name="d=")
    public synchronized IRubyObject set_d(final ThreadContext context, IRubyObject value) {
        if ( privateKey != null ) {
            throw newRSAError(context.runtime, "illegal modification");
        }
        rsa_d = BN.getBigInteger(value);
        generatePrivateKeyIfParams(context);
        return value;
    }

    @JRubyMethod(name="p=")
    public synchronized IRubyObject set_p(final ThreadContext context, IRubyObject value) {
        if ( privateKey != null ) {
            throw newRSAError(context.runtime, "illegal modification");
        }
        rsa_p = BN.getBigInteger(value);
        generatePrivateKeyIfParams(context);
        return value;
    }

    @JRubyMethod(name="q=")
    public synchronized IRubyObject set_q(final ThreadContext context, IRubyObject value) {
        if ( privateKey != null ) {
            throw newRSAError(context.runtime, "illegal modification");
        }
        rsa_q = BN.getBigInteger(value);
        generatePrivateKeyIfParams(context);
        return value;
    }

    @JRubyMethod(name="dmp1=")
    public synchronized IRubyObject set_dmp1(final ThreadContext context, IRubyObject value) {
        if ( privateKey != null ) {
            throw newRSAError(context.runtime, "illegal modification");
        }
        rsa_dmp1 = BN.asBigInteger(value);
        generatePrivateKeyIfParams(context);
        return value;
    }

    @JRubyMethod(name="dmq1=")
    public synchronized IRubyObject set_dmq1(final ThreadContext context, IRubyObject value) {
        if ( privateKey != null ) {
            throw newRSAError(context.runtime, "illegal modification");
        }
        rsa_dmq1 = BN.asBigInteger(value);
        generatePrivateKeyIfParams(context);
        return value;
    }

    @JRubyMethod(name="iqmp=")
    public synchronized IRubyObject set_iqmp(final ThreadContext context, IRubyObject value) {
        if ( privateKey != null ) {
            throw newRSAError(context.runtime, "illegal modification");
        }
        rsa_iqmp = BN.asBigInteger(value);
        generatePrivateKeyIfParams(context);
        return value;
    }

    @JRubyMethod(name="iqmp")
    public synchronized IRubyObject get_iqmp() {
        BigInteger iqmp = this.rsa_iqmp;
        if (iqmp == null && privateKey instanceof RSAPrivateCrtKey) {
            iqmp = ((RSAPrivateCrtKey) privateKey).getCrtCoefficient();
        }

        if (iqmp != null) return BN.newBN(getRuntime(), iqmp);
        return getRuntime().getNil();
    }

    @JRubyMethod(name="dmp1")
    public synchronized IRubyObject get_dmp1() {
        BigInteger dmp1 = this.rsa_dmp1;
        if (dmp1 == null && privateKey instanceof RSAPrivateCrtKey) {
            dmp1 = ((RSAPrivateCrtKey) privateKey).getPrimeExponentP();
        }

        if (dmp1 != null) return BN.newBN(getRuntime(), dmp1);
        return getRuntime().getNil();
    }

    @JRubyMethod(name="dmq1")
    public synchronized IRubyObject get_dmq1() {
        BigInteger dmq1 = this.rsa_dmq1;
        if (dmq1 == null && privateKey instanceof RSAPrivateCrtKey) {
            dmq1 = ((RSAPrivateCrtKey) privateKey).getPrimeExponentQ();
        }

        if (dmq1 != null) return BN.newBN(getRuntime(), dmq1);
        return getRuntime().getNil();
    }

    @JRubyMethod(name="d")
    public synchronized IRubyObject get_d() {
        final BigInteger d = getPrivateExponent();
        if (d != null) return BN.newBN(getRuntime(), d);
        return getRuntime().getNil();
    }

    private BigInteger getPrivateExponent() {
        BigInteger d = rsa_d;
        if (d == null && privateKey != null) {
            d = privateKey.getPrivateExponent();
        }
        return d;
    }

    @JRubyMethod(name="p")
    public synchronized IRubyObject get_p() {
        BigInteger p = rsa_p;
        if (p == null && privateKey instanceof RSAPrivateCrtKey) {
            p = ((RSAPrivateCrtKey) privateKey).getPrimeP();
        }

        if (p != null) return BN.newBN(getRuntime(), p);
        return getRuntime().getNil();
    }

    @JRubyMethod(name="q")
    public synchronized IRubyObject get_q() {
        BigInteger q = rsa_q;
        if (q == null && privateKey instanceof RSAPrivateCrtKey) {
            q = ((RSAPrivateCrtKey) privateKey).getPrimeQ();
        }

        if (q != null) return BN.newBN(getRuntime(), q);
        return getRuntime().getNil();
    }

    private BigInteger getPublicExponent() {
        if (rsa_e != null) return rsa_e;

        if (publicKey != null) return publicKey.getPublicExponent();
        if (privateKey instanceof RSAPrivateCrtKey) return ((RSAPrivateCrtKey) privateKey).getPublicExponent();
        return null;
    }

    @JRubyMethod(name="e")
    public synchronized IRubyObject get_e() {
        BigInteger e = getPublicExponent();
        if (e != null) {
            return BN.newBN(getRuntime(), e);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="e=")
    public synchronized IRubyObject set_e(final ThreadContext context, IRubyObject value) {
        this.rsa_e = BN.getBigInteger(value);

        if ( privateKey == null ) {
            generatePrivateKeyIfParams(context);
        }
        if ( publicKey == null ) {
            generatePublicKeyIfParams(context);
        }

        return value;
    }

    private BigInteger getModulus() {
        if (rsa_n != null) return rsa_n;

        if (publicKey != null) return publicKey.getModulus();
        if (privateKey != null) return privateKey.getModulus();
        return null;
    }

    @JRubyMethod(name="n")
    public synchronized IRubyObject get_n() {
        BigInteger n = getModulus();
        if (n != null) {
            return BN.newBN(getRuntime(), n);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="n=")
    public synchronized IRubyObject set_n(final ThreadContext context, IRubyObject value) {
        this.rsa_n = BN.getBigInteger(value);

        if ( privateKey == null ) {
            generatePrivateKeyIfParams(context);
        }
        if ( publicKey == null ) {
            generatePublicKeyIfParams(context);
        }

        return value;
    }

    @JRubyMethod
    public IRubyObject set_key(final ThreadContext context, IRubyObject n, IRubyObject e, IRubyObject d) {
        this.rsa_n = BN.getBigInteger(n);
        this.rsa_e = BN.getBigInteger(e);
        this.rsa_d = BN.getBigInteger(d);
        generatePublicKeyIfParams(context);
        generatePrivateKeyIfParams(context);
        return this;
    }

    @JRubyMethod
    public IRubyObject set_factors(final ThreadContext context, IRubyObject p, IRubyObject q) {
        this.rsa_p = BN.getBigInteger(p);
        this.rsa_q = BN.getBigInteger(q);
        generatePrivateKeyIfParams(context);
        return this;
    }

    @JRubyMethod
    public IRubyObject set_crt_params(final ThreadContext context, IRubyObject dmp1, IRubyObject dmq1, IRubyObject iqmp) {
        this.rsa_dmp1 = BN.asBigInteger(dmp1);
        this.rsa_dmq1 = BN.asBigInteger(dmq1);
        this.rsa_iqmp = BN.asBigInteger(iqmp);
        generatePrivateKeyIfParams(context);
        return this;
    }

    private void generatePublicKeyIfParams(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        // Don't access the rsa_n and rsa_e fields directly. They may have
        // already been consumed and cleared by generatePrivateKeyIfParams.
        BigInteger _rsa_n = getModulus();
        BigInteger _rsa_e = getPublicExponent();

        if (_rsa_n != null && _rsa_e != null) {
            final KeyFactory rsaFactory;
            try {
                rsaFactory = SecurityHelper.getKeyFactory("RSA");
            }
            catch (Exception ex) {
                throw runtime.newLoadError("unsupported key algorithm (RSA)");
            }

            try {
                publicKey = (RSAPublicKey) rsaFactory.generatePublic(new RSAPublicKeySpec(_rsa_n, _rsa_e));
            }
            catch (InvalidKeySpecException ex) {
                throw newRSAError(runtime, "invalid parameters");
            }
            rsa_e = null;
            rsa_n = null;
        }
    }

    private void generatePrivateKeyIfParams(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        // Don't access the rsa_n and rsa_e fields directly. They may have
        // already been consumed and cleared by generatePublicKeyIfParams.
        final BigInteger rsa_n = getModulus();
        final BigInteger rsa_e = getPublicExponent();
        final BigInteger rsa_d = getPrivateExponent();

        if (rsa_n != null && rsa_e != null && rsa_d != null) {
            final KeyFactory rsaFactory;
            try {
                rsaFactory = SecurityHelper.getKeyFactory("RSA");
            }
            catch (NoSuchAlgorithmException e) {
                throw runtime.newLoadError("unsupported key algorithm (RSA)");
            }

            if (rsa_p != null && rsa_q != null && rsa_dmp1 != null && rsa_dmq1 != null && rsa_iqmp != null) {
                try {
                    privateKey = (RSAPrivateCrtKey) rsaFactory.generatePrivate(
                            new RSAPrivateCrtKeySpec(rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp)
                    );
                } catch (InvalidKeySpecException e) {
                    throw newRSAError(runtime, "invalid parameters", e);
                }
                this.rsa_n = this.rsa_e = this.rsa_d = null;
                this.rsa_p = this.rsa_q = null;
                this.rsa_dmp1 = this.rsa_dmq1 = this.rsa_iqmp = null;
            } else {
                try {
                    privateKey = (RSAPrivateKey) rsaFactory.generatePrivate(new RSAPrivateKeySpec(rsa_n, rsa_d));
                } catch (InvalidKeySpecException e) {
                    throw newRSAError(runtime, "invalid parameters", e);
                }
            }
        }
    }

}// PKeyRSA
