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
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static javax.crypto.Cipher.*;

import org.bouncycastle.asn1.ASN1Primitive;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyBignum;
import org.jruby.RubyBoolean;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;

import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.impl.PKey.readRSAPrivateKey;
import static org.jruby.ext.openssl.impl.PKey.readRSAPublicKey;
import static org.jruby.ext.openssl.impl.PKey.toASN1Primitive;
import static org.jruby.ext.openssl.impl.PKey.toDerRSAKey;

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
        return Utils.newError(runtime, _PKey(runtime).getClass("RSAError"), cause.getMessage(), cause);
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
    private volatile transient RSAPrivateCrtKey privateKey;

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

    static PKeyRSA newInstance(final Ruby runtime, final PublicKey publicKey) {
        //if ( publicKey instanceof RSAPublicKey ) {
        return new PKeyRSA(runtime, (RSAPublicKey) publicKey);
        //}
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
            catch (IOException e) { debug(runtime, "PKeyRSA could not read private key", e); }
            catch (RuntimeException e) {
                if ( isKeyGenerationFailure(e) ) debug(runtime, "PKeyRSA could not read private key", e);
                else debugStackTrace(runtime, e);
            }
        }
        if ( key == null && ! noClassDef ) { // d2i_RSAPublicKey_bio
            try { key = readRSAPublicKey(rsaFactory, str.getBytes()); }
            catch (NoClassDefFoundError e) { noClassDef = true; debugStackTrace(runtime, e); }
            catch (InvalidKeySpecException e) { debug(runtime, "PKeyRSA could not read public key", e); }
            catch (IOException e) { debug(runtime, "PKeyRSA could not read public key", e); }
            catch (RuntimeException e) {
                if ( isKeyGenerationFailure(e) ) debug(runtime, "PKeyRSA could not read public key", e);
                else debugStackTrace(runtime, e);
            }
        }

        if ( key == null ) key = tryPKCS8EncodedKey(runtime, rsaFactory, str.getBytes());
        if ( key == null ) key = tryX509EncodedKey(runtime, rsaFactory, str.getBytes());

        if ( key == null ) throw newRSAError(runtime, "Neither PUB key nor PRIV key:");

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
            try {
                this.publicKey = (RSAPublicKey) rsaFactory.generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
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

    @Override
    @JRubyMethod(name = "to_der")
    public RubyString to_der() {
        final byte[] bytes;
        try {
            bytes = toDerRSAKey(publicKey, privateKey);
        }
        catch (NoClassDefFoundError e) {
            throw newRSAError(getRuntime(), bcExceptionMessage(e));
        }
        catch (IOException e) {
            throw newRSAError(getRuntime(), e.getMessage());
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
        if ( privateKey != null ) {
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
        if (privateKey != null) {
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
            if ( privateKey != null ) {
                PEMInputOutput.writeRSAPrivateKey(writer, privateKey, spec, passwd);
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

    private String getPadding(final int padding) {
        if ( padding < 1 || padding > 4 ) {
            throw newRSAError(getRuntime(), "");
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
        if ( privateKey == null ) throw newRSAError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, ENCRYPT_MODE, privateKey);
    }

    @JRubyMethod(rest = true)
    public IRubyObject private_decrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil())  {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( privateKey == null ) throw newRSAError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, DECRYPT_MODE, privateKey);
    }

    @JRubyMethod(rest = true)
    public IRubyObject public_encrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil())  {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( publicKey == null ) throw newRSAError(context.runtime, "incomplete RSA");
        return doCipherRSA(context.runtime, args[0], padding, ENCRYPT_MODE, publicKey);
    }

    @JRubyMethod(rest = true)
    public IRubyObject public_decrypt(final ThreadContext context, final IRubyObject[] args) {
        int padding = 1;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 2) == 2 && ! args[1].isNil() ) {
            padding = RubyNumeric.fix2int(args[1]);
        }
        if ( publicKey == null ) throw newRSAError(context.runtime, "incomplete RSA");
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
        BigInteger iqmp;
        if (privateKey != null) {
            iqmp = privateKey.getCrtCoefficient();
        } else {
            iqmp = rsa_iqmp;
        }
        if (iqmp != null) {
            return BN.newBN(getRuntime(), iqmp);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="dmp1")
    public synchronized IRubyObject get_dmp1() {
        BigInteger dmp1;
        if (privateKey != null) {
            dmp1 = privateKey.getPrimeExponentP();
        } else {
            dmp1 = rsa_dmp1;
        }
        if (dmp1 != null) {
            return BN.newBN(getRuntime(), dmp1);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="dmq1")
    public synchronized IRubyObject get_dmq1() {
        BigInteger dmq1;
        if (privateKey != null) {
            dmq1 = privateKey.getPrimeExponentQ();
        } else {
            dmq1 = rsa_dmq1;
        }
        if (dmq1 != null) {
            return BN.newBN(getRuntime(), dmq1);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="d")
    public synchronized IRubyObject get_d() {
        BigInteger d;
        if (privateKey != null) {
            d = privateKey.getPrivateExponent();
        } else {
            d = rsa_d;
        }
        if (d != null) {
            return BN.newBN(getRuntime(), d);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="p")
    public synchronized IRubyObject get_p() {
        BigInteger p;
        if (privateKey != null) {
            p = privateKey.getPrimeP();
        } else {
            p = rsa_p;
        }
        if (p != null) {
            return BN.newBN(getRuntime(), p);
        }
        return getRuntime().getNil();
    }

    @JRubyMethod(name="q")
    public synchronized IRubyObject get_q() {
        BigInteger q;
        if (privateKey != null) {
            q = privateKey.getPrimeQ();
        } else {
            q = rsa_q;
        }
        if (q != null) {
            return BN.newBN(getRuntime(), q);
        }
        return getRuntime().getNil();
    }

    private BigInteger getPublicExponent() {
        if (publicKey != null) {
            return publicKey.getPublicExponent();
        } else if (privateKey != null) {
            return privateKey.getPublicExponent();
        } else {
            return rsa_e;
        }
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
        if (publicKey != null) {
            return publicKey.getModulus();
        } else if (privateKey != null) {
            return privateKey.getModulus();
        } else {
            return rsa_n;
        }
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

    private void generatePublicKeyIfParams(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        if ( publicKey != null ) throw newRSAError(runtime, "illegal modification");

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

        if ( privateKey != null ) throw newRSAError(runtime, "illegal modification");

        // Don't access the rsa_n and rsa_e fields directly. They may have
        // already been consumed and cleared by generatePublicKeyIfParams.
        BigInteger _rsa_n = getModulus();
        BigInteger _rsa_e = getPublicExponent();

        if (_rsa_n != null && _rsa_e != null && rsa_p != null && rsa_q != null && rsa_d != null && rsa_dmp1 != null && rsa_dmq1 != null && rsa_iqmp != null) {
            final KeyFactory rsaFactory;
            try {
                rsaFactory = SecurityHelper.getKeyFactory("RSA");
            }
            catch (NoSuchAlgorithmException e) {
                throw runtime.newLoadError("unsupported key algorithm (RSA)");
            }

            try {
                privateKey = (RSAPrivateCrtKey) rsaFactory.generatePrivate(
                    new RSAPrivateCrtKeySpec(_rsa_n, _rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp)
                );
            }
            catch (InvalidKeySpecException e) {
                throw newRSAError(runtime, "invalid parameters");
            }
            rsa_n = null; rsa_e = null;
            rsa_d = null; rsa_p = null; rsa_q = null;
            rsa_dmp1 = null; rsa_dmq1 = null; rsa_iqmp = null;
        }
    }

}// PKeyRSA
