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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;

import org.jruby.ext.openssl.x509store.PEMInputOutput;
import static org.jruby.ext.openssl.OpenSSL.*;
import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.util.ByteList;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public abstract class PKey extends RubyObject {
    private static final long serialVersionUID = 6114668087816965720L;

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
        return Utils.newError(runtime, (RubyClass) _PKey(runtime).getConstantAt("PKeyError"), message);
    }

    static RubyModule _PKey(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstantAt("PKey");
    }

    public static class PKeyModule {

        @JRubyMethod(name = "read", meta = true, required = 1, optional = 1)
        public static IRubyObject read(final ThreadContext context, IRubyObject recv, IRubyObject[] args) {
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
            Object key = null;
            // d2i_PrivateKey_bio
            try {
                key = readPrivateKey(str, pass);
            } catch (IOException e) { /* ignore */ }
            // PEM_read_bio_PrivateKey
            if (key != null) {
                final KeyPair keyPair = (KeyPair) key;
                final String alg = getAlgorithm(keyPair);
                if ( "RSA".equals(alg) ) {
                    return new PKeyRSA(runtime, _PKey(runtime).getClass("RSA"),
                            (RSAPrivateCrtKey) keyPair.getPrivate(), (RSAPublicKey) keyPair.getPublic()
                    );
                }
                if ( "DSA".equals(alg) ) {
                    return new PKeyDSA(runtime, _PKey(runtime).getClass("DSA"),
                            (DSAPrivateKey) keyPair.getPrivate(), (DSAPublicKey) keyPair.getPublic()
                    );
                }
                if ( "ECDSA".equals(alg) ) {
                    return new PKeyEC(runtime, _PKey(runtime).getClass("EC"),
                            (PrivateKey) keyPair.getPrivate(), (PublicKey) keyPair.getPublic()
                    );
                }
            }

            PublicKey pubKey = null;
            try {
                pubKey = PEMInputOutput.readRSAPublicKey(new StringReader(str.toString()), null);
                return new PKeyRSA(runtime, (RSAPublicKey) pubKey);
            } catch (IOException e) { /* ignore */ }
            try {
                pubKey = PEMInputOutput.readDSAPublicKey(new StringReader(str.toString()), null);
                return new PKeyDSA(runtime, (DSAPublicKey) pubKey);
            } catch (IOException e) { /* ignore */ }

            final byte[] input = StringHelper.readX509PEM(context, str);
            // d2i_PUBKEY_bio
            try {
                pubKey = org.jruby.ext.openssl.impl.PKey.readPublicKey(input);
            } catch (IOException|GeneralSecurityException e) { /* ignore */ }
            // PEM_read_bio_PUBKEY
            if (pubKey == null) {
                try {
                    pubKey = PEMInputOutput.readPubKey(new StringReader(str.toString()));
                } catch (IOException e) { /* ignore */ }
            }

            if (pubKey != null) {
                if ( "RSA".equals(pubKey.getAlgorithm()) ) {
                    return new PKeyRSA(runtime, (RSAPublicKey) pubKey);
                }
                if ( "DSA".equals(pubKey.getAlgorithm()) ) {
                    return new PKeyDSA(runtime, (DSAPublicKey) pubKey);
                }
                if ( "ECDSA".equals(pubKey.getAlgorithm()) ) {
                    return new PKeyEC(runtime, pubKey);
                }
            }

            throw runtime.newArgumentError("Could not parse PKey");
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

    public boolean isPrivateKey() { return getPrivateKey() != null; }

    public abstract RubyString to_der() ;

    public abstract RubyString to_pem(ThreadContext context, final IRubyObject[] args) ;

    @Deprecated
    public RubyString to_pem(final IRubyObject[] args) {
        return to_pem(getRuntime().getCurrentContext(), args);
    }

    @Deprecated
    public RubyString export(final IRubyObject[] args) {
        return to_pem(getRuntime().getCurrentContext(), args);
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
    }

    public ASN1Primitive toASN1PublicInfo() throws IOException {
        ASN1InputStream input = new ASN1InputStream(to_der().getBytes());

        ASN1Primitive data = input.readObject();
        if (data instanceof ASN1Sequence) {
            return ((ASN1Sequence) data).getObjectAt(1).toASN1Primitive();
        }
        return data;
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
        String digAlg = (digest instanceof Digest) ? ((Digest) digest).getShortAlgorithm() : digest.asJavaString();
        final String algorithm = digAlg + "WITH" + getAlgorithm();
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
    }

    static RubyString convertToString(final Ruby runtime, final IRubyObject str, final String errorType, final CharSequence errorMsg) {
        try {
            return str.convertToString();
        }
        catch (RaiseException ex) { // to_str conversion failed
            throw Utils.newError(runtime, (RubyClass) runtime.getClassFromPath(errorType), errorMsg == null ? null : errorMsg.toString());
        }
    }

    static boolean verify(final String signAlg, final PublicKey publicKey, final ByteList data, final ByteList sign)
        throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = SecurityHelper.getSignature(signAlg);
        signature.initVerify(publicKey);
        signature.update(data.getUnsafeBytes(), data.getBegin(), data.getRealSize());
        return signature.verify(sign.getUnsafeBytes(), sign.getBegin(), sign.getRealSize());
    }

    static SecureRandom getSecureRandom(final Ruby runtime) {
        return OpenSSL.getSecureRandom(runtime);
    }

    // shared Helpers for PKeyRSA / PKeyDSA :

    protected PrivateKey tryPKCS8EncodedKey(final Ruby runtime, final KeyFactory keyFactory, final byte[] encodedKey) {
        try {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
        }
        catch (InvalidKeySpecException e) {
            if ( isDebug(runtime) ) {
                debug(runtime, getClass().getSimpleName() + " could not generate (PKCS8) private key", e);
            }
        }
        catch (RuntimeException e) {
            if ( isKeyGenerationFailure(e) ) {
                if( isDebug(runtime) ) {
                    debug(runtime, getClass().getSimpleName() + " could not generate (PKCS8) private key", e);
                }
            }
            else debugStackTrace(runtime, e);
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
            if ( isDebug(runtime) ) {
                debug(runtime, getClass().getSimpleName() + " could not generate (X509) public key", e);
            }
        }
        catch (RuntimeException e) {
            if ( isKeyGenerationFailure(e) ) { // NOTE: not (yet) detected with X.509
                if( isDebug(runtime) ) {
                    debug(runtime, getClass().getSimpleName() + " could not generate (X509) public key", e);
                }
            }
            else debugStackTrace(runtime, e);
        }
        return null;
    }

    protected static void addSplittedAndFormatted(StringBuilder result, BigInteger value) {
        String v = value.toString(16);
        if ((v.length() % 2) != 0) {
            v = "0" + v;
        }
        String sep = "";
        for (int i = 0; i < v.length(); i += 2) {
            result.append(sep);
            if ((i % 30) == 0) {
                result.append("\n    ");
            }
            result.append(v.substring(i, i + 2));
            sep = ":";
        }
        result.append("\n");
    }

    protected static CipherSpec cipherSpec(final IRubyObject cipher) {
        if ( cipher != null && ! cipher.isNil() ) {
            final Cipher c = (Cipher) cipher;
            return new CipherSpec(c.getCipherInstance(), c.getName(), c.getKeyLength() * 8);
        }
        return null;
    }

    @Deprecated
    protected static char[] password(final IRubyObject pass) {
        if ( pass != null && ! pass.isNil() ) {
            return pass.toString().toCharArray();
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

    static Object readPrivateKey(final String str, final char[] passwd)
        throws PEMInputOutput.PasswordRequiredException, IOException {
        return PEMInputOutput.readPrivateKey(new StringReader(str), passwd);
    }

    static Object readPrivateKey(final RubyString str, final char[] passwd)
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
            throw Utils.newError(runtime, errorClass, "unsupported key / digest algorithm ( "+ keyAlg +" / "+ digAlg +" )");
        }
    }

    static void supportedSignatureAlgorithm(final Ruby runtime, final PKey key, final Digest digest) {
        supportedSignatureAlgorithm(runtime, _OpenSSLError(runtime), key, digest);
    }

}// PKey
