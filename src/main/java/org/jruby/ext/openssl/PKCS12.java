/*
 * The MIT License
 *
 * Copyright 2026 Karol Bucek.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newString;

@JRubyClass(name = "OpenSSL::PKCS12")
public class PKCS12 extends RubyObject {
    private static final long serialVersionUID = 8087765252844713771L;

    private static final ObjectAllocator ALLOCATOR = (runtime, klass) -> new PKCS12(runtime, klass);

    private static final int KEY_EX = 0x10;
    private static final int KEY_SIG = 0x80;

    // PKCSObjectIdentifiers.id_PBMAC1 (missing in BC-FIPS)
    private static final ASN1ObjectIdentifier id_PBMAC1 = new ASN1ObjectIdentifier("1.2.840.113549.1.5.14");

    // OpenSSL's PKCS12 defaults: PKCS12_DEFAULT_ITER / PKCS12_SALT_LEN
    private static final int PBE_DEFAULT_ITER = 2048;
    private static final int PBE_SALT_LEN = 16;

    // EVP_MAX_MD_SIZE - OpenSSL's upper bound for a PBMAC1 PBKDF2 key length (bytes)
    private static final int MAX_MAC_KEY_LENGTH = 64;

    static void createPKCS12(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyClass _PKCS12 = OpenSSL.defineClassUnder("PKCS12", runtime.getObject(), ALLOCATOR);
        _PKCS12.defineClassUnder("PKCS12Error", OpenSSLError, OpenSSLError.getAllocator());
        _PKCS12.defineAnnotatedMethods(PKCS12.class);

        // from OpenSSL's MSIE-specific key usage constants
        _PKCS12.setConstant("KEY_EX", runtime.newFixnum(KEY_EX));
        _PKCS12.setConstant("KEY_SIG", runtime.newFixnum(KEY_SIG));
    }

    private IRubyObject key;
    private IRubyObject certificate;
    private RubyArray<X509Cert> caCerts;
    private byte[] storeBytes; // DER

    public PKCS12(Ruby runtime, RubyClass type) {
        super(runtime, type);
        this.key = runtime.getNil();
        this.certificate = runtime.getNil();
    }

    @JRubyMethod(meta = true, rest = true)
    public static IRubyObject create(final ThreadContext context,
                                     final IRubyObject self,
                                     final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        Arity.checkArgumentCount(runtime, args, 4, 10);

        final PKCS12 pkcs12 = new PKCS12(runtime, (RubyClass) self);
        pkcs12.generate(context, args);
        return pkcs12;
    }

    @JRubyMethod(name = "initialize", optional = 2, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context,
                                  final IRubyObject[] args,
                                  final Block unusedBlock) {
        final Ruby runtime = context.runtime;
        if (Arity.checkArgumentCount(runtime, args, 0, 2) == 0) {
            storeBytes = null;
            return this;
        }

        final RubyString input = StringHelper.readPossibleDERInput(context, args[0]);
        storeBytes = input.getBytes();

        final IRubyObject passArg = args.length > 1 ? args[1] : runtime.getNil();
        final char[] password = toPasswordChars(passArg);
        try {
            loadBags(context, password);
        }
        catch (Exception e) {
            if (e instanceof RaiseException) throw (RaiseException) e;
            throw newPKCS12Error(runtime, e);
        }
        catch (Throwable e) { // unapproved MAC/KDF under FIPS
            return OpenSSL.handlePotentialOperationError(runtime, e);
        }
        finally {
            clearChars(password);
        }

        return this;
    }

    @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final PKCS12 that = (PKCS12) original;
        this.key = that.key;
        this.certificate = that.certificate;
        this.caCerts = that.caCerts;
        this.storeBytes = that.storeBytes == null ? null : that.storeBytes.clone();
        return this;
    }

    @JRubyMethod
    public IRubyObject key() {
        return key;
    }

    @JRubyMethod
    public IRubyObject certificate() {
        return certificate;
    }

    @JRubyMethod(name = "ca_certs")
    public IRubyObject ca_certs(final ThreadContext context) {
        return caCerts == null ? context.nil : caCerts;
    }

    @JRubyMethod(name = "to_der")
    public IRubyObject to_der(final ThreadContext context) {
        if (storeBytes == null) return context.nil;
        return newString(context.runtime, storeBytes.clone());
    }

    @JRubyMethod(name = "set_mac", rest = true)
    public IRubyObject set_mac(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        Arity.checkArgumentCount(runtime, args, 1, 4);
        checkFrozen();

        final char[] password = toPasswordChars(args[0].convertToString());
        try {
            final byte[] salt;
            if (args.length > 1 && !args[1].isNil()) {
                salt = args[1].convertToString().getBytes();
            } else {
                salt = new byte[PBE_SALT_LEN];
                OpenSSL.getSecureRandom(context).nextBytes(salt);
            }
            final int iterationCount = args.length > 2 && !args[2].isNil() ?
                RubyNumeric.num2int(args[2]) : PBE_DEFAULT_ITER;
            final ASN1ObjectIdentifier digest = args.length > 3 && !args[3].isNil() ?
                ASN1.getObjectID(runtime, args[3].asJavaString()) :
                new ASN1ObjectIdentifier("1.3.14.3.2.26");
            storeBytes = setMac(storeBytes, password, salt, iterationCount, digest);
        }
        catch (Exception e) {
            if (e instanceof RaiseException) throw (RaiseException) e;
            throw newPKCS12Error(runtime, e);
        }
        catch (Throwable e) {
            return OpenSSL.handlePotentialOperationError(runtime, e);
        }
        finally {
            clearChars(password);
        }
        return context.nil;
    }

    private void generate(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        final IRubyObject passArg = args[0];
        final IRubyObject nameArg = args[1];
        final IRubyObject keyArg = args[2];
        final IRubyObject certArg = args[3];
        final IRubyObject caArg = args.length > 4 ? args[4] : runtime.getNil();

        if (!(keyArg instanceof PKey)) throw runtime.newTypeError(keyArg, PKey._PKey(runtime).getClass("PKey"));
        if (!(certArg instanceof X509Cert)) throw runtime.newTypeError(certArg, X509Cert._Certificate(runtime));

        validateCreateOptions(runtime, args);

        final char[] password = toPasswordChars(passArg);
        try {
            final PrivateKey privateKey = ((PKey) keyArg).getPrivateKey();
            if (privateKey == null) throw newPKCS12Error(runtime, "private key not set");

            final RubyArray<X509Cert> caCerts = caArg.isNil() ? null : caArg.convertToArray();
            final Certificate[] chain = buildCertificateChain(runtime, (X509Cert) certArg, caCerts);

            final Provider provider = SecurityHelper.getSecurityProvider();
            final String alias = aliasName(nameArg);
            // localKeyId is opaque - OpenSSL associates key/cert by public key not by (SHA-1) digest
            final byte[] keyId = SecurityHelper.getMessageDigest("SHA-256").digest(chain[0].getEncoded());

            final PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();

            final PKCS12SafeBag[] certBags = new PKCS12SafeBag[chain.length];
            for (int i = 0; i < chain.length; i++) {
                final PKCS12SafeBagBuilder certBag = new JcaPKCS12SafeBagBuilder((X509Certificate) chain[i]);
                if (i == 0) { // leaf - associates the certificate with the key bag
                    certBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
                    certBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(keyId));
                }
                certBags[i] = certBag.build();
            }
            final int pbeIterCount = iterationCount(args, 7);
            pfx.addEncryptedData(pbeEncryptor(provider, password, args, 6, pbeIterCount), certBags);

            final PKCS12SafeBagBuilder keyBag =
                new JcaPKCS12SafeBagBuilder(privateKey, pbeEncryptor(provider, password, args, 5, pbeIterCount));
            keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
            keyBag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(keyId));
            pfx.addData(keyBag.build());

            final int macIterCount = iterationCount(args, 8);
            final PKCS12MacCalculatorBuilder macBuilder = SecurityHelper.isFipsVariant() ?
                pbMac1MacCalculatorBuilder(provider, macIterCount) :
                pkcs12MacCalculatorBuilder(provider, macIterCount);
            storeBytes = pfx.build(macBuilder, password).getEncoded();

            this.key = keyArg;
            this.certificate = certArg;
            this.caCerts = caCerts;
        }
        catch (Exception e) {
            if (e instanceof RaiseException) throw (RaiseException) e;
            throw newPKCS12Error(runtime, e);
        }
        catch (Throwable e) { // unapproved MAC/KDF
            OpenSSL.handlePotentialOperationError(runtime, e);
        }
        finally {
            clearChars(password);
        }
    }

    private void loadBags(final ThreadContext context, final char[] password) throws Exception {
        final Ruby runtime = context.runtime;
        final Provider provider = SecurityHelper.getSecurityProvider();
        final PKCS12PfxPdu pfx = new PKCS12PfxPdu(storeBytes);

        if (pfx.hasMac() && !isMacValid(pfx, provider, password)) {
            throw newPKCS12Error(runtime, "PKCS12 MAC verification failed");
        }

        final InputDecryptorProvider decryptor = new JcePKCSPBEInputDecryptorProviderBuilder()
            .setProvider(provider).build(password);

        PrivateKeyInfo privateKey = null;
        byte[] keyId = null;
        final ArrayList<PKCS12SafeBag> certBags = new ArrayList<>();

        for (ContentInfo info : pfx.getContentInfos()) {
            final PKCS12SafeBagFactory factory =
                PKCSObjectIdentifiers.encryptedData.equals(info.getContentType()) ?
                    new PKCS12SafeBagFactory(info, decryptor) : new PKCS12SafeBagFactory(info);

            for (PKCS12SafeBag bag : factory.getSafeBags()) {
                final ASN1ObjectIdentifier type = bag.getType();
                if (PKCSObjectIdentifiers.certBag.equals(type)) certBags.add(bag);
                else if (privateKey == null) {
                    if (PKCSObjectIdentifiers.pkcs8ShroudedKeyBag.equals(type)) {
                        privateKey = ((PKCS8EncryptedPrivateKeyInfo) bag.getBagValue()).decryptPrivateKeyInfo(decryptor);
                    }
                    else if (PKCSObjectIdentifiers.keyBag.equals(type)) {
                        privateKey = (PrivateKeyInfo) bag.getBagValue();
                    }
                    else continue;
                    keyId = localKeyId(bag);
                }
            }
        }

        final PKey selectedKey;
        if (privateKey != null) {
            key = readPKey(context, privateKey.getEncoded());
            selectedKey = (PKey) key;
        }
        else {
            selectedKey = null;
        }

        final int leaf = certLeafIndex(certBags, keyId, selectedKey);
        final RubyArray<X509Cert> chain = runtime.newArray();

        if (selectedKey == null) {
            for (int i = 0; i < certBags.size(); i++) {
                final X509CertificateHolder leafHolder = certificateHolderAt(certBags, i);
                chain.append(X509Cert.wrap(context, leafHolder.toASN1Structure()));
            }
        }
        else if (leaf >= 0) {
            final X509CertificateHolder leafHolder = certificateHolderAt(certBags, leaf);
            certificate = X509Cert.wrap(context, leafHolder.getEncoded());

            X500Name issuer = leafHolder.getIssuer();
            X500Name subject = leafHolder.getSubject();
            int previous = leaf;
            while (!issuer.equals(subject)) {
                int next = -1;
                for (int i = 0; i < certBags.size(); i++) {
                    if (i == previous) continue;
                    final X509CertificateHolder holder = certificateHolderAt(certBags, i);
                    if (issuer.equals(holder.getSubject())) {
                        next = i;
                        break;
                    }
                }
                if (next < 0) break;
                final X509CertificateHolder holder = certificateHolderAt(certBags, next);
                chain.append(X509Cert.wrap(context, holder.toASN1Structure()));
                issuer = holder.getIssuer();
                subject = holder.getSubject();
                previous = next;
            }
        }

        caCerts = chain;
    }

    private static X509CertificateHolder certificateHolderAt(final ArrayList<PKCS12SafeBag> certBags, final int index) {
        return (X509CertificateHolder) certBags.get(index).getBagValue();
    }

    // certificate belonging to the selected key (local keyId is only a fallback)
    private static int certLeafIndex(final ArrayList<PKCS12SafeBag> certBags, final byte[] keyId, final PKey selectedKey)
        throws IOException {

        if (selectedKey == null || certBags.isEmpty()) return -1;

        final PublicKey publicKey = selectedKey.getPublicKey();
        if (publicKey != null) {
            final byte[] encodedKey = publicKey.getEncoded();
            for (int i = 0; i < certBags.size(); i++) {
                if (Arrays.equals(encodedKey, certificateHolderAt(certBags, i).getSubjectPublicKeyInfo().getEncoded())) {
                    return i;
                }
            }
        }

        if (keyId != null) {
            for (int i = 0; i < certBags.size(); i++) {
                if (Arrays.equals(keyId, localKeyId(certBags.get(i)))) return i;
            }
        }
        return -1;
    }

    private static byte[] localKeyId(final PKCS12SafeBag bag) {
        final Attribute[] attributes = bag.getAttributes();
        if (attributes == null) return null;
        for (Attribute attribute : attributes) {
            if (PKCS12SafeBag.localKeyIdAttribute.equals(attribute.getAttrType())) {
                return ASN1OctetString.getInstance(attribute.getAttributeValues()[0]).getOctets();
            }
        }
        return null;
    }

    /**
     * PBMAC1 (RFC 9579) is what OpenSSL (3) writes under FIPS
     * PKCS12 provider only knows the classic (PKCS12KDF) MAC, which is not approved
     */
    private static boolean isMacValid(final PKCS12PfxPdu pfx, final Provider provider, final char[] password)
        throws OperatorCreationException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException {

        final MacData macData = pfx.toASN1Structure().getMacData();
        final AlgorithmIdentifier algorithmId = macData.getMac().getAlgorithmId();
        if (!id_PBMAC1.equals(algorithmId.getAlgorithm())) {
            final ASN1OctetString authSafe = ASN1OctetString.getInstance(pfx.toASN1Structure().getAuthSafe().getContent());
            final byte[] expected = calculateMac(
                    authSafe, password,
                    macData.getSalt(),
                    macData.getIterationCount().intValueExact(),
                    algorithmId.getAlgorithm()
            );
            return MessageDigest.isEqual(expected, macData.getMac().getDigest());
        }

        // older BC-FIPS releases do not implement RFC 9579 PBMAC1 verification
        final MacCalculator calculator = pbMac1Calculator(algorithmId, provider, password);
        final ASN1OctetString authSafe = ASN1OctetString.getInstance(pfx.toASN1Structure().getAuthSafe().getContent());
        try (OutputStream output = calculator.getOutputStream()) {
            output.write(authSafe.getOctets());
        }
        return MessageDigest.isEqual(calculator.getMac(), macData.getMac().getDigest());
    }

    private static byte[] setMac(final byte[] encoded,
                                 final char[] password,
                                 final byte[] salt,
                                 final int iterationCount,
                                 final ASN1ObjectIdentifier digest)
        throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {

        final ContentInfo authSafe = new PKCS12PfxPdu(encoded).toASN1Structure().getAuthSafe();
        final ASN1OctetString authSafeContent = ASN1OctetString.getInstance(authSafe.getContent());
        final byte[] macValue = calculateMac(authSafeContent, password, salt, iterationCount, digest);
        final DigestInfo macInfo = new DigestInfo(new AlgorithmIdentifier(digest, DERNull.INSTANCE), macValue);
        return new Pfx(authSafe, new MacData(macInfo, salt, iterationCount)).getEncoded();
    }

    private static byte[] calculateMac(final ASN1OctetString content,
                                       final char[] password,
                                       final byte[] salt,
                                       final int iterationCount,
                                       final ASN1ObjectIdentifier algorithm)
        throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalStateException {

        final String macAlgorithm = pkcs12MacAlgorithm(algorithm);
        final Provider provider = SecurityHelper.getSecurityProvider();
        final Mac mac = provider == null ? Mac.getInstance(macAlgorithm) : Mac.getInstance(macAlgorithm, provider);
        mac.init(new PKCS12Key(password), new PBEParameterSpec(salt, iterationCount));
        return mac.doFinal(content.getOctets());
    }

    private static String pkcs12MacAlgorithm(final ASN1ObjectIdentifier digest) throws NoSuchAlgorithmException {
        final String oid = digest.getId();
        if ("1.3.14.3.2.26".equals(oid)) return "PBEWITHHMACSHA";
        if ("2.16.840.1.101.3.4.2.4".equals(oid)) return "PBEWITHHMACSHA224";
        if ("2.16.840.1.101.3.4.2.1".equals(oid)) return "PBEWITHHMACSHA256";
        if ("2.16.840.1.101.3.4.2.2".equals(oid)) return "PBEWITHHMACSHA384";
        if ("2.16.840.1.101.3.4.2.3".equals(oid)) return "PBEWITHHMACSHA512";
        throw new NoSuchAlgorithmException("unsupported PKCS12 MAC digest: " + oid);
    }

    private static MacCalculator pbMac1Calculator(final AlgorithmIdentifier algorithmId,
                                                  final Provider provider,
                                                  final char[] password)
        throws OperatorCreationException {

        try {
            final ASN1Sequence params = ASN1Sequence.getInstance(algorithmId.getParameters());
            final AlgorithmIdentifier kdf = AlgorithmIdentifier.getInstance(params.getObjectAt(0));
            if (!PKCSObjectIdentifiers.id_PBKDF2.equals(kdf.getAlgorithm())) {
                throw new OperatorCreationException("PBMAC1 KDF is not PBKDF2");
            }

            final PBKDF2Params pbkdf2 = PBKDF2Params.getInstance(kdf.getParameters());
            // RFC 9579 / OpenSSL reject a missing or out-of-range PBKDF2 keyLength (0 < len <= EVP_MAX_MD_SIZE)
            final int keyBytes = pbkdf2.getKeyLength() == null ? 0 : pbkdf2.getKeyLength().intValueExact();
            if (keyBytes <= 0 || keyBytes > MAX_MAC_KEY_LENGTH) {
                throw new OperatorCreationException("PBMAC1 PBKDF2 key length is out of range");
            }

            final AlgorithmIdentifier macAlgorithm = AlgorithmIdentifier.getInstance(params.getObjectAt(1));
            final int keySize = keyBytes * 8;

            return new JcePBMac1CalculatorBuilder(macAlgorithm.getAlgorithm().getId(), keySize,
                    ignored -> macAlgorithm)
                .setProvider(provider)
                .setSalt(pbkdf2.getSalt())
                .setIterationCount(pbkdf2.getIterationCount().intValueExact())
                .setPrf(pbkdf2.getPrf())
                .build(password);
        }
        catch (OperatorCreationException e) {
            throw e;
        }
        catch (Exception e) {
            throw new OperatorCreationException("unable to create PBMAC1 calculator", e);
        }
    }

    // PBES2 with PBKDF2 (HMAC-SHA256) - what OpenSSL uses to protect key/cert bags
    private static OutputEncryptor pbes2Encryptor(final Provider provider,
                                                  final char[] password,
                                                  final ASN1ObjectIdentifier cipherOid,
                                                  final int iterationCount)
        throws OperatorCreationException {

        final PBKDF2Config kdf = new PBKDF2Config.Builder()
            .withIterationCount(iterationCount)
            .withSaltLength(PBE_SALT_LEN)
            .withPRF(PBKDF2Config.PRF_SHA256)
            .build();

        final JcePKCSPBEOutputEncryptorBuilder builder =
            new JcePKCSPBEOutputEncryptorBuilder(kdf, cipherOid);
        if (provider != null) builder.setProvider(provider);
        return builder.build(password);
    }

    // PBMAC1 (RFC 9579) MAC calculator ~ OpenSSL (under FIPS)
    private static PKCS12MacCalculatorBuilder pbMac1MacCalculatorBuilder(final Provider provider,
                                                                         final int iterationCount) {
        return new PKCS12MacCalculatorBuilder() {
            private MacCalculator macCalculator;

            public MacCalculator build(final char[] password) throws OperatorCreationException {
                final JcePBMac1CalculatorBuilder builder =
                    new JcePBMac1CalculatorBuilder("HMACSHA256", 256)
                        .setIterationCount(iterationCount)
                        .setSaltLength(PBE_SALT_LEN);
                if (provider != null) builder.setProvider(provider);
                return macCalculator = builder.build(password);
            }

            public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
                // BC writes id_PBES2 as the PBMAC1 keyDerivationFunc, OpenSSL requires id_PBKDF2
                final AlgorithmIdentifier mac = macCalculator.getAlgorithmIdentifier();
                final ASN1Sequence params = ASN1Sequence.getInstance(mac.getParameters());
                final AlgorithmIdentifier kdf = AlgorithmIdentifier.getInstance(params.getObjectAt(0));
                final AlgorithmIdentifier macAlg = AlgorithmIdentifier.getInstance(params.getObjectAt(1));
                final AlgorithmIdentifier fixedKdf =
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, kdf.getParameters());
                return new AlgorithmIdentifier(mac.getAlgorithm(),
                    new DERSequence(new ASN1Encodable[] { fixedKdf, macAlg }));
            }
        };
    }

    private static PKCS12MacCalculatorBuilder pkcs12MacCalculatorBuilder(final Provider provider,
                                                                         final int iterationCount) {
        final JcePKCS12MacCalculatorBuilder builder = new JcePKCS12MacCalculatorBuilder()
            .setIterationCount(iterationCount);
        if (provider != null) builder.setProvider(provider);
        return builder;
    }

    // args[5] is the key PBE, args[6] the cert PBE
    private static OutputEncryptor pbeEncryptor(final Provider provider,
                                                final char[] password,
                                                final IRubyObject[] args,
                                                final int index,
                                                final int iterationCount)
        throws OperatorCreationException {

        if (args.length > index && !args[index].isNil()) {
            final String name = args[index].convertToString().asJavaString();
            final ASN1ObjectIdentifier legacyPbe = legacyPbeOID(name);
            if (legacyPbe != null) return legacyPbeEncryptor(provider, password, legacyPbe, iterationCount);
        }
        return pbes2Encryptor(provider, password, pbeCipherOID(args, index), iterationCount);
    }

    private static ASN1ObjectIdentifier pbeCipherOID(final IRubyObject[] args, final int index) {
        if (args.length > index && !args[index].isNil()) {
            final String name = args[index].convertToString().asJavaString();
            if ("AES-128-CBC".equals(name)) return NISTObjectIdentifiers.id_aes128_CBC;
            if ("AES-192-CBC".equals(name)) return NISTObjectIdentifiers.id_aes192_CBC;
        }
        return NISTObjectIdentifiers.id_aes256_CBC; // OpenSSL's default
    }

    private static ASN1ObjectIdentifier legacyPbeOID(final String name) {
        if ("PBE-SHA1-3DES".equals(name)) return PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC;
        if ("PBE-SHA1-RC2-40".equals(name)) return PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC;
        return null;
    }

    private static OutputEncryptor legacyPbeEncryptor(final Provider provider,
                                                       final char[] password,
                                                       final ASN1ObjectIdentifier algorithm,
                                                       final int iterationCount)
        throws OperatorCreationException {

        final JcePKCSPBEOutputEncryptorBuilder builder =
            new JcePKCSPBEOutputEncryptorBuilder(algorithm).setIterationCount(iterationCount);
        if (provider != null) builder.setProvider(provider);
        return builder.build(password);
    }

    private static int iterationCount(final IRubyObject[] args, final int index) {
        if (args.length <= index || args[index].isNil()) return PBE_DEFAULT_ITER;
        final int iterationCount = RubyNumeric.num2int(args[index]);
        return iterationCount == 0 ? PBE_DEFAULT_ITER : iterationCount;
    }

    private static IRubyObject readPKey(final ThreadContext context, final byte[] encoded) {
        final Ruby runtime = context.runtime;
        return PKey.PKeyModule.read(context, PKey._PKey(runtime), newString(runtime, encoded));
    }

    static Certificate[] buildCertificateChain(final Ruby runtime, final X509Cert cert, final RubyArray<X509Cert> caCerts) {

        final List<Certificate> certificates = new ArrayList<>();
        certificates.add(cert.getAuxCert());

        if (caCerts != null) {
            for (int i = 0; i < caCerts.size(); i++) {
                final IRubyObject item = caCerts.eltInternal(i);
                if (!(item instanceof X509Cert)) {
                    throw runtime.newTypeError(item, X509Cert._Certificate(runtime));
                }
                certificates.add(((X509Cert) item).getAuxCert());
            }
        }

        return certificates.toArray(new Certificate[certificates.size()]);
    }

    private static String aliasName(final IRubyObject name) {
        return name.isNil() ? "" : name.convertToString().asJavaString();
    }

    private static void validateCreateOptions(final Ruby runtime, final IRubyObject[] args) {
        if (args.length > 5 && !args[5].isNil()) pbeValidate(runtime, args[5]);
        if (args.length > 6 && !args[6].isNil()) pbeValidate(runtime, args[6]);
        if (args.length > 7 && !args[7].isNil()) RubyNumeric.num2int(args[7]);
        if (args.length > 8 && !args[8].isNil()) RubyNumeric.num2int(args[8]);
        if (args.length > 9 && !args[9].isNil()) {
            final int keyType = RubyNumeric.num2int(args[9]);
            if (keyType != 0 && keyType != KEY_EX && keyType != KEY_SIG) {
                throw runtime.newArgumentError("Unknown key usage type " + keyType);
            }
        }
    }

    private static void pbeValidate(final Ruby runtime, final IRubyObject pbe) {
        final String name = pbe.convertToString().asJavaString();
        if (legacyPbeOID(name) != null) {
            if (!SecurityHelper.isFipsVariant()) return;
            throw runtime.newArgumentError("PBE algorithm " + pbe.inspect() + " is not available"); // in FIPS mode
        }
        if ("AES-128-CBC".equals(name) || "AES-192-CBC".equals(name) || "AES-256-CBC".equals(name)) return;
        throw runtime.newArgumentError("Unknown PBE algorithm " + pbe.inspect());
    }

    static char[] toPasswordChars(final IRubyObject passwd) {
        if (passwd == null || passwd.isNil()) return new char[0];

        final RubyString str = passwd.convertToString();
        final ByteList byteList = str.getByteList();

        return toPasswordChars(
                byteList.getUnsafeBytes(), byteList.getBegin(), byteList.getRealSize(),
                byteList.getEncoding().getCharset()
        );
    }

    // Package-private for testing
    static char[] toPasswordChars(final byte[] bytes, final int offset, final int length, Charset charset) {
        if (length == 0) return new char[0];

        if (charset == null) charset = StandardCharsets.ISO_8859_1;

        final ByteBuffer byteBuf = ByteBuffer.wrap(bytes, offset, length);
        final CharBuffer charBuf = charset.decode(byteBuf);

        final char[] result = new char[charBuf.remaining()];
        charBuf.get(result);

        // Clear the decoder's intermediate buffer
        if (charBuf.hasArray()) {
            Arrays.fill(charBuf.array(), '\0');
        }

        return result;
    }

    static void clearChars(final char[] chars) {
        if (chars.length > 0) Arrays.fill(chars, '\0');
    }

    private static RaiseException newPKCS12Error(final Ruby runtime, final Throwable e) {
        return newError(runtime, _PKCS12(runtime).getClass("PKCS12Error"), e);
    }

    private static RaiseException newPKCS12Error(final Ruby runtime, final String message) {
        return newError(runtime, _PKCS12(runtime).getClass("PKCS12Error"), message);
    }

    private static RubyClass _PKCS12(final Ruby runtime) {
        return runtime.getModule("OpenSSL").getClass("PKCS12");
    }
}
