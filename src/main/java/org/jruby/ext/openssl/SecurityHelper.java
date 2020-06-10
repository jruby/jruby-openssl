/*
 * The MIT License
 *
 * Copyright 2014 Karol Bucek.
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

import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509CRL;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.net.ssl.SSLContext;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.bc.BcDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.jruby.util.SafePropertyAccessor;

/**
 * Java Security (and JCE) helpers.
 *
 * @author kares
 */
public abstract class SecurityHelper {

    private static String BC_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    static boolean setBouncyCastleProvider = true; // (package access for tests)
    static volatile Provider securityProvider; // 'BC' provider (package access for tests)
    private static volatile Boolean registerProvider = null;
    static final Map<String, Class> implEngines = new ConcurrentHashMap<>(16, 0.75f, 1);

    private static String BCJSSE_PROVIDER_CLASS = "org.bouncycastle.jsse.provider.BouncyCastleJsseProvider";
    static boolean setJsseProvider = true;
    static volatile Provider jsseProvider;

    public static Provider getSecurityProvider() {
        Provider provider = securityProvider;
        if ( setBouncyCastleProvider && provider == null ) {
            synchronized(SecurityHelper.class) {
                provider = securityProvider;
                if ( setBouncyCastleProvider && provider == null ) {
                    provider = setBouncyCastleProvider();
                    setBouncyCastleProvider = false;
                }
            }
        }
        doRegisterProvider(provider);
        return provider;
    }

    private static Provider getJsseProvider(final String name) {
        Provider provider = jsseProvider;
        if ( setJsseProvider && provider == null ) {
            synchronized(SecurityHelper.class) {
                provider = jsseProvider;
                if ( setJsseProvider && provider == null ) {
                    try {
                        provider = Security.getProvider(name);
                    }
                    catch (Exception ex) {
                        debug("failed to get provider: " + name, ex);
                    }
                    if (provider == null && "BCJSSE".equals(name)) {
                        provider = newBouncyCastleProvider(BCJSSE_PROVIDER_CLASS);
                    }
                    jsseProvider = provider; setJsseProvider = false;
                }
            }
        }
        return provider;
    }

    static final boolean SPI_ACCESSIBLE;

    static {
        boolean canSetAccessible = true;
        if ( OpenSSL.javaVersion9(true) ) {
            final Provider provider = getSecurityProvider();
            if ( provider != null ) {
                try {
                    // NOTE: some getXxx pieces might still work
                    // where SPI are returned directly + there's a public <init> e.g. MessageDigest(...)
                    getCertificateFactory("X.509", provider); // !!! disables EVERYTHING :(
                }
                catch (CertificateException ex) {
                    debugStackTrace(ex);
                    canSetAccessible = false;
                }
                catch (RuntimeException ex) {
                    debugStackTrace(ex);
                    // java.lang.reflect.InaccessibleObjectException (extends RuntimeException)
                    canSetAccessible = false;
                }
            }
        }
        SPI_ACCESSIBLE = canSetAccessible;
    }

    static Provider getSecurityProviderIfAccessible() {
        return SPI_ACCESSIBLE ? getSecurityProvider() : null;
    }

    public static synchronized void setSecurityProvider(final Provider provider) {
        if ( provider != null ) OpenSSL.debug("using (security) provider: " + provider);
        securityProvider = provider;
    }

    static synchronized Provider setBouncyCastleProvider() {
        Provider provider = newBouncyCastleProvider(BC_PROVIDER_CLASS);
        setSecurityProvider(provider);
        return provider;
    }

    private static Provider newBouncyCastleProvider(final String klass) {
        try {
            return (Provider) Class.forName(klass).newInstance();
        }
        catch (Throwable ignored) {
            OpenSSL.debug("can not instantiate bouncy-castle provider (" + klass  + ")", ignored);
        }
        return null;
    }

    public static synchronized void setRegisterProvider(final boolean register) {
        registerProvider = Boolean.valueOf(register);
        if ( register ) getSecurityProvider(); // so that securityProvider != null
        // getSecurityProvider does doRegisterProvider();
    }

    static boolean isProviderAvailable(final String name) {
        return Security.getProvider(name) != null;
    }

    public static boolean isProviderRegistered() {
        if ( securityProvider == null ) return false;
        return Security.getProvider(securityProvider.getName()) != null;
    }

    private static void doRegisterProvider(final Provider securityProvider) {
        if ( registerProvider != null ) {
            synchronized(SecurityHelper.class) {
                final Boolean register = registerProvider;
                if ( register != null && register.booleanValue() ) {
                    if ( securityProvider != null ) {
                        Security.addProvider(securityProvider);
                        registerProvider = null;
                    }
                }
            }
        }
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static CertificateFactory getCertificateFactory(final String type)
        throws CertificateException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getCertificateFactory(type, provider);
        }
        catch (CertificateException e) { debugStackTrace(e); }
        return CertificateFactory.getInstance(type);
    }

    static CertificateFactory getCertificateFactory(final String type, final Provider provider)
        throws CertificateException {
        final CertificateFactorySpi spi = (CertificateFactorySpi) getImplEngine("CertificateFactory", type);
        if ( spi == null ) throw new CertificateException(type + " not found");
        return CertificateFactory.getInstance(type, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyFactory getKeyFactory(final String algorithm)
        throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getKeyFactory(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        return KeyFactory.getInstance(algorithm);
    }

    static KeyFactory getKeyFactory(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyFactory.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyPairGenerator getKeyPairGenerator(final String algorithm)
        throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getKeyPairGenerator(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        return KeyPairGenerator.getInstance(algorithm);
    }

    @SuppressWarnings("unchecked")
    static KeyPairGenerator getKeyPairGenerator(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyStore getKeyStore(final String type)
        throws KeyStoreException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getKeyStore(type, provider);
        }
        catch (KeyStoreException e) { }
        return KeyStore.getInstance(type);
    }

    static KeyStore getKeyStore(final String type, final Provider provider)
        throws KeyStoreException {
        return KeyStore.getInstance(type, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static MessageDigest getMessageDigest(final String algorithm) throws NoSuchAlgorithmException {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nsae) {
            // try reflective logic
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getMessageDigest(algorithm, provider);

            throw nsae; // give up
        }
    }

    @SuppressWarnings("unchecked")
    static MessageDigest getMessageDigest(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public static SecureRandom getSecureRandom() {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) {
                final String algorithm = getSecureRandomAlgorithm(provider);
                if ( algorithm != null ) {
                    return getSecureRandom(algorithm, provider);
                }
            }
        }
        catch (NoSuchAlgorithmException e) { }
        return new SecureRandom(); // likely "SHA1PRNG" from SPI sun.security.provider.SecureRandom
    }

    private static SecureRandom getSecureRandom(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return SecureRandom.getInstance(algorithm, provider);
    }

    // NOTE: none (at least for BC 1.47)
    private static String getSecureRandomAlgorithm(final Provider provider) {
        for ( Provider.Service service : provider.getServices() ) {
            if ( "SecureRandom".equals( service.getType() ) ) {
                return service.getAlgorithm();
            }
        }
        return null;
    }

    private static Boolean tryCipherInternal = Boolean.FALSE;

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static Cipher getCipher(final String transformation)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        try {
            if ( tryCipherInternal == Boolean.FALSE ) {
                final Provider provider = getSecurityProvider();
                if ( provider != null ) {
                    return getCipher(transformation, provider);
                }
            }
        }
        catch (NoSuchAlgorithmException e) { }
        catch (NoSuchPaddingException e) { }
        catch (SecurityException e) {
            // java.lang.SecurityException: JCE cannot authenticate the provider BC
            if ( tryCipherInternal != null ) tryCipherInternal = Boolean.TRUE;
            debugStackTrace(e);
        }
        if ( tryCipherInternal == Boolean.TRUE ) {
            try {
                final Provider provider = getSecurityProvider();
                if ( provider != null ) {
                    return getCipherInternal(transformation, provider);
                }
            }
            catch (NoSuchAlgorithmException e) { }
            catch (RuntimeException e) {
                // likely javax.crypto.JceSecurityManager.isCallerTrusted gets
                // us a NPE from javax.crypto.Cipher.<init>(Cipher.java:264)
                tryCipherInternal = null; // do not try BC at all
                debugStackTrace(e);
            }
        }
        return Cipher.getInstance(transformation);
    }

    static Cipher getCipher(final String transformation, final Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(transformation, provider);
    }

    private static final Class<?>[] STRING_PARAM = { String.class };

    private static Cipher getCipherInternal(String transformation, final Provider provider)
        throws NoSuchAlgorithmException {
        CipherSpi spi = (CipherSpi) getImplEngine("Cipher", transformation);
        if ( spi == null ) {
            //
            // try the long way
            //
            StringTokenizer tok = new StringTokenizer(transformation, "/");
            final String algorithm = tok.nextToken();

            spi = (CipherSpi) getImplEngine("Cipher", algorithm);
            if ( spi == null ) {
                throw new NoSuchAlgorithmException(transformation + " not found");
            }

            //
            // make sure we don't get fooled by a "//" in the string
            //
            if ( tok.hasMoreTokens() && ! transformation.regionMatches(algorithm.length(), "//", 0, 2) ) {
                // spi.engineSetMode(tok.nextToken()) :
                invoke(spi, CipherSpi.class, "engineSetMode", STRING_PARAM, tok.nextToken());
            }
            if ( tok.hasMoreTokens() ) {
                // spi.engineSetPadding(tok.nextToken()) :
                invoke(spi, CipherSpi.class, "engineSetPadding", STRING_PARAM, tok.nextToken());
            }

        }
        try {
            // this constructor does not verify the provider
            return Cipher.getInstance(transformation, provider);
        }
        catch (Exception e) { // TODO now seems like a redundant left over
            // this constructor does verify the provider which might fail
            return newInstance(Cipher.class,
                    new Class[] { CipherSpi.class, Provider.class, String.class },
                    new Object[] { spi, provider, transformation }
            );
        }
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static Signature getSignature(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getSignature(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        return Signature.getInstance(algorithm);
    }

    @SuppressWarnings("unchecked")
    static Signature getSignature(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static Mac getMac(final String algorithm) throws NoSuchAlgorithmException {
        Mac mac = null;
        final Provider provider = getSecurityProviderIfAccessible();
        if ( provider != null ) {
            mac = getMac(algorithm, provider, true);
        }
        if ( mac == null ) mac = Mac.getInstance(algorithm);
        return mac;
    }

    static Mac getMac(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return getMac(algorithm, provider, false);
    }

    private static Mac getMac(final String algorithm, final Provider provider, boolean silent)
        throws NoSuchAlgorithmException {
        try {
            return Mac.getInstance(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) {
            if ( silent ) return null;
            throw e;
        }
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyGenerator getKeyGenerator(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getKeyGenerator(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (SecurityException e) { debugStackTrace(e); }
        return KeyGenerator.getInstance(algorithm);
    }

    static KeyGenerator getKeyGenerator(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static KeyAgreement getKeyAgreement(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getKeyAgreement(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (SecurityException e) { debugStackTrace(e); }
        return KeyAgreement.getInstance(algorithm);
    }

    static KeyAgreement getKeyAgreement(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return KeyAgreement.getInstance(algorithm, provider);
    }

    /**
     * @note code calling this should not assume BC provider internals !
     */
    public static SecretKeyFactory getSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
        try {
            final Provider provider = getSecurityProviderIfAccessible();
            if ( provider != null ) return getSecretKeyFactory(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e) { }
        catch (SecurityException e) { debugStackTrace(e); }
        return SecretKeyFactory.getInstance(algorithm);
    }

    static SecretKeyFactory getSecretKeyFactory(final String algorithm, final Provider provider)
        throws NoSuchAlgorithmException {
        return SecretKeyFactory.getInstance(algorithm, provider);
    }

    private static final String providerSSLContext; // NOTE: experimental support for using BCJSSE
    static {
        String providerSSL = SafePropertyAccessor.getProperty("jruby.openssl.ssl.provider", "");
        switch (providerSSL.trim()) {
            case "BC": case "true":
                providerSSL = "BCJSSE"; break;
            case "":  case "false":
                providerSSL = null; break;
        }
        providerSSLContext = providerSSL;
    }

    public static SSLContext getSSLContext(final String protocol)
        throws NoSuchAlgorithmException {
        try {
            if ( providerSSLContext != null && ! "SSL".equals(protocol) ) { // only TLS supported in BCJSSE
                final Provider provider = getJsseProvider(providerSSLContext);
                if ( provider != null ) {
                    return getSSLContext(protocol, provider);
                }
            }
        }
        catch (NoSuchAlgorithmException e) { }
        return SSLContext.getInstance(protocol); // built-in SunJSSE provider on HotSpot
    }

    private static SSLContext getSSLContext(final String protocol, final Provider provider)
        throws NoSuchAlgorithmException {
        return SSLContext.getInstance(protocol, provider);
    }

    public static boolean verify(final X509CRL crl, final PublicKey publicKey)
        throws NoSuchAlgorithmException, CRLException, InvalidKeyException, SignatureException {
        return verify(crl, publicKey, false);
    }

    static boolean verify(final X509CRL crl, final PublicKey publicKey, final boolean silent)
        throws NoSuchAlgorithmException, CRLException, InvalidKeyException, SignatureException {

        if ( crl instanceof X509CRLObject ) {
            final CertificateList crlList = (CertificateList) getCertificateList(crl);
            final AlgorithmIdentifier tbsSignatureId = crlList.getTBSCertList().getSignature();
            if ( ! crlList.getSignatureAlgorithm().equals(tbsSignatureId) ) {
                if ( silent ) return false;
                throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList.");
            }

            final Signature signature = getSignature(crl.getSigAlgName(), securityProvider);

            signature.initVerify(publicKey);
            signature.update(crl.getTBSCertList());

            if ( ! signature.verify( crl.getSignature() ) ) {
                if ( silent ) return false;
                throw new SignatureException("CRL does not verify with supplied public key.");
            }
            return true;
        }
        else {
            try {
                final DigestAlgorithmIdentifierFinder digestAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
                final ContentVerifierProvider verifierProvider;
                if ( "DSA".equalsIgnoreCase( publicKey.getAlgorithm() )) {
                    BigInteger y = ((DSAPublicKey) publicKey).getY();
                    DSAParams params = ((DSAPublicKey) publicKey).getParams();
                    DSAParameters parameters = new DSAParameters(params.getP(), params.getQ(), params.getG());
                    AsymmetricKeyParameter dsaKey = new DSAPublicKeyParameters(y, parameters);
                    verifierProvider = new BcDSAContentVerifierProviderBuilder(digestAlgFinder).build(dsaKey);
                }
                else {
                    BigInteger mod = ((RSAPublicKey) publicKey).getModulus();
                    BigInteger exp = ((RSAPublicKey) publicKey).getPublicExponent();
                    AsymmetricKeyParameter rsaKey = new RSAKeyParameters(false, mod, exp);
                    verifierProvider = new BcRSAContentVerifierProviderBuilder(digestAlgFinder).build(rsaKey);
                }
                return new X509CRLHolder(crl.getEncoded()).isSignatureValid( verifierProvider );
            }
            catch (OperatorException e) {
                throw new SignatureException(e);
            }
            catch (CertException e) {
                throw new SignatureException(e);
            }
            // can happen if the input is DER but does not match expected structure
            catch (ClassCastException e) {
                throw new SignatureException(e);
            }
            catch (IOException e) {
                throw new SignatureException(e);
            }
        }
    }

    private static Object getCertificateList(final Object crl) { // X509CRLObject
        try { // private CertificateList c;
            final Field cField = X509CRLObject.class.getDeclaredField("c");
            cField.setAccessible(true);
            return cField.get(crl);
        }
        catch (NoSuchFieldException e) {
            debugStackTrace(e); return null;
        }
        catch (IllegalAccessException e) { return null; }
        catch (SecurityException e) { return null; }
    }

    // these are BC JCE (@see javax.crypto.JCEUtil) inspired internals :
    // https://github.com/bcgit/bc-java/blob/master/jce/src/main/java/javax/crypto/JCEUtil.java

    private static Object getImplEngine(String baseName, String algorithm) {
        Object engine = findImplEngine(baseName, algorithm.toUpperCase(Locale.ENGLISH));
        if (engine == null) {
            engine = findImplEngine(baseName, algorithm);
        }
        return engine;
    }

    private static Object findImplEngine(final String baseName, String algorithm) {
        Class implEngineClass = implEngines.get(baseName + ":" + algorithm);

        if (implEngineClass == null) {
            final Provider bcProvider = securityProvider;
            String alias;
            while ((alias = bcProvider.getProperty("Alg.Alias." + baseName + "." + algorithm)) != null) {
                algorithm = alias;
            }
            final String className = bcProvider.getProperty(baseName + "." + algorithm);
            if (className != null) {
                try {
                    ClassLoader loader = bcProvider.getClass().getClassLoader();
                    if (loader != null) {
                        implEngineClass = loader.loadClass(className);
                    } else {
                        implEngineClass = Class.forName(className);
                    }
                    implEngineClass.newInstance(); // this instance is thrown away to test newInstance, but only once
                } catch (ClassNotFoundException e) {
                    throw new IllegalStateException("algorithm " + algorithm + " in provider " + bcProvider.getName() + " but no class \"" + className + "\" found!");
                } catch (Exception e) {
                    throw new IllegalStateException("algorithm " + algorithm + " in provider " + bcProvider.getName() + " but class \"" + className + "\" inaccessible!");
                }
            } else {
                return null;
            }

            implEngines.put(baseName + ":" + algorithm, implEngineClass);
        }

        try {
            return implEngineClass.newInstance();
        } catch (Exception e) {
            final Provider bcProvider = securityProvider;
            String className = implEngineClass.getName();
            throw new IllegalStateException("algorithm " + algorithm + " in provider " + bcProvider.getName() + " but class \"" + className + "\" inaccessible!");
        }
    }

    private static <T> T newInstance(Class<T> klass, Class<?>[] paramTypes, Object... params) {
        final Constructor<T> constructor;
        try {
            constructor = klass.getDeclaredConstructor(paramTypes);
            constructor.setAccessible(true);
            return constructor.newInstance(params);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e.getTargetException());
        } catch (InstantiationException e) {
            throw new IllegalStateException(e);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T invoke(Object object, Class<?> klass, String methodName, Class<?>[] paramTypes, Object... params) {
        final Method method;
        try {
            method = klass.getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            return (T) method.invoke(object, params);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e.getTargetException());
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void setField(Object obj, Class<?> fieldOwner, String fieldName, Object value) {
        final Field field;
        try {
            field = fieldOwner.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(obj, value);
        } catch (NoSuchFieldException e) {
            throw new IllegalStateException("no field '" + fieldName + "' declared in " + fieldOwner + "", e);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
