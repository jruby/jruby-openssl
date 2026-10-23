package org.jruby.ext.openssl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SSLKeyStoreTest extends OpenSSLHelper {

    private RSAPrivateKey key;
    private X509Certificate certificate;

    @BeforeAll
    public void setUp() throws Exception {
        setUpRuntime();
        runtime.evalScriptlet(
            "$key = OpenSSL::PKey::RSA.new(2048)\n" +
            "$cert = OpenSSL::X509::Certificate.new\n" +
            "$cert.version = 2; $cert.serial = 1\n" +
            "$cert.subject = $cert.issuer = OpenSSL::X509::Name.parse('/CN=TLS KeyStore Test')\n" +
            "$cert.public_key = $key.public_key\n" +
            "$cert.not_before = Time.now - 3600; $cert.not_after = Time.now + 3600\n" +
            "$cert.sign($key, OpenSSL::Digest::SHA256.new)\n");
        key = new OpaqueRSAKey((RSAPrivateKey) ((PKey) runtime.evalScriptlet("$key")).getPrivateKey());
        certificate = ((X509Cert) runtime.evalScriptlet("$cert")).getAuxCert();
    }

    @AfterAll
    public void tearDown() {
        tearDownRuntime();
    }

    private SSLKeyStore keyStore() throws Exception {
        return new SSLKeyStore(Collections.singletonMap("rsa", new KeyStore.PrivateKeyEntry(
            key, new X509Certificate[] { certificate })));
    }

    @Test
    public void preservesOpaquePrivateKey() throws Exception {
        SSLKeyStore store = keyStore();
        assertSame(key, store.getKey("rsa", null));
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) store.getEntry(
            "rsa", new KeyStore.PasswordProtection(new char[0]));
        assertSame(key, entry.getPrivateKey());
        assertSame(certificate, entry.getCertificate());
    }

    @Test
    public void nativeKeyManagersPreserveOpaquePrivateKey() throws Exception {
        Provider[] providers = { SecurityHelper.getJsseProvider(), Security.getProvider("SunJSSE") };
        for (Provider provider : providers) {
            assertNotNull(provider);
            KeyManagerFactory factory = KeyManagerFactory.getInstance("PKIX", provider);
            factory.init(keyStore(), null);
            X509KeyManager manager = (X509KeyManager) factory.getKeyManagers()[0];
            String[] aliases = manager.getServerAliases("RSA", null);
            assertNotNull(aliases, provider.getName());
            assertEquals(1, aliases.length, provider.getName());
            assertSame(key, manager.getPrivateKey(aliases[0]), provider.getName());
            assertArrayEquals(new Certificate[] { certificate }, manager.getCertificateChain(aliases[0]));
        }
    }

    @Test
    public void returnedCertificateChainsAreIndependent() throws Exception {
        SSLKeyStore store = keyStore();
        Certificate[] first = store.getCertificateChain("rsa");
        Certificate[] second = store.getCertificateChain("rsa");
        assertNotSame(first, second);
        first[0] = null;
        assertSame(certificate, second[0]);
        assertSame(certificate, store.getCertificateChain("rsa")[0]);
    }

    @Test
    public void rejectsCredentialMutationAndPersistence() throws Exception {
        SSLKeyStore store = keyStore();
        Certificate[] chain = { certificate };
        assertThrows(KeyStoreException.class, () -> store.setKeyEntry("new", key, null, chain));
        assertThrows(KeyStoreException.class, () -> store.setKeyEntry("new", new byte[] { 1 }, chain));
        assertThrows(KeyStoreException.class, () -> store.setCertificateEntry("new", certificate));
        assertThrows(KeyStoreException.class, () -> store.deleteEntry("rsa"));
        assertThrows(KeyStoreException.class,
            () -> store.setEntry("new", new KeyStore.PrivateKeyEntry(key, chain), null));
        assertThrows(Exception.class, () -> store.store(new ByteArrayOutputStream(), null));
        assertThrows(Exception.class, () -> store.load(new ByteArrayInputStream(new byte[0]), null));
        assertEquals(1, store.size());
        assertSame(key, store.getKey("rsa", null));
        assertSame(certificate, store.getCertificate("rsa"));
    }

    @Test
    public void missingAliasesReturnNull() throws Exception {
        SSLKeyStore store = keyStore();
        assertNull(store.getKey("missing", null));
        assertNull(store.getEntry("missing", null));
        assertNull(store.getCertificate("missing"));
        assertNull(store.getCertificateChain("missing"));
        assertNull(store.getCreationDate("missing"));
        assertFalse(store.containsAlias("missing"));
        assertFalse(store.isKeyEntry("missing"));
        assertFalse(store.isCertificateEntry("missing"));
    }

    private static final class OpaqueRSAKey implements RSAPrivateKey {
        private final RSAPrivateKey key;

        OpaqueRSAKey(RSAPrivateKey key) { this.key = key; }

        @Override
        public BigInteger getPrivateExponent() { return key.getPrivateExponent(); }

        @Override
        public BigInteger getModulus() { return key.getModulus(); }

        @Override
        public String getAlgorithm() { return key.getAlgorithm(); }

        @Override
        public String getFormat() { return null; }

        @Override
        public byte[] getEncoded() { throw new AssertionError("opaque key must not be encoded"); }
    }
}
