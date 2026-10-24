package org.jruby.ext.openssl;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class SSLKeyManagerTest extends OpenSSLHelper {

    private static final Principal[] UNRELATED_ISSUERS = { new X500Principal("CN=Unrelated CA") };
    private static final AlgorithmConstraints REJECT_ALL = new AlgorithmConstraints() {
        @Override
        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
            return false;
        }

        @Override
        public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
            return false;
        }

        @Override
        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
            return false;
        }
    };

    private PrivateKey key;
    private X509Certificate clientCertificate;
    private X509Certificate serverCertificate;

    @BeforeAll
    public void setUp() throws Exception {
        setUpRuntime();
        runtime.evalScriptlet(
            "$key = OpenSSL::PKey::RSA.new(2048)\n" +
            "$certs = ['clientAuth', 'serverAuth'].map.with_index do |usage, serial|\n" +
            "  cert = OpenSSL::X509::Certificate.new\n" +
            "  cert.version = 2; cert.serial = serial + 1\n" +
            "  cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=TLS KeyManager Test')\n" +
            "  cert.public_key = $key.public_key\n" +
            "  cert.not_before = Time.now - 3600; cert.not_after = Time.now + 3600\n" +
            "  factory = OpenSSL::X509::ExtensionFactory.new\n" +
            "  factory.subject_certificate = factory.issuer_certificate = cert\n" +
            "  cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true))\n" +
            "  cert.add_extension(factory.create_extension('extendedKeyUsage', usage, true))\n" +
            "  cert.sign($key, OpenSSL::Digest::SHA256.new)\n" +
            "  cert\n" +
            "end\n");
        key = ((PKey) runtime.evalScriptlet("$key")).getPrivateKey();
        clientCertificate = ((X509Cert) runtime.evalScriptlet("$certs[0]")).getAuxCert();
        serverCertificate = ((X509Cert) runtime.evalScriptlet("$certs[1]")).getAuxCert();
    }

    @AfterAll
    public void tearDown() {
        tearDownRuntime();
    }

    private Provider[] providers() {
        return new Provider[] { SecurityHelper.getJsseProvider(), Security.getProvider("SunJSSE") };
    }

    private KeyStore.PrivateKeyEntry entry(X509Certificate certificate) {
        return new KeyStore.PrivateKeyEntry(key, new X509Certificate[] { certificate });
    }

    private X509ExtendedKeyManager manager(Provider provider, X509Certificate certificate) throws Exception {
        return manager(provider, Collections.singletonMap("credential", entry(certificate)));
    }

    private X509ExtendedKeyManager manager(Provider provider, Map<String, KeyStore.PrivateKeyEntry> entries) throws Exception {
        return (X509ExtendedKeyManager) SSLKeyManager.create(provider, entries)[0];
    }

    private javax.net.ssl.SSLContext context(Provider provider) throws Exception {
        javax.net.ssl.SSLContext context = javax.net.ssl.SSLContext.getInstance("TLS", provider);
        context.init(new KeyManager[0], null, null);
        return context;
    }

    private SSLEngine engine(Provider provider, boolean client) throws Exception {
        SSLEngine engine = context(provider).createSSLEngine();
        engine.setUseClientMode(client);
        engine.setEnabledProtocols(new String[] { "TLSv1.2" });
        return engine;
    }

    private String serverKeyType(Provider provider) {
        return "BCJSSE".equals(provider.getName()) ? "ECDHE_RSA" : "RSA";
    }

    private void assertCredential(X509ExtendedKeyManager manager, String alias, X509Certificate certificate) throws Exception {
        assertNotNull(alias);
        assertSame(key, manager.getPrivateKey(alias));
        X509Certificate[] chain = manager.getCertificateChain(alias);
        assertEquals(1, chain.length);
        assertSame(certificate, chain[0]);
        assertArrayEquals(certificate.getEncoded(), chain[0].getEncoded());
        assertEquals(certificate.getExtendedKeyUsage(), chain[0].getExtendedKeyUsage());
    }

    @Test
    public void clientCredentialSurvivesUnrelatedIssuerHints() throws Exception {
        for (Provider provider : providers()) {
            X509ExtendedKeyManager manager = manager(provider, clientCertificate);
            String alias = manager.chooseEngineClientAlias(new String[] { "RSA" }, UNRELATED_ISSUERS, engine(provider, true));
            assertCredential(manager, alias, clientCertificate);
            try (SSLSocket socket = (SSLSocket) context(provider).getSocketFactory().createSocket()) {
                socket.setUseClientMode(true);
                assertCredential(manager,
                    manager.chooseClientAlias(new String[] { "RSA" }, UNRELATED_ISSUERS, socket), clientCertificate);
            }
        }
    }

    @Test
    public void oppositeExtendedKeyUsagePreservesOriginalCredentials() throws Exception {
        for (Provider provider : providers()) {
            X509ExtendedKeyManager server = manager(provider, clientCertificate);
            assertCredential(server,
                server.chooseEngineServerAlias(serverKeyType(provider), null, engine(provider, false)), clientCertificate);
            X509ExtendedKeyManager client = manager(provider, serverCertificate);
            assertCredential(client,
                client.chooseEngineClientAlias(new String[] { "RSA" }, UNRELATED_ISSUERS, engine(provider, true)), serverCertificate);
            try (SSLSocket socket = (SSLSocket) context(provider).getSocketFactory().createSocket()) {
                socket.setUseClientMode(false);
                assertCredential(server,
                    server.chooseServerAlias(serverKeyType(provider), null, socket), clientCertificate);
                socket.setUseClientMode(true);
                assertCredential(client,
                    client.chooseClientAlias(new String[] { "RSA" }, UNRELATED_ISSUERS, socket), serverCertificate);
            }
        }
    }

    @Test
    public void nativeSuitableCredentialTakesPrecedenceOverCompatibilityFallback() throws Exception {
        Map<String, KeyStore.PrivateKeyEntry> entries = new LinkedHashMap<>();
        entries.put("client-only", entry(clientCertificate));
        entries.put("server-only", entry(serverCertificate));
        for (Provider provider : providers()) {
            X509ExtendedKeyManager manager = manager(provider, entries);
            assertCredential(manager,
                manager.chooseEngineServerAlias(serverKeyType(provider), null, engine(provider, false)), serverCertificate);
            assertCredential(manager,
                manager.chooseEngineClientAlias(new String[] { "RSA" }, null, engine(provider, true)), clientCertificate);
        }
    }

    @Test
    public void engineAlgorithmConstraintsApplyThroughCompatibilityFallbacks() throws Exception {
        for (Provider provider : providers()) {
            SSLEngine client = engine(provider, true);
            SSLParameters parameters = client.getSSLParameters();
            parameters.setAlgorithmConstraints(REJECT_ALL);
            client.setSSLParameters(parameters);
            X509ExtendedKeyManager clientManager = manager(provider, serverCertificate);
            assertNull(clientManager.chooseEngineClientAlias(new String[] { "RSA" }, UNRELATED_ISSUERS, client), provider.getName());

            SSLEngine server = engine(provider, false);
            parameters = server.getSSLParameters();
            parameters.setAlgorithmConstraints(REJECT_ALL);
            server.setSSLParameters(parameters);
            X509ExtendedKeyManager serverManager = manager(provider, clientCertificate);
            assertNull(serverManager.chooseEngineServerAlias(serverKeyType(provider), null, server), provider.getName());
        }
    }

    @Test
    public void connectedSocketAlgorithmConstraintsApplyThroughCompatibilityFallbacks() throws Exception {
        for (Provider provider : providers()) {
            try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                 SSLSocket socket = (SSLSocket) context(provider).getSocketFactory()
                     .createSocket(listener.getInetAddress(), listener.getLocalPort());
                 Socket peer = listener.accept()) {
                socket.setUseClientMode(true);
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setAlgorithmConstraints(REJECT_ALL);
                socket.setSSLParameters(parameters);
                X509ExtendedKeyManager client = manager(provider, serverCertificate);
                assertNull(client.chooseClientAlias(new String[] { "RSA" }, UNRELATED_ISSUERS, socket), provider.getName());

                socket.setUseClientMode(false);
                X509ExtendedKeyManager server = manager(provider, clientCertificate);
                assertNull(server.chooseServerAlias(serverKeyType(provider), null, socket), provider.getName());
            }
        }
    }
}
