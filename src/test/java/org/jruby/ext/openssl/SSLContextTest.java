package org.jruby.ext.openssl;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;

import org.jruby.RubyArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SSLContextTest extends OpenSSLHelper {
    @BeforeEach
    public void setUp() throws Exception {
        setUpRuntime();
    }

    @AfterEach
    public void tearDown() {
        tearDownRuntime();
    }

    @Test
    public void mldsaCredentialSourcesUseTlsProvider() throws Exception {
        for (int parameter : new int[] {44, 65, 87}) {
            loadMLDSAIdentity(parameter);
            for (String credentials : new String[] {
                    "ctx.cert = $cert; ctx.key = $key",
                    "ctx.add_certificate($cert, $key)",
                    "ctx.client_cert_cb = proc { [$cert, $key] }"}) {
                SSLContext context = context("ctx = OpenSSL::SSL::SSLContext.new; " + credentials + "; ctx");
                assertEquals(engineClass("TLS"), context.createSSLEngine(null, 0).getClass());
                assertEquals("SSL", context.getProtocol(), "provider selection must not change the SSL method");
            }
        }
    }

    @Test
    public void cipherQueriesFollowMldsaCredentials() {
        loadMLDSAIdentity(44);
        RubyArray tlsCiphers = (RubyArray) runtime.evalScriptlet("OpenSSL::SSL::SSLContext.new(:TLS).ciphers");
        RubyArray sslCiphers = (RubyArray) runtime.evalScriptlet("OpenSSL::SSL::SSLContext.new.ciphers");
        for (String credentials : new String[] {
                "$ctx.cert = $cert; $ctx.key = $key",
                "$ctx.add_certificate($cert, $key)",
                "$ctx.client_cert_cb = proc { $calls += 1; [$cert, $key] }"}) {
            SSLContext context = (SSLContext) runtime.evalScriptlet(
                "$calls = 0; $ctx = OpenSSL::SSL::SSLContext.new; $ctx.ciphers; " + credentials + "; $ctx");
            boolean callback = credentials.contains("client_cert_cb");
            assertEquals(callback ? sslCiphers : tlsCiphers, context.ciphers(currentContext()));
            assertEquals("0", runtime.evalScriptlet("$calls").toString(), "cipher queries must not call client_cert_cb");
            context.doSetup(currentContext());
            assertEquals(tlsCiphers, context.ciphers(currentContext()));
        }

        runtime.evalScriptlet("$ctx = OpenSSL::SSL::SSLContext.new; $ctx.cert = $cert; $ctx.key = $key");
        assertEquals(tlsCiphers, runtime.evalScriptlet("$ctx.ciphers"));
        assertEquals(sslCiphers, runtime.evalScriptlet("$ctx.key = nil; $ctx.ciphers"));
    }

    @Test
    public void emptyAndClassicalContextsKeepDefaultProvider() throws Exception {
        SSLContext empty = context("OpenSSL::SSL::SSLContext.new");
        assertEquals(engineClass("SSL"), empty.createSSLEngine(null, 0).getClass());
        SSLContext rsa = context(
            "ctx = OpenSSL::SSL::SSLContext.new; " +
            "ctx.cert = OpenSSL::X509::Certificate.new(File.read('test/ssl/client.crt')); " +
            "ctx.key = OpenSSL::PKey.read(File.read('test/ssl/client.key')); ctx");
        assertEquals(engineClass("SSL"), rsa.createSSLEngine(null, 0).getClass());
    }

    @Test
    public void mixedCredentialsUseTlsProvider() throws Exception {
        loadMLDSAIdentity(44);
        SSLContext context = context(
            "ctx = OpenSSL::SSL::SSLContext.new; " +
            "ctx.cert = OpenSSL::X509::Certificate.new(File.read('test/ssl/client.crt')); " +
            "ctx.key = OpenSSL::PKey.read(File.read('test/ssl/client.key')); " +
            "ctx.add_certificate($cert, $key); ctx");
        assertEquals(engineClass("TLS"), context.createSSLEngine(null, 0).getClass());
    }

    @Test
    public void mldsaCredentialsPreserveExplicitMethods() throws Exception {
        loadMLDSAIdentity(44);
        for (String method : new String[] {"TLSv1_2", "SSLv3"}) {
            SSLContext context = context("ctx = OpenSSL::SSL::SSLContext.new(:" + method + "); " +
                "ctx.cert = $cert; ctx.key = $key; ctx");
            assertEquals(engineClass(context.getProtocol()), context.createSSLEngine(null, 0).getClass());
        }
    }

    @Test
    public void mldsaCredentialsPreserveProtocolBoundsAndOptions() {
        loadMLDSAIdentity(44);
        SSLContext bounded = context("ctx = OpenSSL::SSL::SSLContext.new; " +
            "ctx.cert = $cert; ctx.key = $key; " +
            "ctx.min_version = ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION; ctx");
        assertArrayEquals(new String[] {"TLSv1.3"}, bounded.createSSLEngine(null, 0).getEnabledProtocols());
        SSLContext disabled = context("ctx = OpenSSL::SSL::SSLContext.new; " +
            "ctx.cert = $cert; ctx.key = $key; " +
            "ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION; " +
            "ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION; " +
            "ctx.options |= OpenSSL::SSL::OP_NO_TLSv1_3; ctx");
        assertArrayEquals(new String[] {"TLSv1.2"}, disabled.createSSLEngine(null, 0).getEnabledProtocols());
    }

    private void loadMLDSAIdentity(int parameter) {
        runtime.evalScriptlet(
            "$key = OpenSSL::PKey.read(File.read('test/fixtures/mldsa/ml-dsa-" + parameter + "-seed.pem')); " +
            "$cert = OpenSSL::X509::Certificate.new; $cert.version = 2; $cert.serial = 1; " +
            "$cert.subject = $cert.issuer = OpenSSL::X509::Name.parse('/CN=ML-DSA test'); " +
            "$cert.public_key = $key; " +
            "$cert.not_before = Time.now - 60; $cert.not_after = Time.now + 3600; $cert.sign($key, nil)");
    }

    private SSLContext context(String script) {
        SSLContext context = (SSLContext) runtime.evalScriptlet(script);
        context.doSetup(currentContext());
        return context;
    }

    private Class<?> engineClass(String protocol) throws Exception {
        javax.net.ssl.SSLContext context = SecurityHelper.getSSLContext(protocol);
        context.init(null, new TrustManager[0], null);
        return context.createSSLEngine().getClass();
    }
}
