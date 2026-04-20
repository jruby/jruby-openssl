package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.runtime.ThreadContext;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

abstract class OpenSSLHelper {

    protected Ruby runtime;

    void setUpRuntime() throws ClassNotFoundException {
        runtime = Ruby.newInstance();
        loadOpenSSL(runtime);
    }

    void tearDownRuntime() {
        if (runtime != null) runtime.tearDown(false);
    }

    protected void loadOpenSSL(final Ruby runtime) throws ClassNotFoundException {
        // prepend lib/ so openssl.rb + jopenssl/ are loaded instead of bundled OpenSSL in jruby-stdlib
        final String libDir = new File("lib").getAbsolutePath();
        runtime.evalScriptlet("$LOAD_PATH.unshift '" + libDir + "'");
        runtime.evalScriptlet("require 'openssl'");

        // sanity: verify openssl was loaded from the project, not jruby-stdlib :
        final String versionFile = new File(libDir, "jopenssl/version.rb").getAbsolutePath();
        final String expectedVersion = runtime.evalScriptlet(
                "File.read('" + versionFile + "').match( /.*\\sVERSION\\s*=\\s*['\"](.*)['\"]/ )[1]")
                .toString();
        final String loadedVersion = runtime.evalScriptlet("JOpenSSL::VERSION").toString();
        assertEquals(expectedVersion, loadedVersion, "OpenSSL must be loaded from project " +
                "(got version " + loadedVersion + "), not from jruby-stdlib");

        // Also check the Java extension classes were resolved from the project, not jruby-stdlib :
        final String classOrigin = runtime.getJRubyClassLoader()
                .loadClass("org.jruby.ext.openssl.OpenSSL")
                .getProtectionDomain().getCodeSource().getLocation().toString();
        assertTrue(classOrigin.endsWith("/pkg/classes/"), "OpenSSL.class (via JRuby classloader) " +
                "come from project, got: " + classOrigin);
    }

    // HELPERS

    public ThreadContext currentContext() {
        return runtime.getCurrentContext();
    }

    public static String readResource(final String resource) {
        int n;
        try (InputStream in = SSLSocketTest.class.getResourceAsStream(resource)) {
            if (in == null) throw new IllegalArgumentException(resource + " not found on classpath");

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("failed to load" + resource, e);
        }
    }
}
