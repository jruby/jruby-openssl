package org.jruby.ext.openssl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CipherStringsTest {

    private static final String[] SUITES = {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    };

    @Test
    public void ecdheSelectorsMatchOpenSSLAuthenticationRules() {
        final List<String> authenticated = Arrays.asList(
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384"
        );
        final List<String> withAnonymous = Arrays.asList(
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "AECDH-AES128-SHA",
            "ECDHE-RSA-AES256-SHA384"
        );

        assertEquals(authenticated, names("ECDHE"));
        assertEquals(authenticated, names("EECDH"));
        assertEquals(withAnonymous, names("kECDHE"));
        assertEquals(withAnonymous, names("kEECDH"));
        assertEquals(withAnonymous, names("ECDH"));
        assertEquals(Arrays.asList("AECDH-AES128-SHA"), names("AECDH"));
        assertEquals(Arrays.asList("ECDHE-ECDSA-AES128-GCM-SHA256"), names("ECDHE+aECDSA"));
        assertEquals(Arrays.asList("ECDHE-ECDSA-AES128-GCM-SHA256"), names("ECDHE+ECDSA"));

        final Collection<CipherStrings.Def> enabled = CipherStrings.matchingCiphers("ECDHE", SUITES, true);
        final List<String> javaNames = new ArrayList<>(enabled.size());
        for (final CipherStrings.Def cipher : enabled) javaNames.add(cipher.getCipherSuite());
        assertEquals(Arrays.asList(
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
        ), javaNames);
    }

    private static final String[] ENC_SUITES = {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    };

    @Test
    public void encryptionSelectorsMatchKeySize() {
        assertEquals(Arrays.asList("ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES128-SHA"), names("AES128", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-AES256-GCM-SHA384"), names("AES256", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-CHACHA20-POLY1305", "DHE-RSA-CHACHA20-POLY1305"), names("CHACHA20", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-CHACHA20-POLY1305"), names("EECDH+CHACHA20", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-AES128-GCM-SHA256"), names("EECDH+AES128", ENC_SUITES));
    }

    @Test
    public void unknownAliasVoidsCombinedRule() {
        assertEquals(Arrays.asList(), names("EECDH+FOO", ENC_SUITES));
        assertEquals(Arrays.asList(), names("FOO+EECDH", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-AES256-GCM-SHA384"), names("EECDH+FOO:EECDH+AES256", ENC_SUITES));
    }

    @Test
    public void combinedRuleAcceptsCipherNames() {
        assertEquals(Arrays.asList("ECDHE-RSA-AES128-GCM-SHA256"), names("AES128+ECDHE-RSA-AES128-GCM-SHA256", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-AES128-GCM-SHA256"), names("ECDHE-RSA-AES128-GCM-SHA256+AES128", ENC_SUITES));
        assertEquals(Arrays.asList("ECDHE-RSA-AES128-GCM-SHA256"), names("AES128+TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ENC_SUITES));
        assertEquals(Arrays.asList(), names("AES256+ECDHE-RSA-AES128-GCM-SHA256", ENC_SUITES));
    }

    @Test
    public void rfcCipherName() {
        assertEquals(Arrays.asList("ECDHE-RSA-AES128-GCM-SHA256"), names("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ENC_SUITES));
    }

    private static List<String> names(final String selector) {
        return names(selector, SUITES);
    }

    private static List<String> names(final String selector, final String[] suites) {
        final Collection<CipherStrings.Def> ciphers = CipherStrings.matchingCiphers(selector, suites, false);
        final List<String> names = new ArrayList<>(ciphers.size());
        for (final CipherStrings.Def cipher : ciphers) names.add(cipher.name);
        return names;
    }
}
