
package org.jruby.ext.openssl.x509store;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class StoreContextTest {

    @Test
    public void getExtraDataAtSizeReturnsNull() {
        final StoreContext ctx = new StoreContext(new Store());
        ctx.setApplicationData("app"); // sets idx 0, so extraData.size() == 1
        assertNull(ctx.getExtraData(StoreContext.ossl_ssl_ex_vcb_idx)); // idx 1 == size()
    }

    @Test
    public void getExtraDataRoundTrips() {
        final StoreContext ctx = new StoreContext(new Store());
        assertNull(ctx.getExtraData(0)); // no data yet
        ctx.setApplicationData("app");
        assertEquals("app", ctx.getExtraData(0));
        assertNull(ctx.getExtraData(3)); // beyond populated range
    }

    @Test
    public void auxCertificateEqualityIgnoresAux() throws Exception {
        final String pem = "-----BEGIN CERTIFICATE-----\n" +
            "MIIC/jCCAmegAwIBAgIBATANBgkqhkiG9w0BAQUFADBNMQswCQYDVQQGEwJKUDER\n" +
            "MA8GA1UECgwIY3Rvci5vcmcxFDASBgNVBAsMC0RldmVsb3BtZW50MRUwEwYDVQQD\n" +
            "DAxodHRwLWFjY2VzczIwHhcNMDcwOTExMTM1ODMxWhcNMDkwOTEwMTM1ODMxWjBN\n" +
            "MQswCQYDVQQGEwJKUDERMA8GA1UECgwIY3Rvci5vcmcxFDASBgNVBAsMC0RldmVs\n" +
            "b3BtZW50MRUwEwYDVQQDDAxodHRwLWFjY2VzczIwgZ8wDQYJKoZIhvcNAQEBBQAD\n" +
            "gY0AMIGJAoGBALi66ujWtUCQm5HpMSyr/AAIFYVXC/dmn7C8TR/HMiUuW3waY4uX\n" +
            "LFqCDAGOX4gf177pX+b99t3mpaiAjJuqc858D9xEECzhDWgXdLbhRqWhUOble4RY\n" +
            "c1yWYC990IgXJDMKx7VAuZ3cBhdBxtlE9sb1ZCzmHQsvTy/OoRzcJCrTAgMBAAGj\n" +
            "ge0wgeowDwYDVR0TAQH/BAUwAwEB/zAxBglghkgBhvhCAQ0EJBYiUnVieS9PcGVu\n" +
            "U1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUJNE0GGaRKmN2qhnO\n" +
            "FyBWVl4Qj6owDgYDVR0PAQH/BAQDAgEGMHUGA1UdIwRuMGyAFCTRNBhmkSpjdqoZ\n" +
            "zhcgVlZeEI+qoVGkTzBNMQswCQYDVQQGEwJKUDERMA8GA1UECgwIY3Rvci5vcmcx\n" +
            "FDASBgNVBAsMC0RldmVsb3BtZW50MRUwEwYDVQQDDAxodHRwLWFjY2VzczKCAQEw\n" +
            "DQYJKoZIhvcNAQEFBQADgYEAH11tstSUuqFpMqoh/vM5l3Nqb8ygblbqEYQs/iG/\n" +
            "UeQkOZk/P1TxB6Ozn2htJ1srqDpUsncFVZ/ecP19GkeOZ6BmIhppcHhE5WyLBcPX\n" +
            "It5q1BW0PiAzT9LlEGoaiW0nw39so0Pr1whJDfc1t4fjdk+kSiMIzRHbTDvHWfpV\n" +
            "nTA=\n" +
            "-----END CERTIFICATE-----\n";
        final X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        final X509AuxCertificate plain = new X509AuxCertificate(x509);
        final X509Aux aux = new X509Aux("alias", null, Collections.singletonList("1.3.6.1.5.5.7.3.1"), null, null);
        final X509AuxCertificate withAux = new X509AuxCertificate(x509, aux);

        assertEquals(plain, withAux);
        assertEquals(withAux, plain);
        assertEquals(plain.hashCode(), withAux.hashCode());
        assertEquals(plain, plain.cert);
        assertTrue(new Certificate(plain).matches(new Certificate(withAux)));
    }
}
