package org.jruby.ext.openssl.impl.pem;

import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMEncryptor;

import java.security.SecureRandom;

/**
 * @author kares
 */
public abstract class MiscPEMGeneratorHelper {

    public static MiscPEMGenerator newGenerator(final Object obj,
        final String algorithm, final char[] password, final SecureRandom random) {
        return new MiscPEMGenerator(obj, buildPEMEncryptor(algorithm, password, random));
    }

    private static PEMEncryptor buildPEMEncryptor(final String algorithm,
                                                  final char[] password, final SecureRandom random) {

        int ivLength = algorithm.toUpperCase().startsWith("AES-") ? 16 : 8;
        final byte[] iv = new byte[ivLength];
        ( random == null ? new SecureRandom() : random ).nextBytes(iv);

        return new PEMEncryptor() {
            public String getAlgorithm() { return algorithm; }

            public byte[] getIV() { return iv; }

            public byte[] encrypt(byte[] encoding) throws EncryptionException {
                return PEMUtilities.crypt(true, encoding, password, algorithm, iv);
            }
        };
    }

}
