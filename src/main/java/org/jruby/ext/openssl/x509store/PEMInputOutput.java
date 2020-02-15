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
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
 * Copyright (C) 2007 William N Dortch <bill.dortch@gmail.com>
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
package org.jruby.ext.openssl.x509store;

import java.io.IOException;
import java.io.Writer;
import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.Reader;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.cms.CMSSignedData;

import org.jruby.ext.openssl.Cipher.Algorithm;
import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.ext.openssl.impl.PKCS10Request;
import org.jruby.ext.openssl.SecurityHelper;
import org.jruby.ext.openssl.util.ByteArrayOutputStream;

/**
 * Helper class to read and write PEM files correctly.
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class PEMInputOutput {

    public static final String BEF = "-----";
    public static final String AFT = "-----";
    public static final String BEF_G = BEF + "BEGIN ";
    public static final String BEF_E = BEF + "END ";
    public static final String PEM_STRING_X509_OLD="X509 CERTIFICATE";
    public static final String PEM_STRING_X509="CERTIFICATE";
    public static final String PEM_STRING_X509_PAIR="CERTIFICATE PAIR";
    public static final String PEM_STRING_X509_TRUSTED="TRUSTED CERTIFICATE";
    public static final String PEM_STRING_X509_REQ_OLD="NEW CERTIFICATE REQUEST";
    public static final String PEM_STRING_X509_REQ="CERTIFICATE REQUEST";
    public static final String PEM_STRING_X509_CRL="X509 CRL";
    public static final String PEM_STRING_EVP_PKEY="ANY PRIVATE KEY";
    public static final String PEM_STRING_PUBLIC="PUBLIC KEY";
    public static final String PEM_STRING_RSA="RSA PRIVATE KEY";
    public static final String PEM_STRING_RSA_PUBLIC="RSA PUBLIC KEY";
    public static final String PEM_STRING_DSA="DSA PRIVATE KEY";
    public static final String PEM_STRING_DSA_PUBLIC="DSA PUBLIC KEY";
    public static final String PEM_STRING_PKCS7="PKCS7";
    public static final String PEM_STRING_PKCS8="ENCRYPTED PRIVATE KEY";
    public static final String PEM_STRING_PKCS8INF="PRIVATE KEY";
    public static final String PEM_STRING_DHPARAMS="DH PARAMETERS";
    public static final String PEM_STRING_SSL_SESSION="SSL SESSION PARAMETERS";
    public static final String PEM_STRING_DSAPARAMS="DSA PARAMETERS";
    public static final String PEM_STRING_ECDSA_PUBLIC="ECDSA PUBLIC KEY";
    public static final String PEM_STRING_ECPARAMETERS="EC PARAMETERS";
    public static final String PEM_STRING_ECPRIVATEKEY="EC PRIVATE KEY";

    private static final String BEG_STRING_PUBLIC = BEF_G + PEM_STRING_PUBLIC;
    private static final String BEG_STRING_DSA = BEF_G + PEM_STRING_DSA;
    private static final String BEG_STRING_RSA = BEF_G + PEM_STRING_RSA;
    private static final String BEG_STRING_RSA_PUBLIC = BEF_G + PEM_STRING_RSA_PUBLIC;
    private static final String BEG_STRING_X509_OLD = BEF_G + PEM_STRING_X509_OLD;
    private static final String BEG_STRING_X509 = BEF_G + PEM_STRING_X509;
    private static final String BEG_STRING_X509_TRUSTED = BEF_G + PEM_STRING_X509_TRUSTED;
    private static final String BEG_STRING_X509_CRL = BEF_G + PEM_STRING_X509_CRL;
    private static final String BEG_STRING_X509_REQ = BEF_G + PEM_STRING_X509_REQ;

    private static BufferedReader makeBuffered(Reader in) {
        if (in instanceof BufferedReader) {
            return (BufferedReader) in;
        }
        return new BufferedReader(in);
    }

    private static BufferedWriter makeBuffered(Writer out) {
        if (out instanceof BufferedWriter) {
            return (BufferedWriter) out;
        }
        return new BufferedWriter(out);
    }

    /**
     * @deprecated Prefer passing in a buffered-reader esp. in loops as the
     * method might return a X.509 object before reading the full PEM file !
     */
    public static Object readPEM(final Reader in, final char[] passwd) throws IOException {
        return readPEM(makeBuffered(in), passwd);
    }

    /**
     * c: PEM_X509_INFO_read_bio
     */
    public static Object readPEM(final BufferedReader reader, final char[] passwd) throws IOException {
        String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PUBLIC) != -1 ) {
                try {
                    return readPublicKey(reader,BEF_E+PEM_STRING_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating public key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_DSA) != -1 ) {
                try {
                    return readKeyPair(reader,passwd, "DSA", BEF_E+PEM_STRING_DSA);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA private key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_RSA_PUBLIC) != -1 ) {
                try {
                    return readPublicKey(reader,BEF_E+PEM_STRING_RSA_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA public key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_OLD) != -1 ) {
                try {
                    return readAuxCertificate(reader,BEF_E+PEM_STRING_X509_OLD);
                } catch (Exception e) {
                    throw new IOException("problem creating X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509) != -1 ) {
                try {
                    return readAuxCertificate(reader,BEF_E+PEM_STRING_X509);
                } catch (Exception e) {
                    throw new IOException("problem creating X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if( line.indexOf(BEG_STRING_X509_TRUSTED) != -1 ) {
                try {
                    return readAuxCertificate(reader,BEF_E+PEM_STRING_X509_TRUSTED);
                } catch (Exception e) {
                    throw new IOException("problem creating X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if( line.indexOf(BEG_STRING_X509_CRL) != -1 ) {
                try {
                    return readCRL(reader,BEF_E+PEM_STRING_X509_CRL);
                } catch (Exception e) {
                    throw new IOException("problem creating X509 CRL: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_REQ) != -1 ) {
                try {
                    return readCertificateRequest(reader,BEF_E+PEM_STRING_X509_REQ);
                } catch (Exception e) {
                    throw new IOException("problem creating X509 REQ: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    public static byte[] readX509PEM(final Reader in) throws IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_X509_OLD) != -1 ) {
                try {
                    return readBase64Bytes(reader, BEF_E + PEM_STRING_X509_OLD);
                } catch (Exception e) {
                    throw new IOException("problem reading PEM X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509) != -1 ) {
                try {
                    return readBase64Bytes(reader, BEF_E + PEM_STRING_X509);
                } catch (Exception e) {
                    throw new IOException("problem reading PEM X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_TRUSTED) != -1 ) {
                try {
                    return readBase64Bytes(reader, BEF_E + PEM_STRING_X509_TRUSTED);
                } catch (Exception e) {
                    throw new IOException("problem reading PEM X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_CRL) != -1 ) {
                try {
                    return readBase64Bytes(reader, BEF_E + PEM_STRING_X509_CRL);
                } catch (Exception e) {
                    throw new IOException("problem reading PEM X509 CRL: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_REQ) != -1 ) {
                try {
                    return readBase64Bytes(reader, BEF_E + PEM_STRING_X509_REQ);
                } catch (Exception e) {
                    throw new IOException("problem reading PEM X509 REQ: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    /**
     * c: PEM_read_PrivateKey + PEM_read_bio_PrivateKey
     * CAUTION: KeyPair#getPublic() may be null.
     */
    public static KeyPair readPrivateKey(final Reader in, char[] passwd)
        throws PasswordRequiredException, IOException {
        final String BEG_STRING_ECPRIVATEKEY = BEF_G + PEM_STRING_ECPRIVATEKEY;
        final String BEG_STRING_PKCS8INF = BEF_G + PEM_STRING_PKCS8INF;
        final String BEG_STRING_PKCS8 = BEF_G + PEM_STRING_PKCS8;

        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_RSA) != -1 ) {
                try {
                    return readKeyPair(reader, passwd, "RSA", BEF_E + PEM_STRING_RSA);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA private key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_DSA) != -1 ) {
                try {
                    return readKeyPair(reader, passwd, "DSA", BEF_E + PEM_STRING_DSA);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA private key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_ECPRIVATEKEY) != -1) {
                try {
                    return readKeyPair(reader, passwd, "ECDSA", BEF_E + PEM_STRING_ECPRIVATEKEY);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA private key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_PKCS8INF) != -1) {
                try {
                    byte[] bytes = readBase64Bytes(reader, BEF_E + PEM_STRING_PKCS8INF);
                    PrivateKeyInfo info = PrivateKeyInfo.getInstance(bytes);
                    String type = getPrivateKeyTypeFromObjectId(info.getPrivateKeyAlgorithm().getAlgorithm());
                    return org.jruby.ext.openssl.impl.PKey.readPrivateKey(((ASN1Object) info.parsePrivateKey()).getEncoded(ASN1Encoding.DER), type);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating private key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_PKCS8) != -1 ) {
                try {
                    byte[] bytes = readBase64Bytes(reader, BEF_E + PEM_STRING_PKCS8);
                    EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.getInstance(bytes);
                    AlgorithmIdentifier algId = eIn.getEncryptionAlgorithm();
                    PrivateKey privKey;
                    if (algId.getAlgorithm().toString().equals("1.2.840.113549.1.5.13")) { // PBES2
                        privKey = derivePrivateKeyPBES2(eIn, algId, passwd);
                    } else {
                        privKey = derivePrivateKeyPBES1(eIn, algId, passwd);
                    }
                    return new KeyPair(null, privKey);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating private key: ", e);
                }
            }
        }
        return null;
    }

    private static IOException mapReadException(final String message, final Exception ex) {
        if ( ex instanceof PasswordRequiredException ) {
            return (PasswordRequiredException) ex;
        }
        return new IOException(message + ex, ex);
    }

    private static PrivateKey derivePrivateKeyPBES1(EncryptedPrivateKeyInfo eIn, AlgorithmIdentifier algId, char[] password)
            throws GeneralSecurityException, IOException {
        // From BC's PEMReader
        PKCS12PBEParams pkcs12Params = PKCS12PBEParams.getInstance(algId.getParameters());
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        PBEParameterSpec pbeParams = new PBEParameterSpec(
            pkcs12Params.getIV(), pkcs12Params.getIterations().intValue()
        );

        String algorithm = ASN1Registry.o2a(algId.getAlgorithm());
        algorithm = (algorithm.split("-"))[0];

        SecretKeyFactory secKeyFactory = SecurityHelper.getSecretKeyFactory(algorithm);

        Cipher cipher = SecurityHelper.getCipher(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secKeyFactory.generateSecret(pbeSpec), pbeParams);

        PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(
            ASN1Primitive.fromByteArray(cipher.doFinal(eIn.getEncryptedData()))
        );

        KeyFactory keyFactory = getKeyFactory( pInfo.getPrivateKeyAlgorithm() );
        return keyFactory.generatePrivate( new PKCS8EncodedKeySpec( pInfo.getEncoded() ) );
    }

    private static PrivateKey derivePrivateKeyPBES2(EncryptedPrivateKeyInfo eIn, AlgorithmIdentifier algId, char[] password)
            throws GeneralSecurityException, InvalidCipherTextException {
        PBES2Parameters pbeParams = PBES2Parameters.getInstance((ASN1Sequence) algId.getParameters());
        CipherParameters cipherParams = extractPBES2CipherParams(password, pbeParams);

        EncryptionScheme scheme = pbeParams.getEncryptionScheme();
        BufferedBlockCipher cipher;
        if ( scheme.getAlgorithm().equals( PKCSObjectIdentifiers.RC2_CBC ) ) {
            RC2CBCParameter rc2Params = RC2CBCParameter.getInstance(scheme);
            byte[] iv = rc2Params.getIV();
            CipherParameters param = new ParametersWithIV(cipherParams, iv);
            cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new RC2Engine()));
            cipher.init(false, param);
        } else {
            byte[] iv = ASN1OctetString.getInstance( scheme.getParameters() ).getOctets();
            CipherParameters param = new ParametersWithIV(cipherParams, iv);
            cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()));
            cipher.init(false, param);
        }

        byte[] data = eIn.getEncryptedData();
        byte[] out = new byte[cipher.getOutputSize(data.length)];
        int len = cipher.processBytes(data, 0, data.length, out, 0);
        len += cipher.doFinal(out, len);
        byte[] pkcs8 = new byte[len];
        System.arraycopy(out, 0, pkcs8, 0, len);
        KeyFactory fact = SecurityHelper.getKeyFactory("RSA"); // It seems to work for both RSA and DSA.
        return fact.generatePrivate( new PKCS8EncodedKeySpec(pkcs8) );
    }

    private static CipherParameters extractPBES2CipherParams(char[] password, PBES2Parameters pbeParams) {
        PBKDF2Params pbkdfParams = PBKDF2Params.getInstance(pbeParams.getKeyDerivationFunc().getParameters());
        int keySize = 192;
        if (pbkdfParams.getKeyLength() != null) {
            keySize = pbkdfParams.getKeyLength().intValue() * 8;
        }
        int iterationCount = pbkdfParams.getIterationCount().intValue();
        byte[] salt = pbkdfParams.getSalt();
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt, iterationCount);
        return generator.generateDerivedParameters(keySize);
    }

    // PEM_read_bio_PUBKEY
    public static PublicKey readPubKey(Reader in) throws IOException {
        PublicKey pubKey = readRSAPubKey(in);
        if (pubKey == null) pubKey = readDSAPubKey(in);
        if (pubKey == null) pubKey = readECPubKey(in);
        return pubKey;
    }

    /*
     * c: PEM_read_bio_DSA_PUBKEY
     */
    public static DSAPublicKey readDSAPubKey(Reader in) throws IOException {
        final String BEG_STRING_DSA_PUBLIC = BEF_G + PEM_STRING_DSA_PUBLIC;
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PUBLIC) != -1 ) {
                try {
                    return readDSAPublicKey(reader, BEF_E + PEM_STRING_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA public key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_DSA_PUBLIC) != -1 ) {
                try {
                    return readDSAPublicKey(reader, BEF_E + PEM_STRING_DSA_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA public key: ", e);
                }
            }
        }
        return null;
    }

    /*
     * c: PEM_read_bio_DSAPublicKey
     */
    public static DSAPublicKey readDSAPublicKey(final Reader in, final char[] passwd) throws IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PUBLIC) != -1 ) {
                try {
                    return (DSAPublicKey) readPublicKey(reader, "DSA", BEF_E + PEM_STRING_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA public key: ", e);
                }
            }
        }
        return null;
    }

    /*
     * c: PEM_read_bio_DSAPrivateKey
     */
    public static KeyPair readDSAPrivateKey(final Reader in, final char[] passwd)
        throws PasswordRequiredException, IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_DSA) != -1 ) {
                try {
                    return readKeyPair(reader, passwd, "DSA", BEF_E + PEM_STRING_DSA);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating DSA private key: ", e);
                }
            }
        }
        return null;
    }

    /**
     * reads an RSA public key encoded in an SubjectPublicKeyInfo RSA structure.
     * c: PEM_read_bio_RSA_PUBKEY
     */
    public static RSAPublicKey readRSAPubKey(Reader in) throws IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PUBLIC) != -1 ) {
                try {
                    return readRSAPublicKey(reader, BEF_E + PEM_STRING_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA public key: ", e);
                }
            }
            else if ( line.indexOf(BEG_STRING_RSA_PUBLIC) != -1 ) {
                try {
                    return readRSAPublicKey(reader, BEF_E + PEM_STRING_RSA_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA public key: ", e);
                }
            }
        }
        return null;
    }

    /**
     * reads an RSA public key encoded in an PKCS#1 RSA structure.
     * c: PEM_read_bio_RSAPublicKey
     */
    public static RSAPublicKey readRSAPublicKey(Reader in, char[] f)
        throws PasswordRequiredException, IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PUBLIC) != -1 ) {
                try {
                    return (RSAPublicKey) readPublicKey(reader, "RSA", BEF_E + PEM_STRING_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA public key: ", e);
                }
            }
            else if ( line.indexOf(BEF_G + PEM_STRING_RSA_PUBLIC) != -1 ) {
                try {
                    return (RSAPublicKey) readPublicKey(reader, "RSA", BEF_E + PEM_STRING_RSA_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA public key: ", e);
                }
            }
        }
        return null;
    }

    /**
     * c: PEM_read_bio_RSAPrivateKey
     */
    public static KeyPair readRSAPrivateKey(Reader in, char[] f)
        throws PasswordRequiredException, IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_RSA) != -1 ) {
                try {
                    return readKeyPair(reader,f, "RSA", BEF_E + PEM_STRING_RSA);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating RSA private key: ", e);
                }
            }
        }
        return null;
    }

    public static ECPublicKey readECPubKey(Reader in) throws IOException {
        final String BEG_STRING_EC_PUBLIC = BEF_G + "EC PUBLIC KEY";
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_EC_PUBLIC) != -1 ) {
                try {
                    return (ECPublicKey) readPublicKey(reader, "ECDSA", BEF_E + "EC PUBLIC KEY");
                }
                catch (Exception e) {
                    throw mapReadException("problem creating ECDSA public key: ", e);
                }
            }
        }
        return null;
    }

    public static ECPublicKey readECPublicKey(final Reader in, final char[] passwd) throws IOException {
        // final String BEG_STRING_EC = BEF_G + "EC PUBLIC KEY";
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PUBLIC) != -1 ) {
                try {
                    return (ECPublicKey) readPublicKey(reader, "ECDSA", BEF_E + PEM_STRING_PUBLIC);
                }
                catch (Exception e) {
                    throw mapReadException("problem creating ECDSA public key: ", e);
                }
            }
        }
        return null;
    }

    public static KeyPair readECPrivateKey(final Reader in, final char[] passwd)
        throws PasswordRequiredException, IOException {
        final String BEG_STRING_EC = BEF_G + "EC PRIVATE KEY";
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_EC) != -1 ) {
                try {
                    return readKeyPair(reader, passwd, "ECDSA", BEF_E + "EC PRIVATE KEY");
                }
                catch (Exception e) {
                    throw mapReadException("problem creating ECDSA private key: ", e);
                }
            }
        }
        return null;
    }

    public static CMSSignedData readPKCS7(Reader in, char[] f) throws IOException {
        final String BEG_STRING_PKCS7 = BEF_G + PEM_STRING_PKCS7;
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_PKCS7) != -1 ) {
                try {
                    return readPKCS7(reader,f, BEF_E + PEM_STRING_PKCS7);
                }
                catch (Exception e) {
                    throw new IOException("problem creating PKCS7: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    /**
     * @deprecated Prefer passing in a buffered-reader esp. in loops as the
     * method might return a X.509 object before reading the full PEM file !
     */
    public static X509AuxCertificate readX509Certificate(final Reader in, final char[] passwd) throws IOException {
        return readX509Certificate(makeBuffered(in), passwd);
    }

    public static X509AuxCertificate readX509Certificate(final BufferedReader reader, final char[] passwd)
        throws IOException {
        String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_X509_OLD) != -1 ) {
                try {
                    return new X509AuxCertificate(readCertificate(reader,BEF_E+PEM_STRING_X509_OLD));
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509) != -1 ) {
                try {
                    return new X509AuxCertificate(readCertificate(reader,BEF_E+PEM_STRING_X509));
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_TRUSTED) != -1 ) {
                try {
                    return new X509AuxCertificate(readCertificate(reader,BEF_E+PEM_STRING_X509_TRUSTED));
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 certificate: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    /**
     * @deprecated Prefer passing in a buffered-reader esp. in loops as the
     * method might return a X.509 object before reading the full PEM file !
     */
    public static X509AuxCertificate readX509Aux(final Reader in, final char[] passwd) throws IOException {
        return readX509Aux(makeBuffered(in), passwd);
    }

    public static X509AuxCertificate readX509Aux(final BufferedReader reader, final char[] passwd)
        throws IOException {
        String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_X509_OLD) != -1 ) {
                try {
                    return readAuxCertificate(reader, BEF_E + PEM_STRING_X509_OLD);
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509) != -1 ) {
                try {
                    return readAuxCertificate(reader, BEF_E + PEM_STRING_X509);
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 Aux certificate: " + e.toString(), e);
                }
            }
            else if ( line.indexOf(BEG_STRING_X509_TRUSTED) != -1 ) {
                try {
                    return readAuxCertificate(reader, BEF_E + PEM_STRING_X509_TRUSTED);
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 Aux certificate: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    /**
     * @deprecated Prefer passing in a buffered-reader esp. in loops as the
     * method might return a X.509 object before reading the full PEM file !
     */
    public static X509CRL readX509CRL(final Reader reader, final char[] passwd) throws IOException {
        return readX509CRL(makeBuffered(reader), passwd);
    }

    public static X509CRL readX509CRL(final BufferedReader reader, final char[] passwd) throws IOException {
        String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_X509_CRL) != -1 ) {
                try {
                    return readCRL(reader, BEF_E + PEM_STRING_X509_CRL);
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 CRL: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    public static PKCS10Request readX509Request(final Reader in, final char[] passwd)
        throws IOException {
        final BufferedReader reader = makeBuffered(in); String line;
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_X509_REQ) != -1 ) {
                try {
                    return readCertificateRequest(reader, BEF_E + PEM_STRING_X509_REQ);
                }
                catch (Exception e) {
                    throw new IOException("problem creating X509 REQ: " + e.toString(), e);
                }
            }
        }
        return null;
    }

    public static DHParameterSpec readDHParameters(final Reader in) throws IOException {
        final String BEG_STRING_DHPARAMS = BEF_G + PEM_STRING_DHPARAMS;

        final BufferedReader reader = makeBuffered(in); String line;
        final StringBuilder lines = new StringBuilder();
        while ( ( line = reader.readLine() ) != null ) {
            if ( line.indexOf(BEG_STRING_DHPARAMS) >= 0 ) {
                final String endParams = BEF_E + PEM_STRING_DHPARAMS;
                do {
                    lines.append(line.trim());
                }
                while ( line.indexOf(endParams) < 0 && ( line = reader.readLine() ) != null );
                break;
            }
        }

        final Pattern DH_PARAMS_PATTERN = Pattern.compile(
            "(-----BEGIN DH PARAMETERS-----)(.*)(-----END DH PARAMETERS-----)",
            Pattern.MULTILINE);
        final int DH_PARAMS_GROUP = 2; // the group above containing encoded params

        final Matcher matcher = DH_PARAMS_PATTERN.matcher( lines.toString() );
        if ( matcher.find() ) {
            try {
                byte[] decoded = Base64.decode(matcher.group(DH_PARAMS_GROUP));
                return org.jruby.ext.openssl.impl.PKey.readDHParameter(decoded);
            }
            catch (IOException e) {
                // TODO
            }
        }
        return null;
    }

    private static byte[] getEncoded(java.security.Key key) {
        if ( key == null ) return new byte[] { '0', 0 };
        return key.getEncoded();
    }

    private static byte[] getEncoded(ASN1Encodable obj) throws IOException {
        if ( obj == null ) return new byte[] { '0', 0 };
        return obj.toASN1Primitive().getEncoded();
    }

    private static byte[] getEncoded(CMSSignedData obj) throws IOException {
        if ( obj == null ) return new byte[] { '0', 0 };
        return obj.getEncoded();
    }

    private static byte[] getEncoded(X509Certificate cert) throws IOException {
        if ( cert == null ) return new byte[] { '0', 0 };
        try {
            return cert.getEncoded();
        }
        catch (GeneralSecurityException e) {
            throw new IOException("problem with encoding object in write_X509", e);
        }
    }

    private static byte[] getEncoded(X509CRL crl) throws IOException {
        if ( crl == null ) return new byte[] { '0', 0 };
        try {
            return crl.getEncoded();
        }
        catch (GeneralSecurityException e) {
            throw new IOException("problem with encoding object in write_X509_CRL", e);
        }
    }

    public static void writeDSAPublicKey(Writer _out, DSAPublicKey obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] enc = getEncoded(obj);
        out.write(BEF_G + PEM_STRING_PUBLIC + AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E + PEM_STRING_PUBLIC + AFT);
        out.newLine();
        out.flush();
    }

    /** writes an RSA public key encoded in an PKCS#1 RSA structure. */
    public static void writeRSAPublicKey(Writer _out, RSAPublicKey obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] enc = getEncoded(obj);
        out.write(BEF_G + PEM_STRING_PUBLIC + AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E + PEM_STRING_PUBLIC + AFT);
        out.newLine();
        out.flush();
    }

    public static void writeECPublicKey(Writer _out, ECPublicKey obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] enc = getEncoded(obj);
        out.write(BEF_G); out.write(PEM_STRING_PUBLIC); out.write(AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E); out.write(PEM_STRING_PUBLIC); out.write(AFT);
        out.newLine();
        out.flush();
    }

    public static void writePKCS7(Writer _out, ContentInfo obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] enc = getEncoded(obj);
        out.write(BEF_G + PEM_STRING_PKCS7 + AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E + PEM_STRING_PKCS7 + AFT);
        out.newLine();
        out.flush();
    }
    public static void writePKCS7(Writer _out, CMSSignedData obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] enc = getEncoded(obj);
        out.write(BEF_G + PEM_STRING_PKCS7 + AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E + PEM_STRING_PKCS7 + AFT);
        out.newLine();
        out.flush();
    }
    public static void writePKCS7(final Writer _out, final byte[] enc) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        out.write(BEF_G + PEM_STRING_PKCS7 + AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E + PEM_STRING_PKCS7 + AFT);
        out.newLine();
        out.flush();
    }
    public static void writeX509Certificate(final Writer _out, final X509Certificate cert) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] enc = getEncoded(cert);
        out.write(BEF_G + PEM_STRING_X509 + AFT);
        out.newLine();
        writeEncoded(out, enc, enc.length);
        out.write(BEF_E + PEM_STRING_X509 + AFT);
        out.newLine();
        out.flush();
    }
    public static void writeX509Aux(final Writer _out, final X509AuxCertificate cert) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        final byte[] encoding; final int encLen;
        try {
            if ( cert.aux == null ) {
                encoding = cert.getEncoded(); encLen = encoding.length;
            }
            else {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] enc = cert.getEncoded();
                baos.write(enc, 0, enc.length);

                final X509Aux aux = cert.aux;
                ASN1EncodableVector a1 = new ASN1EncodableVector();
                if ( aux.trust.size() > 0 ) {
                    ASN1EncodableVector a2 = new ASN1EncodableVector();
                    for ( String trust : aux.trust ) {
                        a2.add(new ASN1ObjectIdentifier(trust));
                    }
                    a1.add(new DLSequence(a2));
                }
                if ( aux.reject.size() > 0 ) {
                    ASN1EncodableVector a2 = new ASN1EncodableVector();
                    for ( String reject : aux.reject ) {
                        a2.add(new ASN1ObjectIdentifier(reject));
                    }
                    a1.add(new DERTaggedObject(0,new DLSequence(a2)));
                }
                if ( aux.alias != null ) {
                    a1.add(new DERUTF8String(aux.alias));
                }
                if ( aux.keyid != null ) {
                    a1.add(new DEROctetString(aux.keyid));
                }
                if ( aux.other.size() > 0 ) {
                    ASN1EncodableVector a2 = new ASN1EncodableVector();
                    for ( ASN1Primitive other : aux.other ) a2.add(other);
                    a1.add( new DERTaggedObject( 1, new DLSequence(a2) ) );
                }
                enc = new DLSequence(a1).getEncoded();
                baos.write(enc, 0, enc.length);
                encoding = baos.buffer(); encLen = baos.size();
            }
        }
        catch (CertificateEncodingException e) {
            throw new IOException("problem with encoding object in write_X509_AUX", e);
        }
        out.write(BEF_G + PEM_STRING_X509_TRUSTED + AFT);
        out.newLine();
        writeEncoded(out, encoding, encLen);
        out.write(BEF_E + PEM_STRING_X509_TRUSTED + AFT);
        out.newLine();
        out.flush();
    }
    public static void writeX509CRL(Writer _out, X509CRL obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        byte[] encoding = getEncoded(obj);
        out.write(BEF_G + PEM_STRING_X509_CRL + AFT);
        out.newLine();
        writeEncoded(out, encoding, encoding.length);
        out.write(BEF_E + PEM_STRING_X509_CRL + AFT);
        out.newLine();
        out.flush();
    }
    public static void writeX509Request(Writer _out, PKCS10Request obj) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        byte[] encoding = getEncoded(obj.toASN1Structure());
        out.write(BEF_G + PEM_STRING_X509_REQ + AFT);
        out.newLine();
        writeEncoded(out, encoding, encoding.length);
        out.write(BEF_E + PEM_STRING_X509_REQ + AFT);
        out.newLine();
        out.flush();
    }

    public static void writeDSAPrivateKey(Writer _out, DSAPrivateKey obj, CipherSpec cipher, char[] passwd) throws IOException {
        BufferedWriter out = makeBuffered(_out);
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(new ASN1InputStream(getEncoded(obj)).readObject());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);

        DSAParameter p = DSAParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(BigInteger.ZERO));
        v.add(new ASN1Integer(p.getP()));
        v.add(new ASN1Integer(p.getQ()));
        v.add(new ASN1Integer(p.getG()));

        BigInteger x = obj.getX();
        BigInteger y = p.getG().modPow(x, p.getP());

        v.add(new ASN1Integer(y));
        v.add(new ASN1Integer(x));

        aOut.writeObject(new DLSequence(v));

        if (cipher != null && passwd != null) {
            writePemEncrypted(out, PEM_STRING_DSA, bOut.buffer(), bOut.size(), cipher, passwd);
        } else {
            writePemPlain(out, PEM_STRING_DSA, bOut.buffer(), bOut.size());
        }
    }

    public static void writeRSAPrivateKey(Writer _out, RSAPrivateCrtKey obj, CipherSpec cipher, char[] passwd) throws IOException {
        assert (obj != null);
        BufferedWriter out = makeBuffered(_out);
        org.bouncycastle.asn1.pkcs.RSAPrivateKey keyStruct = new org.bouncycastle.asn1.pkcs.RSAPrivateKey(obj.getModulus(), obj.getPublicExponent(), obj.getPrivateExponent(), obj.getPrimeP(),
                obj.getPrimeQ(), obj.getPrimeExponentP(), obj.getPrimeExponentQ(), obj.getCrtCoefficient());

        if (cipher != null && passwd != null) {
            writePemEncrypted(out, PEM_STRING_RSA, keyStruct.getEncoded(), cipher, passwd);
        } else {
            writePemPlain(out, PEM_STRING_RSA, keyStruct.getEncoded());
        }
    }

    public static void writeECPrivateKey(Writer _out, ECPrivateKey obj, CipherSpec cipher, char[] passwd) throws IOException {
        assert (obj != null);
        final String PEM_STRING_EC = "EC PRIVATE KEY";
        BufferedWriter out = makeBuffered(_out);
        final int bitLength = obj.getParams().getOrder().bitLength();
        org.bouncycastle.asn1.sec.ECPrivateKey keyStruct = new org.bouncycastle.asn1.sec.ECPrivateKey(bitLength, obj.getS());
        if (cipher != null && passwd != null) {
            writePemEncrypted(out, PEM_STRING_EC, keyStruct.getEncoded(), cipher, passwd);
        } else {
            writePemPlain(out, PEM_STRING_EC, keyStruct.getEncoded());
        }
    }

    public static void writeECParameters(Writer _out, ASN1ObjectIdentifier obj, CipherSpec cipher, char[] passwd) throws IOException {
        assert (obj != null);
        final String PEM_STRING_EC = "EC PARAMETERS";
        BufferedWriter out = makeBuffered(_out);
        if (cipher != null && passwd != null) {
            writePemEncrypted(out, PEM_STRING_EC, obj.getEncoded(), cipher, passwd);
        } else {
            writePemPlain(out, PEM_STRING_EC, obj.getEncoded());
        }
    }

    private static void writePemPlain(final BufferedWriter out,
        final String PEM_ID, final byte[] encoding) throws IOException {
        writePemPlain(out, PEM_ID, encoding, encoding.length);
    }

    private static void writePemPlain(final BufferedWriter out,
        final String PEM_ID, final byte[] encoding, final int encLen) throws IOException {
        out.write(BEF_G); out.write(PEM_ID); out.write(AFT);
        out.newLine();
        writeEncoded(out, encoding, encLen);
        out.write(BEF_E); out.write(PEM_ID); out.write(AFT);
        out.newLine();
        out.flush();
    }

    private static void writePemEncrypted(final BufferedWriter out,
        final String PEM_ID, final byte[] encoding,
        final CipherSpec cipherSpec, final char[] passwd) throws IOException {
        writePemEncrypted(out, PEM_ID, encoding, encoding.length, cipherSpec, passwd);
    }

    private static void writePemEncrypted(final BufferedWriter out,
        final String PEM_ID, final byte[] encoding, final int encCount,
        final CipherSpec cipherSpec, final char[] passwd) throws IOException {

        final Cipher cipher = cipherSpec.getCipher();
        final byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom().nextBytes(iv);
        final byte[] salt = new byte[8];
        System.arraycopy(iv, 0, salt, 0, 8);
        OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();
        pGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(passwd), salt);

        KeyParameter param = (KeyParameter) pGen.generateDerivedParameters(cipherSpec.getKeyLenInBits());
        SecretKey secretKey = new SecretKeySpec(param.getKey(), Algorithm.getAlgorithmBase(cipher));
        final byte[] encData;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            encData = cipher.doFinal(encoding, 0, encCount);
        }
        catch (InvalidKeyException e) {
            final String msg = e.getMessage();
            if ( msg != null && msg.startsWith("Invalid key length") ) {
                throw new IOException("Invalid key length. See http://wiki.jruby.org/UnlimitedStrengthCrypto", e);
            }
            throw new IOException("exception using cipher: "+ cipherSpec.getOsslName()  + " (" + e + ")", e);
        }
        catch (GeneralSecurityException e) {
            throw new IOException("exception using cipher: "+ cipherSpec.getOsslName()  + " (" + e + ")", e);
        }
        out.write(BEF_G); out.write(PEM_ID); out.write(AFT);
        out.newLine();
        out.write("Proc-Type: 4,ENCRYPTED");
        out.newLine();
        out.write("DEK-Info: " + cipherSpec.getOsslName() + ',');
        writeHexEncoded(out, iv);
        out.newLine();
        out.newLine();
        writeEncoded(out, encData, encData.length);
        out.write(BEF_E); out.write(PEM_ID); out.write(AFT);
        out.flush();
    }

    private static SecureRandom random;

    private static SecureRandom secureRandom() {
        if ( random == null ) {
            try {
                random = SecureRandom.getInstance("SHA1PRNG");
            }
            catch (NoSuchAlgorithmException e) {
                random = new SecureRandom();
            }
        }
        return random;
    }

    public static void writeDHParameters(Writer _out, DHParameterSpec params) throws IOException {
        final BufferedWriter out = makeBuffered(_out);

        ASN1EncodableVector v = new ASN1EncodableVector();

        BigInteger value;
        if ( ( value = params.getP() ) != null ) {
            v.add( new ASN1Integer(value) );
        }
        if ( ( value = params.getG() ) != null ) {
            v.add( new ASN1Integer(value) );
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(new DLSequence(v));

        out.write(BEF_G); out.write(PEM_STRING_DHPARAMS); out.write(AFT);
        out.newLine();
        writeEncoded(out, bOut.buffer(), bOut.size());
        out.write(BEF_E); out.write(PEM_STRING_DHPARAMS); out.write(AFT);
        out.newLine();
        out.flush();
    }

    private static String getPrivateKeyTypeFromObjectId(ASN1ObjectIdentifier oid) {
        if ( ASN1Registry.oid2nid(oid) == ASN1Registry.NID_rsaEncryption ) {
            return "RSA";
        } else {
            return "DSA";
        }
    }

    private static RSAPublicKey readRSAPublicKey(BufferedReader in, String endMarker) throws IOException {
        Object asnObject = new ASN1InputStream(readBase64Bytes(in, endMarker)).readObject();
        ASN1Sequence sequence = (ASN1Sequence) asnObject;
        org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPubStructure = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(sequence);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(rsaPubStructure.getModulus(), rsaPubStructure.getPublicExponent());

        try {
            return (RSAPublicKey) SecurityHelper.getKeyFactory("RSA").generatePublic(keySpec);
        }
        catch (NoSuchAlgorithmException e) { /* ignore */ }
        catch (InvalidKeySpecException e) { /* ignore */ }
        return null;
    }

    private static DSAPublicKey readDSAPublicKey(BufferedReader in, String endMarker) throws IOException {
        Object asnObject = new ASN1InputStream(readBase64Bytes(in, endMarker)).readObject();
        Enumeration seq = ((ASN1Sequence) asnObject).getObjects();
        ASN1Integer y = ASN1Integer.getInstance(seq.nextElement());
        ASN1Integer p = ASN1Integer.getInstance(seq.nextElement());
        ASN1Integer q = ASN1Integer.getInstance(seq.nextElement());
        ASN1Integer g = ASN1Integer.getInstance(seq.nextElement());

        DSAPublicKeySpec keySpec = new DSAPublicKeySpec(
                y.getPositiveValue(), p.getPositiveValue(), q.getPositiveValue(), g.getPositiveValue()
        );

        try {
            return (DSAPublicKey) SecurityHelper.getKeyFactory("DSA").generatePublic(keySpec);
        }
        catch (NoSuchAlgorithmException e) { /* ignore */ }
        catch (InvalidKeySpecException e) { /* ignore */ }
        return null;
    }

    private static PublicKey readPublicKey(byte[] input, String alg, String endMarker) throws IOException {
        KeySpec keySpec = new X509EncodedKeySpec(input);
        try {
            return SecurityHelper.getKeyFactory(alg).generatePublic(keySpec);
        }
        catch (NoSuchAlgorithmException e) { /* ignore */ }
        catch (InvalidKeySpecException e) { /* ignore */ }
        return null;
    }

    private static PublicKey readPublicKey(BufferedReader in, String alg, String endMarker) throws IOException {
        return readPublicKey(readBase64Bytes(in, endMarker), alg, endMarker);
    }

    private static PublicKey readPublicKey(BufferedReader in, String endMarker) throws IOException {
        byte[] input = readBase64Bytes(in, endMarker);
        String[] algs = { "RSA", "DSA", "ECDSA" };
        for (int i = 0; i < algs.length; i++) {
            PublicKey key = readPublicKey(input, algs[i], endMarker);
            if (key != null) {
                return key;
            }
        }
        return null;
    }

    /**
     * Read a Key Pair
     */
    private static KeyPair readKeyPair(BufferedReader in, char[] passwd, String type, String endMarker)
        throws PasswordRequiredException, IOException, GeneralSecurityException {
        boolean isEncrypted = false;
        String dekInfo = null;

        String line; StringBuilder buffer = new StringBuilder(512);
        while ( ( line = in.readLine() ) != null ) {
            if ( line.startsWith("Proc-Type: 4,ENCRYPTED") ) {
                isEncrypted = true;
            }
            else if ( line.startsWith("DEK-Info:") ) {
                dekInfo = line.substring(10);
            }
            else if ( line.contains(endMarker) ) {
                break;
            }
            else {
                buffer.append( line.trim() );
            }
        }
        byte[] decoded = Base64.decode( buffer.toString() );

        final byte[] keyBytes;
        if ( isEncrypted ) {
            keyBytes = decrypt(decoded, dekInfo, passwd);
        } else {
            keyBytes = decoded;
        }
        return org.jruby.ext.openssl.impl.PKey.readPrivateKey(keyBytes, type);
    }

    private static byte[] decrypt(byte[] decoded, String dekInfo, char[] passwd)
        throws PasswordRequiredException, IOException, GeneralSecurityException {
        if ( passwd == null ) throw new PasswordRequiredException();

        StringTokenizer tknz = new StringTokenizer(dekInfo, ",");
        String algorithm = tknz.nextToken();
        byte[] iv = Hex.decode(tknz.nextToken());
        // NOTE: shall be fine and bubble up on-demand (if really not supported)
        //if ( ! org.jruby.ext.openssl.Cipher.isSupportedCipher(algorithm) ) {
        //    throw new IOException("Unknown algorithm: " + algorithm);
        //}

        String realName = Algorithm.getRealName(algorithm);
        int[] lengths = Algorithm.osslKeyIvLength(algorithm);
        int keyLen = lengths[0];
        int ivLen = lengths[1];
        if (iv.length != ivLen) {
            throw new IOException("Illegal IV length");
        }
        byte[] salt = new byte[8];
        System.arraycopy(iv, 0, salt, 0, 8);
        OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();
        pGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(passwd), salt);
        KeyParameter param = (KeyParameter) pGen.generateDerivedParameters(keyLen * 8);
        SecretKey secretKey = new SecretKeySpec(param.getKey(), realName);
        Cipher cipher = SecurityHelper.getCipher(realName);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(decoded);
    }

    public static class PasswordRequiredException extends IOException {

        PasswordRequiredException() {
            super();
        }

    }

    /**
     * Reads in a X509Certificate.
     *
     * @return the X509Certificate
     * @throws IOException if an I/O error occured
     */
    private static X509Certificate readCertificate(final BufferedReader in, final String endMarker)
        throws IOException {
        final byte[] bytes = readBase64Bytes(in, endMarker);
        try {
            return (X509Certificate) getX509CertificateFactory().generateCertificate( new ByteArrayInputStream( bytes ) );
        }
        catch (CertificateException e) {
            throw new IOException("failed to read certificate: " + e, e);
        }
        //catch (RuntimeException e) {
        //    throw new IOException("problem generating cert: " + e.toString(), e);
        //}
    }

    private static X509AuxCertificate readAuxCertificate(final BufferedReader in, final String endMarker)
        throws IOException {
        final byte[] bytes = readBase64Bytes(in, endMarker);

        final ASN1InputStream asn1 = new ASN1InputStream(bytes);
        ByteArrayInputStream certBytes = new ByteArrayInputStream( ( asn1.readObject() ).getEncoded() );

        try {
            final X509Certificate cert = (X509Certificate) getX509CertificateFactory().generateCertificate(certBytes);
            final ASN1Sequence auxSeq = (ASN1Sequence) asn1.readObject();
            final X509Aux aux;
            if ( auxSeq != null ) {
                // X509Aux fields :
                final List<String> trust;
                final List<String> reject;
                final String alias;
                final byte[] keyid;
                final List<ASN1Primitive> other;

                int ix = 0; ASN1Encodable obj = null;
                if ( auxSeq.size() > ix ) obj = auxSeq.getObjectAt(ix);

                if ( obj instanceof ASN1Sequence ) {
                    trust = new ArrayList<String>();
                    final ASN1Sequence trustSeq = (ASN1Sequence) obj;
                    for ( int i = 0; i < trustSeq.size(); i++ ) {
                        trust.add( ((ASN1ObjectIdentifier) trustSeq.getObjectAt(i)).getId() );
                    }

                    obj = ( auxSeq.size() > ++ix ) ? auxSeq.getObjectAt(ix) : null; // next obj
                }
                else trust = Collections.emptyList();

                if ( obj instanceof ASN1TaggedObject && ((ASN1TaggedObject) obj).getTagNo() == 0 ) {
                    reject = new ArrayList<String>();
                    final ASN1Sequence rejectSeq = (ASN1Sequence) ((ASN1TaggedObject) obj).getObject();
                    for( int i = 0; i < rejectSeq.size(); i++ ) {
                        reject.add( ((ASN1ObjectIdentifier) rejectSeq.getObjectAt(i)).getId() );
                    }

                    obj = ( auxSeq.size() > ++ix ) ? auxSeq.getObjectAt(ix) : null; // next obj
                }
                else reject = Collections.emptyList();

                if ( obj instanceof DERUTF8String ) {
                    alias = ((DERUTF8String) obj).getString();

                    obj = ( auxSeq.size() > ++ix ) ? auxSeq.getObjectAt(ix) : null; // next obj
                }
                else alias = null;

                if ( obj instanceof DEROctetString ) {
                    keyid = ((DEROctetString) obj).getOctets();

                    obj = ( auxSeq.size() > ++ix ) ? auxSeq.getObjectAt(ix) : null; // next obj
                }
                else keyid = null;

                if ( obj instanceof ASN1TaggedObject && ((ASN1TaggedObject) obj).getTagNo() == 1 ) {
                    other = new ArrayList<ASN1Primitive>();
                    final ASN1Sequence otherSeq = (ASN1Sequence) ((ASN1TaggedObject) obj).getObject();
                    for( int i = 0; i < otherSeq.size(); i++ ) {
                        other.add( (ASN1Primitive) otherSeq.getObjectAt(i) );
                    }

                    //obj = ( auxSeq.size() > ++ix ) ? auxSeq.getObjectAt(ix) : null; // next obj
                }
                else other = Collections.emptyList();

                aux = new X509Aux(alias, keyid,
                        Collections.unmodifiableList(trust),
                        Collections.unmodifiableList(reject),
                        Collections.unmodifiableList(other));
            }
            else {
                aux = null;
            }
            return new X509AuxCertificate(cert, aux);
        }
        catch (CertificateException e) {
            throw new IOException("failed to read aux cert: " + e, e);
        }
    }

    /**
     * Reads in a X509CRL.
     *
     * @return the X509CRL
     * @throws IOException if an I/O error occured
     */
    private static X509CRL readCRL(BufferedReader in, String endMarker) throws IOException {
        final byte[] bytes = readBase64Bytes(in, endMarker);
        try {
            return (X509CRL) getX509CertificateFactory().generateCRL( new ByteArrayInputStream( bytes ) );
        }
        catch (CRLException e) {
            throw new IOException("failed to read crl: " + e, e);
        }
        //catch (RuntimeException e) {
        //    throw new IOException("problem parsing cert: " + e.toString(), e);
        //}
    }

    /**
     * Reads in a PKCS10 certification request.
     *
     * @return the certificate request.
     * @throws IOException if an I/O error occured
     */
    private static PKCS10Request readCertificateRequest(BufferedReader in, String endMarker) throws IOException {
        final byte[] bytes = readBase64Bytes(in, endMarker);
        try {
            return new PKCS10Request( bytes );
        }
        catch (RuntimeException e) {
            throw new IOException("problem parsing cert: " + e.toString(), e);
        }
    }

    /**
     * Reads in a PKCS7 object. This returns a ContentInfo object suitable for use with the CMS
     * API.
     *
     * @return the X509Certificate
     * @throws IOException if an I/O error occured
     */
    private static CMSSignedData readPKCS7(BufferedReader in, char[] p, String endMarker) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        String line; StringBuilder buffer = new StringBuilder();
        while ( (line = in.readLine()) != null ) {
            if ( line.contains(endMarker) ) break;

            buffer.append( line.trim() );
            final int len = buffer.length();
            Base64.decode( buffer.substring(0, (len / 4) * 4), bytes );
            buffer.delete(0, (len / 4) * 4);
        }

        if (buffer.length() != 0) {
            throw new IOException("base64 data appears to be truncated");
        }
        if (line == null) throw new IOException(endMarker + " not found");

        try {
            ASN1InputStream aIn = new ASN1InputStream(bytes.toByteArray());
            return new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
        }
        catch (CMSException e) {
            throw new IOException("problem parsing PKCS7 object: " + e, e);
        }
    }

    public static KeyFactory getKeyFactory(final AlgorithmIdentifier algId)
        throws NoSuchAlgorithmException {

        final ASN1ObjectIdentifier algIdentifier = algId.getAlgorithm();

        String algorithm = null;
        if ( X9ObjectIdentifiers.id_ecPublicKey.equals(algIdentifier) ) {
            algorithm = "ECDSA";
        }
        else if ( PKCSObjectIdentifiers.rsaEncryption.equals(algIdentifier) ) {
            algorithm = "RSA";
        }
        else if ( X9ObjectIdentifiers.id_dsa.equals(algIdentifier) ) {
            algorithm = "DSA";
        }

        if ( algorithm == null ) algorithm = algIdentifier.getId();

        return SecurityHelper.getKeyFactory(algorithm);
    }

    private static CertificateFactory getX509CertificateFactory() {
        try {
            return SecurityHelper.getCertificateFactory("X.509");
        }
        catch (CertificateException e) {
            throw new IllegalStateException(e); // X.509 not supported?!
        }
    }

    private static void writeHexEncoded(BufferedWriter out, byte[] bytes) throws IOException {
        bytes = Hex.encode(bytes);
        for (int i = 0; i != bytes.length; i++) {
            out.write((char)bytes[i]);
        }
    }

    private static void writeEncoded(BufferedWriter out,
        byte[] bytes, final int bytesLen) throws IOException {
        final char[] buf = new char[64];
        bytes = Base64.encode(bytes, 0 ,bytesLen);
        for (int i = 0; i < bytes.length; i += buf.length) {
            int index = 0;

            while (index != buf.length) {
                if ((i + index) >= bytes.length) {
                    break;
                }
                buf[index] = (char) bytes[i + index];
                index++;
            }
            out.write(buf, 0, index);
            out.newLine();
        }
    }

    private static byte[] readBase64Bytes(BufferedReader in, String endMarker) throws IOException {
        return Base64.decode( readLines(in, endMarker).toString() );
    }

    private static StringBuilder readLines(final BufferedReader reader, final String endMarker) throws IOException {
        String line;
        StringBuilder lines = new StringBuilder(64);

        while ( ( line = reader.readLine() ) != null ) {
            if ( line.contains(endMarker) ) break;
            lines.append( line.trim() );
        }

        if ( line == null ) {
            throw new IOException(endMarker + " not found");
        }
        return lines;
    }

}// PEM
