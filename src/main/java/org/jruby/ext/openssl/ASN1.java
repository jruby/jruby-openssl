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
 * Copyright (C) 2006, 2007 Ola Bini <ola@ologix.com>
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
package org.jruby.ext.openssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.asn1.*;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.impl.ASN1Registry;

import static org.jruby.ext.openssl.OpenSSL.*;
import org.jruby.ext.openssl.util.ByteArrayOutputStream;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class ASN1 {

    private static Map<Ruby, Map<String, ASN1ObjectIdentifier>> SYM_TO_OID = new WeakHashMap<Ruby, Map<String, ASN1ObjectIdentifier>>(8);
    private static Map<Ruby, Map<ASN1ObjectIdentifier, String>> OID_TO_SYM = new WeakHashMap<Ruby, Map<ASN1ObjectIdentifier, String>>(8);
    private static Map<Ruby, Map<ASN1ObjectIdentifier, Integer>> OID_TO_NID = new WeakHashMap<Ruby, Map<ASN1ObjectIdentifier, Integer>>(8);
    private static Map<Ruby, Map<Integer, ASN1ObjectIdentifier>> NID_TO_OID = new WeakHashMap<Ruby, Map<Integer, ASN1ObjectIdentifier>>(8);
    private static Map<Ruby, Map<Integer, String>> NID_TO_SN = new WeakHashMap<Ruby, Map<Integer, String>>(8);
    private static Map<Ruby, Map<Integer, String>> NID_TO_LN = new WeakHashMap<Ruby, Map<Integer, String>>(8);

    @SuppressWarnings("unchecked")
    private static synchronized void initMaps(final Ruby runtime) {
        final int size = 200; final float fact = 1.0f;

        SYM_TO_OID.put(runtime, new HashMap<String, ASN1ObjectIdentifier>(size, fact));
        OID_TO_SYM.put(runtime, new HashMap<ASN1ObjectIdentifier, String>(size, fact));
        OID_TO_NID.put(runtime, new HashMap<ASN1ObjectIdentifier, Integer>(size, fact));
        NID_TO_OID.put(runtime, new HashMap<Integer, ASN1ObjectIdentifier>(size, fact));
        NID_TO_SN.put(runtime, new HashMap<Integer, String>(size, fact));
        NID_TO_LN.put(runtime, new HashMap<Integer, String>(size, fact));

        defaultObjects(runtime);
    }

    private static void defaultObjects(final Ruby runtime) {
        addObject(runtime, 0, null, null,"1.2.840.113549.1.12.1");
        addObject(runtime, 1, null, "rsadsi","1.2.840.113549");
        addObject(runtime, 2, null, "pkcs","1.2.840.113549.1");
        addObject(runtime, 3, "MD2", "md2","1.2.840.113549.2.2");
        addObject(runtime, 4, "MD5", "md5","1.2.840.113549.2.5");
        addObject(runtime, 5, "RC4", "rc4","1.2.840.113549.3.4");
        addObject(runtime, 6, null, "rsaEncryption","1.2.840.113549.1.1.1");
        addObject(runtime, 7, "RSA-MD2", "md2WithRSAEncryption","1.2.840.113549.1.1.2");
        addObject(runtime, 8, "RSA-MD5", "md5WithRSAEncryption","1.2.840.113549.1.1.4");
        addObject(runtime, 9, "PBE-MD2-DES", "pbeWithMD2AndDES-CBC","1.2.840.113549.1.5.1");
        addObject(runtime, 10, "PBE-MD5-DES", "pbeWithMD5AndDES-CBC","1.2.840.113549.1.5.3");
        addObject(runtime, 11, null, "X500","2.5");
        addObject(runtime, 12, null, "X509","2.5.4");
        addObject(runtime, 13, "CN", "commonName","2.5.4.3");
        addObject(runtime, 14, "C", "countryName","2.5.4.6");
        addObject(runtime, 15, "L", "localityName","2.5.4.7");
        addObject(runtime, 16, "ST", "stateOrProvinceName","2.5.4.8");
        addObject(runtime, 17, "O", "organizationName","2.5.4.10");
        addObject(runtime, 18, "OU", "organizationalUnitName","2.5.4.11");
        addObject(runtime, 19, "RSA", "rsa","2.5.8.1.1");
        addObject(runtime, 20, null, "pkcs7","1.2.840.113549.1.7");
        addObject(runtime, 21, null, "pkcs7-data","1.2.840.113549.1.7.1");
        addObject(runtime, 22, null, "pkcs7-signedData","1.2.840.113549.1.7.2");
        addObject(runtime, 23, null, "pkcs7-envelopedData","1.2.840.113549.1.7.3");
        addObject(runtime, 24, null, "pkcs7-signedAndEnvelopedData","1.2.840.113549.1.7.4");
        addObject(runtime, 25, null, "pkcs7-digestData","1.2.840.113549.1.7.5");
        addObject(runtime, 26, null, "pkcs7-encryptedData","1.2.840.113549.1.7.6");
        addObject(runtime, 27, null, "pkcs3","1.2.840.113549.1.3");
        addObject(runtime, 28, null, "dhKeyAgreement","1.2.840.113549.1.3.1");
        addObject(runtime, 29, "DES-ECB", "des-ecb","1.3.14.3.2.6");
        addObject(runtime, 30, "DES-CFB", "des-cfb","1.3.14.3.2.9");
        addObject(runtime, 31, "DES-CBC", "des-cbc","1.3.14.3.2.7");
        addObject(runtime, 32, "DES-EDE", "des-ede","1.3.14.3.2.17");
        addObject(runtime, 33, "DES-EDE3", "des-ede3",null);
        addObject(runtime, 34, "IDEA-CBC", "idea-cbc","1.3.6.1.4.1.188.7.1.1.2");
        addObject(runtime, 35, "IDEA-CFB", "idea-cfb",null);
        addObject(runtime, 36, "IDEA-ECB", "idea-ecb",null);
        addObject(runtime, 37, "RC2-CBC", "rc2-cbc","1.2.840.113549.3.2");
        addObject(runtime, 38, "RC2-ECB", "rc2-ecb",null);
        addObject(runtime, 39, "RC2-CFB", "rc2-cfb",null);
        addObject(runtime, 40, "RC2-OFB", "rc2-ofb",null);
        addObject(runtime, 41, "SHA", "sha","1.3.14.3.2.18");
        addObject(runtime, 42, "RSA-SHA", "shaWithRSAEncryption","1.3.14.3.2.15");
        addObject(runtime, 43, "DES-EDE-CBC", "des-ede-cbc",null);
        addObject(runtime, 44, "DES-EDE3-CBC", "des-ede3-cbc","1.2.840.113549.3.7");
        addObject(runtime, 45, "DES-OFB", "des-ofb","1.3.14.3.2.8");
        addObject(runtime, 46, "IDEA-OFB", "idea-ofb",null);
        addObject(runtime, 47, null, "pkcs9","1.2.840.113549.1.9");
        addObject(runtime, 48, null, "emailAddress","1.2.840.113549.1.9.1");
        addObject(runtime, 49, null, "unstructuredName","1.2.840.113549.1.9.2");
        addObject(runtime, 50, null, "contentType","1.2.840.113549.1.9.3");
        addObject(runtime, 51, null, "messageDigest","1.2.840.113549.1.9.4");
        addObject(runtime, 52, null, "signingTime","1.2.840.113549.1.9.5");
        addObject(runtime, 53, null, "countersignature","1.2.840.113549.1.9.6");
        addObject(runtime, 54, null, "challengePassword","1.2.840.113549.1.9.7");
        addObject(runtime, 55, null, "unstructuredAddress","1.2.840.113549.1.9.8");
        addObject(runtime, 56, null, "extendedCertificateAttributes","1.2.840.113549.1.9.9");
        addObject(runtime, 57, "Netscape", "Netscape Communications Corp.","2.16.840.1.113730");
        addObject(runtime, 58, "nsCertExt", "Netscape Certificate Extension","2.16.840.1.113730.1");
        addObject(runtime, 59, "nsDataType", "Netscape Data Type","2.16.840.1.113730.2");
        addObject(runtime, 60, "DES-EDE-CFB", "des-ede-cfb",null);
        addObject(runtime, 61, "DES-EDE3-CFB", "des-ede3-cfb",null);
        addObject(runtime, 62, "DES-EDE-OFB", "des-ede-ofb",null);
        addObject(runtime, 63, "DES-EDE3-OFB", "des-ede3-ofb",null);
        addObject(runtime, 64, "SHA1", "sha1","1.3.14.3.2.26");
        addObject(runtime, 65, "RSA-SHA1", "sha1WithRSAEncryption","1.2.840.113549.1.1.5");
        addObject(runtime, 66, "DSA-SHA", "dsaWithSHA","1.3.14.3.2.13");
        addObject(runtime, 67, "DSA-old", "dsaEncryption-old","1.3.14.3.2.12");
        addObject(runtime, 68, "PBE-SHA1-RC2-64", "pbeWithSHA1AndRC2-CBC","1.2.840.113549.1.5.11");
        addObject(runtime, 69, null, "PBKDF2","1.2.840.113549.1.5.12");
        addObject(runtime, 70, "DSA-SHA1-old", "dsaWithSHA1-old","1.3.14.3.2.27");
        addObject(runtime, 71, "nsCertType", "Netscape Cert Type","2.16.840.1.113730.1.1");
        addObject(runtime, 72, "nsBaseUrl", "Netscape Base Url","2.16.840.1.113730.1.2");
        addObject(runtime, 73, "nsRevocationUrl", "Netscape Revocation Url","2.16.840.1.113730.1.3");
        addObject(runtime, 74, "nsCaRevocationUrl", "Netscape CA Revocation Url","2.16.840.1.113730.1.4");
        addObject(runtime, 75, "nsRenewalUrl", "Netscape Renewal Url","2.16.840.1.113730.1.7");
        addObject(runtime, 76, "nsCaPolicyUrl", "Netscape CA Policy Url","2.16.840.1.113730.1.8");
        addObject(runtime, 77, "nsSslServerName", "Netscape SSL Server Name","2.16.840.1.113730.1.12");
        addObject(runtime, 78, "nsComment", "Netscape Comment","2.16.840.1.113730.1.13");
        addObject(runtime, 79, "nsCertSequence", "Netscape Certificate Sequence","2.16.840.1.113730.2.5");
        addObject(runtime, 80, "DESX-CBC", "desx-cbc",null);
        addObject(runtime, 81, "id-ce", null,"2.5.29");
        addObject(runtime, 82, "subjectKeyIdentifier", "X509v3 Subject Key Identifier","2.5.29.14");
        addObject(runtime, 83, "keyUsage", "X509v3 Key Usage","2.5.29.15");
        addObject(runtime, 84, "privateKeyUsagePeriod", "X509v3 Private Key Usage Period","2.5.29.16");
        addObject(runtime, 85, "subjectAltName", "X509v3 Subject Alternative Name","2.5.29.17");
        addObject(runtime, 86, "issuerAltName", "X509v3 Issuer Alternative Name","2.5.29.18");
        addObject(runtime, 87, "basicConstraints", "X509v3 Basic Constraints","2.5.29.19");
        addObject(runtime, 88, "crlNumber", "X509v3 CRL Number","2.5.29.20");
        addObject(runtime, 89, "certificatePolicies", "X509v3 Certificate Policies","2.5.29.32");
        addObject(runtime, 90, "authorityKeyIdentifier", "X509v3 Authority Key Identifier","2.5.29.35");
        addObject(runtime, 91, "BF-CBC", "bf-cbc","1.3.6.1.4.1.3029.1.2");
        addObject(runtime, 92, "BF-ECB", "bf-ecb",null);
        addObject(runtime, 93, "BF-CFB", "bf-cfb",null);
        addObject(runtime, 94, "BF-OFB", "bf-ofb",null);
        addObject(runtime, 95, "MDC2", "mdc2","2.5.8.3.101");
        addObject(runtime, 96, "RSA-MDC2", "mdc2withRSA","2.5.8.3.100");
        addObject(runtime, 97, "RC4-40", "rc4-40",null);
        addObject(runtime, 98, "RC2-40-CBC", "rc2-40-cbc",null);
        addObject(runtime, 99, "G", "givenName","2.5.4.42");
        addObject(runtime, 100, "S", "surname","2.5.4.4");
        addObject(runtime, 101, "I", "initials","2.5.4.43");
        addObject(runtime, 102, "UID", "uniqueIdentifier","2.5.4.45"); // BC prefers UID to map to userId ?!
        addObject(runtime, 103, "crlDistributionPoints", "X509v3 CRL Distribution Points","2.5.29.31");
        addObject(runtime, 104, "RSA-NP-MD5", "md5WithRSA","1.3.14.3.2.3");
        addObject(runtime, 105, null, "serialNumber","2.5.4.5");
        addObject(runtime, 106, "T", "title","2.5.4.12");
        addObject(runtime, 107, "D", "description","2.5.4.13");
        addObject(runtime, 108, "CAST5-CBC", "cast5-cbc","1.2.840.113533.7.66.10");
        addObject(runtime, 109, "CAST5-ECB", "cast5-ecb",null);
        addObject(runtime, 110, "CAST5-CFB", "cast5-cfb",null);
        addObject(runtime, 111, "CAST5-OFB", "cast5-ofb",null);
        addObject(runtime, 112, null, "pbeWithMD5AndCast5CBC","1.2.840.113533.7.66.12");
        addObject(runtime, 113, "DSA-SHA1", "dsaWithSHA1","1.2.840.10040.4.3");
        addObject(runtime, 114, "MD5-SHA1", "md5-sha1",null);
        addObject(runtime, 115, "RSA-SHA1-2", "sha1WithRSA","1.3.14.3.2.29");
        addObject(runtime, 116, "DSA", "dsaEncryption","1.2.840.10040.4.1");
        addObject(runtime, 117, "RIPEMD160", "ripemd160","1.3.36.3.2.1");
        addObject(runtime, 118, "RSA-RIPEMD160", "ripemd160WithRSA","1.3.36.3.3.1.2");
        addObject(runtime, 119, "RC5-CBC", "rc5-cbc","1.2.840.113549.3.8");
        addObject(runtime, 120, "RC5-ECB", "rc5-ecb",null);
        addObject(runtime, 121, "RC5-CFB", "rc5-cfb",null);
        addObject(runtime, 122, "RC5-OFB", "rc5-ofb",null);
        addObject(runtime, 123, "RLE", "run length compression","1.1.1.1.666.1");
        addObject(runtime, 124, "ZLIB", "zlib compression","1.1.1.1.666.2");
        addObject(runtime, 125, "extendedKeyUsage", "X509v3 Extended Key Usage","2.5.29.37");
        addObject(runtime, 126, "PKIX", null,"1.3.6.1.5.5.7");
        addObject(runtime, 127, "id-kp", null,"1.3.6.1.5.5.7.3");
        addObject(runtime, 128, "serverAuth", "TLS Web Server Authentication","1.3.6.1.5.5.7.3.1");
        addObject(runtime, 129, "clientAuth", "TLS Web Client Authentication","1.3.6.1.5.5.7.3.2");
        addObject(runtime, 130, "codeSigning", "Code Signing","1.3.6.1.5.5.7.3.3");
        addObject(runtime, 131, "emailProtection", "E-mail Protection","1.3.6.1.5.5.7.3.4");
        addObject(runtime, 132, "timeStamping", "Time Stamping","1.3.6.1.5.5.7.3.8");
        addObject(runtime, 133, "msCodeInd", "Microsoft Individual Code Signing","1.3.6.1.4.1.311.2.1.21");
        addObject(runtime, 134, "msCodeCom", "Microsoft Commercial Code Signing","1.3.6.1.4.1.311.2.1.22");
        addObject(runtime, 135, "msCTLSign", "Microsoft Trust List Signing","1.3.6.1.4.1.311.10.3.1");
        addObject(runtime, 136, "msSGC", "Microsoft Server Gated Crypto","1.3.6.1.4.1.311.10.3.3");
        addObject(runtime, 137, "msEFS", "Microsoft Encrypted File System","1.3.6.1.4.1.311.10.3.4");
        addObject(runtime, 138, "nsSGC", "Netscape Server Gated Crypto","2.16.840.1.113730.4.1");
        addObject(runtime, 139, "deltaCRL", "X509v3 Delta CRL Indicator","2.5.29.27");
        addObject(runtime, 140, "CRLReason", "CRL Reason Code","2.5.29.21");
        addObject(runtime, 141, "invalidityDate", "Invalidity Date","2.5.29.24");
        addObject(runtime, 142, "SXNetID", "Strong Extranet ID","1.3.101.1.4.1");
        addObject(runtime, 143, "PBE-SHA1-RC4-128", "pbeWithSHA1And128BitRC4","1.2.840.113549.1.12.1.1");
        addObject(runtime, 144, "PBE-SHA1-RC4-40", "pbeWithSHA1And40BitRC4","1.2.840.113549.1.12.1.2");
        addObject(runtime, 145, "PBE-SHA1-3DES", "pbeWithSHA1And3-KeyTripleDES-CBC","1.2.840.113549.1.12.1.3");
        addObject(runtime, 146, "PBE-SHA1-2DES", "pbeWithSHA1And2-KeyTripleDES-CBC","1.2.840.113549.1.12.1.4");
        addObject(runtime, 147, "PBE-SHA1-RC2-128", "pbeWithSHA1And128BitRC2-CBC","1.2.840.113549.1.12.1.5");
        addObject(runtime, 148, "PBE-SHA1-RC2-40", "pbeWithSHA1And40BitRC2-CBC","1.2.840.113549.1.12.1.6");
        addObject(runtime, 149, null, "keyBag","1.2.840.113549.1.12.10.1.1");
        addObject(runtime, 150, null, "pkcs8ShroudedKeyBag","1.2.840.113549.1.12.10.1.2");
        addObject(runtime, 151, null, "certBag","1.2.840.113549.1.12.10.1.3");
        addObject(runtime, 152, null, "crlBag","1.2.840.113549.1.12.10.1.4");
        addObject(runtime, 153, null, "secretBag","1.2.840.113549.1.12.10.1.5");
        addObject(runtime, 154, null, "safeContentsBag","1.2.840.113549.1.12.10.1.6");
        addObject(runtime, 155, null, "PBES2","1.2.840.113549.1.5.13");
        addObject(runtime, 156, null, "PBMAC1","1.2.840.113549.1.5.14");
        addObject(runtime, 157, null, "hmacWithSHA1","1.2.840.113549.2.7");
        addObject(runtime, 158, "id-qt-cps", "Policy Qualifier CPS","1.3.6.1.5.5.7.2.1");
        addObject(runtime, 159, "id-qt-unotice", "Policy Qualifier User Notice","1.3.6.1.5.5.7.2.2");
        addObject(runtime, 160, "RC2-64-CBC", "rc2-64-cbc",null);
        addObject(runtime, 161, "SMIME-CAPS", "S/MIME Capabilities","1.2.840.113549.1.9.15");
        addObject(runtime, 162, "PBE-MD2-RC2-64", "pbeWithMD2AndRC2-CBC","1.2.840.113549.1.5.4");
        addObject(runtime, 163, "PBE-MD5-RC2-64", "pbeWithMD5AndRC2-CBC","1.2.840.113549.1.5.6");
        addObject(runtime, 164, "PBE-SHA1-DES", "pbeWithSHA1AndDES-CBC","1.2.840.113549.1.5.10");
        addObject(runtime, 165, "msExtReq", "Microsoft Extension Request","1.3.6.1.4.1.311.2.1.14");
        addObject(runtime, 166, "extReq", "Extension Request","1.2.840.113549.1.9.14");
        addObject(runtime, 167, "name", "name","2.5.4.41");
        addObject(runtime, 168, "dnQualifier", "dnQualifier","2.5.4.46");
        addObject(runtime, 169, "id-pe", null,"1.3.6.1.5.5.7.1");
        addObject(runtime, 170, "id-ad", null,"1.3.6.1.5.5.7.48");
        addObject(runtime, 171, "authorityInfoAccess", "Authority Information Access","1.3.6.1.5.5.7.1.1");
        addObject(runtime, 172, "OCSP", "OCSP","1.3.6.1.5.5.7.48.1");
        addObject(runtime, 173, "caIssuers", "CA Issuers","1.3.6.1.5.5.7.48.2");
        addObject(runtime, 174, "OCSPSigning", "OCSP Signing","1.3.6.1.5.5.7.3.9");
        addObject(runtime, 175, "AES-128-EBC", "aes-128-ebc","2.16.840.1.101.3.4.1.1");
        addObject(runtime, 176, "AES-128-CBC", "aes-128-cbc","2.16.840.1.101.3.4.1.2");
        addObject(runtime, 177, "AES-128-OFB", "aes-128-ofb","2.16.840.1.101.3.4.1.3");
        addObject(runtime, 178, "AES-128-CFB", "aes-128-cfb","2.16.840.1.101.3.4.1.4");
        addObject(runtime, 179, "AES-192-EBC", "aes-192-ebc","2.16.840.1.101.3.4.1.21");
        addObject(runtime, 180, "AES-192-CBC", "aes-192-cbc","2.16.840.1.101.3.4.1.22");
        addObject(runtime, 181, "AES-192-OFB", "aes-192-ofb","2.16.840.1.101.3.4.1.23");
        addObject(runtime, 182, "AES-192-CFB", "aes-192-cfb","2.16.840.1.101.3.4.1.24");
        addObject(runtime, 183, "AES-256-EBC", "aes-256-ebc","2.16.840.1.101.3.4.1.41");
        addObject(runtime, 184, "AES-256-CBC", "aes-256-cbc","2.16.840.1.101.3.4.1.42");
        addObject(runtime, 185, "AES-256-OFB", "aes-256-ofb","2.16.840.1.101.3.4.1.43");
        addObject(runtime, 186, "AES-256-CFB", "aes-256-cfb","2.16.840.1.101.3.4.1.44");
        addObject(runtime, 672, "SHA256", "sha256", "2.16.840.1.101.3.4.2.1");

        addObject(runtime, 660, "street", "streetAddress", "2.5.4.9");
        addObject(runtime, 391, "DC", "domainComponent", "0.9.2342.19200300.100.1.25");
        //addObject(runtime, 509, null, "generationQualifier", "2.5.4.44");
        //addObject(runtime, 510, null, "pseudonym", "2.5.4.65");
        //addObject(runtime, 661, null, "postalCode", "2.5.4.17");
        //addObject(runtime, 861, null, "postalAddress", "2.5.4.16");

        // NOTE: left-overs from BC's org.bouncycastle.asn1.x509.X509Name
        /*
            DefaultLookUp.put("uid", UID);

            DefaultLookUp.put("dn", DN_QUALIFIER);

            DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
            DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
            DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);gen
            DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
            DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
            DefaultLookUp.put("gender", GENDER);
            DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
            DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        */
    }

    private static void addObject(final Ruby runtime, final int nid,
        final String sn, final String ln, final String oid) {
        if ( oid != null && ( sn != null || ln != null ) ) {

            ASN1ObjectIdentifier objectId = new ASN1ObjectIdentifier(oid);

            if ( sn != null ) {
                symToOid(runtime).put(sn.toLowerCase(), objectId);
            }
            if ( ln != null ) {
                symToOid(runtime).put(ln.toLowerCase(), objectId);
            }

            oidToSym(runtime).put(objectId, sn == null ? ln : sn);
            oidToNid(runtime).put(objectId, nid);
            nidToOid(runtime).put(nid, objectId);
            nidToSn(runtime).put(nid, sn);
            nidToLn(runtime).put(nid, ln);
        }
    }

    private static Map<String, ASN1ObjectIdentifier> symToOid(final Ruby runtime) {
        Map<String, ASN1ObjectIdentifier> map = SYM_TO_OID.get(runtime);
        if ( map == null ) {
            synchronized(ASN1.class) {
                map = SYM_TO_OID.get(runtime);
                if ( map == null ) {
                    initMaps(runtime);
                    map = SYM_TO_OID.get(runtime);
                }
            }
        }
        return map;
    }

    private static Map<ASN1ObjectIdentifier, String> oidToSym(final Ruby runtime) {
        Map<ASN1ObjectIdentifier, String> map = OID_TO_SYM.get(runtime);
        if ( map == null ) {
            synchronized(ASN1.class) {
                map = OID_TO_SYM.get(runtime);
                if ( map == null ) {
                    initMaps(runtime);
                    map = OID_TO_SYM.get(runtime);
                }
            }
        }
        return map;
    }

    private static Map<Integer, ASN1ObjectIdentifier> nidToOid(final Ruby runtime) {
        Map<Integer, ASN1ObjectIdentifier> map = NID_TO_OID.get(runtime);
        if ( map == null ) {
            synchronized(ASN1.class) {
                map = NID_TO_OID.get(runtime);
                if ( map == null ) {
                    initMaps(runtime);
                    map = NID_TO_OID.get(runtime);
                }
            }
        }
        return map;
    }

    private static Map<ASN1ObjectIdentifier, Integer> oidToNid(final Ruby runtime) {
        Map<ASN1ObjectIdentifier, Integer> map = OID_TO_NID.get(runtime);
        if ( map == null ) {
            synchronized(ASN1.class) {
                map = OID_TO_NID.get(runtime);
                if ( map == null ) {
                    initMaps(runtime);
                    map = OID_TO_NID.get(runtime);
                }
            }
        }
        return map;
    }

    private static Map<Integer, String> nidToSn(final Ruby runtime) {
        Map<Integer, String> map = NID_TO_SN.get(runtime);
        if ( map == null ) {
            synchronized(ASN1.class) {
                map = NID_TO_SN.get(runtime);
                if ( map == null ) {
                    initMaps(runtime);
                    map = NID_TO_SN.get(runtime);
                }
            }
        }
        return map;
    }

    private static Map<Integer, String> nidToLn(final Ruby runtime) {
        Map<Integer, String> map = NID_TO_LN.get(runtime);
        if ( map == null ) {
            synchronized(ASN1.class) {
                map = NID_TO_LN.get(runtime);
                if ( map == null ) {
                    initMaps(runtime);
                    map = NID_TO_LN.get(runtime);
                }
            }
        }
        return map;
    }

    static String ln2oid(final Ruby runtime, final String ln) {
        Map<String, ASN1ObjectIdentifier> map = symToOid(runtime);
        final ASN1ObjectIdentifier val = map.get(ln);
        if ( val == null ) {
            throw new NullPointerException("oid not found for ln = '" + ln + "' (" + runtime + ")");
        }
        return val.getId();
    }

    static Integer oid2nid(final Ruby runtime, final ASN1ObjectIdentifier oid) {
        return oidToNid(runtime).get(oid);
    }

    static String o2a(final Ruby runtime, final ASN1ObjectIdentifier oid) {
        return o2a(runtime, oid, false);
    }

    static String o2a(final Ruby runtime, final ASN1ObjectIdentifier oid, final boolean silent) {
        Integer nid = oidToNid(runtime).get(oid);
        if ( nid != null ) {
            final String name = nid2ln(runtime, nid, false);
            return name == null ? nid2sn(runtime, nid, false) : name;
        }
        nid = ASN1Registry.oid2nid(oid);
        if ( nid == null ) {
            if ( silent ) return null;
            throw new NullPointerException("nid not found for oid = '" + oid + "' (" + runtime + ")");
        }
        final String name = nid2ln(runtime, nid, false);
        if ( name != null ) return name;
        return nid2sn(runtime, nid, true);
    }

    static String oid2name(final Ruby runtime, final ASN1ObjectIdentifier oid, final boolean silent) {
        Integer nid = oidToNid(runtime).get(oid);
        if ( nid != null ) {
            final String name = nid2sn(runtime, nid, false);
            return name == null ? nid2ln(runtime, nid, false) : name;
        }
        nid = ASN1Registry.oid2nid(oid);
        if ( nid == null ) {
            if ( silent ) return null;
            throw new NullPointerException("nid not found for oid = '" + oid + "' (" + runtime + ")");
        }
        final String name = nid2sn(runtime, nid, false);
        if ( name != null ) return name;
        return nid2ln(runtime, nid, true);
        /*
        if ( nid == null ) nid = ASN1Registry.oid2nid(oid);
        if ( nid == null ) {
            if ( silent ) return null;
            throw new NullPointerException("nid not found for oid = '" + oid + "' (" + runtime + ")");
        }
        final String name = nid2sn(runtime, nid, true);
        if ( name != null ) return name;
        return nid2ln(runtime, nid, true); */
    }


    static String oid2name(final Ruby runtime, final String oid) {
        return oid2name(runtime, new ASN1ObjectIdentifier(oid), false);
    }

    static String nid2sn(final Ruby runtime, final Integer nid) {
        return nid2sn(runtime, nid, true);
    }

    private static String nid2sn(final Ruby runtime, final Integer nid, boolean fallback) {
        final String ln = nidToSn(runtime).get(nid);
        if ( ln == null && fallback ) return ASN1Registry.nid2sn(nid);
        return ln;
    }

    static String nid2ln(final Ruby runtime, final Integer nid) {
        return nid2ln(runtime, nid, true);
    }

    private static String nid2ln(final Ruby runtime, final Integer nid, boolean fallback) {
        final String ln = nidToLn(runtime).get(nid);
        if ( ln == null && fallback ) return ASN1Registry.nid2ln(nid);
        return ln;
    }

    static String oid2Sym(final Ruby runtime, final ASN1ObjectIdentifier oid) {
        return oid2Sym(runtime, oid, false);
    }

    static String oid2Sym(final Ruby runtime, final ASN1ObjectIdentifier oid, final boolean fallback) {
        final String sym = getSymLookup(runtime).get(oid);
        return ( sym == null && fallback ) ? ASN1Registry.oid2sym(oid) : sym;
    }

    static ASN1ObjectIdentifier sym2Oid(final Ruby runtime, final String name) {
        return getOIDLookup(runtime).get(name);
    }

    private static Map<String, ASN1ObjectIdentifier> getOIDLookup(final Ruby runtime) {
        return symToOid(runtime);
    }

    private static Map<ASN1ObjectIdentifier, String> getSymLookup(final Ruby runtime) {
        return oidToSym(runtime);
    }

    private final static Object[][] ASN1_INFO = {
        { "EOC", null, "EndOfContent" }, // OpenSSL::ASN1::EOC (0)
        { "BOOLEAN", org.bouncycastle.asn1.ASN1Boolean.class, "Boolean" },
        { "INTEGER", org.bouncycastle.asn1.ASN1Integer.class, "Integer" },
        { "BIT_STRING", org.bouncycastle.asn1.DERBitString.class, "BitString" },
        { "OCTET_STRING", org.bouncycastle.asn1.DEROctetString.class, "OctetString" },
        { "NULL", org.bouncycastle.asn1.DERNull.class, "Null" },
        // OpenSSL::ASN1::OBJECT (6) :
        { "OBJECT", org.bouncycastle.asn1.ASN1ObjectIdentifier.class, "ObjectId" },
        { "OBJECT_DESCRIPTOR", null, null },
        { "EXTERNAL", null, null },
        { "REAL", null, null },
        // OpenSSL::ASN1::ENUMERATED (10) :
        { "ENUMERATED", org.bouncycastle.asn1.ASN1Enumerated.class, "Enumerated" },
        { "EMBEDDED_PDV", null, null },
        // OpenSSL::ASN1::UTF8STRING (12) :
        { "UTF8STRING", org.bouncycastle.asn1.DERUTF8String.class, "UTF8String" },
        { "RELATIVE_OID", null, null },
        { "[UNIVERSAL 14]", null, null },
        { "[UNIVERSAL 15]", null, null },
        // OpenSSL::ASN1::SEQUENCE (16) :
        // NOTE: org.bouncycastle.asn1.DERSequence does not have a getInstance
        //{ "SEQUENCE", org.bouncycastle.asn1.ASN1Sequence.class, "Sequence" },
        { "SEQUENCE", org.bouncycastle.asn1.DERSequence.class, "Sequence" },
        // OpenSSL::ASN1::SET (17) :
        // NOTE: org.bouncycastle.asn1.DERSet does not have a getInstance
        //{ "SET", org.bouncycastle.asn1.ASN1Set.class, "Set" },
        { "SET", org.bouncycastle.asn1.DERSet.class, "Set" },
        { "NUMERICSTRING", org.bouncycastle.asn1.DERNumericString.class, "NumericString" },
        { "PRINTABLESTRING", org.bouncycastle.asn1.DERPrintableString.class, "PrintableString" },
        { "T61STRING", org.bouncycastle.asn1.DERT61String.class, "T61String" },
        { "VIDEOTEXSTRING", org.bouncycastle.asn1.DERVideotexString.class, "VideotexString" },
        { "IA5STRING", org.bouncycastle.asn1.DERIA5String.class, "IA5String" },
        { "UTCTIME", org.bouncycastle.asn1.DERUTCTime.class, "UTCTime" },
        { "GENERALIZEDTIME", org.bouncycastle.asn1.DERGeneralizedTime.class, "GeneralizedTime" },
        { "GRAPHICSTRING", org.bouncycastle.asn1.DERGraphicString.class, "GraphicString" },
        { "ISO64STRING", org.bouncycastle.asn1.DERVisibleString.class, "ISO64String" },
        { "GENERALSTRING",  org.bouncycastle.asn1.DERGeneralString.class, "GeneralString" },
        // OpenSSL::ASN1::UNIVERSALSTRING (28) :
        { "UNIVERSALSTRING", org.bouncycastle.asn1.DERUniversalString.class, "UniversalString" },
        { "CHARACTER_STRING", null, null },
        // OpenSSL::ASN1::BMPSTRING (30) :
        { "BMPSTRING", org.bouncycastle.asn1.DERBMPString.class, "BMPString" }};

    final static int EOC = 0; // OpenSSL::ASN1::EOC (0)
    final static int BOOLEAN = 1; // OpenSSL::ASN1::BOOLEAN (1)
    final static int INTEGER = 2; //  OpenSSL::ASN1::INTEGER (2)
    final static int BIT_STRING = 3; // OpenSSL::ASN1::BIT_STRING (3)
    final static int OCTET_STRING = 4; // OpenSSL::ASN1::OCTET_STRING (4)
    final static int NULL = 5; // OpenSSL::ASN1::NULL (5)
    final static int OBJECT = 6; // OpenSSL::ASN1::OBJECT (6)
    final static int ENUMERATED = 10; //  OpenSSL::ASN1::ENUMERATED (10)
    final static int UTF8STRING = 12; // OpenSSL::ASN1::UTF8STRING (12)
    final static int SEQUENCE = 16; //  OpenSSL::ASN1::SEQUENCE (16)
    final static int SET = 17; // OpenSSL::ASN1::SET (17)
    final static int NUMERICSTRING = 18; //  OpenSSL::ASN1::NUMERICSTRING (18)
    final static int PRINTABLESTRING = 19; // OpenSSL::ASN1::PRINTABLESTRING (19)
    final static int T61STRING = 20; // OpenSSL::ASN1::T61STRING (20)
    final static int VIDEOTEXSTRING = 21; // OpenSSL::ASN1::VIDEOTEXSTRING (21)
    final static int IA5STRING = 22; // OpenSSL::ASN1::IA5STRING (22)
    final static int UTCTIME = 23; // OpenSSL::ASN1::UTCTIME (23)
    final static int GENERALIZEDTIME = 24; // OpenSSL::ASN1::GENERALIZEDTIME (24)
    final static int GRAPHICSTRING = 25; // OpenSSL::ASN1::GRAPHICSTRING (25)
    final static int ISO64STRING = 26; // OpenSSL::ASN1::ISO64STRING (26)
    final static int GENERALSTRING = 27; // OpenSSL::ASN1::GENERALSTRING (27)
    final static int UNIVERSALSTRING = 28; // OpenSSL::ASN1::UNIVERSALSTRING (28)
    final static int BMPSTRING = 30; // OpenSSL::ASN1::BMPSTRING (30)

    private final static Map<Class<?>, Integer> JCLASS_TO_ID = new HashMap<Class<?>, Integer>(24, 1);
    private final static Map<String, Integer> RCLASS_TO_ID = new HashMap<String, Integer>(28, 1);

    static {
        for ( int i = 0; i < ASN1_INFO.length; i++ ) {
            final Object[] info = ASN1_INFO[i];
            if ( info[1] != null ) {
                JCLASS_TO_ID.put((Class) info[1], Integer.valueOf(i));
            }
            if ( info[2] != null ) {
                RCLASS_TO_ID.put((String) info[2], Integer.valueOf(i));
            }

            switch (i) {
                case EOC: assert "EOC".equals(info[0]); break;
                case BOOLEAN: assert "BOOLEAN".equals(info[0]); break;
                case INTEGER: assert "INTEGER".equals(info[0]); break;
                case BIT_STRING: assert "BIT_STRING".equals(info[0]); break;
                case OCTET_STRING: assert "OCTET_STRING".equals(info[0]); break;
                case NULL: assert "NULL".equals(info[0]); break;
                case OBJECT: assert "OBJECT".equals(info[0]); break;
                case ENUMERATED: assert "ENUMERATED".equals(info[0]); break;
                case UTF8STRING: assert "UTF8STRING".equals(info[0]); break;
                case SEQUENCE: assert "SEQUENCE".equals(info[0]); break;
                case SET: assert "SET".equals(info[0]); break;
                case NUMERICSTRING: assert "NUMERICSTRING".equals(info[0]); break;
                case PRINTABLESTRING: assert "PRINTABLESTRING".equals(info[0]); break;
                case T61STRING: assert "T61STRING".equals(info[0]); break;
                case VIDEOTEXSTRING: assert "VIDEOTEXSTRING".equals(info[0]); break;
                case IA5STRING: assert "IA5STRING".equals(info[0]); break;
                case UTCTIME: assert "UTCTIME".equals(info[0]); break;
                case GENERALIZEDTIME: assert "GENERALIZEDTIME".equals(info[0]); break;
                case GRAPHICSTRING: assert "GRAPHICSTRING".equals(info[0]); break;
                case ISO64STRING: assert "ISO64STRING".equals(info[0]); break;
                case GENERALSTRING: assert "GENERALSTRING".equals(info[0]); break;
                case UNIVERSALSTRING: assert "UNIVERSALSTRING".equals(info[0]); break;
                case BMPSTRING: assert "BMPSTRING".equals(info[0]); break;
            }
        }
    }

    private static Integer typeId(Class<?> type) {
        Integer id = null;
        while ( type != Object.class && id == null ) {
            id = JCLASS_TO_ID.get(type);
            if ( id == null ) type = type.getSuperclass();
        }
        return id; //return v == null ? -1 : v.intValue();
    }

    static Integer typeId(final ASN1Encodable obj) {
        return typeId( obj.getClass() );
    }

    private static Integer typeId(final RubyClass metaClass) {
        final String name = metaClass.getRealClass().getBaseName();
        final Integer id = RCLASS_TO_ID.get(name);
        return id == null ? null : id;
    }

    @SuppressWarnings("unchecked")
    static Class<? extends ASN1Encodable> typeClass(final RubyClass metaClass) {
        final Integer tag = typeId( metaClass );
        if ( tag == null ) return null;
        return (Class<? extends ASN1Encodable>) ASN1_INFO[tag][1];
    }

    @SuppressWarnings("unchecked")
    static Class<? extends ASN1Encodable> typeClass(final int typeId) {
        return (Class<? extends ASN1Encodable>) ASN1_INFO[typeId][1];
    }

    static Class<? extends ASN1Encodable> typeClassSafe(final int typeId) {
        if (typeId >= ASN1_INFO.length || typeId < 0) return null;
        return typeClass(typeId);
    }

    public static void createASN1(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule ASN1 = OpenSSL.defineModuleUnder("ASN1");
        ASN1.defineClassUnder("ASN1Error", OpenSSLError, OpenSSLError.getAllocator());

        ASN1.defineAnnotatedMethods(ASN1.class);

        final RubyArray UNIVERSAL_TAG_NAME = runtime.newArray(ASN1_INFO.length);
        for ( int i = 0; i < ASN1_INFO.length; i++ ) {
            final String name = (String) ASN1_INFO[i][0];
            if ( name.charAt(0) != '[' ) {
                UNIVERSAL_TAG_NAME.append( runtime.newString(name) );
                ASN1.setConstant( name, runtime.newFixnum(i) );
            } else {
                UNIVERSAL_TAG_NAME.append( runtime.getNil() );
            }
        }
        ASN1.setConstant("UNIVERSAL_TAG_NAME", UNIVERSAL_TAG_NAME);

        final ThreadContext context = runtime.getCurrentContext();

        final ObjectAllocator asn1DataAllocator = ASN1Data.ALLOCATOR;
        RubyClass _ASN1Data = ASN1.defineClassUnder("ASN1Data", runtime.getObject(), asn1DataAllocator);
        _ASN1Data.addReadWriteAttribute(context, "value");
        _ASN1Data.addReadWriteAttribute(context, "tag");
        _ASN1Data.addReadWriteAttribute(context, "tag_class");
        _ASN1Data.addReadWriteAttribute(context, "indefinite_length");
        _ASN1Data.defineAlias( "infinite_length", "indefinite_length");
        _ASN1Data.defineAlias( "infinite_length=", "indefinite_length=");
        _ASN1Data.defineAnnotatedMethods(ASN1Data.class);

        final ObjectAllocator primitiveAllocator = Primitive.ALLOCATOR;
        RubyClass Primitive = ASN1.defineClassUnder("Primitive", _ASN1Data, primitiveAllocator);
        Primitive.addReadWriteAttribute(context, "tagging");
        Primitive.undefineMethod("infinite_length=");
        Primitive.undefineMethod("indefinite_length=");
        Primitive.defineAnnotatedMethods(Primitive.class);

        final ObjectAllocator constructiveAllocator = Constructive.ALLOCATOR;
        RubyClass Constructive = ASN1.defineClassUnder("Constructive", _ASN1Data, constructiveAllocator);
        Constructive.includeModule( runtime.getModule("Enumerable") );
        Constructive.addReadWriteAttribute(context, "tagging");
        Constructive.defineAnnotatedMethods(Constructive.class);

        final ObjectAllocator eocAllocator = EndOfContent.ALLOCATOR;
        RubyClass EndOfContent = ASN1.defineClassUnder("EndOfContent", _ASN1Data, eocAllocator);
        EndOfContent.defineAnnotatedMethods(EndOfContent.class);

        ASN1.defineClassUnder("Boolean", Primitive, primitiveAllocator); // OpenSSL::ASN1::Boolean <=> value is a Boolean
        ASN1.defineClassUnder("Integer", Primitive, primitiveAllocator); // OpenSSL::ASN1::Integer <=> value is a Number
        ASN1.defineClassUnder("Null", Primitive, primitiveAllocator); // OpenSSL::ASN1::Null <=> value is always nil
        ASN1.defineClassUnder("Object", Primitive, primitiveAllocator); // OpenSSL::ASN1::Object <=> value is a String
        ASN1.defineClassUnder("Enumerated", Primitive, primitiveAllocator); // OpenSSL::ASN1::Enumerated <=> value is a Number

        RubyClass BitString = ASN1.defineClassUnder("BitString", Primitive, primitiveAllocator);
        BitString.addReadWriteAttribute(context, "unused_bits");
        ASN1.defineClassUnder("OctetString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("UTF8String", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("NumericString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("PrintableString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("T61String", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("VideotexString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("IA5String", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("GraphicString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("ISO64String", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("GeneralString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("UniversalString", Primitive, primitiveAllocator);
        ASN1.defineClassUnder("BMPString", Primitive, primitiveAllocator);

        ASN1.defineClassUnder("UTCTime", Primitive, primitiveAllocator); // OpenSSL::ASN1::UTCTime <=> value is a Time
        ASN1.defineClassUnder("GeneralizedTime", Primitive, primitiveAllocator); // OpenSSL::ASN1::GeneralizedTime <=> value is a Time

        ASN1.defineClassUnder("ObjectId", Primitive, primitiveAllocator).
                defineAnnotatedMethods(ObjectId.class);

        ASN1.defineClassUnder("Sequence", Constructive, Constructive.getAllocator());
        ASN1.defineClassUnder("Set", Constructive, Constructive.getAllocator());
    }

    static ASN1ObjectIdentifier getObjectID(final Ruby runtime, final String nameOrOid)
        throws IllegalArgumentException {
        final String name = nameOrOid.toLowerCase();

        ASN1ObjectIdentifier objectId = getOIDLookup(runtime).get( name );
        if ( objectId != null ) return objectId;

        final String objectIdStr = ASN1Registry.getOIDLookup().get( name );
        if ( objectIdStr != null ) return toObjectID(objectIdStr, false);

        return new ASN1ObjectIdentifier( nameOrOid );
    }

    static ASN1ObjectIdentifier toObjectID(final String oid, final boolean silent)
        throws IllegalArgumentException {
        try {
            return new ASN1ObjectIdentifier(oid);
        }
        catch (IllegalArgumentException e) {
            if ( silent ) return null;
            throw e;
        }
    }

    @JRubyMethod(name="Boolean", module=true, rest=true)
    public static IRubyObject fact_Boolean(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "Boolean", args);
    }

    @JRubyMethod(name="Integer", module=true, rest=true)
    public static IRubyObject fact_Integer(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "Integer", args);
    }

    @JRubyMethod(name="Enumerated", module=true, rest=true)
    public static IRubyObject fact_Enumerated(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "Enumerated", args);
    }

    @JRubyMethod(name="BitString", module=true, rest=true)
    public static IRubyObject fact_BitString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "BitString", args);
    }

    @JRubyMethod(name="OctetString", module=true, rest=true)
    public static IRubyObject fact_OctetString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "OctetString", args);
    }

    @JRubyMethod(name="UTF8String", module=true, rest=true)
    public static IRubyObject fact_UTF8String(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "UTF8String", args);
    }

    @JRubyMethod(name="NumericString", module=true, rest=true)
    public static IRubyObject fact_NumericString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "NumericString", args);
    }

    @JRubyMethod(name="PrintableString", module=true, rest=true)
    public static IRubyObject fact_PrintableString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "PrintableString", args);
    }

    @JRubyMethod(name="T61String", module=true, rest=true)
    public static IRubyObject fact_T61String(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "T61String", args);
    }

    @JRubyMethod(name="VideotexString", module=true, rest=true)
    public static IRubyObject fact_VideotexString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "VideotexString", args);
    }

    @JRubyMethod(name="IA5String", module=true, rest=true)
    public static IRubyObject fact_IA5String(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "IA5String", args);
    }

    @JRubyMethod(name="GraphicString", module=true, rest=true)
    public static IRubyObject fact_GraphicString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "GraphicString", args);
    }

    @JRubyMethod(name="ISO64String", module=true, rest=true)
    public static IRubyObject fact_ISO64String(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "ISO64String", args);
    }

    @JRubyMethod(name="GeneralString", module=true, rest=true)
    public static IRubyObject fact_GeneralString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "GeneralString", args);
    }

    @JRubyMethod(name="UniversalString", module=true, rest=true)
    public static IRubyObject fact_UniversalString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "UniversalString", args);
    }

    @JRubyMethod(name="BMPString", module=true, rest=true)
    public static IRubyObject fact_BMPString(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "BMPString", args);
    }

    @JRubyMethod(name={"Null", "Nul"}, module=true, rest=true) // TODO Nul name should be dropped
    public static IRubyObject fact_Null(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "Null", args);
    }

    @JRubyMethod(name="ObjectId", module=true, rest=true)
    public static IRubyObject fact_ObjectId(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "ObjectId", args);
    }

    @JRubyMethod(name="UTCTime", module=true, rest=true)
    public static IRubyObject fact_UTCTime(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "UTCTime", args);
    }

    @JRubyMethod(name="GeneralizedTime", module=true, rest=true)
    public static IRubyObject fact_GeneralizedTime(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "GeneralizedTime", args);
    }

    @JRubyMethod(name="EndOfContent", module=true, rest=true)
    public static IRubyObject fact_EndOfContent(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "EndOfContent", args);
    }

    @JRubyMethod(name="Sequence", module=true, rest=true)
    public static IRubyObject fact_Sequence(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "Sequence", args);
    }

    @JRubyMethod(name="Set", module=true, rest=true)
    public static IRubyObject fact_Set(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        return newInstance(context, self, "Set", args);
    }

    private static IRubyObject newInstance(final ThreadContext context, final IRubyObject parent,
                                           final String className, final IRubyObject[] args) {
        return ((RubyModule) parent).getClass(className).newInstance(context, args, Block.NULL_BLOCK);
    }

    public static class ObjectId {

        @JRubyMethod(meta = true, rest = true)
        public static IRubyObject register(final IRubyObject self, final IRubyObject[] args) {
            final Ruby runtime = self.getRuntime();
            final ASN1ObjectIdentifier derOid = new ASN1ObjectIdentifier( args[0].toString() );
            final String a1 = args[1].toString();
            final String a2 = args[2].toString();
            synchronized(ASN1.class) {
                Map<String, ASN1ObjectIdentifier> sym2oid = getOIDLookup(runtime);
                sym2oid.put( a1.toLowerCase(), derOid );
                sym2oid.put( a2.toLowerCase(), derOid );
                getSymLookup(runtime).put( derOid, a1 );
            }
            return runtime.getTrue();
        }

        @JRubyMethod(name = { "sn", "short_name" })
        public static RubyString sn(final ThreadContext context, final IRubyObject self) {
            return name(context, self.callMethod(context, "value"), false);
        }

        @JRubyMethod(name = { "ln", "long_name" })
        public static RubyString ln(final ThreadContext context, final IRubyObject self) {
            return name(context, self.callMethod(context, "value"), true);
        }

        @JRubyMethod
        public static RubyString oid(final ThreadContext context, final IRubyObject self) {
            final Ruby runtime = context.runtime;
            return runtime.newString( getObjectID(runtime, self.callMethod(context, "value").toString()).getId() );
        }

        @JRubyMethod(name = "==")
        public static IRubyObject eq(final ThreadContext context, final IRubyObject self, final IRubyObject other) {
            if (!other.getMetaClass().equals(_ASN1(context.runtime).getClass("ObjectId"))) {
                return context.runtime.getFalse();
            }
            return self.callMethod(context, "value").op_eqq(context, other.callMethod(context, "value"));
        }

        private static RubyString name(final ThreadContext context, IRubyObject value,
            final boolean longName) {
            final Ruby runtime = context.runtime;
            final String oid = value.toString(); // name or oid
            Integer nid = null;
            try {
                nid = ASN1.oid2nid(runtime, ASN1.getObjectID(runtime, oid));
            }
            catch (IllegalArgumentException e) { /* ignored */ } // not an oid
            if ( nid != null ) {
                String val = longName ? nid2ln(runtime, nid) : nid2sn(runtime, nid);
                if ( val != null ) return runtime.newString(val);
            }
            return value.asString();
        }

    } // ObjectId

    static IRubyObject decodeObject(final ThreadContext context,
        final RubyModule ASN1, final org.bouncycastle.asn1.ASN1Encodable obj)
        throws IOException, IllegalArgumentException {
        final Ruby runtime = context.runtime;

        if ( obj instanceof ASN1Integer ) {
            final BN val = BN.newBN(runtime, ((ASN1Integer) obj).getValue());
            return ASN1.getClass("Integer").newInstance(context, val, Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1BitString ) {
            final ASN1BitString derObj = (ASN1BitString) obj;
            RubyString str = runtime.newString(new ByteList(derObj.getBytes(), false));
            IRubyObject bitString = ASN1.getClass("BitString").newInstance(context, str, Block.NULL_BLOCK);
            bitString.getInstanceVariables().setInstanceVariable("@unused_bits", runtime.newFixnum(derObj.getPadBits()));
            return bitString;
        }
        if ( obj instanceof ASN1String ) {
            final Integer typeId = typeId( obj.getClass() );
            String type = typeId == null ? null : (String) ( ASN1_INFO[typeId][2] );
            final ByteList bytes;
            if ( obj instanceof ASN1UTF8String ) {
                if ( type == null ) type = "UTF8String";
                bytes = new ByteList(((ASN1UTF8String) obj).getString().getBytes(StandardCharsets.UTF_8), false);
            }
            else if ( obj instanceof ASN1UniversalString ) {
                if ( type == null ) type = "UniversalString";
                bytes = new ByteList(((ASN1UniversalString) obj).getOctets(), false);
            }
            else if ( obj instanceof ASN1BMPString ) {
                if ( type == null ) type = "BMPString";
                final String val = ((ASN1BMPString) obj).getString();
                final byte[] valBytes = new byte[val.length() * 2];
                for (int i = 0; i < val.length(); i++) {
                    char c = val.charAt(i);
                    valBytes[i * 2] = (byte) ((c >> 8) & 0xff);
                    valBytes[i * 2 + 1] = (byte) (c & 0xff);
                }
                bytes = new ByteList(valBytes, false);
            }
            else {
                if ( type == null ) {
                    if ( obj instanceof ASN1NumericString ) {
                        type = "NumericString";
                    }
                    else if ( obj instanceof ASN1PrintableString ) {
                        type = "PrintableString";
                    }
                    else if ( obj instanceof ASN1IA5String ) {
                        type = "IA5String";
                    }
                    else if ( obj instanceof ASN1T61String ) {
                        type = "T61String";
                    }
                    else if ( obj instanceof ASN1GeneralString ) {
                        type = "GeneralString";
                    }
                    else if ( obj instanceof ASN1VideotexString ) {
                        type = "VideotexString";
                    }
                    else if ( obj instanceof ASN1VisibleString ) {
                        type = "ISO64String";
                    }
                    else if ( obj instanceof ASN1GraphicString ) {
                        type = "GraphicString";
                    }
                    else {
                        throw new IllegalArgumentException("could not handle ASN1 string type: " + obj + " (" + obj.getClass().getName() + ")");
                    }
                }
                bytes = ByteList.create(((ASN1String) obj).getString());
            }
            return ASN1.getClass(type).newInstance(context, runtime.newString(bytes), Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1OctetString ) {
            final ByteList octets = new ByteList(((ASN1OctetString) obj).getOctets(), false);
            // NOTE: sometimes MRI does include the tag but it really should not ;( !
            //final ByteList octets = new ByteList(((ASN1OctetString) obj).getEncoded(ASN1Encoding.DER), false);
            return ASN1.getClass("OctetString").newInstance(context, runtime.newString(octets), Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1Null ) {
            return ASN1.getClass("Null").newInstance(context, runtime.getNil(), Block.NULL_BLOCK);
        }
        if ( obj instanceof ASN1Boolean ) {
            final boolean val = ((ASN1Boolean) obj).isTrue();
            return ASN1.getClass("Boolean").newInstance(context, runtime.newBoolean(val), Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1UTCTime ) {
            final Date adjustedTime;
            try { adjustedTime = ((ASN1UTCTime) obj).getAdjustedDate(); }
            catch (ParseException e) { throw new IOException(e); }
            final RubyTime time = RubyTime.newTime(runtime, adjustedTime.getTime());
            return ASN1.getClass("UTCTime").newInstance(context, time, Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1GeneralizedTime ) {
            final Date generalTime;
            try { generalTime = ((ASN1GeneralizedTime) obj).getDate(); }
            catch (ParseException e) { throw new IOException(e); }
            final RubyTime time = RubyTime.newTime(runtime, generalTime.getTime());
            return ASN1.getClass("GeneralizedTime").newInstance(context, time, Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1ObjectIdentifier ) {
            final String objId = ((ASN1ObjectIdentifier) obj).getId();
            return ASN1.getClass("ObjectId").newInstance(context, runtime.newString(objId), Block.NULL_BLOCK);
        }

        if (obj instanceof ASN1TaggedObject) {
            final ASN1TaggedObject taggedObj = (ASN1TaggedObject) obj;
            final IRubyObject tag = runtime.newFixnum(taggedObj.getTagNo());
            final IRubyObject tag_class;
            switch (taggedObj.getTagClass()) {
                case BERTags.PRIVATE:
                    tag_class = runtime.newSymbol("PRIVATE");
                    break;
                case BERTags.APPLICATION:
                    tag_class = runtime.newSymbol("APPLICATION");
                    break;
                case BERTags.CONTEXT_SPECIFIC:
                    tag_class = runtime.newSymbol("CONTEXT_SPECIFIC");
                    break;
                default:
                    tag_class = runtime.newSymbol("UNIVERSAL");
                    break;
            }

            try {
                final ASN1Sequence sequence = (ASN1Sequence) taggedObj.getBaseUniversal(false, SEQUENCE);
                @SuppressWarnings("unchecked")
                final RubyArray valArr = decodeObjects(context, ASN1, sequence.getObjects());
                return ASN1.getClass("ASN1Data").newInstance(context, new IRubyObject[] { valArr, tag, tag_class }, Block.NULL_BLOCK);
            } catch (IllegalStateException e) {
                IRubyObject val = decodeObject(context, ASN1, taggedObj.getBaseObject()).callMethod(context, "value");
                return ASN1.getClass("ASN1Data").newInstance(context, new IRubyObject[] { val, tag, tag_class }, Block.NULL_BLOCK);
            }
        }

        if ( obj instanceof ASN1Sequence ) {
            @SuppressWarnings("unchecked")
            RubyArray arr = decodeObjects(context, ASN1, ((ASN1Sequence) obj).getObjects());
            return ASN1.getClass("Sequence").newInstance(context, arr, Block.NULL_BLOCK);
        }
        if ( obj instanceof ASN1Set ) {
            @SuppressWarnings("unchecked")
            RubyArray arr = decodeObjects(context, ASN1, ((ASN1Set) obj).getObjects());
            return ASN1.getClass("Set").newInstance(context, arr, Block.NULL_BLOCK);
        }

        if ( obj instanceof ASN1Enumerated ) {
            final RubyInteger value = RubyBignum.bignorm(runtime, ((ASN1Enumerated) obj).getValue());
            return ASN1.getClass("Enumerated").newInstance(context, value, Block.NULL_BLOCK);
        }

        throw new IllegalArgumentException("unable to decode object: " + obj + " (" + ( obj == null ? "" : obj.getClass().getName() ) + ")");
    }

    private static RubyArray decodeObjects(final ThreadContext context, final RubyModule ASN1,
        final Enumeration<ASN1Encodable> e)
        throws IOException {
        final RubyArray arr = context.runtime.newArray();
        while ( e.hasMoreElements() ) {
            arr.append( decodeObject(context, ASN1, e.nextElement()) );
        }
        return arr;
    }

    @JRubyMethod(meta = true)
    public static IRubyObject decode(final ThreadContext context,
        final IRubyObject self, final IRubyObject obj) {
        try {
            return decodeImpl(context, (RubyModule) self, obj);
        }
        catch (IOException e) {
            throw newASN1Error(context.runtime, e);
        }
        catch (IllegalArgumentException e) {
            debugStackTrace(context.runtime, e);
            throw (RaiseException) context.runtime.newArgumentError(e.getMessage()).initCause(e);
        }
        catch (RuntimeException e) {

            debugStackTrace(context.runtime, e);
            throw Utils.newRuntimeError(context.runtime, e);
        }
    }

    static IRubyObject decodeImpl(final ThreadContext context, IRubyObject obj)
        throws IOException, IllegalArgumentException {
        return decodeImpl(context, _ASN1(context.runtime), obj);
    }

    static IRubyObject decodeImpl(final ThreadContext context,
        final RubyModule ASN1, IRubyObject obj) throws IOException, IllegalArgumentException {
        obj = to_der_if_possible(context, obj);
        BytesInputStream in = new BytesInputStream( obj.asString().getByteList() );
        final IRubyObject decoded = decodeImpl(context, ASN1, in);
        if ( in.available() > 0 ) {
            final int read = in.readCount();
            throw new IOException("Type mismatch. Total bytes read: "+ read + " Bytes available: " + in.available());
        }
        return decoded;
    }

    private static class BytesInputStream extends ByteArrayInputStream {

        private BytesInputStream(final ByteList bytes) {
            super(bytes.unsafeBytes(), bytes.getBegin(), bytes.getRealSize());
        }

        final byte[] bytes() { return buf; }

        final int readCount() { return pos - mark; } // since last mark

        final int position() { return pos; }

        final int offset() { return mark; }

    }

    private static IRubyObject decodeImpl(final ThreadContext context, final RubyModule ASN1, final BytesInputStream in)
        throws IOException, IllegalArgumentException {
        final byte[] asn1 = in.bytes();
        int offset = in.offset();
        final int tag = asn1[offset] & 0xFF;

        if ( ( tag & BERTags.CONSTRUCTED ) == 0 ) {
            return decodeObject(context, ASN1, readObject(in));
        }

        // NOTE: need to handle OpenSSL::ASN1::Constructive wrapping by hand :
        int tagNo = tag & 0x1f;
        if (tagNo == 0x1f)
        {
            tagNo = 0;
            int b = asn1[ ++offset ];

            // X.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // Note: -1 will pass
            {
                throw new IOException("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0))
            {
                tagNo |= (b & 0x7f);
                tagNo <<= 7;
                b = asn1[ ++offset ];
            }

            if (b < 0)
            {
                throw new IOException("EOF found inside tag value.");
            }

            tagNo |= (b & 0x7f);
        }
        final int length = asn1[ ++offset ] & 0xFF;
        final boolean isIndefiniteLength = length == 0x80;
        IRubyObject decoded;

        decoded = decodeObject(context, ASN1, readObject(in));

        final boolean isUniversal = ((ASN1Data) decoded).isUniversal(context);

        if (isIndefiniteLength) {
            if (tagNo == BERTags.SEQUENCE || tagNo == BERTags.SET) {
                return ASN1Data.setInfiniteLength(context, decoded);
            } else if (isUniversal) {
                decoded = Constructive.newInfiniteLength(context, context.runtime.newArray(decoded), tagNo);
            } else {
                if (decoded instanceof ASN1Data) {
                    return ASN1Data.setInfiniteLength(context, decoded);
                } else {
                    decoded = ASN1Data.newInfiniteLength(context, context.runtime.newArray(decoded), tagNo, ((ASN1Data) decoded).tagClass());
                }
            }
        }
        return decoded;
    }

    @JRubyMethod(meta = true, required = 1)
    public static IRubyObject decode_all(final ThreadContext context,
        final IRubyObject self, IRubyObject obj) {
        obj = to_der_if_possible(context, obj);

        BytesInputStream in = new BytesInputStream( obj.asString().getByteList() );
        final RubyModule ASN1 = _ASN1(context.runtime);
        final RubyArray arr = context.runtime.newArray();
        while ( in.available() > 0 ) {
            try {
                in.mark(0); // set offset() before each object is read
                arr.append( decodeImpl(context, ASN1, in) );
            }
            catch (IOException e) {
                throw newASN1Error(context.runtime, e);
            }
            catch (IllegalArgumentException e) {
                debugStackTrace(context.runtime, e);
                throw context.runtime.newArgumentError(e.getMessage());
            }
        }
        return arr;
    }

    @JRubyMethod(meta = true, required = 1)
    public static IRubyObject traverse(final ThreadContext context, final IRubyObject self, IRubyObject arg) {
        warn(context, "WARNING: unimplemented method called: OpenSSL::ASN1#traverse");
        return context.runtime.getNil();
    }

    public static RaiseException newASN1Error(Ruby runtime, String message) {
        return Utils.newError(runtime, _ASN1(runtime).getClass("ASN1Error"), message, false);
    }

    static RaiseException newASN1Error(Ruby runtime, Throwable ex) {
        return (RaiseException) newASN1Error(runtime, ex.getMessage()).initCause(ex);
    }

    static RubyModule _ASN1(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstant("ASN1");
    }

    static org.bouncycastle.asn1.ASN1Primitive readObject(final byte[] bytes)
        throws IOException {
        return new ASN1InputStream(new ByteArrayInputStream(bytes)).readObject();
    }

    private static org.bouncycastle.asn1.ASN1Primitive readObject(final InputStream bytes)
        throws IOException {
        return new ASN1InputStream(bytes).readObject();
    }

    public static class ASN1Data extends RubyObject {
        private static final long serialVersionUID = 6117598347932209839L;

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new ASN1Data(runtime, klass);
            }
        };

        static final int MAX_TAG_VALUE = ASN1_INFO.length;

        public ASN1Data(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }

        @JRubyMethod(visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context,
            final IRubyObject value, final IRubyObject tag, final IRubyObject tag_class) {
            checkTag(context.runtime, tag, tag_class);
            this.callMethod(context, "tag=", tag);
            this.callMethod(context, "value=", value);
            this.callMethod(context, "tag_class=", tag_class);
            this.setInstanceVariable("@indefinite_length", context.runtime.getFalse());
            return this;
        }

        static ASN1Data newInfiniteLength(final ThreadContext context,
            final IRubyObject value, final int defaultTag, final IRubyObject tagClass) {
            final Ruby runtime = context.runtime;

            final RubyClass klass = _ASN1(runtime).getClass("ASN1Data");
            final ASN1Data self = new Constructive(runtime, klass);

            ASN1Data.newInfiniteLengthImpl(context, self, value, defaultTag, tagClass);
            return self;
        }

        static void newInfiniteLengthImpl(final ThreadContext context, final ASN1Data self, final IRubyObject value, final int defaultTag, final IRubyObject tagClass) {
            self.setInstanceVariable("@tag", context.runtime.newFixnum(defaultTag));
            self.setInstanceVariable("@value", value);
            self.setInstanceVariable("@tag_class", tagClass);
            self.setInstanceVariable("@tagging", context.nil);

            setInfiniteLength(context, self);
        }

        static ASN1Data setInfiniteLength(final ThreadContext context, final IRubyObject constructive) {
            final ASN1Data instance = ((ASN1Data) constructive);
            final IRubyObject value = instance.value(context);
            value.callMethod(context, "<<", EndOfContent.newInstance(context));
            instance.setInstanceVariable("@indefinite_length", context.runtime.getTrue());
            return instance;
        }

        private void checkTag(final Ruby runtime, final IRubyObject tag, final IRubyObject tagClass) {
            if ( ! (tagClass instanceof RubySymbol) ) {
                throw newASN1Error(runtime, "invalid tag class");
            }
            if ( "UNIVERSAL".equals(tagClass.toString()) && RubyNumeric.fix2int(tag) > MAX_TAG_VALUE ) {
                throw newASN1Error(runtime, "tag number for :UNIVERSAL too large (" + tag + ")");
            }
        }

        private boolean isConstructive() {
            return "Constructive".equals(getMetaClass().getRealClass().getBaseName());
        }

        boolean isInfiniteLength() {
            return getInstanceVariable("@indefinite_length").isTrue();
        }

        boolean isEOC(final ThreadContext context) {
            return getTag(context) == 0 && isUniversal((context));
        }

        boolean isUniversal(final ThreadContext context) {
            return getTagClass(context) == BERTags.UNIVERSAL;
        }

        IRubyObject tagging() {
            return getInstanceVariable("@tagging");
        }

        IRubyObject tagClass() {
            return getInstanceVariable("@tag_class");
        }

        boolean isExplicitTagging() { return ! isImplicitTagging(); }

        boolean isImplicitTagging() { return true; }

        int getTag(final ThreadContext context) {
            return RubyNumeric.fix2int(getInstanceVariable("@tag"));
        }

        int getTagClass(final ThreadContext context) {
            IRubyObject tag_class = getInstanceVariable("@tag_class");
            if (tag_class instanceof RubySymbol) {
                switch (((RubySymbol) tag_class).asJavaString()) {
                    case "PRIVATE":
                        return BERTags.PRIVATE;
                    case "APPLICATION":
                        return BERTags.APPLICATION;
                    case "CONTEXT_SPECIFIC":
                        return BERTags.CONTEXT_SPECIFIC;
                    default: // fallback to BERTags.UNIVERSAL
                }
            }
            return BERTags.UNIVERSAL; // 0
        }

        ASN1Encodable toASN1(final ThreadContext context) {
            return toASN1TaggedObject(context);
        }

        final ASN1TaggedObject toASN1TaggedObject(final ThreadContext context) {
            final int tag = getTag(context);
            final int tagClass = getTagClass(context);

            final IRubyObject value = callMethod(context, "value");
            if (value instanceof RubyArray) {
                // Cruby openssl joins elements of array and casts to string
                final RubyArray arr = (RubyArray) value;

                StringBuilder values = new StringBuilder();
                ASN1EncodableVector vec = new ASN1EncodableVector();

                for (final IRubyObject obj : arr.toJavaArray()) {
                    if (obj instanceof ASN1Data) {
                        ASN1Encodable data = ((ASN1Data) obj).toASN1(context);
                        if (data == null) break;
                        vec.add(data);
                    } else {
                        final IRubyObject string = obj.checkStringType();
                        if (string instanceof RubyString) {
                            values.append(string.asJavaString());
                        } else {
                            throw context.runtime.newTypeError(
                                    "no implicit conversion of " + obj.getMetaClass().getBaseName() + " into String");
                        }
                    }
                }

                if (values.length() > 0) {
                    return new DERTaggedObject(isExplicitTagging(), tagClass, tag, new DERGeneralString(values.toString()));
                } else {
                    // array of strings as value (default)
                    return new DERTaggedObject(isExplicitTagging(), tagClass, tag, new BERSequence(vec));
                }
            } else if (value instanceof ASN1Data) {
                return new DERTaggedObject(isExplicitTagging(), tagClass, tag, ((ASN1Data) value).toASN1(context));
            } else if (value instanceof RubyObject) {
                if (isEOC(context)) {
                    return null;
                }
                final IRubyObject string = value.checkStringType();
                if (string instanceof RubyString) {
                    return new DERTaggedObject(isExplicitTagging(), tagClass, tag,
                            new DERGeneralString(string.asJavaString()));
                } else {
                    throw context.runtime.newTypeError(
                            "no implicit conversion of " + value.getMetaClass().getBaseName() + " into String");
                }
            } else {
                throw context.runtime.newTypeError(
                        "no implicit conversion of " + value.getMetaClass().getBaseName() + " into String");
            }
        }

        @JRubyMethod
        public IRubyObject to_der(final ThreadContext context) {
            try {
                final byte[] encoded = toDER(context);
                return context.runtime.newString(new ByteList(encoded, false));
            }
            catch (IOException e) {
                throw newASN1Error(context.runtime, e.getMessage());
            }
        }

        byte[] toDER(final ThreadContext context) throws IOException {
            if (
                ("ASN1Data".equals(getClassBaseName()) && isUniversal(context))
            ) {
                    return toDERInternal(context, isConstructive(), isInfiniteLength(), value(context));
            }

            final ASN1Primitive prim = toASN1(context).toASN1Primitive();

            if (isInfiniteLength()) {
                final java.io.ByteArrayOutputStream tagOut = new ByteArrayOutputStream();
                final java.io.ByteArrayOutputStream contentOut = new ByteArrayOutputStream();
                final java.io.ByteArrayOutputStream out = new ByteArrayOutputStream();
                prim.encodeTo(contentOut, ASN1Encoding.DER);
                writeDERIdentifier(getTag(context), getTagClass(context) | BERTags.CONSTRUCTED, tagOut);

                byte[] tagOutArr = tagOut.toByteArray();
                byte[] contentOutArr = contentOut.toByteArray();

                out.write(tagOutArr);
                out.write(0x80);
                out.write(contentOutArr, tagOutArr.length + 1, contentOutArr.length - tagOutArr.length - 1);
                out.write(0x00);
                out.write(0x00);

                return out.toByteArray();
             } else {
                return prim.getEncoded(ASN1Encoding.DER);
            }
        }

        byte[] toDERInternal(final ThreadContext context, boolean isConstructed, boolean isIndefiniteLength, final IRubyObject value) throws IOException {
            // handstitch conversion
            final java.io.ByteArrayOutputStream out = new ByteArrayOutputStream();

            final byte[] valueBytes;

            if (value == null) {
                valueBytes = new byte[] {};
            } else if (value instanceof RubyArray) {
                final IRubyObject[] arr = ((RubyArray) value).toJavaArray();
                final java.io.ByteArrayOutputStream valueOut = new ByteArrayOutputStream();


                for ( int i = 0; i < arr.length; i++ ) {
                   final IRubyObject obj = arr[i];

                   if (obj instanceof EndOfContent && i != arr.length - 1) {
                    throw newASN1Error(context.runtime, "illegal EOC octets in value");
                   }

                    final byte[] objBytes;

                    if (obj.respondsTo("to_der")) {
                        objBytes = ((RubyString) obj.callMethod(context, "to_der")).getBytes();
                    } else {
                        objBytes = ((RubyString) obj.convertToString()).getBytes();
                    }

                    valueOut.write(objBytes);
                }

                if (isIndefiniteLength) {
                    if (arr.length != 0 && !(arr[arr.length - 1] instanceof EndOfContent)) {
                        // indefinite length object with no EOC object in the array.
                        valueOut.write(0x00);
                        valueOut.write(0x00);
                    }
                }

                valueBytes = valueOut.toByteArray();
            } else {
                if (isIndefiniteLength) {
                    throw newASN1Error(
                        context.runtime,
                        "indefinite length form cannot be used with primitive encoding"
                    );
                }

                if (value instanceof RubyString) {
                    valueBytes = ((RubyString) value).getBytes();
                } else {
                    valueBytes = value.convertToString().getBytes();
                }
            }

            int flags = getTagClass(context);
            if (isConstructed) {
                flags |= BERTags.CONSTRUCTED;
            }
            // tag
            writeDERIdentifier(getTag(context), flags, out);
            if (isIndefiniteLength) {
                out.write(0x80);
            } else {
                writeDERLength(valueBytes.length, out);
            }
            // value
            out.write(valueBytes);

            return out.toByteArray();
        }

        void writeDERIdentifier(int tag, int flags, java.io.ByteArrayOutputStream out) {
            if (tag > 0x1f) {
                byte[] stack = new byte[6];
                int pos = stack.length;

                stack[--pos] = (byte)(tag & 0x7F);
                while (tag > 127)
                {
                    tag >>>= 7;
                    stack[--pos] = (byte)(tag & 0x7F | 0x80);
                }

                stack[--pos] = (byte)(flags | 0x1F);

                out.write(stack, pos, stack.length - pos);
            } else {
                out.write(flags | tag);
            }
        }

        void writeDERLength(int length, java.io.ByteArrayOutputStream out) {
            if (length < 128) {
                out.write(length);
            } else {
                byte[] stack = new byte[5];
                int pos = stack.length;

                do
                {
                    stack[--pos] = (byte)length;
                    length >>>= 8;
                }
                while (length != 0);

                int count = stack.length - pos;
                stack[--pos] = (byte)(0x80 | count);

                out.write(stack, pos, count - pos);
            }
        }

        protected IRubyObject defaultTag() {
            final Integer id = typeId( getMetaClass() );
            if ( id == null ) return getRuntime().getNil();
            return getRuntime().newFixnum( id.intValue() );
        }

        final IRubyObject value() {
            return value(getRuntime().getCurrentContext());
        }

        IRubyObject value(final ThreadContext context) {
            return callMethod(context, "value");
        }

        final String getClassBaseName() { return getMetaClass().getBaseName(); }

        @Override
        public String toString() {
            return value().toString();
        }

        protected final void print() {
            print(0);
        }

        protected void print(int indent) {
            final PrintStream out = getRuntime().getOut();
            printIndent(out, indent);
            final IRubyObject value = value();
            out.println("ASN1Data: ");
            if ( value instanceof RubyArray ) {
                printArray(out, indent, (RubyArray) value);
            } else {
                ((ASN1Data) value).print(indent + 1);
            }
        }

        static void printIndent(final PrintStream out, final int indent) {
            for ( int i = 0; i < indent; i++) out.print(" ");
        }

        static void printArray(final PrintStream out, final int indent, final RubyArray array) {
            for ( int i = 0; i < array.size(); i++ ) {
                ((ASN1Data) array.entry(i)).print(indent + 1);
            }
        }

    }

    public static class EndOfContent extends ASN1Data {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new EndOfContent(runtime, klass);
            }
        };

        public EndOfContent(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }


        @JRubyMethod(required = 0, optional = 0, visibility = Visibility.PRIVATE)
        public static IRubyObject initialize(final ThreadContext context, final IRubyObject self) {
            final Ruby runtime = context.runtime;
            self.getInstanceVariables().setInstanceVariable("@tag", runtime.newFixnum(0));
            self.getInstanceVariables().setInstanceVariable("@value", RubyString.newEmptyString(context.runtime));
            self.getInstanceVariables().setInstanceVariable("@tag_class", runtime.newSymbol("UNIVERSAL"));
            return self;
        }

        static IRubyObject newInstance(final ThreadContext context) {
            RubyClass klass = _ASN1(context.runtime).getClass("EndOfContent");
            return klass.newInstance(context, Block.NULL_BLOCK);
        }

        @Override
        boolean isImplicitTagging() {
            IRubyObject tagging = tagging();
            if ( tagging.isNil() ) return true;
            return "IMPLICIT".equals( tagging.toString() );
        }

        @Override
        byte[] toDER(final ThreadContext context) throws IOException {
            return toDERInternal(context, false, false, null);
        }
    }

    public static class Primitive extends ASN1Data {
        private static final long serialVersionUID = 8489625559339190259L;

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new Primitive(runtime, klass);
            }
        };

        public Primitive(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }

        @Override
        @JRubyMethod
        public IRubyObject to_der(final ThreadContext context) {
            if ( value(context).isNil() && !isNull() ) {
                // MRI compatibility but avoids Java exceptions as well e.g.
                // Java::JavaLang::NumberFormatException
                //    java.math.BigInteger.<init>(BigInteger.java:296)
                //    java.math.BigInteger.<init>(BigInteger.java:476)
                //    org.jruby.ext.openssl.ASN1$ASN1Primitive.toASN1(ASN1.java:1287)
                //    org.jruby.ext.openssl.ASN1$ASN1Data.to_der(ASN1.java:1129)
                //    org.jruby.ext.openssl.ASN1$ASN1Primitive.to_der(ASN1.java:1202)
                throw context.runtime.newTypeError("nil value");
            }
            return super.to_der(context);
        }

        @JRubyMethod(required = 0, optional = 4, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            initializeImpl(context, this, args);
            return this;
        }

        // shared initialize logic between Primitive and Constructive
        static void initializeImpl(final ThreadContext context,
            final ASN1Data self, final IRubyObject[] args) {
            final Ruby runtime = context.runtime;
            final int len = args.length;

            IRubyObject value = len == 0 ? runtime.getNil() : args[0];
            final IRubyObject tag;
            IRubyObject tagging = runtime.getNil();
            IRubyObject tag_class = runtime.getNil();

            if ( len > 1 ) {
                tag = args[1];
                if ( len > 2 ) {
                    tagging = args[2];
                    if ( len > 3 ) tag_class = args[3];
                }

                if ( tag.isNil() ) throw newASN1Error(runtime, "must specify tag number");

                if ( tagging.isNil()) {
                    if (tag_class.isNil()) {
                        tag_class = runtime.newSymbol("UNIVERSAL");
                    }
                } else {
                    if (!(tagging instanceof RubySymbol)) {
                        throw newASN1Error(runtime, "invalid tagging method");
                    }

                    if (tag_class.isNil()) {
                        tag_class = runtime.newSymbol("CONTEXT_SPECIFIC");
                    }
                }

                if ( ! (tag_class instanceof RubySymbol) ) {
                    throw newASN1Error(runtime, "invalid tag class");
                }

                if ( tagging.toString().equals("IMPLICIT") && RubyNumeric.fix2int(tag) > MAX_TAG_VALUE ) {
                    throw newASN1Error(runtime, "tag number for Universal too large");
                }
            }
            else {
                tag = self.defaultTag();
                tag_class = runtime.newSymbol("UNIVERSAL");
            }

            // NOTE: Primitive only
            final String baseName = self.getMetaClass().getRealClass().getBaseName();
            switch (baseName) {
                case "ObjectId":
                    final String name;
                    try {
                        name = oid2Sym( runtime, getObjectID(runtime, value.toString()), true );
                    }
                    catch (IllegalArgumentException e) {
                        // e.g. in case of nil "string  not an OID"
                        throw runtime.newTypeError(e.getMessage());
                    }
                    if ( name != null ) value = runtime.newString(name);
                    break;
                case "BitString":
                    self.setInstanceVariable("@unused_bits", runtime.newFixnum(0));
                    break;
            }

            self.setInstanceVariable("@tag", tag);
            self.setInstanceVariable("@value", value);
            self.setInstanceVariable("@tag_class", tag_class);
            self.setInstanceVariable("@tagging", tagging);
            self.setInstanceVariable("@indefinite_length", runtime.getFalse());
        }

        boolean isTagged() {
            return !tagging().isNil();
        }

        @Override
        boolean isExplicitTagging() {
            return "EXPLICIT".equals( tagging().toString() );
        }

        @Override
        boolean isImplicitTagging() {
            IRubyObject tagging = tagging();
            if ( tagging.isNil() ) return true;
            return "IMPLICIT".equals( tagging.toString() );
        }

        @Override
        boolean isEOC(final ThreadContext context) {
            return false;
        }

        private boolean isNull() {
            return "Null".equals(getMetaClass().getRealClass().getBaseName());
        }

        @Override
        byte[] toDER(final ThreadContext context) throws IOException {
            Class<? extends ASN1Encodable> type = typeClass( getMetaClass() );
            final IRubyObject value = value(context);

            if ( type == null ) {
                RubyString string;

                if (value instanceof RubyString) {
                    string = (RubyString) value;
                } else {
                    string = value.convertToString();
                }

                return toDERInternal(context, false, false, string);
            }

            return toASN1(context).toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }

        @Override
        ASN1Encodable toASN1(final ThreadContext context) {
            final ASN1Encodable primitive = toASN1Primitive(context);
            if (isTagged()) {
                return new DERTaggedObject(isExplicitTagging(), getTagClass(context), getTag(context), primitive);
            }
            return primitive;
        }

        private ASN1Encodable toASN1Primitive(final ThreadContext context) {
            Class<? extends ASN1Encodable> type = typeClass( getMetaClass() );

            final IRubyObject val = value(context);
            if ( type == ASN1ObjectIdentifier.class ) {
                return getObjectID(context.runtime, val.toString());
            }
            if ( type == DERNull.class || type == ASN1Null.class ) {
                return DERNull.INSTANCE;
            }
            if ( ASN1Boolean.class.isAssignableFrom(type) ) {
                return ASN1Boolean.getInstance(val.isTrue());
            }
            if ( type == DERUTCTime.class ) {
                if ( val instanceof RubyTime ) {
                    return new DERUTCTime(((RubyTime) val).getJavaDate());
                }
                return DERUTCTime.getInstance( val.asString().getBytes() );
            }
            if ( type == DERGeneralizedTime.class ) {
                if ( val instanceof RubyTime ) {
                    return new DERGeneralizedTime(((RubyTime) val).getJavaDate());
                }
                return DERGeneralizedTime.getInstance( val.asString().getBytes() );
            }
            if ( ASN1Integer.class.isAssignableFrom(type) ) {
                return new ASN1Integer( bigIntegerValue(val) );
            }
            if ( ASN1Enumerated.class.isAssignableFrom(type) ) {
                return new ASN1Enumerated( bigIntegerValue(val) );
            }
            if ( ASN1OctetString.class.isAssignableFrom(type) ) {
                return new DEROctetString( val.asString().getBytes() );
            }
            if ( type == DERBitString.class ) {
                final byte[] data = val.asString().getBytes();
                int padBits = 0;
                IRubyObject unused_bits = getInstanceVariable("@unused_bits");
                if (unused_bits != null) {
                    padBits = unused_bits.convertToInteger("to_i").getIntValue();
                }
                try {
                    return new DERBitString(data, padBits);
                } catch (IllegalArgumentException e) {
                    throw newASN1Error(context.runtime, e.getMessage());
                }
            }
            if ( type == DERIA5String.class ) {
                return new DERIA5String( val.asString().toString() );
            }
            if ( type == DERUTF8String.class ) {
                return new DERUTF8String( val.asString().toString() );
            }
            if ( type == DERBMPString.class ) {
                return new DERBMPString(new String(toBMPChars(val.asString().getByteList())));
            }
            if ( type == DERUniversalString.class ) {
                return new DERUniversalString( val.asString().getBytes() );
            }

            if ( type == DERGeneralString.class ) {
                return new DERGeneralString( val.asString().toString() );
            }
            if ( type == DERVisibleString.class ) {
                return new DERVisibleString( val.asString().toString() );
            }
            if ( type == DERNumericString.class ) {
                return new DERNumericString( val.asString().toString() );
            }
            if ( type == DERPrintableString.class ) {
                return new DERPrintableString( val.asString().toString() );
            }
            if ( type == DERT61String.class ) {
                return new DERT61String( val.asString().toString() );
            }
            if ( type == DERVideotexString.class ) {
                return new DERVideotexString( val.asString().getBytes() );
            }
            if ( type == DERGraphicString.class ) {
                return new DERGraphicString( val.asString().getBytes() );
            }

            if (isDebug(context.runtime)) {
                debug(this + " toASN1() could not handle class " + getMetaClass() + " and value: " + val.inspect() + " (" + val.getMetaClass() + ")");
            }
            throw new UnsupportedOperationException("OpenSSL::ASN1Data#toASN1 (" + type + ") not implemented"); // should not happen
        }

        private static char[] toBMPChars(final ByteList string) {
            assert string.length() % 2 == 0;

            final int len = string.length() / 2;
            final char[] chars = new char[len];
            for (int i = 0; i < len; i++) {
                int si = i * 2;
                chars[i] = (char)((string.get(si) << 8) | (string.get(si + 1) & 0xff));
            }
            return chars;
        }

        private static BigInteger bigIntegerValue(final IRubyObject val) {
            if ( val instanceof RubyInteger ) { // RubyBignum
                return ((RubyInteger) val).getBigIntegerValue();
            }
            if ( val instanceof BN ) return ((BN) val).getValue();
            return new BigInteger( val.asString().getBytes() );
        }

        @Override
        protected void print(int indent) {
            final PrintStream out = getRuntime().getOut();
            printIndent(out, indent);
            out.print(getMetaClass().getRealClass().getBaseName());
            out.print(": ");
            out.println(value().callMethod(getRuntime().getCurrentContext(), "inspect").toString());
        }

    }

    public static class Constructive extends ASN1Data { // implements ASN1Encodable {
        private static final long serialVersionUID = -7166662655104776828L;

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new Constructive(runtime, klass);
            }
        };

        public Constructive(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        @JRubyMethod(required = 1, optional = 3, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            Primitive.initializeImpl(context, this, args);
            return this;
        }

        static Constructive newInfiniteLength(final ThreadContext context,
            final IRubyObject value, final int defaultTag) {
            final Ruby runtime = context.runtime;

            final RubyClass klass = _ASN1(context.runtime).getClass("Constructive");
            final Constructive self = new Constructive(runtime, klass);

            ASN1Data.newInfiniteLengthImpl(context, self, value, defaultTag, runtime.newSymbol("UNIVERSAL"));
            return self;
        }

        private boolean rawConstructive() {
            return "Constructive".equals( getClassBaseName() );
        }

        private boolean isSequence() {
            return "Sequence".equals( getClassBaseName() );
        }

        private boolean isSet() {
            return "Set".equals( getClassBaseName() );
        }

        private boolean isTagged() {
            return !tagging().isNil();
        }

        @Override
        boolean isExplicitTagging() {
            return "EXPLICIT".equals( tagging().toString() ); // nil.toString() == ""
        }

        @Override
        boolean isImplicitTagging() {
            return "IMPLICIT".equals( tagging().toString() );
        }

        @Override
        ASN1Encodable toASN1(final ThreadContext context) {
            if ( isInfiniteLength() ) return super.toASN1(context);

            if ( isSequence() ) {
                return new DERSequence( toASN1EncodableVector(context) );
            }
            if ( isSet() ) {
                return new DLSet( toASN1EncodableVector(context) ); // return new BERSet(values);
                //return ASN1Set.getInstance(toASN1TaggedObject(context), isExplicitTagging());
            }
            switch ( getTag(context) ) { // "raw" Constructive ?!?
            case OCTET_STRING:
                final ASN1EncodableVector values = toASN1EncodableVector(context);
                ASN1OctetString[] octets = new ASN1OctetString[ values.size() ];
                for ( int i = 0; i < values.size(); i++ ) {
                    octets[i] = (ASN1OctetString) values.get(i).toASN1Primitive();
                }
                return new BEROctetString(octets);
            case SEQUENCE:
                return new DERSequence( toASN1EncodableVector(context) );
            case SET:
                return new DLSet( toASN1EncodableVector(context) ); // return new BERSet(values);
                //return ASN1Set.getInstance(toASN1TaggedObject(context), isExplicitTagging());
            }
            throw new UnsupportedOperationException( this.inspect().toString() );
        }

        @Override
        @JRubyMethod
        public IRubyObject to_der(final ThreadContext context) {
            return super.to_der(context);
        }

        @Override
        byte[] toDER(final ThreadContext context) throws IOException {
            final int tagNo = getTag(context);
            final boolean isIndefiniteLength = isInfiniteLength();

            if ( isIndefiniteLength ) {
                if ( isSequence() || tagNo == SEQUENCE ) {
                    return sequenceToDER(context);
                }
                if ( isSet() || tagNo == SET)  {
                    return setToDER(context);
                }
                // "raw" Constructive
                switch ( getTag(context) ) {
                case OCTET_STRING:
                    return octetStringToDER(context);
                case BIT_STRING:
                    return bitStringToDER(context);
                }
                return toDERInternal(context, true, isInfiniteLength(), value(context));
            }

            if (isEOC(context)) {
                return toDERInternal(context, true, isIndefiniteLength, null);
            }

            Class<? extends ASN1Encodable> type = typeClass( getMetaClass() );

            if ( type == null ) {
                return toDERInternal(context, true, isIndefiniteLength, valueAsArray(context));
            }

            return super.toDER(context);
        }

        private byte[] bitStringToDER(final ThreadContext context) throws IOException {
            final ASN1EncodableVector values = toASN1EncodableVector(context);
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(BERTags.CONSTRUCTED | BERTags.BIT_STRING);
            out.write(0x80); // infinite-length
            for ( int i = 0; i < values.size(); i++ ) {
                out.write( values.get(i).toASN1Primitive().getEncoded() );
            }
            out.write(0x00); out.write(0x00); // writeBEREnd
            return out.toByteArray();
        }

        private byte[] octetStringToDER(final ThreadContext context) throws IOException {
            final ASN1EncodableVector values = toASN1EncodableVector(context);
            ASN1OctetString[] octets = new ASN1OctetString[ values.size() ];
            for ( int i = 0; i < values.size(); i++ ) {
                octets[i] = (ASN1OctetString) values.get(i).toASN1Primitive();
            }
            return new BEROctetString(octets).getEncoded();
        }

        private byte[] sequenceToDER(final ThreadContext context) throws IOException {
            final ASN1EncodableVector values = toASN1EncodableVector(context);

            final ByteArrayOutputStream out = new ByteArrayOutputStream(64);
            BERSequenceGenerator sequenceGenerator = new BERSequenceGenerator(out);
            for ( int i = 0; i < values.size(); i++ ) {
                final ASN1Encodable value = values.get(i);
                if ( value instanceof InternalEncodable ) { // HACK
                    byte[] nested = ((InternalEncodable) value).entry.toDER(context);
                    out.write(nested, 0, nested.length); continue;
                }
                sequenceGenerator.addObject( values.get(i) );
            }
            sequenceGenerator.close();
            return out.toByteArray();
        }

        private byte[] setToDER(final ThreadContext context) throws IOException {
            final ASN1EncodableVector values = toASN1EncodableVector(context);
            return new BERSet(values).toASN1Primitive().getEncoded();
        }

        private ASN1EncodableVector toASN1EncodableVector(final ThreadContext context) {
            final ASN1EncodableVector vec = new ASN1EncodableVector();
            final IRubyObject value = value(context);
            final RubyArray val = valueAsArray(context);
            for ( int i = 0; i < val.size(); i++ ) {
                if ( addEntry(context, vec, val.entry(i)) ) break;
            }
            return vec;
        }

        private RubyArray valueAsArray(final ThreadContext context) {
            final IRubyObject value = value(context);
            if (value instanceof RubyArray ) {
                return (RubyArray) value;
            } else {
                if (!value.respondsTo("to_a")) {
                    throw context.runtime.newTypeError("can't convert " + value.getMetaClass().getName() + " into Array");
                }
                return (RubyArray) value.callMethod(context, "to_a");
            }
        }

        public ASN1Primitive toASN1Primitive() {
            throw new UnsupportedOperationException();
        }

        private static class InternalEncodable implements ASN1Encodable {

            final Constructive entry;

            InternalEncodable(Constructive entry) { this.entry = entry; }

            @Override
            public ASN1Primitive toASN1Primitive() {
                throw new UnsupportedOperationException();
            }

        }

        private static boolean addEntry(final ThreadContext context, final ASN1EncodableVector vec, final IRubyObject entry) {
            try {
                if ( entry instanceof Constructive ) {
                    final Constructive constructive = (Constructive) entry;
                    if ( constructive.isInfiniteLength() || constructive.rawConstructive() ) {
                        vec.add( new InternalEncodable( (Constructive) entry) );
                    }
                    else {
                        vec.add( constructive.toASN1(context) );
                    }
                }
                else if ( entry instanceof ASN1Data ) {
                    final ASN1Data data = ( (ASN1Data) entry );
                    if ( data.isEOC(context) ) return true;
                    vec.add( data.toASN1(context) );
                }
                else {
                    vec.add( ( (ASN1Data) decodeImpl(context, entry) ).toASN1(context) );
                }
                return false;
            }
            catch (IOException e) { throw Utils.newIOError(context.runtime, e); }
        }

        @JRubyMethod
        public IRubyObject each(final ThreadContext context, final Block block) {
            final IRubyObject value = value(context);
            if ( value instanceof RubyArray ) {
                final RubyArray val = (RubyArray) value;
                for ( int i = 0; i < val.size(); i++ ) {
                    block.yield(context, val.entry(i));
                }
            }
            else {
                value.callMethod(context, "each", NULL_ARRAY, block);
                //final int size = RubyInteger.num2int(value.callMethod(context, "size"));
                //for ( int i = 0; i < size; i++ ) {
                //    final RubyInteger idx = context.runtime.newFixnum(i);
                //    block.yield(context, value.callMethod(context, "[]", idx));
                //}
            }
            return context.runtime.getNil();
        }

        @JRubyMethod
        public IRubyObject size(final ThreadContext context) {
            final IRubyObject value = value(context);
            if ( value instanceof RubyArray ) {
                final RubyArray val = (RubyArray) value;
                return context.runtime.newFixnum(val.size());
            }
            else {
                return value.callMethod(context, "size");
            }
        }

        @Override
        protected void print(int indent) {
            final PrintStream out = getRuntime().getOut();
            printIndent(out, indent);
            out.print(getMetaClass().getRealClass().getBaseName()); out.println(": ");
            printArray( out, indent, (RubyArray) value( getRuntime().getCurrentContext() ) );
        }

    }
}// ASN1
