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


import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x500.X500Name;

import org.jruby.util.SafePropertyAccessor;

/**
 * Contains most of the functionality that beings with X509 in
 * crypty/x509/x509_def.c, crypty/x509/x509_txt.c and others.
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public abstract class X509Utils {

    private X509Utils() {}

    /**
     * c: X509_get_default_private_dir
     */
    public static String getDefaultPrivateDir() {
        return X509_PRIVATE_DIR;
    }

    /**
     * c: X509_get_default_cert_area
     */
    public static String getDefaultCertificateArea() {
        return X509_CERT_AREA;
    }

    /**
     * c: X509_get_default_cert_dir
     */
    public static String getDefaultCertificateDirectory() {
        return X509_CERT_DIR;
    }

    /**
     * c: X509_get_default_cert_file
     */
    public static String getDefaultCertificateFile() {
        return X509_CERT_FILE;
    }

    /**
     * c: X509_get_default_cert_dir_env
     */
    public static String getDefaultCertificateDirectoryEnvironment() {
        return X509_CERT_DIR_EVP;
    }

    /**
     * c: X509_get_default_cert_file_env
     */
    public static String getDefaultCertificateFileEnvironment() {
        return X509_CERT_FILE_EVP;
    }

    /**
     * c: X509_verify_cert_error_string
     */
    public static String verifyCertificateErrorString(final int error) {
        switch (error) {
            case V_OK:
                return("ok");
            case V_ERR_UNABLE_TO_GET_ISSUER_CERT:
                return("unable to get issuer certificate");
            case V_ERR_UNABLE_TO_GET_CRL:
                return("unable to get certificate CRL");
            case V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
                return("unable to decrypt certificate's signature");
            case V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
                return("unable to decrypt CRL's signature");
            case V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
                return("unable to decode issuer public key");
            case V_ERR_CERT_SIGNATURE_FAILURE:
                return("certificate signature failure");
            case V_ERR_CRL_SIGNATURE_FAILURE:
                return("CRL signature failure");
            case V_ERR_CERT_NOT_YET_VALID:
                return("certificate is not yet valid");
            case V_ERR_CRL_NOT_YET_VALID:
                return("CRL is not yet valid");
            case V_ERR_CERT_HAS_EXPIRED:
                return("certificate has expired");
            case V_ERR_CRL_HAS_EXPIRED:
                return("CRL has expired");
            case V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
                return("format error in certificate's notBefore field");
            case V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
                return("format error in certificate's notAfter field");
            case V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
                return("format error in CRL's lastUpdate field");
            case V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
                return("format error in CRL's nextUpdate field");
            case V_ERR_OUT_OF_MEM:
                return("out of memory");
            case V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                return("self signed certificate");
            case V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                return("self signed certificate in certificate chain");
            case V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                return("unable to get local issuer certificate");
            case V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                return("unable to verify the first certificate");
            case V_ERR_CERT_CHAIN_TOO_LONG:
                return("certificate chain too long");
            case V_ERR_CERT_REVOKED:
                return("certificate revoked");
            case V_ERR_INVALID_CA:
                return ("invalid CA certificate");
            case V_ERR_PATH_LENGTH_EXCEEDED:
                return ("path length constraint exceeded");
            case V_ERR_INVALID_PURPOSE:
                return ("unsupported certificate purpose");
            case V_ERR_CERT_UNTRUSTED:
                return ("certificate not trusted");
            case V_ERR_CERT_REJECTED:
                return ("certificate rejected");
            case V_ERR_SUBJECT_ISSUER_MISMATCH:
                return("subject issuer mismatch");
            case V_ERR_AKID_SKID_MISMATCH:
                return("authority and subject key identifier mismatch");
            case V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
                return("authority and issuer serial number mismatch");
            case V_ERR_KEYUSAGE_NO_CERTSIGN:
                return("key usage does not include certificate signing");
            case V_ERR_UNABLE_TO_GET_CRL_ISSUER:
                return("unable to get CRL issuer certificate");
            case V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                return("unhandled critical extension");
            case V_ERR_KEYUSAGE_NO_CRL_SIGN:
                return("key usage does not include CRL signing");
            case V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
                return("unhandled critical CRL extension");
            case V_ERR_INVALID_NON_CA:
                return ("invalid non-CA certificate (has CA markings)");
            case V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
                return("proxy path length constraint exceeded");
            case V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
                return("key usage does not include digital signature");
            case V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
                return("proxy cerificates not allowed, please set the appropriate flag");
            case V_ERR_INVALID_EXTENSION:
                return("invalid or inconsistent certificate extension");
            case V_ERR_INVALID_POLICY_EXTENSION:
                return("invalid or inconsistent certificate policy extension");
            case V_ERR_NO_EXPLICIT_POLICY:
                return("no explicit policy");
            case V_ERR_APPLICATION_VERIFICATION:
                return("application verification failure");
            case V_ERR_PATH_LOOP:
                return("Path Loop");
            case V_ERR_HOSTNAME_MISMATCH:
                return("Hostname mismatch");
            case V_ERR_EMAIL_MISMATCH:
                return("Email address mismatch");
            case V_ERR_IP_ADDRESS_MISMATCH:
                return("IP address mismatch");
        default:
                return "error number " + error;
        }
    }

    static ASN1Primitive get(DEROctetString str) throws IOException {
        return get( str.getOctets() );
    }

    static ASN1Primitive get(final byte[] input) throws IOException {
        return new ASN1InputStream(input).readObject();
    }

    /*
     * c: X509_check_issued + x509_likely_issued + x509_signing_allowed
     */
    static int checkIfIssuedBy(final X509AuxCertificate issuer,
        final X509AuxCertificate subject) throws IOException {

        if ( ! issuer.getSubjectX500Principal().equals(subject.getIssuerX500Principal()) ) {
            return V_ERR_SUBJECT_ISSUER_MISMATCH;
        }

        if ( subject.getExtensionValue("2.5.29.35") != null ) { //authorityKeyID
            // I hate ASN1 and DER
            Object key = get(subject.getExtensionValue("2.5.29.35"));
            if ( ! (key instanceof ASN1Sequence) ) key = get( (DEROctetString) key );

            final ASN1Sequence seq = (ASN1Sequence) key;
            final AuthorityKeyIdentifier sakid;
            if ( seq.size() == 1 && (seq.getObjectAt(0) instanceof ASN1OctetString) ) {
                sakid = AuthorityKeyIdentifier.getInstance(new DLSequence(new DERTaggedObject(0, seq.getObjectAt(0))));
            } else {
                sakid = AuthorityKeyIdentifier.getInstance(seq);
            }

            if ( sakid.getKeyIdentifier() != null ) {
                if ( issuer.getExtensionValue("2.5.29.14") != null ) {
                    DEROctetString der = (DEROctetString) get(issuer.getExtensionValue("2.5.29.14"));
                    SubjectKeyIdentifier iskid = SubjectKeyIdentifier.getInstance(get(der.getOctets()));
                    if ( iskid.getKeyIdentifier() != null ) {
                        if ( ! Arrays.equals( sakid.getKeyIdentifier(), iskid.getKeyIdentifier() ) ) {
                            return V_ERR_AKID_SKID_MISMATCH;
                        }
                    }
                }
            }

            final BigInteger serialNumber = sakid.getAuthorityCertSerialNumber();
            if ( serialNumber != null && ! serialNumber.equals(issuer.getSerialNumber()) ) {
                return V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
            }

            if ( sakid.getAuthorityCertIssuer() != null ) {
                GeneralName[] gens = sakid.getAuthorityCertIssuer().getNames();
                X500Name x500Name = null;
                for ( int i = 0; i < gens.length; i++ ) {
                    if ( gens[i].getTagNo() == GeneralName.directoryName ) {
                        ASN1Encodable name = gens[i].getName();
                        if ( name instanceof X500Name ) {
                            x500Name = (X500Name) name;
                        } else if ( name instanceof ASN1Sequence ) {
                            x500Name = X500Name.getInstance((ASN1Sequence) name);
                        } else {
                            throw new RuntimeException("unknown name type: " + name);
                        }
                        break;
                    }
                }
                if ( x500Name != null ) {
                    if ( ! new Name(x500Name).equalTo( issuer.getIssuerX500Principal() ) ) {
                        return V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
                    }
                }
            }
        }

        final boolean[] keyUsage = issuer.getKeyUsage();
        if ( subject.getExtensionValue("1.3.6.1.5.5.7.1.14") != null ) {
            if ( keyUsage != null && ! keyUsage[0] ) { // KU_DIGITAL_SIGNATURE
                return V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
            }
        }
        else if ( keyUsage != null && ! keyUsage[5] ) { // KU_KEY_CERT_SIGN
            return V_ERR_KEYUSAGE_NO_CERTSIGN;
        }

        return V_OK;
    }

    public static final String OPENSSLDIR;

    public static final String X509_CERT_AREA;
    public static final String X509_CERT_DIR;
    public static final String X509_CERT_FILE;
    public static final String X509_PRIVATE_DIR;

    static {
        // roughly following the ideas from https://www.happyassassin.net/2015/01/12/a-note-about-ssltls-trusted-certificate-stores-and-platforms/
        // and falling back to trust store from java to be on the save side

        // TODO usability in limited environments should be tested/reviewed
        final String JAVA_HOME = SafePropertyAccessor.getProperty("java.home", "");

        // if the default files/dirs exist we use them. with this a switch
        // from MRI to JRuby produces the same results. otherwise we use the
        // certs from JAVA_HOME.
        final String LINUX_CERT_AREA = "/etc/ssl";
        final String MACOS_CERT_AREA = "/System/Library/OpenSSL";

        String certArea, certDir, privateDir;
        String maybeCertFile;
        String maybePkiCertFile = "/etc/pki/tls/certs/ca-bundle.crt";
        try {
            if (new File(LINUX_CERT_AREA).exists()) {
                certArea = LINUX_CERT_AREA;
                certDir = certArea + "/certs";
                privateDir = certArea + "/private";
                maybeCertFile = certDir + "/cert.pem";
            }
            else if (new File(MACOS_CERT_AREA).exists()) {
                certArea = MACOS_CERT_AREA;
                certDir = certArea + "/certs";
                privateDir = certArea + "/private";
                maybeCertFile = certArea + "/cert.pem";
            }
            else {
                certArea = JAVA_HOME + "/lib/security";
                certDir = certArea;
                privateDir = certArea;
                maybeCertFile = maybePkiCertFile;
            }
        }
        catch (SecurityException e) {
            maybeCertFile = null; maybePkiCertFile = null;
            privateDir = certDir = certArea = JAVA_HOME + "/lib/security";
        }

        X509_CERT_AREA = certArea;
        X509_CERT_DIR = certDir;
        X509_PRIVATE_DIR = privateDir;

        if (maybePkiCertFile != null && new File(maybePkiCertFile).exists()) {
            X509_CERT_FILE = maybePkiCertFile;
        }
        else if (maybeCertFile != null && new File(maybeCertFile).exists()) {
            X509_CERT_FILE = maybeCertFile;
        }
        else {
            X509_CERT_FILE = JAVA_HOME + "/lib/security/cacerts";
        }

        // keep it with some meaninful content as it is a public constant
        OPENSSLDIR = X509_CERT_AREA;
    }

    public static final String X509_CERT_DIR_EVP = "SSL_CERT_DIR";
    public static final String X509_CERT_FILE_EVP = "SSL_CERT_FILE";

    public static final int X509_LU_RETRY=-1;
    public static final int X509_LU_FAIL=0;
    public static final int X509_LU_X509=1;
    public static final int X509_LU_CRL=2;
    public static final int X509_LU_PKEY=3;

    public static final int X509_FILETYPE_PEM = 1;
    public static final int X509_FILETYPE_ASN1 = 2;
    public static final int X509_FILETYPE_DEFAULT = 3;

    public static final int X509_L_FILE_LOAD = 1;
    public static final int X509_L_ADD_DIR = 2;

    public static final int V_OK = 0;
    public static final int V_ERR_UNSPECIFIED = 1;
    public static final int	V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
    public static final int	V_ERR_UNABLE_TO_GET_CRL = 3;
    public static final int	V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;
    public static final int	V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;
    public static final int	V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;
    public static final int	V_ERR_CERT_SIGNATURE_FAILURE = 7;
    public static final int	V_ERR_CRL_SIGNATURE_FAILURE = 8;
    public static final int	V_ERR_CERT_NOT_YET_VALID = 9;
    public static final int	V_ERR_CERT_HAS_EXPIRED = 10;
    public static final int	V_ERR_CRL_NOT_YET_VALID = 11;
    public static final int	V_ERR_CRL_HAS_EXPIRED = 12;
    public static final int	V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;
    public static final int	V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;
    public static final int	V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;
    public static final int	V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;
    public static final int	V_ERR_OUT_OF_MEM = 17;
    public static final int	V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
    public static final int	V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
    public static final int	V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
    public static final int	V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;
    public static final int	V_ERR_CERT_CHAIN_TOO_LONG = 22;
    public static final int	V_ERR_CERT_REVOKED = 23;
    public static final int	V_ERR_INVALID_CA = 24;
    public static final int	V_ERR_PATH_LENGTH_EXCEEDED = 25;
    public static final int	V_ERR_INVALID_PURPOSE = 26;
    public static final int	V_ERR_CERT_UNTRUSTED = 27;
    public static final int	V_ERR_CERT_REJECTED = 28;

    public static final int	V_ERR_SUBJECT_ISSUER_MISMATCH = 29;
    public static final int	V_ERR_AKID_SKID_MISMATCH = 30;
    public static final int	V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
    public static final int	V_ERR_KEYUSAGE_NO_CERTSIGN = 32;

    public static final int	V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
    public static final int	V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
    public static final int	V_ERR_KEYUSAGE_NO_CRL_SIGN = 35;
    public static final int	V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;
    public static final int	V_ERR_INVALID_NON_CA = 37;
    public static final int	V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38;
    public static final int	V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;
    public static final int	V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40;

    public static final int	V_ERR_INVALID_EXTENSION = 41;
    public static final int	V_ERR_INVALID_POLICY_EXTENSION = 42;
    public static final int	V_ERR_NO_EXPLICIT_POLICY = 43;

    public static final int	V_ERR_APPLICATION_VERIFICATION = 50;

    /* Another issuer check debug option */
    public static final int	V_ERR_PATH_LOOP = 55;

    /* Host, email and IP check errors */
    public static final int	V_ERR_HOSTNAME_MISMATCH = 62;
    public static final int	V_ERR_EMAIL_MISMATCH = 63;
    public static final int	V_ERR_IP_ADDRESS_MISMATCH = 64;

    // ...

    /* security level errors */
    //public static final int	V_ERR_EE_KEY_TOO_SMALL = 66;
    //public static final int	V_ERR_CA_KEY_TOO_SMALL = 67;
    //public static final int	V_ERR_CA_MD_TOO_WEAK = 68;
    /* Caller error */
    public static final int	V_ERR_INVALID_CALL = 69;
    /* Issuer lookup error */
    public static final int	V_ERR_STORE_LOOKUP = 70;
    /* Certificate transparency */
    //public static final int	V_ERR_NO_VALID_SCTS = 71;

    /* Certificate verify flags */
    public static final int	V_FLAG_CB_ISSUER_CHECK = 0x0 /* Deprecated */;
    public static final int	V_FLAG_USE_CHECK_TIME = 0x2;
    public static final int	V_FLAG_CRL_CHECK = 0x4;
    public static final int	V_FLAG_CRL_CHECK_ALL = 0x8;
    public static final int	V_FLAG_IGNORE_CRITICAL = 0x10;
    public static final int	V_FLAG_X509_STRICT  = 0x20;
    public static final int	V_FLAG_ALLOW_PROXY_CERTS = 0x40;
    public static final int V_FLAG_POLICY_CHECK = 0x80;
    public static final int V_FLAG_EXPLICIT_POLICY = 0x100;
    public static final int	V_FLAG_INHIBIT_ANY = 0x200;
    public static final int V_FLAG_INHIBIT_MAP = 0x400;
    public static final int V_FLAG_NOTIFY_POLICY = 0x800;
    // NOTE: these aren't implemented:
    /* Extended CRL features such as indirect CRLs, alternate CRL signing keys */
    //public static final int V_FLAG_EXTENDED_CRL_SUPPORT = 0x1000;
    /* Delta CRL support */
    //public static final int V_FLAG_USE_DELTAS = 0x2000;
    /* Check self-signed CA signature */
    public static final int V_FLAG_CHECK_SS_SIGNATURE = 0x4000;
    /* Use trusted store first */
    public static final int V_FLAG_TRUSTED_FIRST = 0x8000;

    // ...

    /* Allow partial chains if at least one certificate is in trusted store */
    public static final int V_FLAG_PARTIAL_CHAIN = 0x80000;
    /*
     * If the initial chain is not trusted, do not attempt to build an alternative
     * chain. Alternate chain checking was introduced in 1.1.0. Setting this flag
     * will force the behaviour to match that of previous versions.
     */
    public static final int V_FLAG_NO_ALT_CHAINS = 0x100000;
    /* Do not check certificate/CRL validity against current time */
    public static final int V_FLAG_NO_CHECK_TIME = 0x200000;


    /* Internal use: mask of policy related options */
    public static final int V_FLAG_POLICY_MASK = (V_FLAG_POLICY_CHECK |
                                                  V_FLAG_EXPLICIT_POLICY |
                                                  V_FLAG_INHIBIT_ANY |
                                                  V_FLAG_INHIBIT_MAP);

    public static final int X509_R_BAD_X509_FILETYPE = 100;
    public static final int X509_R_BASE64_DECODE_ERROR = 118;
    public static final int X509_R_CANT_CHECK_DH_KEY = 114;
    public static final int X509_R_CERT_ALREADY_IN_HASH_TABLE = 101;
    public static final int X509_R_ERR_ASN1_LIB = 102;
    public static final int X509_R_INVALID_DIRECTORY = 113;
    public static final int X509_R_INVALID_FIELD_NAME = 119;
    public static final int X509_R_INVALID_TRUST = 123;
    public static final int X509_R_KEY_TYPE_MISMATCH = 115;
    public static final int X509_R_KEY_VALUES_MISMATCH = 116;
    public static final int X509_R_LOADING_CERT_DIR = 103;
    public static final int X509_R_LOADING_DEFAULTS = 104;
    public static final int X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105;
    public static final int X509_R_SHOULD_RETRY = 106;
    public static final int X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107;
    public static final int X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108;
    public static final int X509_R_UNKNOWN_KEY_TYPE = 117;
    public static final int X509_R_UNKNOWN_NID = 109;
    public static final int X509_R_UNKNOWN_PURPOSE_ID = 121;
    public static final int X509_R_UNKNOWN_TRUST_ID = 120;
    public static final int X509_R_UNSUPPORTED_ALGORITHM = 111;
    public static final int X509_R_WRONG_LOOKUP_TYPE = 112;
    public static final int X509_R_WRONG_TYPE = 122;
    public static final int X509_R_METHOD_NOT_SUPPORTED = 124;
    public static final int X509_R_PUBLIC_KEY_DECODE_ERROR = 125;
    public static final int X509_R_PUBLIC_KEY_ENCODE_ERROR = 126;

    public static final int X509_VP_FLAG_DEFAULT = 0x1;
    public static final int X509_VP_FLAG_OVERWRITE = 0x2;
    public static final int X509_VP_FLAG_RESET_FLAGS = 0x4;
    public static final int X509_VP_FLAG_LOCKED = 0x8;
    public static final int X509_VP_FLAG_ONCE = 0x10;

    public static final int X509_PURPOSE_SSL_CLIENT = 1;
    public static final int X509_PURPOSE_SSL_SERVER = 2;
    public static final int X509_PURPOSE_NS_SSL_SERVER = 3;
    public static final int X509_PURPOSE_SMIME_SIGN = 4;
    public static final int X509_PURPOSE_SMIME_ENCRYPT = 5;
    public static final int X509_PURPOSE_CRL_SIGN = 6;
    public static final int X509_PURPOSE_ANY = 7;
    public static final int X509_PURPOSE_OCSP_HELPER = 8;

    public static final int X509_PURPOSE_DYNAMIC = 0x1;
    public static final int X509_PURPOSE_DYNAMIC_NAME = 0x2;

    public static final int X509_PURPOSE_MIN = 1;
    public static final int X509_PURPOSE_MAX = 8;

    public static final int X509_TRUST_DEFAULT = 0; /* Only valid in purpose settings */

    public static final int X509_TRUST_COMPAT = 1;
    public static final int X509_TRUST_SSL_CLIENT = 2;
    public static final int X509_TRUST_SSL_SERVER = 3;
    public static final int X509_TRUST_EMAIL = 4;
    public static final int X509_TRUST_OBJECT_SIGN = 5;
    public static final int X509_TRUST_OCSP_SIGN = 6;
    public static final int X509_TRUST_OCSP_REQUEST = 7;
    public static final int X509_TRUST_TSA = 8;

    public static final int X509_TRUST_MIN = 1;
    public static final int X509_TRUST_MAX = 8;

    /* trust_flags values */
    public static final int X509_TRUST_DYNAMIC = (1 << 0);
    public static final int X509_TRUST_DYNAMIC_NAME = (1 << 1);
    /* No compat trust if self-signed, preempts "DO_SS" */
    public static final int X509_TRUST_NO_SS_COMPAT = (1 << 2);
    /* Compat trust if no explicit accepted trust EKUs */
    public static final int X509_TRUST_DO_SS_COMPAT = (1 << 3);
    /* Accept "anyEKU" as a wildcard rejection OID and as a wildcard trust OID */
    public static final int X509_TRUST_OK_ANY_EKU = (1 << 4);

    public static final int X509_TRUST_TRUSTED = 1;
    public static final int X509_TRUST_REJECTED = 2;
    public static final int X509_TRUST_UNTRUSTED = 3;

    public static final int NS_SSL_CLIENT=0x80;
    public static final int NS_SSL_SERVER=0x40;
    public static final int NS_SMIME=0x20;
    public static final int NS_OBJSIGN=0x10;
    public static final int NS_SSL_CA=0x04;
    public static final int NS_SMIME_CA=0x02;
    public static final int NS_OBJSIGN_CA=0x01;
    public static final int NS_ANY_CA=(NS_SSL_CA|NS_SMIME_CA|NS_OBJSIGN_CA);

    public static final int X509V3_R_BAD_IP_ADDRESS = 118;
    public static final int X509V3_R_BAD_OBJECT = 119;
    public static final int X509V3_R_BN_DEC2BN_ERROR = 100;
    public static final int X509V3_R_BN_TO_ASN1_INTEGER_ERROR = 101;
    public static final int X509V3_R_DIRNAME_ERROR = 149;
    public static final int X509V3_R_DUPLICATE_ZONE_ID = 133;
    public static final int X509V3_R_ERROR_CONVERTING_ZONE = 131;
    public static final int X509V3_R_ERROR_CREATING_EXTENSION = 144;
    public static final int X509V3_R_ERROR_IN_EXTENSION = 128;
    public static final int X509V3_R_EXPECTED_A_SECTION_NAME = 137;
    public static final int X509V3_R_EXTENSION_EXISTS = 145;
    public static final int X509V3_R_EXTENSION_NAME_ERROR = 115;
    public static final int X509V3_R_EXTENSION_NOT_FOUND = 102;
    public static final int X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED = 103;
    public static final int X509V3_R_EXTENSION_VALUE_ERROR = 116;
    public static final int X509V3_R_ILLEGAL_EMPTY_EXTENSION = 151;
    public static final int X509V3_R_ILLEGAL_HEX_DIGIT = 113;
    public static final int X509V3_R_INCORRECT_POLICY_SYNTAX_TAG = 152;
    public static final int X509V3_R_INVALID_BOOLEAN_STRING = 104;
    public static final int X509V3_R_INVALID_EXTENSION_STRING = 105;
    public static final int X509V3_R_INVALID_NAME = 106;
    public static final int X509V3_R_INVALID_NULL_ARGUMENT = 107;
    public static final int X509V3_R_INVALID_NULL_NAME = 108;
    public static final int X509V3_R_INVALID_NULL_VALUE = 109;
    public static final int X509V3_R_INVALID_NUMBER = 140;
    public static final int X509V3_R_INVALID_NUMBERS = 141;
    public static final int X509V3_R_INVALID_OBJECT_IDENTIFIER = 110;
    public static final int X509V3_R_INVALID_OPTION = 138;
    public static final int X509V3_R_INVALID_POLICY_IDENTIFIER = 134;
    public static final int X509V3_R_INVALID_PROXY_POLICY_SETTING = 153;
    public static final int X509V3_R_INVALID_PURPOSE = 146;
    public static final int X509V3_R_INVALID_SECTION = 135;
    public static final int X509V3_R_INVALID_SYNTAX = 143;
    public static final int X509V3_R_ISSUER_DECODE_ERROR = 126;
    public static final int X509V3_R_MISSING_VALUE = 124;
    public static final int X509V3_R_NEED_ORGANIZATION_AND_NUMBERS = 142;
    public static final int X509V3_R_NO_CONFIG_DATABASE = 136;
    public static final int X509V3_R_NO_ISSUER_CERTIFICATE = 121;
    public static final int X509V3_R_NO_ISSUER_DETAILS = 127;
    public static final int X509V3_R_NO_POLICY_IDENTIFIER = 139;
    public static final int X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED = 154;
    public static final int X509V3_R_NO_PUBLIC_KEY = 114;
    public static final int X509V3_R_NO_SUBJECT_DETAILS = 125;
    public static final int X509V3_R_ODD_NUMBER_OF_DIGITS = 112;
    public static final int X509V3_R_OPERATION_NOT_DEFINED = 148;
    public static final int X509V3_R_OTHERNAME_ERROR = 147;
    public static final int X509V3_R_POLICY_LANGUAGE_ALREADTY_DEFINED = 155;
    public static final int X509V3_R_POLICY_PATH_LENGTH = 156;
    public static final int X509V3_R_POLICY_PATH_LENGTH_ALREADTY_DEFINED = 157;
    public static final int X509V3_R_POLICY_SYNTAX_NOT_CURRENTLY_SUPPORTED = 158;
    public static final int X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY = 159;
    public static final int X509V3_R_SECTION_NOT_FOUND = 150;
    public static final int X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS = 122;
    public static final int X509V3_R_UNABLE_TO_GET_ISSUER_KEYID = 123;
    public static final int X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT = 111;
    public static final int X509V3_R_UNKNOWN_EXTENSION = 129;
    public static final int X509V3_R_UNKNOWN_EXTENSION_NAME = 130;
    public static final int X509V3_R_UNKNOWN_OPTION = 120;
    public static final int X509V3_R_UNSUPPORTED_OPTION = 117;
    public static final int X509V3_R_USER_TOO_LONG = 132;

    public static final int ERR_R_FATAL=64;
    public static final int ERR_R_MALLOC_FAILURE=(1|ERR_R_FATAL);
    public static final int ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED=(2|ERR_R_FATAL);
    public static final int ERR_R_PASSED_NULL_PARAMETER=(3|ERR_R_FATAL);
    public static final int ERR_R_INTERNAL_ERROR=(4|ERR_R_FATAL);
    public static final int ERR_R_DISABLED=(5|ERR_R_FATAL);

    public static final int EXFLAG_BCONS=0x1;
    //public static final int EXFLAG_KUSAGE=0x2;
    public static final int EXFLAG_XKUSAGE=0x4;
    //public static final int EXFLAG_NSCERT=0x8;

    public static final int EXFLAG_CA=0x10;
    public static final int EXFLAG_SI=0x20; /* self-issued, maybe not self-signed */
    public static final int EXFLAG_V1=0x40;
    //public static final int EXFLAG_INVALID=0x80;
    /* EXFLAG_SET is set to indicate that some values have been precomputed */
    //public static final int EXFLAG_SET=0x100;
    //public static final int EXFLAG_CRITICAL=0x200;
    public static final int EXFLAG_PROXY=0x400;

    //public static final int EXFLAG_INVALID_POLICY=0x800;
    //public static final int EXFLAG_FRESHEST=0x1000;
    public static final int EXFLAG_SS=0x2000; /* cert is apparently self-signed */

    public static final int XKU_SSL_SERVER=0x1;
    public static final int XKU_SSL_CLIENT=0x2;
    public static final int XKU_SMIME=0x4;
    public static final int XKU_CODE_SIGN=0x8;
    public static final int XKU_SGC=0x8;
    public static final int XKU_OCSP_SIGN=0x20;
    public static final int XKU_TIMESTAMP=0x40;
    public static final int XKU_DVCS=0x80;
    public static final int XKU_ANYEKU=0x100;

    public static final int POLICY_FLAG_ANY_POLICY = 0x2;
}// X509
