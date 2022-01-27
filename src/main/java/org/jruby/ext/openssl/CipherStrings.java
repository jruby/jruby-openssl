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
 * Copyright (C) 2008 Ola Bini <ola.bini@gmail.com>
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.jruby.ext.openssl.SSL.SSL3_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_1_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_2_VERSION;

/**
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class CipherStrings {

    public final static String SSL2_TXT_DES_64_CFB64_WITH_MD5_1 = "DES-CFB-M1";
    public final static String SSL2_TXT_NULL_WITH_MD5 = "NULL-MD5";
    public final static String SSL2_TXT_RC4_128_WITH_MD5 = "RC4-MD5";
    public final static String SSL2_TXT_RC4_128_EXPORT40_WITH_MD5 = "EXP-RC4-MD5";
    public final static String SSL2_TXT_RC2_128_CBC_WITH_MD5 = "RC2-CBC-MD5";
    public final static String SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = "EXP-RC2-CBC-MD5";
    public final static String SSL2_TXT_IDEA_128_CBC_WITH_MD5 = "IDEA-CBC-MD5";
    public final static String SSL2_TXT_DES_64_CBC_WITH_MD5 = "DES-CBC-MD5";
    public final static String SSL2_TXT_DES_64_CBC_WITH_SHA = "DES-CBC-SHA";
    public final static String SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5 = "DES-CBC3-MD5";
    public final static String SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA = "DES-CBC3-SHA";
    public final static String SSL2_TXT_RC4_64_WITH_MD5 = "RC4-64-MD5";
    public final static String SSL2_TXT_NULL = "NULL";

    public final static String SSL3_TXT_RSA_NULL_MD5 = "NULL-MD5";
    public final static String SSL3_TXT_RSA_NULL_SHA = "NULL-SHA";
    public final static String SSL3_TXT_RSA_RC4_40_MD5 = "EXP-RC4-MD5";
    public final static String SSL3_TXT_RSA_RC4_128_MD5 = "RC4-MD5";
    public final static String SSL3_TXT_RSA_RC4_128_SHA = "RC4-SHA";
    public final static String SSL3_TXT_RSA_RC2_40_MD5 = "EXP-RC2-CBC-MD5";
    public final static String SSL3_TXT_RSA_IDEA_128_SHA = "IDEA-CBC-SHA";
    public final static String SSL3_TXT_RSA_DES_40_CBC_SHA = "EXP-DES-CBC-SHA";
    public final static String SSL3_TXT_RSA_DES_64_CBC_SHA = "DES-CBC-SHA";
    public final static String SSL3_TXT_RSA_DES_192_CBC3_SHA = "DES-CBC3-SHA";
    public final static String SSL3_TXT_DH_DSS_DES_40_CBC_SHA = "EXP-DH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_DSS_DES_64_CBC_SHA = "DH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_DSS_DES_192_CBC3_SHA = "DH-DSS-DES-CBC3-SHA";
    public final static String SSL3_TXT_DH_RSA_DES_40_CBC_SHA = "EXP-DH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_RSA_DES_64_CBC_SHA = "DH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_RSA_DES_192_CBC3_SHA = "DH-RSA-DES-CBC3-SHA";
    public final static String SSL3_TXT_EDH_DSS_DES_40_CBC_SHA = "EXP-EDH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_DSS_DES_64_CBC_SHA = "EDH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA = "EDH-DSS-DES-CBC3-SHA";
    public final static String SSL3_TXT_EDH_RSA_DES_40_CBC_SHA = "EXP-EDH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_RSA_DES_64_CBC_SHA = "EDH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA = "EDH-RSA-DES-CBC3-SHA";
    public final static String SSL3_TXT_ADH_RC4_40_MD5 = "EXP-ADH-RC4-MD5";
    public final static String SSL3_TXT_ADH_RC4_128_MD5 = "ADH-RC4-MD5";
    public final static String SSL3_TXT_ADH_DES_40_CBC_SHA = "EXP-ADH-DES-CBC-SHA";
    public final static String SSL3_TXT_ADH_DES_64_CBC_SHA = "ADH-DES-CBC-SHA";
    public final static String SSL3_TXT_ADH_DES_192_CBC_SHA = "ADH-DES-CBC3-SHA";
    public final static String SSL3_TXT_FZA_DMS_NULL_SHA = "FZA-NULL-SHA";
    public final static String SSL3_TXT_FZA_DMS_FZA_SHA = "FZA-FZA-CBC-SHA";
    public final static String SSL3_TXT_FZA_DMS_RC4_SHA = "FZA-RC4-SHA";
    public final static String SSL3_TXT_KRB5_DES_64_CBC_SHA = "KRB5-DES-CBC-SHA";
    public final static String SSL3_TXT_KRB5_DES_192_CBC3_SHA = "KRB5-DES-CBC3-SHA";
    public final static String SSL3_TXT_KRB5_RC4_128_SHA = "KRB5-RC4-SHA";
    public final static String SSL3_TXT_KRB5_IDEA_128_CBC_SHA = "KRB5-IDEA-CBC-SHA";
    public final static String SSL3_TXT_KRB5_DES_64_CBC_MD5 = "KRB5-DES-CBC-MD5";
    public final static String SSL3_TXT_KRB5_DES_192_CBC3_MD5 = "KRB5-DES-CBC3-MD5";
    public final static String SSL3_TXT_KRB5_RC4_128_MD5 = "KRB5-RC4-MD5";
    public final static String SSL3_TXT_KRB5_IDEA_128_CBC_MD5 = "KRB5-IDEA-CBC-MD5";
    public final static String SSL3_TXT_KRB5_DES_40_CBC_SHA = "EXP-KRB5-DES-CBC-SHA";
    public final static String SSL3_TXT_KRB5_RC2_40_CBC_SHA = "EXP-KRB5-RC2-CBC-SHA";
    public final static String SSL3_TXT_KRB5_RC4_40_SHA = "EXP-KRB5-RC4-SHA";
    public final static String SSL3_TXT_KRB5_DES_40_CBC_MD5 = "EXP-KRB5-DES-CBC-MD5";
    public final static String SSL3_TXT_KRB5_RC2_40_CBC_MD5 = "EXP-KRB5-RC2-CBC-MD5";
    public final static String SSL3_TXT_KRB5_RC4_40_MD5 = "EXP-KRB5-RC4-MD5";

    public final static String SSL_TXT_NULL_WITH_MD5 = SSL2_TXT_NULL_WITH_MD5;
    public final static String SSL_TXT_RC4_128_WITH_MD5 = SSL2_TXT_RC4_128_WITH_MD5;
    public final static String SSL_TXT_RC4_128_EXPORT40_WITH_MD5 = SSL2_TXT_RC4_128_EXPORT40_WITH_MD5;
    public final static String SSL_TXT_RC2_128_CBC_WITH_MD5 = SSL2_TXT_RC2_128_CBC_WITH_MD5;
    public final static String SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5;
    public final static String SSL_TXT_IDEA_128_CBC_WITH_MD5 = SSL2_TXT_IDEA_128_CBC_WITH_MD5;
    public final static String SSL_TXT_DES_64_CBC_WITH_MD5 = SSL2_TXT_DES_64_CBC_WITH_MD5;
    public final static String SSL_TXT_DES_64_CBC_WITH_SHA = SSL2_TXT_DES_64_CBC_WITH_SHA;
    public final static String SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 = SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5;
    public final static String SSL_TXT_DES_192_EDE3_CBC_WITH_SHA = SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA;

    public final static String SSL_TXT_KRB5_DES_64_CBC_SHA = SSL3_TXT_KRB5_DES_64_CBC_SHA;
    public final static String SSL_TXT_KRB5_DES_192_CBC3_SHA = SSL3_TXT_KRB5_DES_192_CBC3_SHA;
    public final static String SSL_TXT_KRB5_RC4_128_SHA = SSL3_TXT_KRB5_RC4_128_SHA;
    public final static String SSL_TXT_KRB5_IDEA_128_CBC_SHA = SSL3_TXT_KRB5_IDEA_128_CBC_SHA;
    public final static String SSL_TXT_KRB5_DES_64_CBC_MD5 = SSL3_TXT_KRB5_DES_64_CBC_MD5;
    public final static String SSL_TXT_KRB5_DES_192_CBC3_MD5 = SSL3_TXT_KRB5_DES_192_CBC3_MD5;
    public final static String SSL_TXT_KRB5_RC4_128_MD5 = SSL3_TXT_KRB5_RC4_128_MD5;
    public final static String SSL_TXT_KRB5_IDEA_128_CBC_MD5 = SSL3_TXT_KRB5_IDEA_128_CBC_MD5;

    public final static String SSL_TXT_KRB5_DES_40_CBC_SHA = SSL3_TXT_KRB5_DES_40_CBC_SHA;
    public final static String SSL_TXT_KRB5_RC2_40_CBC_SHA = SSL3_TXT_KRB5_RC2_40_CBC_SHA;
    public final static String SSL_TXT_KRB5_RC4_40_SHA = SSL3_TXT_KRB5_RC4_40_SHA;
    public final static String SSL_TXT_KRB5_DES_40_CBC_MD5 = SSL3_TXT_KRB5_DES_40_CBC_MD5;
    public final static String SSL_TXT_KRB5_RC2_40_CBC_MD5 = SSL3_TXT_KRB5_RC2_40_CBC_MD5;
    public final static String SSL_TXT_KRB5_RC4_40_MD5 = SSL3_TXT_KRB5_RC4_40_MD5;

    public final static String SSL_TXT_LOW = "LOW";
    public final static String SSL_TXT_MEDIUM = "MEDIUM";
    public final static String SSL_TXT_HIGH = "HIGH";
    public final static String SSL_TXT_kFZA = "kFZA";
    public final static String SSL_TXT_aFZA = "aFZA";
    public final static String SSL_TXT_eFZA = "eFZA";
    public final static String SSL_TXT_FZA = "FZA";

    public final static String SSL_TXT_aNULL = "aNULL";
    public final static String SSL_TXT_eNULL = "eNULL";
    public final static String SSL_TXT_NULL = "NULL";

    public final static String SSL_TXT_kKRB5 = "kKRB5";
    public final static String SSL_TXT_aKRB5 = "aKRB5";
    public final static String SSL_TXT_KRB5 = "KRB5";

    public final static String SSL_TXT_kRSA = "kRSA";
    public final static String SSL_TXT_kDHr = "kDHr";
    public final static String SSL_TXT_kDHd = "kDHd";
    public final static String SSL_TXT_kEDH = "kEDH"; /* alias for kDHE */
    public final static String SSL_TXT_kDHE = "kDHE";
    public final static String SSL_TXT_kEECDH = "kEECDH"; /* alias for kECDHE */
    public final static String SSL_TXT_kECDHE = "kECDHE";

    public final static String SSL_TXT_aRSA = "aRSA";
    public final static String SSL_TXT_aDSS = "aDSS";
    public final static String SSL_TXT_aDH = "aDH";
    public final static String SSL_TXT_aECDSA = "aECDSA";

    public final static String SSL_TXT_DSS = "DSS";
    public final static String SSL_TXT_DH = "DH";
    public final static String SSL_TXT_DHE = "DHE"; /* same as "kDHE:-ADH" */;
    public final static String SSL_TXT_EDH = "EDH"; /* alias for DHE */
    public final static String SSL_TXT_ADH = "ADH";
    public final static String SSL_TXT_RSA = "RSA";
    public final static String SSL_TXT_ECDH = "ECDH";
    public final static String SSL_TXT_EECDH = "EECDH"; /* alias for ECDHE" */
    public final static String SSL_TXT_ECDHE = "ECDHE"; /* same as "kECDHE:-AECDH" */
    public final static String SSL_TXT_AECDH = "AECDH";
    public final static String SSL_TXT_ECDSA = "ECDSA";
    //public final static String SSL_TXT_PSK = "PSK";
    //public final static String SSL_TXT_SRP = "SRP";

    public final static String SSL_TXT_DES = "DES";
    public final static String SSL_TXT_3DES = "3DES";
    public final static String SSL_TXT_RC4 = "RC4";
    public final static String SSL_TXT_RC2 = "RC2";
    public final static String SSL_TXT_IDEA = "IDEA";
    public final static String SSL_TXT_SEED = "SEED";
    public final static String SSL_TXT_AES128 = "AES128";
    public final static String SSL_TXT_AES256 = "AES256";
    public final static String SSL_TXT_AES = "AES";
    public final static String SSL_TXT_AES_GCM = "AESGCM";
    public final static String SSL_TXT_AES_CCM = "AESCCM";
    public final static String SSL_TXT_AES_CCM_8 = "AESCCM8";
    public final static String SSL_TXT_CAMELLIA128 = "CAMELLIA128";
    public final static String SSL_TXT_CAMELLIA256 = "CAMELLIA256";
    public final static String SSL_TXT_CAMELLIA = "CAMELLIA";
    public final static String SSL_TXT_CHACHA20 = "CHACHA20";
    public final static String SSL_TXT_GOST = "GOST89";
    public final static String SSL_TXT_ARIA = "ARIA";
    public final static String SSL_TXT_ARIA_GCM = "ARIAGCM";
    public final static String SSL_TXT_ARIA128 = "ARIA128";
    public final static String SSL_TXT_ARIA256 = "ARIA256";

    public final static String SSL_TXT_MD5 = "MD5";
    public final static String SSL_TXT_SHA1 = "SHA1";
    public final static String SSL_TXT_SHA = "SHA";/* same as "SHA1" */
    public final static String SSL_TXT_SHA256 = "SHA256";
    public final static String SSL_TXT_SHA384 = "SHA384";

    public final static String SSL_TXT_EXP = "EXP";
    public final static String SSL_TXT_EXPORT = "EXPORT";
    public final static String SSL_TXT_EXP40 = "EXPORT40";
    public final static String SSL_TXT_EXP56 = "EXPORT56";

    public final static String SSL_TXT_SSLV2 = "SSLv2";
    public final static String SSL_TXT_SSLV3 = "SSLv3";
    public final static String SSL_TXT_TLSV1 = "TLSv1";
    public final static String SSL_TXT_TLSV1_1 = "TLSv1.1";
    public final static String SSL_TXT_TLSV1_2 = "TLSv1.2";

    public final static String SSL_TXT_ALL = "ALL";

    public final static String SSL_TXT_ECC = "ECCdraft";

    public final static String SSL_TXT_CMPALL = "COMPLEMENTOFALL";
    public final static String SSL_TXT_CMPDEF = "COMPLEMENTOFDEFAULT";

    // "ALL:!aNULL:!eNULL:!SSLv2" is for OpenSSL 1.0.0 GA
    public final static String SSL_DEFAULT_CIPHER_LIST = "AES:ALL:!aNULL:!eNULL:!SSLv2:+RC4:@STRENGTH";
    /*
     * The following cipher list is used by default. It also is substituted when
     * an application-defined cipher list string starts with 'DEFAULT'.
     * This applies to ciphersuites for TLSv1.2 and below.
     */
    //public final static String SSL_DEFAULT_CIPHER_LIST = "ALL:!COMPLEMENTOFDEFAULT:!eNULL";
    /* This is the default set of TLSv1.3 ciphersuites */ // TODO REVIEW 1.3 cipher matching
    public final static String TLS_DEFAULT_CIPHERSUITES = "TLS_AES_256_GCM_SHA384:" +
                                                          "TLS_CHACHA20_POLY1305_SHA256:" +
                                                          "TLS_AES_128_GCM_SHA256";

    public final static long SSL_MKEY_MASK = 0x000000FFL;
    /* Bits for algorithm_mkey (key exchange algorithm) */
    /* RSA key exchange */
    public final static long SSL_kRSA = 0x00000001L;
    public final static long SSL_kDHr = 0x00000002L;
    public final static long SSL_kDHd = 0x00000004L;
    public final static long SSL_kFZA = 0x00000008L;
    /* tmp DH key no DH cert */
    public final static long SSL_kDHE = 0x00000010L;
    public final static long SSL_kEDH = SSL_kDHE; /* synonym */
    public final static long SSL_kKRB5 = 0x00000020L;
    public final static long SSL_kECDH = 0x00000040L;
    /* ephemeral ECDH */
    public final static long SSL_kECDHE = 0x00000080L;
    public final static long SSL_kEECDH = SSL_kECDHE; /* synonym */
    public final static long SSL_aNULL = 0x00000800L;
    public final static long SSL_AUTH_MASK = 0x00007F00L;
    public final static long SSL_EDH = (SSL_kEDH|(SSL_AUTH_MASK^SSL_aNULL));
    public final static long SSL_aRSA = 0x00000100L;
    public final static long SSL_aDSS = 0x00000200L;
    public final static long SSL_DSS = SSL_aDSS;
    public final static long SSL_aFZA = 0x00000400L;
    public final static long SSL_aDH = 0x00001000L;
    public final static long SSL_aKRB5 = 0x00002000L;
    public final static long SSL_aECDSA = 0x00004000L;
    public final static long SSL_eFZA = 0x00100000L;
    public final static long SSL_ADH = (SSL_kEDH|SSL_aNULL);
    public final static long SSL_RSA = (SSL_kRSA|SSL_aRSA);
    public final static long SSL_DH = (SSL_kDHr|SSL_kDHd|SSL_kEDH);
    public final static long SSL_ECDH = (SSL_kECDH|SSL_kECDHE);
    public final static long SSL_FZA = (SSL_aFZA|SSL_kFZA|SSL_eFZA);
    public final static long SSL_KRB5 = (SSL_kKRB5|SSL_aKRB5);
    public final static long SSL_ENC_MASK = 0x043F8000L;

    /* Bits for algorithm_enc (symmetric encryption) */
    public final static long SSL_DES = 0x00000001L;
    public final static long SSL_3DES = 0x00000002L;
    public final static long SSL_RC4 = 0x00000004L;
    public final static long SSL_RC2 = 0x00000008L;
    public final static long SSL_IDEA = 0x00000010L;
    public final static long SSL_eNULL = 0x00000020L;
    //public final static long SSL_AES = 0x04000000L;
    public final static long SSL_AES128 = 0x00000040L;
    public final static long SSL_AES256 = 0x00000080L;
    public final static long SSL_CAMELLIA128 = 0x00000100L;
    public final static long SSL_CAMELLIA256 = 0x00000200L;
    public final static long SSL_eGOST2814789CNT = 0x00000400L;
    public final static long SSL_SEED = 0x00000800L;
    public final static long SSL_AES128GCM = 0x00001000L;
    public final static long SSL_AES256GCM = 0x00002000L;
    public final static long SSL_AES128CCM = 0x00004000L;
    public final static long SSL_AES256CCM = 0x00008000L;
    public final static long SSL_AES128CCM8 = 0x00010000L;
    public final static long SSL_AES256CCM8 = 0x00020000L;
    public final static long SSL_eGOST2814789CNT12 = 0x00040000L;
    public final static long SSL_CHACHA20POLY1305 = 0x00080000L;
    public final static long SSL_ARIA128GCM = 0x00100000L;
    public final static long SSL_ARIA256GCM = 0x00200000L;

    public final static long SSL_AESGCM = (SSL_AES128GCM | SSL_AES256GCM);
    public final static long SSL_AESCCM = (SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8);
    public final static long SSL_AES = (SSL_AES128|SSL_AES256|SSL_AESGCM|SSL_AESCCM);
    public final static long SSL_CAMELLIA = (SSL_CAMELLIA128|SSL_CAMELLIA256);
    public final static long SSL_CHACHA20 = (SSL_CHACHA20POLY1305);
    public final static long SSL_ARIAGCM = (SSL_ARIA128GCM | SSL_ARIA256GCM);
    public final static long SSL_ARIA = (SSL_ARIAGCM);

    /* Bits for algorithm_mac (symmetric authentication) */

    public final static long SSL_MAC_MASK = 0x00c00000L;
    /* Bits for algorithm_mac (symmetric authentication) */
    public final static long SSL_MD5 = 0x00400000L; // 0x00000001U
    public final static long SSL_SHA1 = 0x00800000L; // 0x00000002U
    public final static long SSL_SHA = (SSL_SHA1);
    //# define SSL_GOST94      0x00000004U
    //# define SSL_GOST89MAC   0x00000008U
    // NOTE: retrofitted (from 1.1.1) - expected not to used | and w SSL_MAC_MASK
    public final static long SSL_SHA256 = 0x00000010L;
    public final static long SSL_SHA384 = 0x00000020L;

    //public final static long SSL_SSL_MASK = 0x03000000L;
    public final static long SSL_SSLV2 = 0x01000000L;
    public final static long SSL_SSLV3 = 0x02000000L;
    public final static long SSL_TLSV1 = SSL_SSLV3;
    public final static long SSL_EXP_MASK = 0x00000003L;
    public final static long SSL_NOT_EXP = 0x00000001L;
    public final static long SSL_EXPORT = 0x00000002L;
    public final static long SSL_STRONG_MASK = 0x000000fcL;
    public final static long SSL_STRONG_NONE = 0x00000004L;
    public final static long SSL_EXP40 = 0x00000008L;
    public final static long SSL_MICRO = (SSL_EXP40);
    public final static long SSL_EXP56 = 0x00000010L;
    public final static long SSL_MINI = (SSL_EXP56);

    // NOTE: can not be adjusted until SSL_NOT_EXP is around!
    public final static long SSL_LOW = 0x00000020L; // 0x00000002U in OSSL 1.1
    public final static long SSL_MEDIUM = 0x00000040L; // 0x00000004U in OSSL 1.1
    public final static long SSL_HIGH = 0x00000080L; // 0x00000008U in OSSL 1.1
    public final static long SSL_FIPS = 0x00000100L; // 0x00000010U in OSSL 1.1
    public final static long SSL_NOT_DEFAULT = 0x00000200L; // 0x00000020U in OSSL 1.1 TODO: kares

    //public final static long SSL_ALL = 0xffffffffL;
    public final static long SSL_ALL_CIPHERS = (SSL_MKEY_MASK|SSL_AUTH_MASK|SSL_ENC_MASK|SSL_MAC_MASK); // TODO drop
    public final static long SSL_ALL_STRENGTHS = (SSL_EXP_MASK|SSL_STRONG_MASK); // TODO drop
    public final static long SSL_PKEY_RSA_ENC = 0;
    public final static long SSL_PKEY_RSA_SIGN = 1;
    public final static long SSL_PKEY_DSA_SIGN = 2;
    public final static long SSL_PKEY_DH_RSA = 3;
    public final static long SSL_PKEY_DH_DSA = 4;
    public final static long SSL_PKEY_ECC = 5;
    public final static long SSL_PKEY_NUM = 6;

    public final static long SSL3_CK_RSA_NULL_MD5 = 0x03000001;
    public final static long SSL3_CK_RSA_NULL_SHA = 0x03000002;
    public final static long SSL3_CK_RSA_RC4_40_MD5 = 0x03000003;
    public final static long SSL3_CK_RSA_RC4_128_MD5 = 0x03000004;
    public final static long SSL3_CK_RSA_RC4_128_SHA = 0x03000005;
    public final static long SSL3_CK_RSA_RC2_40_MD5 = 0x03000006;
    public final static long SSL3_CK_RSA_IDEA_128_SHA = 0x03000007;
    public final static long SSL3_CK_RSA_DES_40_CBC_SHA = 0x03000008;
    public final static long SSL3_CK_RSA_DES_64_CBC_SHA = 0x03000009;
    public final static long SSL3_CK_RSA_DES_192_CBC3_SHA = 0x0300000A;
    public final static long SSL3_CK_DH_DSS_DES_40_CBC_SHA = 0x0300000B;
    public final static long SSL3_CK_DH_DSS_DES_64_CBC_SHA = 0x0300000C;
    public final static long SSL3_CK_DH_DSS_DES_192_CBC3_SHA = 0x0300000D;
    public final static long SSL3_CK_DH_RSA_DES_40_CBC_SHA = 0x0300000E;
    public final static long SSL3_CK_DH_RSA_DES_64_CBC_SHA = 0x0300000F;
    public final static long SSL3_CK_DH_RSA_DES_192_CBC3_SHA = 0x03000010;
    public final static long SSL3_CK_EDH_DSS_DES_40_CBC_SHA = 0x03000011;
    public final static long SSL3_CK_EDH_DSS_DES_64_CBC_SHA = 0x03000012;
    public final static long SSL3_CK_EDH_DSS_DES_192_CBC3_SHA = 0x03000013;
    public final static long SSL3_CK_EDH_RSA_DES_40_CBC_SHA = 0x03000014;
    public final static long SSL3_CK_EDH_RSA_DES_64_CBC_SHA = 0x03000015;
    public final static long SSL3_CK_EDH_RSA_DES_192_CBC3_SHA = 0x03000016;
    public final static long SSL3_CK_ADH_RC4_40_MD5 = 0x03000017;
    public final static long SSL3_CK_ADH_RC4_128_MD5 = 0x03000018;
    public final static long SSL3_CK_ADH_DES_40_CBC_SHA = 0x03000019;
    public final static long SSL3_CK_ADH_DES_64_CBC_SHA = 0x0300001A;
    public final static long SSL3_CK_ADH_DES_192_CBC_SHA = 0x0300001B;
    public final static long SSL3_CK_FZA_DMS_NULL_SHA = 0x0300001C;
    public final static long SSL3_CK_FZA_DMS_FZA_SHA = 0x0300001D;
    public final static long SSL3_CK_KRB5_DES_64_CBC_SHA = 0x0300001E;
    public final static long SSL3_CK_KRB5_DES_192_CBC3_SHA = 0x0300001F;
    public final static long SSL3_CK_KRB5_RC4_128_SHA = 0x03000020;
    public final static long SSL3_CK_KRB5_IDEA_128_CBC_SHA = 0x03000021;
    public final static long SSL3_CK_KRB5_DES_64_CBC_MD5 = 0x03000022;
    public final static long SSL3_CK_KRB5_DES_192_CBC3_MD5 = 0x03000023;
    public final static long SSL3_CK_KRB5_RC4_128_MD5 = 0x03000024;
    public final static long SSL3_CK_KRB5_IDEA_128_CBC_MD5 = 0x03000025;
    public final static long SSL3_CK_KRB5_DES_40_CBC_SHA = 0x03000026;
    public final static long SSL3_CK_KRB5_RC2_40_CBC_SHA = 0x03000027;
    public final static long SSL3_CK_KRB5_RC4_40_SHA = 0x03000028;
    public final static long SSL3_CK_KRB5_DES_40_CBC_MD5 = 0x03000029;
    public final static long SSL3_CK_KRB5_RC2_40_CBC_MD5 = 0x0300002A;
    public final static long SSL3_CK_KRB5_RC4_40_MD5 = 0x0300002B;

    public final static long TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5 = 0x03000060;
    public final static long TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = 0x03000061;
    public final static long TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x03000062;
    public final static long TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x03000063;
    public final static long TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x03000064;
    public final static long TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x03000065;
    public final static long TLS1_CK_DHE_DSS_WITH_RC4_128_SHA = 0x03000066;
    public final static long TLS1_CK_RSA_WITH_AES_128_SHA = 0x0300002F;
    public final static long TLS1_CK_DH_DSS_WITH_AES_128_SHA = 0x03000030;
    public final static long TLS1_CK_DH_RSA_WITH_AES_128_SHA = 0x03000031;
    public final static long TLS1_CK_DHE_DSS_WITH_AES_128_SHA = 0x03000032;
    public final static long TLS1_CK_DHE_RSA_WITH_AES_128_SHA = 0x03000033;
    public final static long TLS1_CK_ADH_WITH_AES_128_SHA = 0x03000034;
    public final static long TLS1_CK_RSA_WITH_AES_256_SHA = 0x03000035;
    public final static long TLS1_CK_DH_DSS_WITH_AES_256_SHA = 0x03000036;
    public final static long TLS1_CK_DH_RSA_WITH_AES_256_SHA = 0x03000037;
    public final static long TLS1_CK_DHE_DSS_WITH_AES_256_SHA = 0x03000038;
    public final static long TLS1_CK_DHE_RSA_WITH_AES_256_SHA = 0x03000039;
    public final static long TLS1_CK_ADH_WITH_AES_256_SHA = 0x0300003A;
    public final static long TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA = 0x0300C001;
    public final static long TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA = 0x0300C002;
    public final static long TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C003;
    public final static long TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C004;
    public final static long TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C005;
    public final static long TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA = 0x0300C006;
    public final static long TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA = 0x0300C007;
    public final static long TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C008;
    public final static long TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C009;
    public final static long TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C00A;
    public final static long TLS1_CK_ECDH_RSA_WITH_NULL_SHA = 0x0300C00B;
    public final static long TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA = 0x0300C00C;
    public final static long TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA = 0x0300C00D;
    public final static long TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0x0300C00E;
    public final static long TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0x0300C00F;
    public final static long TLS1_CK_ECDHE_RSA_WITH_NULL_SHA = 0x0300C010;
    public final static long TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA = 0x0300C011;
    public final static long TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA = 0x0300C012;
    public final static long TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0x0300C013;
    public final static long TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0x0300C014;
    public final static long TLS1_CK_ECDH_anon_WITH_NULL_SHA = 0x0300C015;
    public final static long TLS_ECDH_anon_WITH_RC4_128_SHA = 0x0300C016;
    public final static long TLS_ECDH_anon_WITH_DES_192_CBC3_SHA = 0x0300C017;
    public final static long TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0x0300C018;
    public final static long TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0x0300C019;

    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5 = "EXP1024-RC4-MD5";
    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = "EXP1024-RC2-CBC-MD5";
    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DES-CBC-SHA";
    public final static String TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DHE-DSS-DES-CBC-SHA";
    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-RC4-SHA";
    public final static String TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-DHE-DSS-RC4-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA = "DHE-DSS-RC4-SHA";
    public final static String TLS1_TXT_RSA_WITH_AES_128_SHA = "AES128-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_128_SHA = "DH-DSS-AES128-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_128_SHA = "DH-RSA-AES128-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_128_SHA = "DHE-DSS-AES128-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_SHA = "DHE-RSA-AES128-SHA";
    public final static String TLS1_TXT_ADH_WITH_AES_128_SHA = "ADH-AES128-SHA";
    public final static String TLS1_TXT_RSA_WITH_AES_256_SHA = "AES256-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_256_SHA = "DH-DSS-AES256-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_256_SHA = "DH-RSA-AES256-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_256_SHA = "DHE-DSS-AES256-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_SHA = "DHE-RSA-AES256-SHA";
    public final static String TLS1_TXT_ADH_WITH_AES_256_SHA = "ADH-AES256-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA = "ECDH-ECDSA-NULL-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA = "ECDH-ECDSA-RC4-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = "ECDH-ECDSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA = "ECDHE-ECDSA-NULL-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA = "ECDHE-ECDSA-RC4-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = "ECDHE-ECDSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_NULL_SHA = "ECDH-RSA-NULL-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA = "ECDH-RSA-RC4-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA = "ECDH-RSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA = "ECDHE-RSA-NULL-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA = "ECDHE-RSA-RC4-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA = "ECDHE-RSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDH_anon_WITH_NULL_SHA = "AECDH-NULL-SHA";

    // struct ssl_cipher_st
    static final class Def implements Comparable<Def>, Cloneable {

        final boolean valid; // TODO NOT IMPLEMENTED!
        final String name;
        private final long id;

        final long algorithms;
        private final long algStrength;
        //final long algorithm2;
        final int algStrengthBits; // bits
        final int algBits; // alg_bits
        private final long mask;
        private final long algStrengthMask;

        // OpenSSL 1.1.1
        private long algorithm_mkey;
        private long algorithm_auth;
        private long algorithm_enc;
        private long algorithm_mac;
        private int min_tls; // "new" format using SSL.TLS_ constants
        private int max_tls; // "new" format using SSL.TLS_ constants

        // JOSSL extra
        private volatile String cipherSuite;

        Def(int valid, String name, long id, long algorithms, long algo_strength, long algorithm2, int strength_bits, int alg_bits, long mask, long maskStrength) {
            this.valid = valid != 0;
            this.name = name;
            this.id = id;
            this.algorithms = algorithms;
            this.algStrength = algo_strength;
            //this.algorithm2 = algorithm2;
            this.algStrengthBits = strength_bits;
            this.algBits = alg_bits;
            this.mask = mask;
            this.algStrengthMask = maskStrength;
        }

        Def(String name, long algorithms, long algo_strength, int strength_bits, int alg_bits, long mask, long maskStrength) {
            this.valid = true;
            this.name = name;
            this.id = 0;
            this.algorithms = algorithms;
            this.algStrength = algo_strength;
            this.algStrengthBits = strength_bits;
            this.algBits = alg_bits;
            this.mask = mask;
            this.algStrengthMask = maskStrength;
        }

        Def(int valid, String name, String stdname, /* RFC name */
            long id, /* uint32_t id, 4 bytes, first is version */
            /*
             * changed in 1.0.0: these four used to be portions of a single value
             * 'algorithms'
             */
            long algorithm_mkey, /* key exchange algorithm */
            long algorithm_auth, /* server authentication */
            long algorithm_enc,  /* symmetric encryption */
            long algorithm_mac,  /* symmetric authentication */
            int min_tls,         /* minimum SSL/TLS protocol version */
            int max_tls          /* maximum SSL/TLS protocol version */) {

            this.valid = valid != 0;
            this.name = name;
            this.id = id;

            this.algorithm_mkey = algorithm_mkey;
            this.algorithm_auth = algorithm_auth;
            this.algorithm_enc = algorithm_enc;
            this.algorithm_mac = algorithm_mac;
            this.min_tls = min_tls;
            this.max_tls = max_tls;

            this.algorithms = algorithm_mkey;
            this.algStrength = 0;
            this.algStrengthBits = 0;
            this.algBits = 0;

            this.mask = 0;
            this.algStrengthMask = 0;
        }


        public String getCipherSuite() {
            return cipherSuite;
        }

        Def setCipherSuite(final String suite) {
            String cipherSuite = this.cipherSuite;
            if (cipherSuite == null) {
                synchronized (this) {
                    if (this.cipherSuite == null) {
                        this.cipherSuite = suite;
                        return this;
                    }
                }
                cipherSuite = suite;
            }
            if (suite.equals(cipherSuite)) return this;
            try {
                Def clone = (Def) super.clone();
                clone.cipherSuite = suite;
                return clone;
            }
            catch (CloneNotSupportedException e) {
                throw new AssertionError(e); // won't happen
            }
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }

        @Override
        public boolean equals(Object other) {
            if ( this == other ) return true;
            if ( other instanceof Def ) {
                return this.name.equals(((Def) other).name);
            }
            return false;
        }

        @Override
        public int compareTo(final Def that) {
            return this.algStrengthBits - that.algStrengthBits;
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + '@' +
                   Integer.toHexString(System.identityHashCode(this)) +
                   '<' + name + '>';
        }

        // from ssl_cipher_apply_rule
        public boolean matches(Def current) {
//            ma = mask & cp->algorithms;
//            ma_s = mask_strength & cp->algo_strength;
//
//            // Select: if none of the mask bit was met from the
//            // cipher or not all of the bits were met, the
//            // selection does not apply.
//            if (((ma == 0) && (ma_s == 0)) ||
//                ((ma & algorithms) != ma) ||
//                ((ma_s & algo_strength) != ma_s))
//                continue; // does not apply
//            }
            final long ma = this.mask & current.algorithms;
            final long ma_s = this.algStrengthMask & current.algStrength;
            if ( ( ma == 0 && ma_s == 0 ) ||
                 ( (ma & this.algorithms) != ma ) ||
                 ( (ma_s & this.algStrength) != ma_s) ) {
                return false;
            }
            return true;
        }

    }

    static Collection<Def> matchingCiphers(final String cipherString, final String[] all,
        final boolean setSuite) {
        final List<Def> matchedList = new LinkedList<Def>();
        Set<Def> removed = null;

        /*
         * If the rule_string begins with DEFAULT, apply the default rule
         * before using the (possibly available) additional rules.
         * (Matching OpenSSL behaviour)
         */
        int offset = 0;
        final String[] parts = cipherString.split("[:, ]+");
        if ( parts.length >= 1 && "DEFAULT".equals(parts[0]) ) {
            final Collection<Def> matching = matchingCiphers(SSL_DEFAULT_CIPHER_LIST, all, setSuite);
            matchedList.addAll(matching);
            offset = offset + 1;
        }

        for ( int i = offset; i < parts.length; i++ ) {
            final String part = parts[i];

            if ( part.equals("@STRENGTH") ) {
                Collections.sort(matchedList); continue;
            }

            int index = 0;
            if (part.length() > 0) {
                switch ( part.charAt(0) ) {
                    case '!': case '+': case '-': index++; break;
                }
            }

            final Collection<Def> matching;
            final String[] defs = part.substring(index).split("[+]");
            if ( defs.length == 1 ) {
                matching = matchingExact(defs[0], all, setSuite);
            }
            else {
                matching = matching(defs, all, setSuite);
            }

            if ( matching != null ) {
                if ( index > 0 ) {
                    switch ( part.charAt(0) ) {
                        case '!':
                            matchedList.removeAll(matching);
                            if ( removed == null ) removed = new HashSet<Def>();
                            removed.addAll(matching);
                            break;
                        case '+': // '+' is for moving entry in the list
                            for ( final Def def : matching ) {
                                if ( removed == null || ! removed.contains(def) ) {
                                    if ( matchedList.remove(def) ) matchedList.add(def);
                                }
                            }
                            break;
                        case '-':
                            matchedList.removeAll(matching);
                            break;
                    }
                }
                else {
                    for ( final Def def : matching ) {
                        if ( removed == null || ! removed.contains(def) ) {
                            if ( ! matchedList.contains(def) ) matchedList.add(def);
                        }
                    }
                }
            }
        }

        return matchedList;
    }

    private static Collection<Def> matchingExact(final String name, final String[] all,
        final boolean setSuite) {
        final Def pattern = Definitions.get(name);
        if (pattern != null) {
            return matchingPattern(pattern, all, true, setSuite);
        }

        final Def def = CipherNames.get(name);
        if (def != null) {
            if (setSuite) {
                for (final String entry : all) {
                    if (name.equals(SuiteToOSSL.get(entry))) {
                        return Collections.singleton(def.setCipherSuite(entry));
                    }
                }
            } else {
                return Collections.singleton(def);
            }
        }
        return null; // Collections.emptyList();
    }

    private static Collection<Def> matching(final String[] defs, final String[] all,
        final boolean setSuite) {
        Collection<Def> matching = null;
        for ( final String name : defs ) {
            final Def pattern = Definitions.get(name);
            if ( pattern != null ) {
                if ( matching == null ) {
                    matching = matchingPattern(pattern, all, true, setSuite);
                }
                else {
                    matching.retainAll( matchingPattern(pattern, all, false, setSuite) );
                }
            }
        }
        return matching;
    }

    private static Collection<Def> matchingPattern(
        final Def pattern, final String[] all, final boolean useSet,
        final boolean setSuite) {
        final Collection<Def> matching;
        if ( useSet ) matching = new LinkedHashSet<Def>();
        else matching = new ArrayList<Def>(all.length);

        for ( final String entry : all ) {
            final String ossl = SuiteToOSSL.get(entry);
            if ( ossl != null ) {
                final Def def = CipherNames.get(ossl);
                if ( def != null && pattern.matches(def) ) {
                    if ( setSuite ) {
                        matching.add( def.setCipherSuite(entry) );
                    }
                    else {
                        matching.add( def );
                    }
                }
            }
        }
        return matching;
    }

    private final static Map<String, Def> Definitions;
    //private final static ArrayList<Def> Ciphers;
    private final static Map<String, Def> CipherNames;
    private final static Map<String, String> SuiteToOSSL;

    static {
        final String NULL = null;

        Object[] cipher_aliases[] = { // NOTE: copied from OpenSSL 1.1 (ssl_ciph.c)
            /* "ALL" doesn't include eNULL (must be specifically enabled) */
            {0, SSL_TXT_ALL, NULL, 0, 0, 0, ~SSL_eNULL},
            /* "COMPLEMENTOFALL" */
            {0, SSL_TXT_CMPALL, NULL, 0, 0, 0, SSL_eNULL},

            /*
             * "COMPLEMENTOFDEFAULT" (does *not* include ciphersuites not found in ALL!)
             */
            {0, SSL_TXT_CMPDEF, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT},

            /*
             * key exchange aliases (some of those using only a single bit here
             * combine multiple key exchange algs according to the RFCs, e.g. kDHE
             * combines DHE_DSS and DHE_RSA)
             */
            {0, SSL_TXT_kRSA, NULL, 0, SSL_kRSA},

            {0, SSL_TXT_kEDH, NULL, 0, SSL_kDHE},
            {0, SSL_TXT_kDHE, NULL, 0, SSL_kDHE},
            {0, SSL_TXT_DH, NULL, 0, SSL_kDHE},

            {0, SSL_TXT_kEECDH, NULL, 0, SSL_kECDHE},
            {0, SSL_TXT_kECDHE, NULL, 0, SSL_kECDHE},
            {0, SSL_TXT_ECDH, NULL, 0, SSL_kECDHE},

            //{0, SSL_TXT_kPSK, NULL, 0, SSL_kPSK},
            //{0, SSL_TXT_kRSAPSK, NULL, 0, SSL_kRSAPSK},
            //{0, SSL_TXT_kECDHEPSK, NULL, 0, SSL_kECDHEPSK},
            //{0, SSL_TXT_kDHEPSK, NULL, 0, SSL_kDHEPSK},
            //{0, SSL_TXT_kSRP, NULL, 0, SSL_kSRP},
            //{0, SSL_TXT_kGOST, NULL, 0, SSL_kGOST},

            /* server authentication aliases */
            {0, SSL_TXT_aRSA, NULL, 0, 0, SSL_aRSA},
            {0, SSL_TXT_aDSS, NULL, 0, 0, SSL_aDSS},
            {0, SSL_TXT_DSS, NULL, 0, 0, SSL_aDSS},
            {0, SSL_TXT_aNULL, NULL, 0, 0, SSL_aNULL},
            {0, SSL_TXT_aECDSA, NULL, 0, 0, SSL_aECDSA},
            {0, SSL_TXT_ECDSA, NULL, 0, 0, SSL_aECDSA},
            //{0, SSL_TXT_aPSK, NULL, 0, 0, SSL_aPSK},
            //{0, SSL_TXT_aGOST01, NULL, 0, 0, SSL_aGOST01},
            //{0, SSL_TXT_aGOST12, NULL, 0, 0, SSL_aGOST12},
            //{0, SSL_TXT_aGOST, NULL, 0, 0, SSL_aGOST01 | SSL_aGOST12},
            //{0, SSL_TXT_aSRP, NULL, 0, 0, SSL_aSRP},

            /* aliases combining key exchange and server authentication */
            {0, SSL_TXT_EDH, NULL, 0, SSL_kDHE, ~SSL_aNULL},
            {0, SSL_TXT_DHE, NULL, 0, SSL_kDHE, ~SSL_aNULL},
            {0, SSL_TXT_EECDH, NULL, 0, SSL_kECDHE, ~SSL_aNULL},
            {0, SSL_TXT_ECDHE, NULL, 0, SSL_kECDHE, ~SSL_aNULL},
            {0, SSL_TXT_NULL, NULL, 0, 0, 0, SSL_eNULL},
            {0, SSL_TXT_RSA, NULL, 0, SSL_kRSA, SSL_aRSA},
            {0, SSL_TXT_ADH, NULL, 0, SSL_kDHE, SSL_aNULL},
            {0, SSL_TXT_AECDH, NULL, 0, SSL_kECDHE, SSL_aNULL},
            //{0, SSL_TXT_PSK, NULL, 0, SSL_PSK},
            //{0, SSL_TXT_SRP, NULL, 0, SSL_kSRP},

            /* symmetric encryption aliases */
            {0, SSL_TXT_3DES, NULL, 0, 0, 0, SSL_3DES},
            {0, SSL_TXT_RC4, NULL, 0, 0, 0, SSL_RC4},
            {0, SSL_TXT_RC2, NULL, 0, 0, 0, SSL_RC2},
            {0, SSL_TXT_IDEA, NULL, 0, 0, 0, SSL_IDEA},
            {0, SSL_TXT_SEED, NULL, 0, 0, 0, SSL_SEED},
            {0, SSL_TXT_eNULL, NULL, 0, 0, 0, SSL_eNULL},
            //{0, SSL_TXT_GOST, NULL, 0, 0, 0, SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12},
            {0, SSL_TXT_AES128, NULL, 0, 0, 0,
                    SSL_AES128 | SSL_AES128GCM | SSL_AES128CCM | SSL_AES128CCM8},
            {0, SSL_TXT_AES256, NULL, 0, 0, 0,
                    SSL_AES256 | SSL_AES256GCM | SSL_AES256CCM | SSL_AES256CCM8},
            {0, SSL_TXT_AES, NULL, 0, 0, 0, SSL_AES},
            {0, SSL_TXT_AES_GCM, NULL, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM},
            {0, SSL_TXT_AES_CCM, NULL, 0, 0, 0,
                    SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8},
            {0, SSL_TXT_AES_CCM_8, NULL, 0, 0, 0, SSL_AES128CCM8 | SSL_AES256CCM8},
            {0, SSL_TXT_CAMELLIA128, NULL, 0, 0, 0, SSL_CAMELLIA128},
            {0, SSL_TXT_CAMELLIA256, NULL, 0, 0, 0, SSL_CAMELLIA256},
            {0, SSL_TXT_CAMELLIA, NULL, 0, 0, 0, SSL_CAMELLIA},
            {0, SSL_TXT_CHACHA20, NULL, 0, 0, 0, SSL_CHACHA20},

            {0, SSL_TXT_ARIA, NULL, 0, 0, 0, SSL_ARIA},
            {0, SSL_TXT_ARIA_GCM, NULL, 0, 0, 0, SSL_ARIA128GCM | SSL_ARIA256GCM},
            {0, SSL_TXT_ARIA128, NULL, 0, 0, 0, SSL_ARIA128GCM},
            {0, SSL_TXT_ARIA256, NULL, 0, 0, 0, SSL_ARIA256GCM},

            /* MAC aliases */
            {0, SSL_TXT_MD5, NULL, 0, 0, 0, 0, SSL_MD5},
            {0, SSL_TXT_SHA1, NULL, 0, 0, 0, 0, SSL_SHA1},
            {0, SSL_TXT_SHA, NULL, 0, 0, 0, 0, SSL_SHA1},
            //{0, SSL_TXT_GOST94, NULL, 0, 0, 0, 0, SSL_GOST94},
            //{0, SSL_TXT_GOST89MAC, NULL, 0, 0, 0, 0, SSL_GOST89MAC | SSL_GOST89MAC12},
            {0, SSL_TXT_SHA256, NULL, 0, 0, 0, 0, SSL_SHA256},
            {0, SSL_TXT_SHA384, NULL, 0, 0, 0, 0, SSL_SHA384},
            //{0, SSL_TXT_GOST12, NULL, 0, 0, 0, 0, SSL_GOST12_256},

            /* protocol version aliases */
            {0, SSL_TXT_SSLV3, NULL, 0, 0, 0, 0, 0, SSL3_VERSION},
            {0, SSL_TXT_TLSV1, NULL, 0, 0, 0, 0, 0, TLS1_VERSION},
            {0, "TLSv1.0", NULL, 0, 0, 0, 0, 0, TLS1_VERSION},
            {0, SSL_TXT_TLSV1_2, NULL, 0, 0, 0, 0, 0, TLS1_2_VERSION},

            /* strength classes */
            {0, SSL_TXT_LOW, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_LOW},
            {0, SSL_TXT_MEDIUM, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_MEDIUM},
            {0, SSL_TXT_HIGH, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_HIGH},
            /* FIPS 140-2 approved ciphersuite */
            //{0, SSL_TXT_FIPS, NULL, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, SSL_FIPS},

            /* "EDH-" aliases to "DHE-" labels (for backward compatibility) */
            //{0, SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA, NULL, 0, SSL_kDHE, SSL_aDSS, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS},
            //{0, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA, NULL, 0, SSL_kDHE, SSL_aRSA, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS},
        };

        Definitions = new HashMap<String, Def>(128);

        for (Object[] a : cipher_aliases) {
            int valid = (Integer) a[0];
            String txt_name = (String) a[1];
            String std_name = (String) a[2];
            long id = (Integer) a[3];
            long algorithm_mkey = a.length > 4 ? ((Number) a[4]).longValue() : 0;
            long algorithm_auth = a.length > 5 ? ((Number) a[5]).longValue() : 0;
            long algorithm_enc = a.length > 6 ? ((Number) a[6]).longValue() : 0;
            long algorithm_mac = a.length > 7 ? ((Number) a[7]).longValue() : 0;
            int min_tls = a.length > 8 ? ((Integer) a[8]) : 0;
            int max_tls = a.length > 9 ? ((Integer) a[9]) : 0;
            Definitions.put(txt_name,
                new Def(valid, txt_name, std_name, id, algorithm_mkey, algorithm_auth, algorithm_enc, algorithm_mac, min_tls, max_tls)
            );
        }

        final ArrayList<Def> Ciphers = new ArrayList<Def>( 96 );
        /* Cipher 01 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_NULL_MD5,
                            SSL3_CK_RSA_NULL_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_MD5|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 02 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_NULL_SHA,
                            SSL3_CK_RSA_NULL_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 03 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC4_40_MD5,
                            SSL3_CK_RSA_RC4_40_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 04 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC4_128_MD5,
                            SSL3_CK_RSA_RC4_128_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 05 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC4_128_SHA,
                            SSL3_CK_RSA_RC4_128_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 06 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC2_40_MD5,
                            SSL3_CK_RSA_RC2_40_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC2  |SSL_MD5 |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 07 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_IDEA_128_SHA,
                            SSL3_CK_RSA_IDEA_128_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_IDEA |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 08 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_DES_40_CBC_SHA,
                            SSL3_CK_RSA_DES_40_CBC_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 09 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_DES_64_CBC_SHA,
                            SSL3_CK_RSA_DES_64_CBC_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0A */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_DES_192_CBC3_SHA,
                            SSL3_CK_RSA_DES_192_CBC3_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* The DH ciphers */
        /* Cipher 0B */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_DSS_DES_40_CBC_SHA,
                            SSL3_CK_DH_DSS_DES_40_CBC_SHA,
                            SSL_kDHd |SSL_aDH|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0C */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_DSS_DES_64_CBC_SHA,
                            SSL3_CK_DH_DSS_DES_64_CBC_SHA,
                            SSL_kDHd |SSL_aDH|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0D */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_DSS_DES_192_CBC3_SHA,
                            SSL3_CK_DH_DSS_DES_192_CBC3_SHA,
                            SSL_kDHd |SSL_aDH|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0E */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_RSA_DES_40_CBC_SHA,
                            SSL3_CK_DH_RSA_DES_40_CBC_SHA,
                            SSL_kDHr |SSL_aDH|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0F */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_RSA_DES_64_CBC_SHA,
                            SSL3_CK_DH_RSA_DES_64_CBC_SHA,
                            SSL_kDHr |SSL_aDH|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 10 */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_RSA_DES_192_CBC3_SHA,
                            SSL3_CK_DH_RSA_DES_192_CBC3_SHA,
                            SSL_kDHr |SSL_aDH|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* The Ephemeral DH ciphers */
        /* Cipher 11 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_DSS_DES_40_CBC_SHA,
                            SSL3_CK_EDH_DSS_DES_40_CBC_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 12 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
                            SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 13 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
                            SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 14 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_RSA_DES_40_CBC_SHA,
                            SSL3_CK_EDH_RSA_DES_40_CBC_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 15 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
                            SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 16 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
                            SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 17 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_RC4_40_MD5,
                            SSL3_CK_ADH_RC4_40_MD5,
                            SSL_kEDH |SSL_aNULL|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 18 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_RC4_128_MD5,
                            SSL3_CK_ADH_RC4_128_MD5,
                            SSL_kEDH |SSL_aNULL|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 19 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_DES_40_CBC_SHA,
                            SSL3_CK_ADH_DES_40_CBC_SHA,
                            SSL_kEDH |SSL_aNULL|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 1A */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_DES_64_CBC_SHA,
                            SSL3_CK_ADH_DES_64_CBC_SHA,
                            SSL_kEDH |SSL_aNULL|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 1B */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_DES_192_CBC_SHA,
                            SSL3_CK_ADH_DES_192_CBC_SHA,
                            SSL_kEDH |SSL_aNULL|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Fortezza */
        /* Cipher 1C */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_FZA_DMS_NULL_SHA,
                            SSL3_CK_FZA_DMS_NULL_SHA,
                            SSL_kFZA|SSL_aFZA |SSL_eNULL |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 1D */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_FZA_DMS_FZA_SHA,
                            SSL3_CK_FZA_DMS_FZA_SHA,
                            SSL_kFZA|SSL_aFZA |SSL_eFZA |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 1E VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_64_CBC_SHA,
                            SSL3_CK_KRB5_DES_64_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_SHA1   |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 1F VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_192_CBC3_SHA,
                            SSL3_CK_KRB5_DES_192_CBC3_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_3DES|SSL_SHA1  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            112,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 20 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_128_SHA,
                            SSL3_CK_KRB5_RC4_128_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_SHA1  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 21 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_IDEA_128_CBC_SHA,
                            SSL3_CK_KRB5_IDEA_128_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_IDEA|SSL_SHA1  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 22 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_64_CBC_MD5,
                            SSL3_CK_KRB5_DES_64_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_MD5    |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 23 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_192_CBC3_MD5,
                            SSL3_CK_KRB5_DES_192_CBC3_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_3DES|SSL_MD5   |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            112,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 24 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_128_MD5,
                            SSL3_CK_KRB5_RC4_128_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_MD5  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 25 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_IDEA_128_CBC_MD5,
                            SSL3_CK_KRB5_IDEA_128_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_IDEA|SSL_MD5  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 26 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_40_CBC_SHA,
                            SSL3_CK_KRB5_DES_40_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_SHA1   |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 27 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC2_40_CBC_SHA,
                            SSL3_CK_KRB5_RC2_40_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC2|SSL_SHA1   |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 28 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_40_SHA,
                            SSL3_CK_KRB5_RC4_40_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_SHA1   |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 29 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_40_CBC_MD5,
                            SSL3_CK_KRB5_DES_40_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_MD5    |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 2A VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC2_40_CBC_MD5,
                            SSL3_CK_KRB5_RC2_40_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC2|SSL_MD5    |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 2B VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_40_MD5,
                            SSL3_CK_KRB5_RC4_40_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_MD5    |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 2F */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_WITH_AES_128_SHA,
                            TLS1_CK_RSA_WITH_AES_128_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_AES|SSL_SHA |SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 30 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_DSS_WITH_AES_128_SHA,
                            TLS1_CK_DH_DSS_WITH_AES_128_SHA,
                            SSL_kDHd|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 31 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_RSA_WITH_AES_128_SHA,
                            TLS1_CK_DH_RSA_WITH_AES_128_SHA,
                            SSL_kDHr|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 32 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
                            TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 33 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
                            TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 34 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ADH_WITH_AES_128_SHA,
                            TLS1_CK_ADH_WITH_AES_128_SHA,
                            SSL_kEDH|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 35 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_WITH_AES_256_SHA,
                            TLS1_CK_RSA_WITH_AES_256_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_AES|SSL_SHA |SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 36 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_DSS_WITH_AES_256_SHA,
                            TLS1_CK_DH_DSS_WITH_AES_256_SHA,
                            SSL_kDHd|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 37 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_RSA_WITH_AES_256_SHA,
                            TLS1_CK_DH_RSA_WITH_AES_256_SHA,
                            SSL_kDHr|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 38 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
                            TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 39 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
                            TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 3A */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ADH_WITH_AES_256_SHA,
                            TLS1_CK_ADH_WITH_AES_256_SHA,
                            SSL_kEDH|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* New TLS Export CipherSuites */
        /* Cipher 60 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5,
                            TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 61 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
                            TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 62 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                            TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 63 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
                            TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_DES|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 64 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA,
                            TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 65 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
                            TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 66 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA,
                            TLS1_CK_DHE_DSS_WITH_RC4_128_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher C001 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA,
                            TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA,
                            SSL_kECDH|SSL_aECDSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C002 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA,
                            SSL_kECDH|SSL_aECDSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C003 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDH|SSL_aECDSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C006 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
                            TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
                            SSL_kECDHE|SSL_aECDSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C007 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
                            SSL_kECDHE|SSL_aECDSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C008 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDHE|SSL_aECDSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C00B */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_RSA_WITH_NULL_SHA,
                            TLS1_CK_ECDH_RSA_WITH_NULL_SHA,
                            SSL_kECDH|SSL_aRSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C00C */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA,
                            SSL_kECDH|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C00D */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDH|SSL_aRSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C010 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
                            TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
                            SSL_kECDHE|SSL_aRSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C011 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
                            SSL_kECDHE|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C012 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDHE|SSL_aRSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C015 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
                            TLS1_CK_ECDH_anon_WITH_NULL_SHA,
                            SSL_kECDHE|SSL_aNULL|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        String name;
        CipherNames = new HashMap<String, Def>(Ciphers.size() + 64, 1);

        SuiteToOSSL = new HashMap<String, String>( 120, 1 );
        SuiteToOSSL.put("SSL_RSA_WITH_NULL_MD5", "NULL-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_NULL_SHA", "NULL-SHA");
        SuiteToOSSL.put("SSL_RSA_EXPORT_WITH_RC4_40_MD5", "EXP-RC4-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_RC4_128_MD5", "RC4-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_RC4_128_SHA", "RC4-SHA");
        SuiteToOSSL.put("SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5","EXP-RC2-CBC-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_IDEA_CBC_SHA","IDEA-CBC-SHA");
        SuiteToOSSL.put("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_DES_CBC_SHA", "DES-CBC-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-DSS-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_DES_CBC_SHA", "EDH-DSS-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "EDH-DSS-DES-CBC3-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_DES_CBC_SHA", "EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "EDH-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", "EXP-ADH-RC4-MD5");
        SuiteToOSSL.put("SSL_DH_anon_WITH_RC4_128_MD5", "ADH-RC4-MD5");
        SuiteToOSSL.put("SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "EXP-ADH-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_DES_CBC_SHA", "ADH-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", "ADH-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_NULL_MD5","NULL-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_NULL_SHA","NULL-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256");
        SuiteToOSSL.put("TLS_RSA_EXPORT_WITH_RC4_40_MD5","EXP-RC4-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_RC4_128_MD5","RC4-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_RC4_128_SHA","RC4-SHA");
        SuiteToOSSL.put("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5","EXP-RC2-CBC-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_IDEA_CBC_SHA","IDEA-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA","EXP-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_DES_CBC_SHA","DES-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_3DES_EDE_CBC_SHA","DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA","EXP-EDH-DSS-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_DES_CBC_SHA","EDH-DSS-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA","EDH-DSS-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA","EXP-EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_DES_CBC_SHA","EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA","EDH-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5","EXP-ADH-RC4-MD5");
        SuiteToOSSL.put("TLS_DH_anon_WITH_RC4_128_MD5","ADH-RC4-MD5");
        SuiteToOSSL.put("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA","EXP-ADH-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_DES_CBC_SHA","ADH-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA","ADH-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA");
        SuiteToOSSL.put("TLS_DH_DSS_WITH_AES_128_CBC_SHA","DH-DSS-AES128-SHA");
        SuiteToOSSL.put("TLS_DH_DSS_WITH_AES_256_CBC_SHA","DH-DSS-AES256-SHA");
        SuiteToOSSL.put("TLS_DH_RSA_WITH_AES_128_CBC_SHA","DH-RSA-AES128-SHA");
        SuiteToOSSL.put("TLS_DH_RSA_WITH_AES_256_CBC_SHA","DH-RSA-AES256-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE-DSS-AES128-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE-DSS-AES256-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_128_CBC_SHA", "ADH-AES128-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_256_CBC_SHA", "ADH-AES256-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_128_CBC_SHA256", "ADH-AES128-SHA256");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ADH-AES256-SHA256");
        SuiteToOSSL.put("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA","EXP1024-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA","EXP1024-RC4-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA","EXP1024-DHE-DSS-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA","EXP1024-DHE-DSS-RC4-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_RC4_128_SHA","DHE-DSS-RC4-SHA");
        SuiteToOSSL.put("SSL_CK_RC4_128_WITH_MD5","RC4-MD5");
        SuiteToOSSL.put("SSL_CK_RC4_128_EXPORT40_WITH_MD5","EXP-RC4-MD5");
        SuiteToOSSL.put("SSL_CK_RC2_128_CBC_WITH_MD5","RC2-MD5");
        SuiteToOSSL.put("SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5","EXP-RC2-MD5");
        SuiteToOSSL.put("SSL_CK_IDEA_128_CBC_WITH_MD5","IDEA-CBC-MD5");
        SuiteToOSSL.put("SSL_CK_DES_64_CBC_WITH_MD5","DES-CBC-MD5");
        SuiteToOSSL.put("SSL_CK_DES_192_EDE3_CBC_WITH_MD5","DES-CBC3-MD5");

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", name = "ECDHE-ECDSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", name = "ECDHE-ECDSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", name = "ECDHE-ECDSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", name = "ECDHE-ECDSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", name = "ECDHE-ECDSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", name = "ECDHE-ECDSA-AES256-SHA384");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", name = "ECDHE-RSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", name = "ECDHE-RSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", name = "ECDHE-RSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_RSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", name = "ECDHE-RSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", name = "ECDHE-RSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", name = "ECDHE-RSA-AES256-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", name = "ECDH-ECDSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", name = "ECDH-ECDSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", name = "ECDH-ECDSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", name = "ECDH-ECDSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",  name = "ECDH-ECDSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",  name = "ECDH-ECDSA-AES256-SHA384");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", name = "ECDH-RSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", name = "ECDH-RSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", name = "ECDH-RSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", name = "ECDH-RSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", name = "ECDH-RSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", name = "ECDH-RSA-AES256-SHA384");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-ECDSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDH-ECDSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "ECDH-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE-ECDSA-RC4-SHA");
        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA");
        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "ECDH-ECDSA-RC4-SHA");
        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_RC4_128_SHA", "ECDH-RSA-RC4-SHA");

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", name = "AECDH-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", name = "AECDH-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", name = "AECDH-DES-CBC3-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aNULL|SSL_3DES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 168, 168, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_RC4_128_SHA", name = "AECDH-RC4-SHA");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aNULL|SSL_RC4|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", name = "DHE-RSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", name = "DHE-RSA-AES128-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", name = "DHE-RSA-AES256-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", name = "DHE-RSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", name = "DHE-DSS-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", name = "DHE-DSS-AES128-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", name = "DHE-DSS-AES256-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", name = "DHE-DSS-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_128_GCM_SHA256", name = "AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_128_CBC_SHA256", name = "AES128-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_256_CBC_SHA256", name = "AES256-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_256_GCM_SHA384", name = "AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_NULL_SHA", "ECDHE-ECDSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_NULL_SHA",   "ECDHE-RSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_NULL_SHA",  "ECDH-ECDSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_NULL_SHA",    "ECDH-RSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDH_anon_WITH_NULL_SHA",   "AECDH-NULL-SHA");

        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_128_GCM_SHA256", "ADH-AES128-GCM-SHA256");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_256_GCM_SHA384", "ADH-AES256-GCM-SHA384");

        /* For IBM JRE: suite names start with "SSL_". On Oracle JRE, the suite names start with "TLS_" */
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_128_CBC_SHA",        "ADH-AES128-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_128_CBC_SHA256",     "ADH-AES128-SHA256");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_128_GCM_SHA256",     "ADH-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_256_CBC_SHA",        "ADH-AES256-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_256_CBC_SHA256",     "ADH-AES256-SHA256");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_256_GCM_SHA384",     "ADH-AES256-GCM-SHA384");

        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_128_CBC_SHA",        "DHE-DSS-AES128-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_128_CBC_SHA256",     "DHE-DSS-AES128-SHA256");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_128_GCM_SHA256",     "DHE-DSS-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_256_CBC_SHA",        "DHE-DSS-AES256-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_256_CBC_SHA256",     "DHE-DSS-AES256-SHA256");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_256_GCM_SHA384",     "DHE-DSS-AES256-GCM-SHA384");

        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_128_CBC_SHA",        "DHE-RSA-AES128-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_128_CBC_SHA256",     "DHE-RSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_128_GCM_SHA256",     "DHE-RSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_256_CBC_SHA",        "DHE-RSA-AES256-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_256_CBC_SHA256",     "DHE-RSA-AES256-SHA256");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_256_GCM_SHA384",     "DHE-RSA-AES256-GCM-SHA384");

        SuiteToOSSL.put("SSL_ECDH_anon_WITH_AES_128_CBC_SHA",      "AECDH-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDH_anon_WITH_AES_256_CBC_SHA",      "AECDH-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDH_anon_WITH_NULL_SHA",             "AECDH-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     "ECDH-ECDSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",  "ECDH-ECDSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",  "ECDH-ECDSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     "ECDH-ECDSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",  "ECDH-ECDSA-AES256-SHA384");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",  "ECDH-ECDSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_NULL_SHA",            "ECDH-ECDSA-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_128_CBC_SHA",       "ECDH-RSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_128_CBC_SHA256",    "ECDH-RSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_128_GCM_SHA256",    "ECDH-RSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_256_CBC_SHA",       "ECDH-RSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_256_CBC_SHA384",    "ECDH-RSA-AES256-SHA384");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_256_GCM_SHA384",    "ECDH-RSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_NULL_SHA",              "ECDH-RSA-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    "ECDHE-ECDSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    "ECDHE-ECDSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_NULL_SHA",           "ECDHE-ECDSA-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA",      "ECDHE-RSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   "ECDHE-RSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA",      "ECDHE-RSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   "ECDHE-RSA-AES128-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   "ECDHE-RSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   "ECDHE-RSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_NULL_SHA",             "ECDHE-RSA-NULL-SHA");

        SuiteToOSSL.put("SSL_RSA_WITH_AES_128_CBC_SHA",            "AES128-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_128_CBC_SHA256",         "AES128-SHA256");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_128_GCM_SHA256",         "AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_256_CBC_SHA",            "AES256-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_256_CBC_SHA256",         "AES256-SHA256");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_256_GCM_SHA384",         "AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_RSA_WITH_NULL_SHA256",                "NULL-SHA256");

        // TLS v1.3 (Java 8/11) streaming ciphers :

        SuiteToOSSL.put("TLS_AES_128_GCM_SHA256", name = "TLS_AES_128_GCM_SHA256");
        CipherNames.put(name, new Def(name,
                SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_AES_256_GCM_SHA384", name = "TLS_AES_256_GCM_SHA384");
        CipherNames.put(name, new Def(name,
                SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        for ( Def def : Ciphers ) CipherNames.put(def.name, def);

	}

}// CipherStrings
