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
package org.jruby.ext.openssl.impl;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class ASN1Registry {

    public static Integer oid2nid(final ASN1ObjectIdentifier oid) {
        return OID_TO_NID.get( oid.getId() );
    }

    public static Integer oid2nid(final String oid) {
        return OID_TO_NID.get(oid);
    }

    public static String oid2sym(final ASN1ObjectIdentifier oid) {
        return OID_TO_SYM.get( oid.getId() );
    }

    public static String o2a(String oid) {
        Integer nid = OID_TO_NID.get(oid);
        if ( nid == null ) return null;
        String name = NID_TO_LN[ nid ];
        if( name == null ) name = NID_TO_SN[ nid ];
        return name;
    }

    public static String o2a(final ASN1ObjectIdentifier oid) {
        return o2a( oid.getId() );
    }

    //@Deprecated
    public static ASN1ObjectIdentifier sym2oid(final String name) {
        final String oid = SYM_TO_OID.get( name.toLowerCase() );
        return oid == null ? null : new ASN1ObjectIdentifier( oid );
    }

    public static String name2oid(final String name) {
        return SYM_TO_OID.get( name.toLowerCase() );
    }

    public static Map<String, String> getOIDLookup() { return SYM_TO_OID; }

    static ASN1ObjectIdentifier nid2obj(int nid) {
        return new ASN1ObjectIdentifier( NID_TO_OID[ nid ] );
    }

    public static String nid2oid(int nid) {
        return NID_TO_OID[ nid ];
    }

    public static String nid2ln(int nid) {
        return NID_TO_LN[ nid ];
    }

    public static String nid2sn(int nid) {
        return NID_TO_SN[ nid ];
    }

    //     ----------------------------------------
    // GENERATED FROM OpenSSL's crypto/objects/obj_dat.h
    //     ----------------------------------------

    
    public static final String SN_undef = "UNDEF";
    public static final String LN_undef = "undefined";
    public static final short NID_undef = 0;
    public static final String OBJ_undef = "0";
    
    public static final String SN_itu_t = "ITU-T";
    public static final String LN_itu_t = "itu-t";
    public static final short NID_itu_t = 645;
    public static final String OBJ_itu_t = "0";
    
    public static final short NID_ccitt = 404;
    public static final String OBJ_ccitt = "0";
    
    public static final String SN_iso = "ISO";
    public static final String LN_iso = "iso";
    public static final short NID_iso = 181;
    public static final String OBJ_iso = "1";
    
    public static final String SN_joint_iso_itu_t = "JOINT-ISO-ITU-T";
    public static final String LN_joint_iso_itu_t = "joint-iso-itu-t";
    public static final short NID_joint_iso_itu_t = 646;
    public static final String OBJ_joint_iso_itu_t = "2";
    
    public static final short NID_joint_iso_ccitt = 393;
    public static final String OBJ_joint_iso_ccitt = "2";
    
    public static final String SN_member_body = "member-body";
    public static final String LN_member_body = "ISO Member Body";
    public static final short NID_member_body = 182;
    public static final String OBJ_member_body = "1.2";
    
    public static final String SN_identified_organization = "identified-organization";
    public static final short NID_identified_organization = 676;
    public static final String OBJ_identified_organization = "1.3";
    
    public static final String SN_hmac_md5 = "HMAC-MD5";
    public static final String LN_hmac_md5 = "hmac-md5";
    public static final short NID_hmac_md5 = 780;
    public static final String OBJ_hmac_md5 = "1.3.6.1.5.5.8.1.1";
    
    public static final String SN_hmac_sha1 = "HMAC-SHA1";
    public static final String LN_hmac_sha1 = "hmac-sha1";
    public static final short NID_hmac_sha1 = 781;
    public static final String OBJ_hmac_sha1 = "1.3.6.1.5.5.8.1.2";
    
    public static final String SN_certicom_arc = "certicom-arc";
    public static final short NID_certicom_arc = 677;
    public static final String OBJ_certicom_arc = "1.3.132";
    
    public static final String SN_international_organizations = "international-organizations";
    public static final String LN_international_organizations = "International Organizations";
    public static final short NID_international_organizations = 647;
    public static final String OBJ_international_organizations = "2.23";
    
    public static final String SN_wap = "wap";
    public static final short NID_wap = 678;
    public static final String OBJ_wap = "2.23.43";
    
    public static final String SN_wap_wsg = "wap-wsg";
    public static final short NID_wap_wsg = 679;
    public static final String OBJ_wap_wsg = "2.23.43.1";
    
    public static final String SN_selected_attribute_types = "selected-attribute-types";
    public static final String LN_selected_attribute_types = "Selected Attribute Types";
    public static final short NID_selected_attribute_types = 394;
    public static final String OBJ_selected_attribute_types = "2.5.1.5";
    
    public static final String SN_clearance = "clearance";
    public static final short NID_clearance = 395;
    public static final String OBJ_clearance = "2.5.1.5.55";
    
    public static final String SN_ISO_US = "ISO-US";
    public static final String LN_ISO_US = "ISO US Member Body";
    public static final short NID_ISO_US = 183;
    public static final String OBJ_ISO_US = "1.2.840";
    
    public static final String SN_X9_57 = "X9-57";
    public static final String LN_X9_57 = "X9.57";
    public static final short NID_X9_57 = 184;
    public static final String OBJ_X9_57 = "1.2.840.10040";
    
    public static final String SN_X9cm = "X9cm";
    public static final String LN_X9cm = "X9.57 CM ?";
    public static final short NID_X9cm = 185;
    public static final String OBJ_X9cm = "1.2.840.10040.4";
    
    public static final String SN_dsa = "DSA";
    public static final String LN_dsa = "dsaEncryption";
    public static final short NID_dsa = 116;
    public static final String OBJ_dsa = "1.2.840.10040.4.1";
    
    public static final String SN_dsaWithSHA1 = "DSA-SHA1";
    public static final String LN_dsaWithSHA1 = "dsaWithSHA1";
    public static final short NID_dsaWithSHA1 = 113;
    public static final String OBJ_dsaWithSHA1 = "1.2.840.10040.4.3";
    
    public static final String SN_ansi_X9_62 = "ansi-X9-62";
    public static final String LN_ansi_X9_62 = "ANSI X9.62";
    public static final short NID_ansi_X9_62 = 405;
    public static final String OBJ_ansi_X9_62 = "1.2.840.10045";
    
    public static final String OBJ_X9_62_id_fieldType = "1.2.840.10045.1";
    
    public static final String SN_X9_62_prime_field = "prime-field";
    public static final short NID_X9_62_prime_field = 406;
    public static final String OBJ_X9_62_prime_field = "1.2.840.10045.1.1";
    
    public static final String SN_X9_62_characteristic_two_field = "characteristic-two-field";
    public static final short NID_X9_62_characteristic_two_field = 407;
    public static final String OBJ_X9_62_characteristic_two_field = "1.2.840.10045.1.2";
    
    public static final String SN_X9_62_id_characteristic_two_basis = "id-characteristic-two-basis";
    public static final short NID_X9_62_id_characteristic_two_basis = 680;
    public static final String OBJ_X9_62_id_characteristic_two_basis = "1.2.840.10045.1.2.3";
    
    public static final String SN_X9_62_onBasis = "onBasis";
    public static final short NID_X9_62_onBasis = 681;
    public static final String OBJ_X9_62_onBasis = "1.2.840.10045.1.2.3.1";
    
    public static final String SN_X9_62_tpBasis = "tpBasis";
    public static final short NID_X9_62_tpBasis = 682;
    public static final String OBJ_X9_62_tpBasis = "1.2.840.10045.1.2.3.2";
    
    public static final String SN_X9_62_ppBasis = "ppBasis";
    public static final short NID_X9_62_ppBasis = 683;
    public static final String OBJ_X9_62_ppBasis = "1.2.840.10045.1.2.3.3";
    
    public static final String OBJ_X9_62_id_publicKeyType = "1.2.840.10045.2";
    
    public static final String SN_X9_62_id_ecPublicKey = "id-ecPublicKey";
    public static final short NID_X9_62_id_ecPublicKey = 408;
    public static final String OBJ_X9_62_id_ecPublicKey = "1.2.840.10045.2.1";
    
    public static final String OBJ_X9_62_ellipticCurve = "1.2.840.10045.3";
    
    public static final String OBJ_X9_62_c_TwoCurve = "1.2.840.10045.3.0";
    
    public static final String SN_X9_62_c2pnb163v1 = "c2pnb163v1";
    public static final short NID_X9_62_c2pnb163v1 = 684;
    public static final String OBJ_X9_62_c2pnb163v1 = "1.2.840.10045.3.0.1";
    
    public static final String SN_X9_62_c2pnb163v2 = "c2pnb163v2";
    public static final short NID_X9_62_c2pnb163v2 = 685;
    public static final String OBJ_X9_62_c2pnb163v2 = "1.2.840.10045.3.0.2";
    
    public static final String SN_X9_62_c2pnb163v3 = "c2pnb163v3";
    public static final short NID_X9_62_c2pnb163v3 = 686;
    public static final String OBJ_X9_62_c2pnb163v3 = "1.2.840.10045.3.0.3";
    
    public static final String SN_X9_62_c2pnb176v1 = "c2pnb176v1";
    public static final short NID_X9_62_c2pnb176v1 = 687;
    public static final String OBJ_X9_62_c2pnb176v1 = "1.2.840.10045.3.0.4";
    
    public static final String SN_X9_62_c2tnb191v1 = "c2tnb191v1";
    public static final short NID_X9_62_c2tnb191v1 = 688;
    public static final String OBJ_X9_62_c2tnb191v1 = "1.2.840.10045.3.0.5";
    
    public static final String SN_X9_62_c2tnb191v2 = "c2tnb191v2";
    public static final short NID_X9_62_c2tnb191v2 = 689;
    public static final String OBJ_X9_62_c2tnb191v2 = "1.2.840.10045.3.0.6";
    
    public static final String SN_X9_62_c2tnb191v3 = "c2tnb191v3";
    public static final short NID_X9_62_c2tnb191v3 = 690;
    public static final String OBJ_X9_62_c2tnb191v3 = "1.2.840.10045.3.0.7";
    
    public static final String SN_X9_62_c2onb191v4 = "c2onb191v4";
    public static final short NID_X9_62_c2onb191v4 = 691;
    public static final String OBJ_X9_62_c2onb191v4 = "1.2.840.10045.3.0.8";
    
    public static final String SN_X9_62_c2onb191v5 = "c2onb191v5";
    public static final short NID_X9_62_c2onb191v5 = 692;
    public static final String OBJ_X9_62_c2onb191v5 = "1.2.840.10045.3.0.9";
    
    public static final String SN_X9_62_c2pnb208w1 = "c2pnb208w1";
    public static final short NID_X9_62_c2pnb208w1 = 693;
    public static final String OBJ_X9_62_c2pnb208w1 = "1.2.840.10045.3.0.10";
    
    public static final String SN_X9_62_c2tnb239v1 = "c2tnb239v1";
    public static final short NID_X9_62_c2tnb239v1 = 694;
    public static final String OBJ_X9_62_c2tnb239v1 = "1.2.840.10045.3.0.11";
    
    public static final String SN_X9_62_c2tnb239v2 = "c2tnb239v2";
    public static final short NID_X9_62_c2tnb239v2 = 695;
    public static final String OBJ_X9_62_c2tnb239v2 = "1.2.840.10045.3.0.12";
    
    public static final String SN_X9_62_c2tnb239v3 = "c2tnb239v3";
    public static final short NID_X9_62_c2tnb239v3 = 696;
    public static final String OBJ_X9_62_c2tnb239v3 = "1.2.840.10045.3.0.13";
    
    public static final String SN_X9_62_c2onb239v4 = "c2onb239v4";
    public static final short NID_X9_62_c2onb239v4 = 697;
    public static final String OBJ_X9_62_c2onb239v4 = "1.2.840.10045.3.0.14";
    
    public static final String SN_X9_62_c2onb239v5 = "c2onb239v5";
    public static final short NID_X9_62_c2onb239v5 = 698;
    public static final String OBJ_X9_62_c2onb239v5 = "1.2.840.10045.3.0.15";
    
    public static final String SN_X9_62_c2pnb272w1 = "c2pnb272w1";
    public static final short NID_X9_62_c2pnb272w1 = 699;
    public static final String OBJ_X9_62_c2pnb272w1 = "1.2.840.10045.3.0.16";
    
    public static final String SN_X9_62_c2pnb304w1 = "c2pnb304w1";
    public static final short NID_X9_62_c2pnb304w1 = 700;
    public static final String OBJ_X9_62_c2pnb304w1 = "1.2.840.10045.3.0.17";
    
    public static final String SN_X9_62_c2tnb359v1 = "c2tnb359v1";
    public static final short NID_X9_62_c2tnb359v1 = 701;
    public static final String OBJ_X9_62_c2tnb359v1 = "1.2.840.10045.3.0.18";
    
    public static final String SN_X9_62_c2pnb368w1 = "c2pnb368w1";
    public static final short NID_X9_62_c2pnb368w1 = 702;
    public static final String OBJ_X9_62_c2pnb368w1 = "1.2.840.10045.3.0.19";
    
    public static final String SN_X9_62_c2tnb431r1 = "c2tnb431r1";
    public static final short NID_X9_62_c2tnb431r1 = 703;
    public static final String OBJ_X9_62_c2tnb431r1 = "1.2.840.10045.3.0.20";
    
    public static final String OBJ_X9_62_primeCurve = "1.2.840.10045.3.1";
    
    public static final String SN_X9_62_prime192v1 = "prime192v1";
    public static final short NID_X9_62_prime192v1 = 409;
    public static final String OBJ_X9_62_prime192v1 = "1.2.840.10045.3.1.1";
    
    public static final String SN_X9_62_prime192v2 = "prime192v2";
    public static final short NID_X9_62_prime192v2 = 410;
    public static final String OBJ_X9_62_prime192v2 = "1.2.840.10045.3.1.2";
    
    public static final String SN_X9_62_prime192v3 = "prime192v3";
    public static final short NID_X9_62_prime192v3 = 411;
    public static final String OBJ_X9_62_prime192v3 = "1.2.840.10045.3.1.3";
    
    public static final String SN_X9_62_prime239v1 = "prime239v1";
    public static final short NID_X9_62_prime239v1 = 412;
    public static final String OBJ_X9_62_prime239v1 = "1.2.840.10045.3.1.4";
    
    public static final String SN_X9_62_prime239v2 = "prime239v2";
    public static final short NID_X9_62_prime239v2 = 413;
    public static final String OBJ_X9_62_prime239v2 = "1.2.840.10045.3.1.5";
    
    public static final String SN_X9_62_prime239v3 = "prime239v3";
    public static final short NID_X9_62_prime239v3 = 414;
    public static final String OBJ_X9_62_prime239v3 = "1.2.840.10045.3.1.6";
    
    public static final String SN_X9_62_prime256v1 = "prime256v1";
    public static final short NID_X9_62_prime256v1 = 415;
    public static final String OBJ_X9_62_prime256v1 = "1.2.840.10045.3.1.7";
    
    public static final String OBJ_X9_62_id_ecSigType = "1.2.840.10045.4";
    
    public static final String SN_ecdsa_with_SHA1 = "ecdsa-with-SHA1";
    public static final short NID_ecdsa_with_SHA1 = 416;
    public static final String OBJ_ecdsa_with_SHA1 = "1.2.840.10045.4.1";
    
    public static final String SN_ecdsa_with_Recommended = "ecdsa-with-Recommended";
    public static final short NID_ecdsa_with_Recommended = 791;
    public static final String OBJ_ecdsa_with_Recommended = "1.2.840.10045.4.2";
    
    public static final String SN_ecdsa_with_Specified = "ecdsa-with-Specified";
    public static final short NID_ecdsa_with_Specified = 792;
    public static final String OBJ_ecdsa_with_Specified = "1.2.840.10045.4.3";
    
    public static final String SN_ecdsa_with_SHA224 = "ecdsa-with-SHA224";
    public static final short NID_ecdsa_with_SHA224 = 793;
    public static final String OBJ_ecdsa_with_SHA224 = "1.2.840.10045.4.3.1";
    
    public static final String SN_ecdsa_with_SHA256 = "ecdsa-with-SHA256";
    public static final short NID_ecdsa_with_SHA256 = 794;
    public static final String OBJ_ecdsa_with_SHA256 = "1.2.840.10045.4.3.2";
    
    public static final String SN_ecdsa_with_SHA384 = "ecdsa-with-SHA384";
    public static final short NID_ecdsa_with_SHA384 = 795;
    public static final String OBJ_ecdsa_with_SHA384 = "1.2.840.10045.4.3.3";
    
    public static final String SN_ecdsa_with_SHA512 = "ecdsa-with-SHA512";
    public static final short NID_ecdsa_with_SHA512 = 796;
    public static final String OBJ_ecdsa_with_SHA512 = "1.2.840.10045.4.3.4";
    
    public static final String OBJ_secg_ellipticCurve = "1.3.132.0";
    
    public static final String SN_secp112r1 = "secp112r1";
    public static final short NID_secp112r1 = 704;
    public static final String OBJ_secp112r1 = "1.3.132.0.6";
    
    public static final String SN_secp112r2 = "secp112r2";
    public static final short NID_secp112r2 = 705;
    public static final String OBJ_secp112r2 = "1.3.132.0.7";
    
    public static final String SN_secp128r1 = "secp128r1";
    public static final short NID_secp128r1 = 706;
    public static final String OBJ_secp128r1 = "1.3.132.0.28";
    
    public static final String SN_secp128r2 = "secp128r2";
    public static final short NID_secp128r2 = 707;
    public static final String OBJ_secp128r2 = "1.3.132.0.29";
    
    public static final String SN_secp160k1 = "secp160k1";
    public static final short NID_secp160k1 = 708;
    public static final String OBJ_secp160k1 = "1.3.132.0.9";
    
    public static final String SN_secp160r1 = "secp160r1";
    public static final short NID_secp160r1 = 709;
    public static final String OBJ_secp160r1 = "1.3.132.0.8";
    
    public static final String SN_secp160r2 = "secp160r2";
    public static final short NID_secp160r2 = 710;
    public static final String OBJ_secp160r2 = "1.3.132.0.30";
    
    public static final String SN_secp192k1 = "secp192k1";
    public static final short NID_secp192k1 = 711;
    public static final String OBJ_secp192k1 = "1.3.132.0.31";
    
    public static final String SN_secp224k1 = "secp224k1";
    public static final short NID_secp224k1 = 712;
    public static final String OBJ_secp224k1 = "1.3.132.0.32";
    
    public static final String SN_secp224r1 = "secp224r1";
    public static final short NID_secp224r1 = 713;
    public static final String OBJ_secp224r1 = "1.3.132.0.33";
    
    public static final String SN_secp256k1 = "secp256k1";
    public static final short NID_secp256k1 = 714;
    public static final String OBJ_secp256k1 = "1.3.132.0.10";
    
    public static final String SN_secp384r1 = "secp384r1";
    public static final short NID_secp384r1 = 715;
    public static final String OBJ_secp384r1 = "1.3.132.0.34";
    
    public static final String SN_secp521r1 = "secp521r1";
    public static final short NID_secp521r1 = 716;
    public static final String OBJ_secp521r1 = "1.3.132.0.35";
    
    public static final String SN_sect113r1 = "sect113r1";
    public static final short NID_sect113r1 = 717;
    public static final String OBJ_sect113r1 = "1.3.132.0.4";
    
    public static final String SN_sect113r2 = "sect113r2";
    public static final short NID_sect113r2 = 718;
    public static final String OBJ_sect113r2 = "1.3.132.0.5";
    
    public static final String SN_sect131r1 = "sect131r1";
    public static final short NID_sect131r1 = 719;
    public static final String OBJ_sect131r1 = "1.3.132.0.22";
    
    public static final String SN_sect131r2 = "sect131r2";
    public static final short NID_sect131r2 = 720;
    public static final String OBJ_sect131r2 = "1.3.132.0.23";
    
    public static final String SN_sect163k1 = "sect163k1";
    public static final short NID_sect163k1 = 721;
    public static final String OBJ_sect163k1 = "1.3.132.0.1";
    
    public static final String SN_sect163r1 = "sect163r1";
    public static final short NID_sect163r1 = 722;
    public static final String OBJ_sect163r1 = "1.3.132.0.2";
    
    public static final String SN_sect163r2 = "sect163r2";
    public static final short NID_sect163r2 = 723;
    public static final String OBJ_sect163r2 = "1.3.132.0.15";
    
    public static final String SN_sect193r1 = "sect193r1";
    public static final short NID_sect193r1 = 724;
    public static final String OBJ_sect193r1 = "1.3.132.0.24";
    
    public static final String SN_sect193r2 = "sect193r2";
    public static final short NID_sect193r2 = 725;
    public static final String OBJ_sect193r2 = "1.3.132.0.25";
    
    public static final String SN_sect233k1 = "sect233k1";
    public static final short NID_sect233k1 = 726;
    public static final String OBJ_sect233k1 = "1.3.132.0.26";
    
    public static final String SN_sect233r1 = "sect233r1";
    public static final short NID_sect233r1 = 727;
    public static final String OBJ_sect233r1 = "1.3.132.0.27";
    
    public static final String SN_sect239k1 = "sect239k1";
    public static final short NID_sect239k1 = 728;
    public static final String OBJ_sect239k1 = "1.3.132.0.3";
    
    public static final String SN_sect283k1 = "sect283k1";
    public static final short NID_sect283k1 = 729;
    public static final String OBJ_sect283k1 = "1.3.132.0.16";
    
    public static final String SN_sect283r1 = "sect283r1";
    public static final short NID_sect283r1 = 730;
    public static final String OBJ_sect283r1 = "1.3.132.0.17";
    
    public static final String SN_sect409k1 = "sect409k1";
    public static final short NID_sect409k1 = 731;
    public static final String OBJ_sect409k1 = "1.3.132.0.36";
    
    public static final String SN_sect409r1 = "sect409r1";
    public static final short NID_sect409r1 = 732;
    public static final String OBJ_sect409r1 = "1.3.132.0.37";
    
    public static final String SN_sect571k1 = "sect571k1";
    public static final short NID_sect571k1 = 733;
    public static final String OBJ_sect571k1 = "1.3.132.0.38";
    
    public static final String SN_sect571r1 = "sect571r1";
    public static final short NID_sect571r1 = 734;
    public static final String OBJ_sect571r1 = "1.3.132.0.39";
    
    public static final String OBJ_wap_wsg_idm_ecid = "2.23.43.1.4";
    
    public static final String SN_wap_wsg_idm_ecid_wtls1 = "wap-wsg-idm-ecid-wtls1";
    public static final short NID_wap_wsg_idm_ecid_wtls1 = 735;
    public static final String OBJ_wap_wsg_idm_ecid_wtls1 = "2.23.43.1.4.1";
    
    public static final String SN_wap_wsg_idm_ecid_wtls3 = "wap-wsg-idm-ecid-wtls3";
    public static final short NID_wap_wsg_idm_ecid_wtls3 = 736;
    public static final String OBJ_wap_wsg_idm_ecid_wtls3 = "2.23.43.1.4.3";
    
    public static final String SN_wap_wsg_idm_ecid_wtls4 = "wap-wsg-idm-ecid-wtls4";
    public static final short NID_wap_wsg_idm_ecid_wtls4 = 737;
    public static final String OBJ_wap_wsg_idm_ecid_wtls4 = "2.23.43.1.4.4";
    
    public static final String SN_wap_wsg_idm_ecid_wtls5 = "wap-wsg-idm-ecid-wtls5";
    public static final short NID_wap_wsg_idm_ecid_wtls5 = 738;
    public static final String OBJ_wap_wsg_idm_ecid_wtls5 = "2.23.43.1.4.5";
    
    public static final String SN_wap_wsg_idm_ecid_wtls6 = "wap-wsg-idm-ecid-wtls6";
    public static final short NID_wap_wsg_idm_ecid_wtls6 = 739;
    public static final String OBJ_wap_wsg_idm_ecid_wtls6 = "2.23.43.1.4.6";
    
    public static final String SN_wap_wsg_idm_ecid_wtls7 = "wap-wsg-idm-ecid-wtls7";
    public static final short NID_wap_wsg_idm_ecid_wtls7 = 740;
    public static final String OBJ_wap_wsg_idm_ecid_wtls7 = "2.23.43.1.4.7";
    
    public static final String SN_wap_wsg_idm_ecid_wtls8 = "wap-wsg-idm-ecid-wtls8";
    public static final short NID_wap_wsg_idm_ecid_wtls8 = 741;
    public static final String OBJ_wap_wsg_idm_ecid_wtls8 = "2.23.43.1.4.8";
    
    public static final String SN_wap_wsg_idm_ecid_wtls9 = "wap-wsg-idm-ecid-wtls9";
    public static final short NID_wap_wsg_idm_ecid_wtls9 = 742;
    public static final String OBJ_wap_wsg_idm_ecid_wtls9 = "2.23.43.1.4.9";
    
    public static final String SN_wap_wsg_idm_ecid_wtls10 = "wap-wsg-idm-ecid-wtls10";
    public static final short NID_wap_wsg_idm_ecid_wtls10 = 743;
    public static final String OBJ_wap_wsg_idm_ecid_wtls10 = "2.23.43.1.4.10";
    
    public static final String SN_wap_wsg_idm_ecid_wtls11 = "wap-wsg-idm-ecid-wtls11";
    public static final short NID_wap_wsg_idm_ecid_wtls11 = 744;
    public static final String OBJ_wap_wsg_idm_ecid_wtls11 = "2.23.43.1.4.11";
    
    public static final String SN_wap_wsg_idm_ecid_wtls12 = "wap-wsg-idm-ecid-wtls12";
    public static final short NID_wap_wsg_idm_ecid_wtls12 = 745;
    public static final String OBJ_wap_wsg_idm_ecid_wtls12 = "2.23.43.1.4.12";
    
    public static final String SN_cast5_cbc = "CAST5-CBC";
    public static final String LN_cast5_cbc = "cast5-cbc";
    public static final short NID_cast5_cbc = 108;
    public static final String OBJ_cast5_cbc = "1.2.840.113533.7.66.10";
    
    public static final String SN_cast5_ecb = "CAST5-ECB";
    public static final String LN_cast5_ecb = "cast5-ecb";
    public static final short NID_cast5_ecb = 109;
    
    public static final String SN_cast5_cfb64 = "CAST5-CFB";
    public static final String LN_cast5_cfb64 = "cast5-cfb";
    public static final short NID_cast5_cfb64 = 110;
    
    public static final String SN_cast5_ofb64 = "CAST5-OFB";
    public static final String LN_cast5_ofb64 = "cast5-ofb";
    public static final short NID_cast5_ofb64 = 111;
    
    public static final String LN_pbeWithMD5AndCast5_CBC = "pbeWithMD5AndCast5CBC";
    public static final short NID_pbeWithMD5AndCast5_CBC = 112;
    public static final String OBJ_pbeWithMD5AndCast5_CBC = "1.2.840.113533.7.66.12";
    
    public static final String SN_id_PasswordBasedMAC = "id-PasswordBasedMAC";
    public static final String LN_id_PasswordBasedMAC = "password based MAC";
    public static final short NID_id_PasswordBasedMAC = 782;
    public static final String OBJ_id_PasswordBasedMAC = "1.2.840.113533.7.66.13";
    
    public static final String SN_id_DHBasedMac = "id-DHBasedMac";
    public static final String LN_id_DHBasedMac = "Diffie-Hellman based MAC";
    public static final short NID_id_DHBasedMac = 783;
    public static final String OBJ_id_DHBasedMac = "1.2.840.113533.7.66.30";
    
    public static final String SN_rsadsi = "rsadsi";
    public static final String LN_rsadsi = "RSA Data Security, Inc.";
    public static final short NID_rsadsi = 1;
    public static final String OBJ_rsadsi = "1.2.840.113549";
    
    public static final String SN_pkcs = "pkcs";
    public static final String LN_pkcs = "RSA Data Security, Inc. PKCS";
    public static final short NID_pkcs = 2;
    public static final String OBJ_pkcs = "1.2.840.113549.1";
    
    public static final String SN_pkcs1 = "pkcs1";
    public static final short NID_pkcs1 = 186;
    public static final String OBJ_pkcs1 = "1.2.840.113549.1.1";
    
    public static final String LN_rsaEncryption = "rsaEncryption";
    public static final short NID_rsaEncryption = 6;
    public static final String OBJ_rsaEncryption = "1.2.840.113549.1.1.1";
    
    public static final String SN_md2WithRSAEncryption = "RSA-MD2";
    public static final String LN_md2WithRSAEncryption = "md2WithRSAEncryption";
    public static final short NID_md2WithRSAEncryption = 7;
    public static final String OBJ_md2WithRSAEncryption = "1.2.840.113549.1.1.2";
    
    public static final String SN_md4WithRSAEncryption = "RSA-MD4";
    public static final String LN_md4WithRSAEncryption = "md4WithRSAEncryption";
    public static final short NID_md4WithRSAEncryption = 396;
    public static final String OBJ_md4WithRSAEncryption = "1.2.840.113549.1.1.3";
    
    public static final String SN_md5WithRSAEncryption = "RSA-MD5";
    public static final String LN_md5WithRSAEncryption = "md5WithRSAEncryption";
    public static final short NID_md5WithRSAEncryption = 8;
    public static final String OBJ_md5WithRSAEncryption = "1.2.840.113549.1.1.4";
    
    public static final String SN_sha1WithRSAEncryption = "RSA-SHA1";
    public static final String LN_sha1WithRSAEncryption = "sha1WithRSAEncryption";
    public static final short NID_sha1WithRSAEncryption = 65;
    public static final String OBJ_sha1WithRSAEncryption = "1.2.840.113549.1.1.5";
    
    public static final String SN_rsaesOaep = "RSAES-OAEP";
    public static final String LN_rsaesOaep = "rsaesOaep";
    public static final short NID_rsaesOaep = 919;
    public static final String OBJ_rsaesOaep = "1.2.840.113549.1.1.7";
    
    public static final String SN_mgf1 = "MGF1";
    public static final String LN_mgf1 = "mgf1";
    public static final short NID_mgf1 = 911;
    public static final String OBJ_mgf1 = "1.2.840.113549.1.1.8";
    
    public static final String SN_pSpecified = "PSPECIFIED";
    public static final String LN_pSpecified = "pSpecified";
    public static final short NID_pSpecified = 935;
    public static final String OBJ_pSpecified = "1.2.840.113549.1.1.9";
    
    public static final String SN_rsassaPss = "RSASSA-PSS";
    public static final String LN_rsassaPss = "rsassaPss";
    public static final short NID_rsassaPss = 912;
    public static final String OBJ_rsassaPss = "1.2.840.113549.1.1.10";
    
    public static final String SN_sha256WithRSAEncryption = "RSA-SHA256";
    public static final String LN_sha256WithRSAEncryption = "sha256WithRSAEncryption";
    public static final short NID_sha256WithRSAEncryption = 668;
    public static final String OBJ_sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
    
    public static final String SN_sha384WithRSAEncryption = "RSA-SHA384";
    public static final String LN_sha384WithRSAEncryption = "sha384WithRSAEncryption";
    public static final short NID_sha384WithRSAEncryption = 669;
    public static final String OBJ_sha384WithRSAEncryption = "1.2.840.113549.1.1.12";
    
    public static final String SN_sha512WithRSAEncryption = "RSA-SHA512";
    public static final String LN_sha512WithRSAEncryption = "sha512WithRSAEncryption";
    public static final short NID_sha512WithRSAEncryption = 670;
    public static final String OBJ_sha512WithRSAEncryption = "1.2.840.113549.1.1.13";
    
    public static final String SN_sha224WithRSAEncryption = "RSA-SHA224";
    public static final String LN_sha224WithRSAEncryption = "sha224WithRSAEncryption";
    public static final short NID_sha224WithRSAEncryption = 671;
    public static final String OBJ_sha224WithRSAEncryption = "1.2.840.113549.1.1.14";
    
    public static final String SN_pkcs3 = "pkcs3";
    public static final short NID_pkcs3 = 27;
    public static final String OBJ_pkcs3 = "1.2.840.113549.1.3";
    
    public static final String LN_dhKeyAgreement = "dhKeyAgreement";
    public static final short NID_dhKeyAgreement = 28;
    public static final String OBJ_dhKeyAgreement = "1.2.840.113549.1.3.1";
    
    public static final String SN_pkcs5 = "pkcs5";
    public static final short NID_pkcs5 = 187;
    public static final String OBJ_pkcs5 = "1.2.840.113549.1.5";
    
    public static final String SN_pbeWithMD2AndDES_CBC = "PBE-MD2-DES";
    public static final String LN_pbeWithMD2AndDES_CBC = "pbeWithMD2AndDES-CBC";
    public static final short NID_pbeWithMD2AndDES_CBC = 9;
    public static final String OBJ_pbeWithMD2AndDES_CBC = "1.2.840.113549.1.5.1";
    
    public static final String SN_pbeWithMD5AndDES_CBC = "PBE-MD5-DES";
    public static final String LN_pbeWithMD5AndDES_CBC = "pbeWithMD5AndDES-CBC";
    public static final short NID_pbeWithMD5AndDES_CBC = 10;
    public static final String OBJ_pbeWithMD5AndDES_CBC = "1.2.840.113549.1.5.3";
    
    public static final String SN_pbeWithMD2AndRC2_CBC = "PBE-MD2-RC2-64";
    public static final String LN_pbeWithMD2AndRC2_CBC = "pbeWithMD2AndRC2-CBC";
    public static final short NID_pbeWithMD2AndRC2_CBC = 168;
    public static final String OBJ_pbeWithMD2AndRC2_CBC = "1.2.840.113549.1.5.4";
    
    public static final String SN_pbeWithMD5AndRC2_CBC = "PBE-MD5-RC2-64";
    public static final String LN_pbeWithMD5AndRC2_CBC = "pbeWithMD5AndRC2-CBC";
    public static final short NID_pbeWithMD5AndRC2_CBC = 169;
    public static final String OBJ_pbeWithMD5AndRC2_CBC = "1.2.840.113549.1.5.6";
    
    public static final String SN_pbeWithSHA1AndDES_CBC = "PBE-SHA1-DES";
    public static final String LN_pbeWithSHA1AndDES_CBC = "pbeWithSHA1AndDES-CBC";
    public static final short NID_pbeWithSHA1AndDES_CBC = 170;
    public static final String OBJ_pbeWithSHA1AndDES_CBC = "1.2.840.113549.1.5.10";
    
    public static final String SN_pbeWithSHA1AndRC2_CBC = "PBE-SHA1-RC2-64";
    public static final String LN_pbeWithSHA1AndRC2_CBC = "pbeWithSHA1AndRC2-CBC";
    public static final short NID_pbeWithSHA1AndRC2_CBC = 68;
    public static final String OBJ_pbeWithSHA1AndRC2_CBC = "1.2.840.113549.1.5.11";
    
    public static final String LN_id_pbkdf2 = "PBKDF2";
    public static final short NID_id_pbkdf2 = 69;
    public static final String OBJ_id_pbkdf2 = "1.2.840.113549.1.5.12";
    
    public static final String LN_pbes2 = "PBES2";
    public static final short NID_pbes2 = 161;
    public static final String OBJ_pbes2 = "1.2.840.113549.1.5.13";
    
    public static final String LN_pbmac1 = "PBMAC1";
    public static final short NID_pbmac1 = 162;
    public static final String OBJ_pbmac1 = "1.2.840.113549.1.5.14";
    
    public static final String SN_pkcs7 = "pkcs7";
    public static final short NID_pkcs7 = 20;
    public static final String OBJ_pkcs7 = "1.2.840.113549.1.7";
    
    public static final String LN_pkcs7_data = "pkcs7-data";
    public static final short NID_pkcs7_data = 21;
    public static final String OBJ_pkcs7_data = "1.2.840.113549.1.7.1";
    
    public static final String LN_pkcs7_signed = "pkcs7-signedData";
    public static final short NID_pkcs7_signed = 22;
    public static final String OBJ_pkcs7_signed = "1.2.840.113549.1.7.2";
    
    public static final String LN_pkcs7_enveloped = "pkcs7-envelopedData";
    public static final short NID_pkcs7_enveloped = 23;
    public static final String OBJ_pkcs7_enveloped = "1.2.840.113549.1.7.3";
    
    public static final String LN_pkcs7_signedAndEnveloped = "pkcs7-signedAndEnvelopedData";
    public static final short NID_pkcs7_signedAndEnveloped = 24;
    public static final String OBJ_pkcs7_signedAndEnveloped = "1.2.840.113549.1.7.4";
    
    public static final String LN_pkcs7_digest = "pkcs7-digestData";
    public static final short NID_pkcs7_digest = 25;
    public static final String OBJ_pkcs7_digest = "1.2.840.113549.1.7.5";
    
    public static final String LN_pkcs7_encrypted = "pkcs7-encryptedData";
    public static final short NID_pkcs7_encrypted = 26;
    public static final String OBJ_pkcs7_encrypted = "1.2.840.113549.1.7.6";
    
    public static final String SN_pkcs9 = "pkcs9";
    public static final short NID_pkcs9 = 47;
    public static final String OBJ_pkcs9 = "1.2.840.113549.1.9";
    
    public static final String LN_pkcs9_emailAddress = "emailAddress";
    public static final short NID_pkcs9_emailAddress = 48;
    public static final String OBJ_pkcs9_emailAddress = "1.2.840.113549.1.9.1";
    
    public static final String LN_pkcs9_unstructuredName = "unstructuredName";
    public static final short NID_pkcs9_unstructuredName = 49;
    public static final String OBJ_pkcs9_unstructuredName = "1.2.840.113549.1.9.2";
    
    public static final String LN_pkcs9_contentType = "contentType";
    public static final short NID_pkcs9_contentType = 50;
    public static final String OBJ_pkcs9_contentType = "1.2.840.113549.1.9.3";
    
    public static final String LN_pkcs9_messageDigest = "messageDigest";
    public static final short NID_pkcs9_messageDigest = 51;
    public static final String OBJ_pkcs9_messageDigest = "1.2.840.113549.1.9.4";
    
    public static final String LN_pkcs9_signingTime = "signingTime";
    public static final short NID_pkcs9_signingTime = 52;
    public static final String OBJ_pkcs9_signingTime = "1.2.840.113549.1.9.5";
    
    public static final String LN_pkcs9_countersignature = "countersignature";
    public static final short NID_pkcs9_countersignature = 53;
    public static final String OBJ_pkcs9_countersignature = "1.2.840.113549.1.9.6";
    
    public static final String LN_pkcs9_challengePassword = "challengePassword";
    public static final short NID_pkcs9_challengePassword = 54;
    public static final String OBJ_pkcs9_challengePassword = "1.2.840.113549.1.9.7";
    
    public static final String LN_pkcs9_unstructuredAddress = "unstructuredAddress";
    public static final short NID_pkcs9_unstructuredAddress = 55;
    public static final String OBJ_pkcs9_unstructuredAddress = "1.2.840.113549.1.9.8";
    
    public static final String LN_pkcs9_extCertAttributes = "extendedCertificateAttributes";
    public static final short NID_pkcs9_extCertAttributes = 56;
    public static final String OBJ_pkcs9_extCertAttributes = "1.2.840.113549.1.9.9";
    
    public static final String SN_ext_req = "extReq";
    public static final String LN_ext_req = "Extension Request";
    public static final short NID_ext_req = 172;
    public static final String OBJ_ext_req = "1.2.840.113549.1.9.14";
    
    public static final String SN_SMIMECapabilities = "SMIME-CAPS";
    public static final String LN_SMIMECapabilities = "S/MIME Capabilities";
    public static final short NID_SMIMECapabilities = 167;
    public static final String OBJ_SMIMECapabilities = "1.2.840.113549.1.9.15";
    
    public static final String SN_SMIME = "SMIME";
    public static final String LN_SMIME = "S/MIME";
    public static final short NID_SMIME = 188;
    public static final String OBJ_SMIME = "1.2.840.113549.1.9.16";
    
    public static final String SN_id_smime_mod = "id-smime-mod";
    public static final short NID_id_smime_mod = 189;
    public static final String OBJ_id_smime_mod = "1.2.840.113549.1.9.16.0";
    
    public static final String SN_id_smime_ct = "id-smime-ct";
    public static final short NID_id_smime_ct = 190;
    public static final String OBJ_id_smime_ct = "1.2.840.113549.1.9.16.1";
    
    public static final String SN_id_smime_aa = "id-smime-aa";
    public static final short NID_id_smime_aa = 191;
    public static final String OBJ_id_smime_aa = "1.2.840.113549.1.9.16.2";
    
    public static final String SN_id_smime_alg = "id-smime-alg";
    public static final short NID_id_smime_alg = 192;
    public static final String OBJ_id_smime_alg = "1.2.840.113549.1.9.16.3";
    
    public static final String SN_id_smime_cd = "id-smime-cd";
    public static final short NID_id_smime_cd = 193;
    public static final String OBJ_id_smime_cd = "1.2.840.113549.1.9.16.4";
    
    public static final String SN_id_smime_spq = "id-smime-spq";
    public static final short NID_id_smime_spq = 194;
    public static final String OBJ_id_smime_spq = "1.2.840.113549.1.9.16.5";
    
    public static final String SN_id_smime_cti = "id-smime-cti";
    public static final short NID_id_smime_cti = 195;
    public static final String OBJ_id_smime_cti = "1.2.840.113549.1.9.16.6";
    
    public static final String SN_id_smime_mod_cms = "id-smime-mod-cms";
    public static final short NID_id_smime_mod_cms = 196;
    public static final String OBJ_id_smime_mod_cms = "1.2.840.113549.1.9.16.0.1";
    
    public static final String SN_id_smime_mod_ess = "id-smime-mod-ess";
    public static final short NID_id_smime_mod_ess = 197;
    public static final String OBJ_id_smime_mod_ess = "1.2.840.113549.1.9.16.0.2";
    
    public static final String SN_id_smime_mod_oid = "id-smime-mod-oid";
    public static final short NID_id_smime_mod_oid = 198;
    public static final String OBJ_id_smime_mod_oid = "1.2.840.113549.1.9.16.0.3";
    
    public static final String SN_id_smime_mod_msg_v3 = "id-smime-mod-msg-v3";
    public static final short NID_id_smime_mod_msg_v3 = 199;
    public static final String OBJ_id_smime_mod_msg_v3 = "1.2.840.113549.1.9.16.0.4";
    
    public static final String SN_id_smime_mod_ets_eSignature_88 = "id-smime-mod-ets-eSignature-88";
    public static final short NID_id_smime_mod_ets_eSignature_88 = 200;
    public static final String OBJ_id_smime_mod_ets_eSignature_88 = "1.2.840.113549.1.9.16.0.5";
    
    public static final String SN_id_smime_mod_ets_eSignature_97 = "id-smime-mod-ets-eSignature-97";
    public static final short NID_id_smime_mod_ets_eSignature_97 = 201;
    public static final String OBJ_id_smime_mod_ets_eSignature_97 = "1.2.840.113549.1.9.16.0.6";
    
    public static final String SN_id_smime_mod_ets_eSigPolicy_88 = "id-smime-mod-ets-eSigPolicy-88";
    public static final short NID_id_smime_mod_ets_eSigPolicy_88 = 202;
    public static final String OBJ_id_smime_mod_ets_eSigPolicy_88 = "1.2.840.113549.1.9.16.0.7";
    
    public static final String SN_id_smime_mod_ets_eSigPolicy_97 = "id-smime-mod-ets-eSigPolicy-97";
    public static final short NID_id_smime_mod_ets_eSigPolicy_97 = 203;
    public static final String OBJ_id_smime_mod_ets_eSigPolicy_97 = "1.2.840.113549.1.9.16.0.8";
    
    public static final String SN_id_smime_ct_receipt = "id-smime-ct-receipt";
    public static final short NID_id_smime_ct_receipt = 204;
    public static final String OBJ_id_smime_ct_receipt = "1.2.840.113549.1.9.16.1.1";
    
    public static final String SN_id_smime_ct_authData = "id-smime-ct-authData";
    public static final short NID_id_smime_ct_authData = 205;
    public static final String OBJ_id_smime_ct_authData = "1.2.840.113549.1.9.16.1.2";
    
    public static final String SN_id_smime_ct_publishCert = "id-smime-ct-publishCert";
    public static final short NID_id_smime_ct_publishCert = 206;
    public static final String OBJ_id_smime_ct_publishCert = "1.2.840.113549.1.9.16.1.3";
    
    public static final String SN_id_smime_ct_TSTInfo = "id-smime-ct-TSTInfo";
    public static final short NID_id_smime_ct_TSTInfo = 207;
    public static final String OBJ_id_smime_ct_TSTInfo = "1.2.840.113549.1.9.16.1.4";
    
    public static final String SN_id_smime_ct_TDTInfo = "id-smime-ct-TDTInfo";
    public static final short NID_id_smime_ct_TDTInfo = 208;
    public static final String OBJ_id_smime_ct_TDTInfo = "1.2.840.113549.1.9.16.1.5";
    
    public static final String SN_id_smime_ct_contentInfo = "id-smime-ct-contentInfo";
    public static final short NID_id_smime_ct_contentInfo = 209;
    public static final String OBJ_id_smime_ct_contentInfo = "1.2.840.113549.1.9.16.1.6";
    
    public static final String SN_id_smime_ct_DVCSRequestData = "id-smime-ct-DVCSRequestData";
    public static final short NID_id_smime_ct_DVCSRequestData = 210;
    public static final String OBJ_id_smime_ct_DVCSRequestData = "1.2.840.113549.1.9.16.1.7";
    
    public static final String SN_id_smime_ct_DVCSResponseData = "id-smime-ct-DVCSResponseData";
    public static final short NID_id_smime_ct_DVCSResponseData = 211;
    public static final String OBJ_id_smime_ct_DVCSResponseData = "1.2.840.113549.1.9.16.1.8";
    
    public static final String SN_id_smime_ct_compressedData = "id-smime-ct-compressedData";
    public static final short NID_id_smime_ct_compressedData = 786;
    public static final String OBJ_id_smime_ct_compressedData = "1.2.840.113549.1.9.16.1.9";
    
    public static final String SN_id_ct_asciiTextWithCRLF = "id-ct-asciiTextWithCRLF";
    public static final short NID_id_ct_asciiTextWithCRLF = 787;
    public static final String OBJ_id_ct_asciiTextWithCRLF = "1.2.840.113549.1.9.16.1.27";
    
    public static final String SN_id_smime_aa_receiptRequest = "id-smime-aa-receiptRequest";
    public static final short NID_id_smime_aa_receiptRequest = 212;
    public static final String OBJ_id_smime_aa_receiptRequest = "1.2.840.113549.1.9.16.2.1";
    
    public static final String SN_id_smime_aa_securityLabel = "id-smime-aa-securityLabel";
    public static final short NID_id_smime_aa_securityLabel = 213;
    public static final String OBJ_id_smime_aa_securityLabel = "1.2.840.113549.1.9.16.2.2";
    
    public static final String SN_id_smime_aa_mlExpandHistory = "id-smime-aa-mlExpandHistory";
    public static final short NID_id_smime_aa_mlExpandHistory = 214;
    public static final String OBJ_id_smime_aa_mlExpandHistory = "1.2.840.113549.1.9.16.2.3";
    
    public static final String SN_id_smime_aa_contentHint = "id-smime-aa-contentHint";
    public static final short NID_id_smime_aa_contentHint = 215;
    public static final String OBJ_id_smime_aa_contentHint = "1.2.840.113549.1.9.16.2.4";
    
    public static final String SN_id_smime_aa_msgSigDigest = "id-smime-aa-msgSigDigest";
    public static final short NID_id_smime_aa_msgSigDigest = 216;
    public static final String OBJ_id_smime_aa_msgSigDigest = "1.2.840.113549.1.9.16.2.5";
    
    public static final String SN_id_smime_aa_encapContentType = "id-smime-aa-encapContentType";
    public static final short NID_id_smime_aa_encapContentType = 217;
    public static final String OBJ_id_smime_aa_encapContentType = "1.2.840.113549.1.9.16.2.6";
    
    public static final String SN_id_smime_aa_contentIdentifier = "id-smime-aa-contentIdentifier";
    public static final short NID_id_smime_aa_contentIdentifier = 218;
    public static final String OBJ_id_smime_aa_contentIdentifier = "1.2.840.113549.1.9.16.2.7";
    
    public static final String SN_id_smime_aa_macValue = "id-smime-aa-macValue";
    public static final short NID_id_smime_aa_macValue = 219;
    public static final String OBJ_id_smime_aa_macValue = "1.2.840.113549.1.9.16.2.8";
    
    public static final String SN_id_smime_aa_equivalentLabels = "id-smime-aa-equivalentLabels";
    public static final short NID_id_smime_aa_equivalentLabels = 220;
    public static final String OBJ_id_smime_aa_equivalentLabels = "1.2.840.113549.1.9.16.2.9";
    
    public static final String SN_id_smime_aa_contentReference = "id-smime-aa-contentReference";
    public static final short NID_id_smime_aa_contentReference = 221;
    public static final String OBJ_id_smime_aa_contentReference = "1.2.840.113549.1.9.16.2.10";
    
    public static final String SN_id_smime_aa_encrypKeyPref = "id-smime-aa-encrypKeyPref";
    public static final short NID_id_smime_aa_encrypKeyPref = 222;
    public static final String OBJ_id_smime_aa_encrypKeyPref = "1.2.840.113549.1.9.16.2.11";
    
    public static final String SN_id_smime_aa_signingCertificate = "id-smime-aa-signingCertificate";
    public static final short NID_id_smime_aa_signingCertificate = 223;
    public static final String OBJ_id_smime_aa_signingCertificate = "1.2.840.113549.1.9.16.2.12";
    
    public static final String SN_id_smime_aa_smimeEncryptCerts = "id-smime-aa-smimeEncryptCerts";
    public static final short NID_id_smime_aa_smimeEncryptCerts = 224;
    public static final String OBJ_id_smime_aa_smimeEncryptCerts = "1.2.840.113549.1.9.16.2.13";
    
    public static final String SN_id_smime_aa_timeStampToken = "id-smime-aa-timeStampToken";
    public static final short NID_id_smime_aa_timeStampToken = 225;
    public static final String OBJ_id_smime_aa_timeStampToken = "1.2.840.113549.1.9.16.2.14";
    
    public static final String SN_id_smime_aa_ets_sigPolicyId = "id-smime-aa-ets-sigPolicyId";
    public static final short NID_id_smime_aa_ets_sigPolicyId = 226;
    public static final String OBJ_id_smime_aa_ets_sigPolicyId = "1.2.840.113549.1.9.16.2.15";
    
    public static final String SN_id_smime_aa_ets_commitmentType = "id-smime-aa-ets-commitmentType";
    public static final short NID_id_smime_aa_ets_commitmentType = 227;
    public static final String OBJ_id_smime_aa_ets_commitmentType = "1.2.840.113549.1.9.16.2.16";
    
    public static final String SN_id_smime_aa_ets_signerLocation = "id-smime-aa-ets-signerLocation";
    public static final short NID_id_smime_aa_ets_signerLocation = 228;
    public static final String OBJ_id_smime_aa_ets_signerLocation = "1.2.840.113549.1.9.16.2.17";
    
    public static final String SN_id_smime_aa_ets_signerAttr = "id-smime-aa-ets-signerAttr";
    public static final short NID_id_smime_aa_ets_signerAttr = 229;
    public static final String OBJ_id_smime_aa_ets_signerAttr = "1.2.840.113549.1.9.16.2.18";
    
    public static final String SN_id_smime_aa_ets_otherSigCert = "id-smime-aa-ets-otherSigCert";
    public static final short NID_id_smime_aa_ets_otherSigCert = 230;
    public static final String OBJ_id_smime_aa_ets_otherSigCert = "1.2.840.113549.1.9.16.2.19";
    
    public static final String SN_id_smime_aa_ets_contentTimestamp = "id-smime-aa-ets-contentTimestamp";
    public static final short NID_id_smime_aa_ets_contentTimestamp = 231;
    public static final String OBJ_id_smime_aa_ets_contentTimestamp = "1.2.840.113549.1.9.16.2.20";
    
    public static final String SN_id_smime_aa_ets_CertificateRefs = "id-smime-aa-ets-CertificateRefs";
    public static final short NID_id_smime_aa_ets_CertificateRefs = 232;
    public static final String OBJ_id_smime_aa_ets_CertificateRefs = "1.2.840.113549.1.9.16.2.21";
    
    public static final String SN_id_smime_aa_ets_RevocationRefs = "id-smime-aa-ets-RevocationRefs";
    public static final short NID_id_smime_aa_ets_RevocationRefs = 233;
    public static final String OBJ_id_smime_aa_ets_RevocationRefs = "1.2.840.113549.1.9.16.2.22";
    
    public static final String SN_id_smime_aa_ets_certValues = "id-smime-aa-ets-certValues";
    public static final short NID_id_smime_aa_ets_certValues = 234;
    public static final String OBJ_id_smime_aa_ets_certValues = "1.2.840.113549.1.9.16.2.23";
    
    public static final String SN_id_smime_aa_ets_revocationValues = "id-smime-aa-ets-revocationValues";
    public static final short NID_id_smime_aa_ets_revocationValues = 235;
    public static final String OBJ_id_smime_aa_ets_revocationValues = "1.2.840.113549.1.9.16.2.24";
    
    public static final String SN_id_smime_aa_ets_escTimeStamp = "id-smime-aa-ets-escTimeStamp";
    public static final short NID_id_smime_aa_ets_escTimeStamp = 236;
    public static final String OBJ_id_smime_aa_ets_escTimeStamp = "1.2.840.113549.1.9.16.2.25";
    
    public static final String SN_id_smime_aa_ets_certCRLTimestamp = "id-smime-aa-ets-certCRLTimestamp";
    public static final short NID_id_smime_aa_ets_certCRLTimestamp = 237;
    public static final String OBJ_id_smime_aa_ets_certCRLTimestamp = "1.2.840.113549.1.9.16.2.26";
    
    public static final String SN_id_smime_aa_ets_archiveTimeStamp = "id-smime-aa-ets-archiveTimeStamp";
    public static final short NID_id_smime_aa_ets_archiveTimeStamp = 238;
    public static final String OBJ_id_smime_aa_ets_archiveTimeStamp = "1.2.840.113549.1.9.16.2.27";
    
    public static final String SN_id_smime_aa_signatureType = "id-smime-aa-signatureType";
    public static final short NID_id_smime_aa_signatureType = 239;
    public static final String OBJ_id_smime_aa_signatureType = "1.2.840.113549.1.9.16.2.28";
    
    public static final String SN_id_smime_aa_dvcs_dvc = "id-smime-aa-dvcs-dvc";
    public static final short NID_id_smime_aa_dvcs_dvc = 240;
    public static final String OBJ_id_smime_aa_dvcs_dvc = "1.2.840.113549.1.9.16.2.29";
    
    public static final String SN_id_smime_alg_ESDHwith3DES = "id-smime-alg-ESDHwith3DES";
    public static final short NID_id_smime_alg_ESDHwith3DES = 241;
    public static final String OBJ_id_smime_alg_ESDHwith3DES = "1.2.840.113549.1.9.16.3.1";
    
    public static final String SN_id_smime_alg_ESDHwithRC2 = "id-smime-alg-ESDHwithRC2";
    public static final short NID_id_smime_alg_ESDHwithRC2 = 242;
    public static final String OBJ_id_smime_alg_ESDHwithRC2 = "1.2.840.113549.1.9.16.3.2";
    
    public static final String SN_id_smime_alg_3DESwrap = "id-smime-alg-3DESwrap";
    public static final short NID_id_smime_alg_3DESwrap = 243;
    public static final String OBJ_id_smime_alg_3DESwrap = "1.2.840.113549.1.9.16.3.3";
    
    public static final String SN_id_smime_alg_RC2wrap = "id-smime-alg-RC2wrap";
    public static final short NID_id_smime_alg_RC2wrap = 244;
    public static final String OBJ_id_smime_alg_RC2wrap = "1.2.840.113549.1.9.16.3.4";
    
    public static final String SN_id_smime_alg_ESDH = "id-smime-alg-ESDH";
    public static final short NID_id_smime_alg_ESDH = 245;
    public static final String OBJ_id_smime_alg_ESDH = "1.2.840.113549.1.9.16.3.5";
    
    public static final String SN_id_smime_alg_CMS3DESwrap = "id-smime-alg-CMS3DESwrap";
    public static final short NID_id_smime_alg_CMS3DESwrap = 246;
    public static final String OBJ_id_smime_alg_CMS3DESwrap = "1.2.840.113549.1.9.16.3.6";
    
    public static final String SN_id_smime_alg_CMSRC2wrap = "id-smime-alg-CMSRC2wrap";
    public static final short NID_id_smime_alg_CMSRC2wrap = 247;
    public static final String OBJ_id_smime_alg_CMSRC2wrap = "1.2.840.113549.1.9.16.3.7";
    
    public static final String SN_id_alg_PWRI_KEK = "id-alg-PWRI-KEK";
    public static final short NID_id_alg_PWRI_KEK = 893;
    public static final String OBJ_id_alg_PWRI_KEK = "1.2.840.113549.1.9.16.3.9";
    
    public static final String SN_id_smime_cd_ldap = "id-smime-cd-ldap";
    public static final short NID_id_smime_cd_ldap = 248;
    public static final String OBJ_id_smime_cd_ldap = "1.2.840.113549.1.9.16.4.1";
    
    public static final String SN_id_smime_spq_ets_sqt_uri = "id-smime-spq-ets-sqt-uri";
    public static final short NID_id_smime_spq_ets_sqt_uri = 249;
    public static final String OBJ_id_smime_spq_ets_sqt_uri = "1.2.840.113549.1.9.16.5.1";
    
    public static final String SN_id_smime_spq_ets_sqt_unotice = "id-smime-spq-ets-sqt-unotice";
    public static final short NID_id_smime_spq_ets_sqt_unotice = 250;
    public static final String OBJ_id_smime_spq_ets_sqt_unotice = "1.2.840.113549.1.9.16.5.2";
    
    public static final String SN_id_smime_cti_ets_proofOfOrigin = "id-smime-cti-ets-proofOfOrigin";
    public static final short NID_id_smime_cti_ets_proofOfOrigin = 251;
    public static final String OBJ_id_smime_cti_ets_proofOfOrigin = "1.2.840.113549.1.9.16.6.1";
    
    public static final String SN_id_smime_cti_ets_proofOfReceipt = "id-smime-cti-ets-proofOfReceipt";
    public static final short NID_id_smime_cti_ets_proofOfReceipt = 252;
    public static final String OBJ_id_smime_cti_ets_proofOfReceipt = "1.2.840.113549.1.9.16.6.2";
    
    public static final String SN_id_smime_cti_ets_proofOfDelivery = "id-smime-cti-ets-proofOfDelivery";
    public static final short NID_id_smime_cti_ets_proofOfDelivery = 253;
    public static final String OBJ_id_smime_cti_ets_proofOfDelivery = "1.2.840.113549.1.9.16.6.3";
    
    public static final String SN_id_smime_cti_ets_proofOfSender = "id-smime-cti-ets-proofOfSender";
    public static final short NID_id_smime_cti_ets_proofOfSender = 254;
    public static final String OBJ_id_smime_cti_ets_proofOfSender = "1.2.840.113549.1.9.16.6.4";
    
    public static final String SN_id_smime_cti_ets_proofOfApproval = "id-smime-cti-ets-proofOfApproval";
    public static final short NID_id_smime_cti_ets_proofOfApproval = 255;
    public static final String OBJ_id_smime_cti_ets_proofOfApproval = "1.2.840.113549.1.9.16.6.5";
    
    public static final String SN_id_smime_cti_ets_proofOfCreation = "id-smime-cti-ets-proofOfCreation";
    public static final short NID_id_smime_cti_ets_proofOfCreation = 256;
    public static final String OBJ_id_smime_cti_ets_proofOfCreation = "1.2.840.113549.1.9.16.6.6";
    
    public static final String LN_friendlyName = "friendlyName";
    public static final short NID_friendlyName = 156;
    public static final String OBJ_friendlyName = "1.2.840.113549.1.9.20";
    
    public static final String LN_localKeyID = "localKeyID";
    public static final short NID_localKeyID = 157;
    public static final String OBJ_localKeyID = "1.2.840.113549.1.9.21";
    
    public static final String SN_ms_csp_name = "CSPName";
    public static final String LN_ms_csp_name = "Microsoft CSP Name";
    public static final short NID_ms_csp_name = 417;
    public static final String OBJ_ms_csp_name = "1.3.6.1.4.1.311.17.1";
    
    public static final String SN_LocalKeySet = "LocalKeySet";
    public static final String LN_LocalKeySet = "Microsoft Local Key set";
    public static final short NID_LocalKeySet = 856;
    public static final String OBJ_LocalKeySet = "1.3.6.1.4.1.311.17.2";
    
    public static final String OBJ_certTypes = "1.2.840.113549.1.9.22";
    
    public static final String LN_x509Certificate = "x509Certificate";
    public static final short NID_x509Certificate = 158;
    public static final String OBJ_x509Certificate = "1.2.840.113549.1.9.22.1";
    
    public static final String LN_sdsiCertificate = "sdsiCertificate";
    public static final short NID_sdsiCertificate = 159;
    public static final String OBJ_sdsiCertificate = "1.2.840.113549.1.9.22.2";
    
    public static final String OBJ_crlTypes = "1.2.840.113549.1.9.23";
    
    public static final String LN_x509Crl = "x509Crl";
    public static final short NID_x509Crl = 160;
    public static final String OBJ_x509Crl = "1.2.840.113549.1.9.23.1";
    
    public static final String OBJ_pkcs12 = "1.2.840.113549.1.12";
    
    public static final String OBJ_pkcs12_pbeids = "1.2.840.113549.1.12.1";
    
    public static final String SN_pbe_WithSHA1And128BitRC4 = "PBE-SHA1-RC4-128";
    public static final String LN_pbe_WithSHA1And128BitRC4 = "pbeWithSHA1And128BitRC4";
    public static final short NID_pbe_WithSHA1And128BitRC4 = 144;
    public static final String OBJ_pbe_WithSHA1And128BitRC4 = "1.2.840.113549.1.12.1.1";
    
    public static final String SN_pbe_WithSHA1And40BitRC4 = "PBE-SHA1-RC4-40";
    public static final String LN_pbe_WithSHA1And40BitRC4 = "pbeWithSHA1And40BitRC4";
    public static final short NID_pbe_WithSHA1And40BitRC4 = 145;
    public static final String OBJ_pbe_WithSHA1And40BitRC4 = "1.2.840.113549.1.12.1.2";
    
    public static final String SN_pbe_WithSHA1And3_Key_TripleDES_CBC = "PBE-SHA1-3DES";
    public static final String LN_pbe_WithSHA1And3_Key_TripleDES_CBC = "pbeWithSHA1And3-KeyTripleDES-CBC";
    public static final short NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146;
    public static final String OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC = "1.2.840.113549.1.12.1.3";
    
    public static final String SN_pbe_WithSHA1And2_Key_TripleDES_CBC = "PBE-SHA1-2DES";
    public static final String LN_pbe_WithSHA1And2_Key_TripleDES_CBC = "pbeWithSHA1And2-KeyTripleDES-CBC";
    public static final short NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147;
    public static final String OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC = "1.2.840.113549.1.12.1.4";
    
    public static final String SN_pbe_WithSHA1And128BitRC2_CBC = "PBE-SHA1-RC2-128";
    public static final String LN_pbe_WithSHA1And128BitRC2_CBC = "pbeWithSHA1And128BitRC2-CBC";
    public static final short NID_pbe_WithSHA1And128BitRC2_CBC = 148;
    public static final String OBJ_pbe_WithSHA1And128BitRC2_CBC = "1.2.840.113549.1.12.1.5";
    
    public static final String SN_pbe_WithSHA1And40BitRC2_CBC = "PBE-SHA1-RC2-40";
    public static final String LN_pbe_WithSHA1And40BitRC2_CBC = "pbeWithSHA1And40BitRC2-CBC";
    public static final short NID_pbe_WithSHA1And40BitRC2_CBC = 149;
    public static final String OBJ_pbe_WithSHA1And40BitRC2_CBC = "1.2.840.113549.1.12.1.6";
    
    public static final String OBJ_pkcs12_Version1 = "1.2.840.113549.1.12.10";
    
    public static final String OBJ_pkcs12_BagIds = "1.2.840.113549.1.12.10.1";
    
    public static final String LN_keyBag = "keyBag";
    public static final short NID_keyBag = 150;
    public static final String OBJ_keyBag = "1.2.840.113549.1.12.10.1.1";
    
    public static final String LN_pkcs8ShroudedKeyBag = "pkcs8ShroudedKeyBag";
    public static final short NID_pkcs8ShroudedKeyBag = 151;
    public static final String OBJ_pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2";
    
    public static final String LN_certBag = "certBag";
    public static final short NID_certBag = 152;
    public static final String OBJ_certBag = "1.2.840.113549.1.12.10.1.3";
    
    public static final String LN_crlBag = "crlBag";
    public static final short NID_crlBag = 153;
    public static final String OBJ_crlBag = "1.2.840.113549.1.12.10.1.4";
    
    public static final String LN_secretBag = "secretBag";
    public static final short NID_secretBag = 154;
    public static final String OBJ_secretBag = "1.2.840.113549.1.12.10.1.5";
    
    public static final String LN_safeContentsBag = "safeContentsBag";
    public static final short NID_safeContentsBag = 155;
    public static final String OBJ_safeContentsBag = "1.2.840.113549.1.12.10.1.6";
    
    public static final String SN_md2 = "MD2";
    public static final String LN_md2 = "md2";
    public static final short NID_md2 = 3;
    public static final String OBJ_md2 = "1.2.840.113549.2.2";
    
    public static final String SN_md4 = "MD4";
    public static final String LN_md4 = "md4";
    public static final short NID_md4 = 257;
    public static final String OBJ_md4 = "1.2.840.113549.2.4";
    
    public static final String SN_md5 = "MD5";
    public static final String LN_md5 = "md5";
    public static final short NID_md5 = 4;
    public static final String OBJ_md5 = "1.2.840.113549.2.5";
    
    public static final String SN_md5_sha1 = "MD5-SHA1";
    public static final String LN_md5_sha1 = "md5-sha1";
    public static final short NID_md5_sha1 = 114;
    
    public static final String LN_hmacWithMD5 = "hmacWithMD5";
    public static final short NID_hmacWithMD5 = 797;
    public static final String OBJ_hmacWithMD5 = "1.2.840.113549.2.6";
    
    public static final String LN_hmacWithSHA1 = "hmacWithSHA1";
    public static final short NID_hmacWithSHA1 = 163;
    public static final String OBJ_hmacWithSHA1 = "1.2.840.113549.2.7";
    
    public static final String LN_hmacWithSHA224 = "hmacWithSHA224";
    public static final short NID_hmacWithSHA224 = 798;
    public static final String OBJ_hmacWithSHA224 = "1.2.840.113549.2.8";
    
    public static final String LN_hmacWithSHA256 = "hmacWithSHA256";
    public static final short NID_hmacWithSHA256 = 799;
    public static final String OBJ_hmacWithSHA256 = "1.2.840.113549.2.9";
    
    public static final String LN_hmacWithSHA384 = "hmacWithSHA384";
    public static final short NID_hmacWithSHA384 = 800;
    public static final String OBJ_hmacWithSHA384 = "1.2.840.113549.2.10";
    
    public static final String LN_hmacWithSHA512 = "hmacWithSHA512";
    public static final short NID_hmacWithSHA512 = 801;
    public static final String OBJ_hmacWithSHA512 = "1.2.840.113549.2.11";
    
    public static final String SN_rc2_cbc = "RC2-CBC";
    public static final String LN_rc2_cbc = "rc2-cbc";
    public static final short NID_rc2_cbc = 37;
    public static final String OBJ_rc2_cbc = "1.2.840.113549.3.2";
    
    public static final String SN_rc2_ecb = "RC2-ECB";
    public static final String LN_rc2_ecb = "rc2-ecb";
    public static final short NID_rc2_ecb = 38;
    
    public static final String SN_rc2_cfb64 = "RC2-CFB";
    public static final String LN_rc2_cfb64 = "rc2-cfb";
    public static final short NID_rc2_cfb64 = 39;
    
    public static final String SN_rc2_ofb64 = "RC2-OFB";
    public static final String LN_rc2_ofb64 = "rc2-ofb";
    public static final short NID_rc2_ofb64 = 40;
    
    public static final String SN_rc2_40_cbc = "RC2-40-CBC";
    public static final String LN_rc2_40_cbc = "rc2-40-cbc";
    public static final short NID_rc2_40_cbc = 98;
    
    public static final String SN_rc2_64_cbc = "RC2-64-CBC";
    public static final String LN_rc2_64_cbc = "rc2-64-cbc";
    public static final short NID_rc2_64_cbc = 166;
    
    public static final String SN_rc4 = "RC4";
    public static final String LN_rc4 = "rc4";
    public static final short NID_rc4 = 5;
    public static final String OBJ_rc4 = "1.2.840.113549.3.4";
    
    public static final String SN_rc4_40 = "RC4-40";
    public static final String LN_rc4_40 = "rc4-40";
    public static final short NID_rc4_40 = 97;
    
    public static final String SN_des_ede3_cbc = "DES-EDE3-CBC";
    public static final String LN_des_ede3_cbc = "des-ede3-cbc";
    public static final short NID_des_ede3_cbc = 44;
    public static final String OBJ_des_ede3_cbc = "1.2.840.113549.3.7";
    
    public static final String SN_rc5_cbc = "RC5-CBC";
    public static final String LN_rc5_cbc = "rc5-cbc";
    public static final short NID_rc5_cbc = 120;
    public static final String OBJ_rc5_cbc = "1.2.840.113549.3.8";
    
    public static final String SN_rc5_ecb = "RC5-ECB";
    public static final String LN_rc5_ecb = "rc5-ecb";
    public static final short NID_rc5_ecb = 121;
    
    public static final String SN_rc5_cfb64 = "RC5-CFB";
    public static final String LN_rc5_cfb64 = "rc5-cfb";
    public static final short NID_rc5_cfb64 = 122;
    
    public static final String SN_rc5_ofb64 = "RC5-OFB";
    public static final String LN_rc5_ofb64 = "rc5-ofb";
    public static final short NID_rc5_ofb64 = 123;
    
    public static final String SN_ms_ext_req = "msExtReq";
    public static final String LN_ms_ext_req = "Microsoft Extension Request";
    public static final short NID_ms_ext_req = 171;
    public static final String OBJ_ms_ext_req = "1.3.6.1.4.1.311.2.1.14";
    
    public static final String SN_ms_code_ind = "msCodeInd";
    public static final String LN_ms_code_ind = "Microsoft Individual Code Signing";
    public static final short NID_ms_code_ind = 134;
    public static final String OBJ_ms_code_ind = "1.3.6.1.4.1.311.2.1.21";
    
    public static final String SN_ms_code_com = "msCodeCom";
    public static final String LN_ms_code_com = "Microsoft Commercial Code Signing";
    public static final short NID_ms_code_com = 135;
    public static final String OBJ_ms_code_com = "1.3.6.1.4.1.311.2.1.22";
    
    public static final String SN_ms_ctl_sign = "msCTLSign";
    public static final String LN_ms_ctl_sign = "Microsoft Trust List Signing";
    public static final short NID_ms_ctl_sign = 136;
    public static final String OBJ_ms_ctl_sign = "1.3.6.1.4.1.311.10.3.1";
    
    public static final String SN_ms_sgc = "msSGC";
    public static final String LN_ms_sgc = "Microsoft Server Gated Crypto";
    public static final short NID_ms_sgc = 137;
    public static final String OBJ_ms_sgc = "1.3.6.1.4.1.311.10.3.3";
    
    public static final String SN_ms_efs = "msEFS";
    public static final String LN_ms_efs = "Microsoft Encrypted File System";
    public static final short NID_ms_efs = 138;
    public static final String OBJ_ms_efs = "1.3.6.1.4.1.311.10.3.4";
    
    public static final String SN_ms_smartcard_login = "msSmartcardLogin";
    public static final String LN_ms_smartcard_login = "Microsoft Smartcardlogin";
    public static final short NID_ms_smartcard_login = 648;
    public static final String OBJ_ms_smartcard_login = "1.3.6.1.4.1.311.20.2.2";
    
    public static final String SN_ms_upn = "msUPN";
    public static final String LN_ms_upn = "Microsoft Universal Principal Name";
    public static final short NID_ms_upn = 649;
    public static final String OBJ_ms_upn = "1.3.6.1.4.1.311.20.2.3";
    
    public static final String SN_idea_cbc = "IDEA-CBC";
    public static final String LN_idea_cbc = "idea-cbc";
    public static final short NID_idea_cbc = 34;
    public static final String OBJ_idea_cbc = "1.3.6.1.4.1.188.7.1.1.2";
    
    public static final String SN_idea_ecb = "IDEA-ECB";
    public static final String LN_idea_ecb = "idea-ecb";
    public static final short NID_idea_ecb = 36;
    
    public static final String SN_idea_cfb64 = "IDEA-CFB";
    public static final String LN_idea_cfb64 = "idea-cfb";
    public static final short NID_idea_cfb64 = 35;
    
    public static final String SN_idea_ofb64 = "IDEA-OFB";
    public static final String LN_idea_ofb64 = "idea-ofb";
    public static final short NID_idea_ofb64 = 46;
    
    public static final String SN_bf_cbc = "BF-CBC";
    public static final String LN_bf_cbc = "bf-cbc";
    public static final short NID_bf_cbc = 91;
    public static final String OBJ_bf_cbc = "1.3.6.1.4.1.3029.1.2";
    
    public static final String SN_bf_ecb = "BF-ECB";
    public static final String LN_bf_ecb = "bf-ecb";
    public static final short NID_bf_ecb = 92;
    
    public static final String SN_bf_cfb64 = "BF-CFB";
    public static final String LN_bf_cfb64 = "bf-cfb";
    public static final short NID_bf_cfb64 = 93;
    
    public static final String SN_bf_ofb64 = "BF-OFB";
    public static final String LN_bf_ofb64 = "bf-ofb";
    public static final short NID_bf_ofb64 = 94;
    
    public static final String SN_id_pkix = "PKIX";
    public static final short NID_id_pkix = 127;
    public static final String OBJ_id_pkix = "1.3.6.1.5.5.7";
    
    public static final String SN_id_pkix_mod = "id-pkix-mod";
    public static final short NID_id_pkix_mod = 258;
    public static final String OBJ_id_pkix_mod = "1.3.6.1.5.5.7.0";
    
    public static final String SN_id_pe = "id-pe";
    public static final short NID_id_pe = 175;
    public static final String OBJ_id_pe = "1.3.6.1.5.5.7.1";
    
    public static final String SN_id_qt = "id-qt";
    public static final short NID_id_qt = 259;
    public static final String OBJ_id_qt = "1.3.6.1.5.5.7.2";
    
    public static final String SN_id_kp = "id-kp";
    public static final short NID_id_kp = 128;
    public static final String OBJ_id_kp = "1.3.6.1.5.5.7.3";
    
    public static final String SN_id_it = "id-it";
    public static final short NID_id_it = 260;
    public static final String OBJ_id_it = "1.3.6.1.5.5.7.4";
    
    public static final String SN_id_pkip = "id-pkip";
    public static final short NID_id_pkip = 261;
    public static final String OBJ_id_pkip = "1.3.6.1.5.5.7.5";
    
    public static final String SN_id_alg = "id-alg";
    public static final short NID_id_alg = 262;
    public static final String OBJ_id_alg = "1.3.6.1.5.5.7.6";
    
    public static final String SN_id_cmc = "id-cmc";
    public static final short NID_id_cmc = 263;
    public static final String OBJ_id_cmc = "1.3.6.1.5.5.7.7";
    
    public static final String SN_id_on = "id-on";
    public static final short NID_id_on = 264;
    public static final String OBJ_id_on = "1.3.6.1.5.5.7.8";
    
    public static final String SN_id_pda = "id-pda";
    public static final short NID_id_pda = 265;
    public static final String OBJ_id_pda = "1.3.6.1.5.5.7.9";
    
    public static final String SN_id_aca = "id-aca";
    public static final short NID_id_aca = 266;
    public static final String OBJ_id_aca = "1.3.6.1.5.5.7.10";
    
    public static final String SN_id_qcs = "id-qcs";
    public static final short NID_id_qcs = 267;
    public static final String OBJ_id_qcs = "1.3.6.1.5.5.7.11";
    
    public static final String SN_id_cct = "id-cct";
    public static final short NID_id_cct = 268;
    public static final String OBJ_id_cct = "1.3.6.1.5.5.7.12";
    
    public static final String SN_id_ppl = "id-ppl";
    public static final short NID_id_ppl = 662;
    public static final String OBJ_id_ppl = "1.3.6.1.5.5.7.21";
    
    public static final String SN_id_ad = "id-ad";
    public static final short NID_id_ad = 176;
    public static final String OBJ_id_ad = "1.3.6.1.5.5.7.48";
    
    public static final String SN_id_pkix1_explicit_88 = "id-pkix1-explicit-88";
    public static final short NID_id_pkix1_explicit_88 = 269;
    public static final String OBJ_id_pkix1_explicit_88 = "1.3.6.1.5.5.7.0.1";
    
    public static final String SN_id_pkix1_implicit_88 = "id-pkix1-implicit-88";
    public static final short NID_id_pkix1_implicit_88 = 270;
    public static final String OBJ_id_pkix1_implicit_88 = "1.3.6.1.5.5.7.0.2";
    
    public static final String SN_id_pkix1_explicit_93 = "id-pkix1-explicit-93";
    public static final short NID_id_pkix1_explicit_93 = 271;
    public static final String OBJ_id_pkix1_explicit_93 = "1.3.6.1.5.5.7.0.3";
    
    public static final String SN_id_pkix1_implicit_93 = "id-pkix1-implicit-93";
    public static final short NID_id_pkix1_implicit_93 = 272;
    public static final String OBJ_id_pkix1_implicit_93 = "1.3.6.1.5.5.7.0.4";
    
    public static final String SN_id_mod_crmf = "id-mod-crmf";
    public static final short NID_id_mod_crmf = 273;
    public static final String OBJ_id_mod_crmf = "1.3.6.1.5.5.7.0.5";
    
    public static final String SN_id_mod_cmc = "id-mod-cmc";
    public static final short NID_id_mod_cmc = 274;
    public static final String OBJ_id_mod_cmc = "1.3.6.1.5.5.7.0.6";
    
    public static final String SN_id_mod_kea_profile_88 = "id-mod-kea-profile-88";
    public static final short NID_id_mod_kea_profile_88 = 275;
    public static final String OBJ_id_mod_kea_profile_88 = "1.3.6.1.5.5.7.0.7";
    
    public static final String SN_id_mod_kea_profile_93 = "id-mod-kea-profile-93";
    public static final short NID_id_mod_kea_profile_93 = 276;
    public static final String OBJ_id_mod_kea_profile_93 = "1.3.6.1.5.5.7.0.8";
    
    public static final String SN_id_mod_cmp = "id-mod-cmp";
    public static final short NID_id_mod_cmp = 277;
    public static final String OBJ_id_mod_cmp = "1.3.6.1.5.5.7.0.9";
    
    public static final String SN_id_mod_qualified_cert_88 = "id-mod-qualified-cert-88";
    public static final short NID_id_mod_qualified_cert_88 = 278;
    public static final String OBJ_id_mod_qualified_cert_88 = "1.3.6.1.5.5.7.0.10";
    
    public static final String SN_id_mod_qualified_cert_93 = "id-mod-qualified-cert-93";
    public static final short NID_id_mod_qualified_cert_93 = 279;
    public static final String OBJ_id_mod_qualified_cert_93 = "1.3.6.1.5.5.7.0.11";
    
    public static final String SN_id_mod_attribute_cert = "id-mod-attribute-cert";
    public static final short NID_id_mod_attribute_cert = 280;
    public static final String OBJ_id_mod_attribute_cert = "1.3.6.1.5.5.7.0.12";
    
    public static final String SN_id_mod_timestamp_protocol = "id-mod-timestamp-protocol";
    public static final short NID_id_mod_timestamp_protocol = 281;
    public static final String OBJ_id_mod_timestamp_protocol = "1.3.6.1.5.5.7.0.13";
    
    public static final String SN_id_mod_ocsp = "id-mod-ocsp";
    public static final short NID_id_mod_ocsp = 282;
    public static final String OBJ_id_mod_ocsp = "1.3.6.1.5.5.7.0.14";
    
    public static final String SN_id_mod_dvcs = "id-mod-dvcs";
    public static final short NID_id_mod_dvcs = 283;
    public static final String OBJ_id_mod_dvcs = "1.3.6.1.5.5.7.0.15";
    
    public static final String SN_id_mod_cmp2000 = "id-mod-cmp2000";
    public static final short NID_id_mod_cmp2000 = 284;
    public static final String OBJ_id_mod_cmp2000 = "1.3.6.1.5.5.7.0.16";
    
    public static final String SN_info_access = "authorityInfoAccess";
    public static final String LN_info_access = "Authority Information Access";
    public static final short NID_info_access = 177;
    public static final String OBJ_info_access = "1.3.6.1.5.5.7.1.1";
    
    public static final String SN_biometricInfo = "biometricInfo";
    public static final String LN_biometricInfo = "Biometric Info";
    public static final short NID_biometricInfo = 285;
    public static final String OBJ_biometricInfo = "1.3.6.1.5.5.7.1.2";
    
    public static final String SN_qcStatements = "qcStatements";
    public static final short NID_qcStatements = 286;
    public static final String OBJ_qcStatements = "1.3.6.1.5.5.7.1.3";
    
    public static final String SN_ac_auditEntity = "ac-auditEntity";
    public static final short NID_ac_auditEntity = 287;
    public static final String OBJ_ac_auditEntity = "1.3.6.1.5.5.7.1.4";
    
    public static final String SN_ac_targeting = "ac-targeting";
    public static final short NID_ac_targeting = 288;
    public static final String OBJ_ac_targeting = "1.3.6.1.5.5.7.1.5";
    
    public static final String SN_aaControls = "aaControls";
    public static final short NID_aaControls = 289;
    public static final String OBJ_aaControls = "1.3.6.1.5.5.7.1.6";
    
    public static final String SN_sbgp_ipAddrBlock = "sbgp-ipAddrBlock";
    public static final short NID_sbgp_ipAddrBlock = 290;
    public static final String OBJ_sbgp_ipAddrBlock = "1.3.6.1.5.5.7.1.7";
    
    public static final String SN_sbgp_autonomousSysNum = "sbgp-autonomousSysNum";
    public static final short NID_sbgp_autonomousSysNum = 291;
    public static final String OBJ_sbgp_autonomousSysNum = "1.3.6.1.5.5.7.1.8";
    
    public static final String SN_sbgp_routerIdentifier = "sbgp-routerIdentifier";
    public static final short NID_sbgp_routerIdentifier = 292;
    public static final String OBJ_sbgp_routerIdentifier = "1.3.6.1.5.5.7.1.9";
    
    public static final String SN_ac_proxying = "ac-proxying";
    public static final short NID_ac_proxying = 397;
    public static final String OBJ_ac_proxying = "1.3.6.1.5.5.7.1.10";
    
    public static final String SN_sinfo_access = "subjectInfoAccess";
    public static final String LN_sinfo_access = "Subject Information Access";
    public static final short NID_sinfo_access = 398;
    public static final String OBJ_sinfo_access = "1.3.6.1.5.5.7.1.11";
    
    public static final String SN_proxyCertInfo = "proxyCertInfo";
    public static final String LN_proxyCertInfo = "Proxy Certificate Information";
    public static final short NID_proxyCertInfo = 663;
    public static final String OBJ_proxyCertInfo = "1.3.6.1.5.5.7.1.14";
    
    public static final String SN_id_qt_cps = "id-qt-cps";
    public static final String LN_id_qt_cps = "Policy Qualifier CPS";
    public static final short NID_id_qt_cps = 164;
    public static final String OBJ_id_qt_cps = "1.3.6.1.5.5.7.2.1";
    
    public static final String SN_id_qt_unotice = "id-qt-unotice";
    public static final String LN_id_qt_unotice = "Policy Qualifier User Notice";
    public static final short NID_id_qt_unotice = 165;
    public static final String OBJ_id_qt_unotice = "1.3.6.1.5.5.7.2.2";
    
    public static final String SN_textNotice = "textNotice";
    public static final short NID_textNotice = 293;
    public static final String OBJ_textNotice = "1.3.6.1.5.5.7.2.3";
    
    public static final String SN_server_auth = "serverAuth";
    public static final String LN_server_auth = "TLS Web Server Authentication";
    public static final short NID_server_auth = 129;
    public static final String OBJ_server_auth = "1.3.6.1.5.5.7.3.1";
    
    public static final String SN_client_auth = "clientAuth";
    public static final String LN_client_auth = "TLS Web Client Authentication";
    public static final short NID_client_auth = 130;
    public static final String OBJ_client_auth = "1.3.6.1.5.5.7.3.2";
    
    public static final String SN_code_sign = "codeSigning";
    public static final String LN_code_sign = "Code Signing";
    public static final short NID_code_sign = 131;
    public static final String OBJ_code_sign = "1.3.6.1.5.5.7.3.3";
    
    public static final String SN_email_protect = "emailProtection";
    public static final String LN_email_protect = "E-mail Protection";
    public static final short NID_email_protect = 132;
    public static final String OBJ_email_protect = "1.3.6.1.5.5.7.3.4";
    
    public static final String SN_ipsecEndSystem = "ipsecEndSystem";
    public static final String LN_ipsecEndSystem = "IPSec End System";
    public static final short NID_ipsecEndSystem = 294;
    public static final String OBJ_ipsecEndSystem = "1.3.6.1.5.5.7.3.5";
    
    public static final String SN_ipsecTunnel = "ipsecTunnel";
    public static final String LN_ipsecTunnel = "IPSec Tunnel";
    public static final short NID_ipsecTunnel = 295;
    public static final String OBJ_ipsecTunnel = "1.3.6.1.5.5.7.3.6";
    
    public static final String SN_ipsecUser = "ipsecUser";
    public static final String LN_ipsecUser = "IPSec User";
    public static final short NID_ipsecUser = 296;
    public static final String OBJ_ipsecUser = "1.3.6.1.5.5.7.3.7";
    
    public static final String SN_time_stamp = "timeStamping";
    public static final String LN_time_stamp = "Time Stamping";
    public static final short NID_time_stamp = 133;
    public static final String OBJ_time_stamp = "1.3.6.1.5.5.7.3.8";
    
    public static final String SN_OCSP_sign = "OCSPSigning";
    public static final String LN_OCSP_sign = "OCSP Signing";
    public static final short NID_OCSP_sign = 180;
    public static final String OBJ_OCSP_sign = "1.3.6.1.5.5.7.3.9";
    
    public static final String SN_dvcs = "DVCS";
    public static final String LN_dvcs = "dvcs";
    public static final short NID_dvcs = 297;
    public static final String OBJ_dvcs = "1.3.6.1.5.5.7.3.10";
    
    public static final String SN_id_it_caProtEncCert = "id-it-caProtEncCert";
    public static final short NID_id_it_caProtEncCert = 298;
    public static final String OBJ_id_it_caProtEncCert = "1.3.6.1.5.5.7.4.1";
    
    public static final String SN_id_it_signKeyPairTypes = "id-it-signKeyPairTypes";
    public static final short NID_id_it_signKeyPairTypes = 299;
    public static final String OBJ_id_it_signKeyPairTypes = "1.3.6.1.5.5.7.4.2";
    
    public static final String SN_id_it_encKeyPairTypes = "id-it-encKeyPairTypes";
    public static final short NID_id_it_encKeyPairTypes = 300;
    public static final String OBJ_id_it_encKeyPairTypes = "1.3.6.1.5.5.7.4.3";
    
    public static final String SN_id_it_preferredSymmAlg = "id-it-preferredSymmAlg";
    public static final short NID_id_it_preferredSymmAlg = 301;
    public static final String OBJ_id_it_preferredSymmAlg = "1.3.6.1.5.5.7.4.4";
    
    public static final String SN_id_it_caKeyUpdateInfo = "id-it-caKeyUpdateInfo";
    public static final short NID_id_it_caKeyUpdateInfo = 302;
    public static final String OBJ_id_it_caKeyUpdateInfo = "1.3.6.1.5.5.7.4.5";
    
    public static final String SN_id_it_currentCRL = "id-it-currentCRL";
    public static final short NID_id_it_currentCRL = 303;
    public static final String OBJ_id_it_currentCRL = "1.3.6.1.5.5.7.4.6";
    
    public static final String SN_id_it_unsupportedOIDs = "id-it-unsupportedOIDs";
    public static final short NID_id_it_unsupportedOIDs = 304;
    public static final String OBJ_id_it_unsupportedOIDs = "1.3.6.1.5.5.7.4.7";
    
    public static final String SN_id_it_subscriptionRequest = "id-it-subscriptionRequest";
    public static final short NID_id_it_subscriptionRequest = 305;
    public static final String OBJ_id_it_subscriptionRequest = "1.3.6.1.5.5.7.4.8";
    
    public static final String SN_id_it_subscriptionResponse = "id-it-subscriptionResponse";
    public static final short NID_id_it_subscriptionResponse = 306;
    public static final String OBJ_id_it_subscriptionResponse = "1.3.6.1.5.5.7.4.9";
    
    public static final String SN_id_it_keyPairParamReq = "id-it-keyPairParamReq";
    public static final short NID_id_it_keyPairParamReq = 307;
    public static final String OBJ_id_it_keyPairParamReq = "1.3.6.1.5.5.7.4.10";
    
    public static final String SN_id_it_keyPairParamRep = "id-it-keyPairParamRep";
    public static final short NID_id_it_keyPairParamRep = 308;
    public static final String OBJ_id_it_keyPairParamRep = "1.3.6.1.5.5.7.4.11";
    
    public static final String SN_id_it_revPassphrase = "id-it-revPassphrase";
    public static final short NID_id_it_revPassphrase = 309;
    public static final String OBJ_id_it_revPassphrase = "1.3.6.1.5.5.7.4.12";
    
    public static final String SN_id_it_implicitConfirm = "id-it-implicitConfirm";
    public static final short NID_id_it_implicitConfirm = 310;
    public static final String OBJ_id_it_implicitConfirm = "1.3.6.1.5.5.7.4.13";
    
    public static final String SN_id_it_confirmWaitTime = "id-it-confirmWaitTime";
    public static final short NID_id_it_confirmWaitTime = 311;
    public static final String OBJ_id_it_confirmWaitTime = "1.3.6.1.5.5.7.4.14";
    
    public static final String SN_id_it_origPKIMessage = "id-it-origPKIMessage";
    public static final short NID_id_it_origPKIMessage = 312;
    public static final String OBJ_id_it_origPKIMessage = "1.3.6.1.5.5.7.4.15";
    
    public static final String SN_id_it_suppLangTags = "id-it-suppLangTags";
    public static final short NID_id_it_suppLangTags = 784;
    public static final String OBJ_id_it_suppLangTags = "1.3.6.1.5.5.7.4.16";
    
    public static final String SN_id_regCtrl = "id-regCtrl";
    public static final short NID_id_regCtrl = 313;
    public static final String OBJ_id_regCtrl = "1.3.6.1.5.5.7.5.1";
    
    public static final String SN_id_regInfo = "id-regInfo";
    public static final short NID_id_regInfo = 314;
    public static final String OBJ_id_regInfo = "1.3.6.1.5.5.7.5.2";
    
    public static final String SN_id_regCtrl_regToken = "id-regCtrl-regToken";
    public static final short NID_id_regCtrl_regToken = 315;
    public static final String OBJ_id_regCtrl_regToken = "1.3.6.1.5.5.7.5.1.1";
    
    public static final String SN_id_regCtrl_authenticator = "id-regCtrl-authenticator";
    public static final short NID_id_regCtrl_authenticator = 316;
    public static final String OBJ_id_regCtrl_authenticator = "1.3.6.1.5.5.7.5.1.2";
    
    public static final String SN_id_regCtrl_pkiPublicationInfo = "id-regCtrl-pkiPublicationInfo";
    public static final short NID_id_regCtrl_pkiPublicationInfo = 317;
    public static final String OBJ_id_regCtrl_pkiPublicationInfo = "1.3.6.1.5.5.7.5.1.3";
    
    public static final String SN_id_regCtrl_pkiArchiveOptions = "id-regCtrl-pkiArchiveOptions";
    public static final short NID_id_regCtrl_pkiArchiveOptions = 318;
    public static final String OBJ_id_regCtrl_pkiArchiveOptions = "1.3.6.1.5.5.7.5.1.4";
    
    public static final String SN_id_regCtrl_oldCertID = "id-regCtrl-oldCertID";
    public static final short NID_id_regCtrl_oldCertID = 319;
    public static final String OBJ_id_regCtrl_oldCertID = "1.3.6.1.5.5.7.5.1.5";
    
    public static final String SN_id_regCtrl_protocolEncrKey = "id-regCtrl-protocolEncrKey";
    public static final short NID_id_regCtrl_protocolEncrKey = 320;
    public static final String OBJ_id_regCtrl_protocolEncrKey = "1.3.6.1.5.5.7.5.1.6";
    
    public static final String SN_id_regInfo_utf8Pairs = "id-regInfo-utf8Pairs";
    public static final short NID_id_regInfo_utf8Pairs = 321;
    public static final String OBJ_id_regInfo_utf8Pairs = "1.3.6.1.5.5.7.5.2.1";
    
    public static final String SN_id_regInfo_certReq = "id-regInfo-certReq";
    public static final short NID_id_regInfo_certReq = 322;
    public static final String OBJ_id_regInfo_certReq = "1.3.6.1.5.5.7.5.2.2";
    
    public static final String SN_id_alg_des40 = "id-alg-des40";
    public static final short NID_id_alg_des40 = 323;
    public static final String OBJ_id_alg_des40 = "1.3.6.1.5.5.7.6.1";
    
    public static final String SN_id_alg_noSignature = "id-alg-noSignature";
    public static final short NID_id_alg_noSignature = 324;
    public static final String OBJ_id_alg_noSignature = "1.3.6.1.5.5.7.6.2";
    
    public static final String SN_id_alg_dh_sig_hmac_sha1 = "id-alg-dh-sig-hmac-sha1";
    public static final short NID_id_alg_dh_sig_hmac_sha1 = 325;
    public static final String OBJ_id_alg_dh_sig_hmac_sha1 = "1.3.6.1.5.5.7.6.3";
    
    public static final String SN_id_alg_dh_pop = "id-alg-dh-pop";
    public static final short NID_id_alg_dh_pop = 326;
    public static final String OBJ_id_alg_dh_pop = "1.3.6.1.5.5.7.6.4";
    
    public static final String SN_id_cmc_statusInfo = "id-cmc-statusInfo";
    public static final short NID_id_cmc_statusInfo = 327;
    public static final String OBJ_id_cmc_statusInfo = "1.3.6.1.5.5.7.7.1";
    
    public static final String SN_id_cmc_identification = "id-cmc-identification";
    public static final short NID_id_cmc_identification = 328;
    public static final String OBJ_id_cmc_identification = "1.3.6.1.5.5.7.7.2";
    
    public static final String SN_id_cmc_identityProof = "id-cmc-identityProof";
    public static final short NID_id_cmc_identityProof = 329;
    public static final String OBJ_id_cmc_identityProof = "1.3.6.1.5.5.7.7.3";
    
    public static final String SN_id_cmc_dataReturn = "id-cmc-dataReturn";
    public static final short NID_id_cmc_dataReturn = 330;
    public static final String OBJ_id_cmc_dataReturn = "1.3.6.1.5.5.7.7.4";
    
    public static final String SN_id_cmc_transactionId = "id-cmc-transactionId";
    public static final short NID_id_cmc_transactionId = 331;
    public static final String OBJ_id_cmc_transactionId = "1.3.6.1.5.5.7.7.5";
    
    public static final String SN_id_cmc_senderNonce = "id-cmc-senderNonce";
    public static final short NID_id_cmc_senderNonce = 332;
    public static final String OBJ_id_cmc_senderNonce = "1.3.6.1.5.5.7.7.6";
    
    public static final String SN_id_cmc_recipientNonce = "id-cmc-recipientNonce";
    public static final short NID_id_cmc_recipientNonce = 333;
    public static final String OBJ_id_cmc_recipientNonce = "1.3.6.1.5.5.7.7.7";
    
    public static final String SN_id_cmc_addExtensions = "id-cmc-addExtensions";
    public static final short NID_id_cmc_addExtensions = 334;
    public static final String OBJ_id_cmc_addExtensions = "1.3.6.1.5.5.7.7.8";
    
    public static final String SN_id_cmc_encryptedPOP = "id-cmc-encryptedPOP";
    public static final short NID_id_cmc_encryptedPOP = 335;
    public static final String OBJ_id_cmc_encryptedPOP = "1.3.6.1.5.5.7.7.9";
    
    public static final String SN_id_cmc_decryptedPOP = "id-cmc-decryptedPOP";
    public static final short NID_id_cmc_decryptedPOP = 336;
    public static final String OBJ_id_cmc_decryptedPOP = "1.3.6.1.5.5.7.7.10";
    
    public static final String SN_id_cmc_lraPOPWitness = "id-cmc-lraPOPWitness";
    public static final short NID_id_cmc_lraPOPWitness = 337;
    public static final String OBJ_id_cmc_lraPOPWitness = "1.3.6.1.5.5.7.7.11";
    
    public static final String SN_id_cmc_getCert = "id-cmc-getCert";
    public static final short NID_id_cmc_getCert = 338;
    public static final String OBJ_id_cmc_getCert = "1.3.6.1.5.5.7.7.15";
    
    public static final String SN_id_cmc_getCRL = "id-cmc-getCRL";
    public static final short NID_id_cmc_getCRL = 339;
    public static final String OBJ_id_cmc_getCRL = "1.3.6.1.5.5.7.7.16";
    
    public static final String SN_id_cmc_revokeRequest = "id-cmc-revokeRequest";
    public static final short NID_id_cmc_revokeRequest = 340;
    public static final String OBJ_id_cmc_revokeRequest = "1.3.6.1.5.5.7.7.17";
    
    public static final String SN_id_cmc_regInfo = "id-cmc-regInfo";
    public static final short NID_id_cmc_regInfo = 341;
    public static final String OBJ_id_cmc_regInfo = "1.3.6.1.5.5.7.7.18";
    
    public static final String SN_id_cmc_responseInfo = "id-cmc-responseInfo";
    public static final short NID_id_cmc_responseInfo = 342;
    public static final String OBJ_id_cmc_responseInfo = "1.3.6.1.5.5.7.7.19";
    
    public static final String SN_id_cmc_queryPending = "id-cmc-queryPending";
    public static final short NID_id_cmc_queryPending = 343;
    public static final String OBJ_id_cmc_queryPending = "1.3.6.1.5.5.7.7.21";
    
    public static final String SN_id_cmc_popLinkRandom = "id-cmc-popLinkRandom";
    public static final short NID_id_cmc_popLinkRandom = 344;
    public static final String OBJ_id_cmc_popLinkRandom = "1.3.6.1.5.5.7.7.22";
    
    public static final String SN_id_cmc_popLinkWitness = "id-cmc-popLinkWitness";
    public static final short NID_id_cmc_popLinkWitness = 345;
    public static final String OBJ_id_cmc_popLinkWitness = "1.3.6.1.5.5.7.7.23";
    
    public static final String SN_id_cmc_confirmCertAcceptance = "id-cmc-confirmCertAcceptance";
    public static final short NID_id_cmc_confirmCertAcceptance = 346;
    public static final String OBJ_id_cmc_confirmCertAcceptance = "1.3.6.1.5.5.7.7.24";
    
    public static final String SN_id_on_personalData = "id-on-personalData";
    public static final short NID_id_on_personalData = 347;
    public static final String OBJ_id_on_personalData = "1.3.6.1.5.5.7.8.1";
    
    public static final String SN_id_on_permanentIdentifier = "id-on-permanentIdentifier";
    public static final String LN_id_on_permanentIdentifier = "Permanent Identifier";
    public static final short NID_id_on_permanentIdentifier = 858;
    public static final String OBJ_id_on_permanentIdentifier = "1.3.6.1.5.5.7.8.3";
    
    public static final String SN_id_pda_dateOfBirth = "id-pda-dateOfBirth";
    public static final short NID_id_pda_dateOfBirth = 348;
    public static final String OBJ_id_pda_dateOfBirth = "1.3.6.1.5.5.7.9.1";
    
    public static final String SN_id_pda_placeOfBirth = "id-pda-placeOfBirth";
    public static final short NID_id_pda_placeOfBirth = 349;
    public static final String OBJ_id_pda_placeOfBirth = "1.3.6.1.5.5.7.9.2";
    
    public static final String SN_id_pda_gender = "id-pda-gender";
    public static final short NID_id_pda_gender = 351;
    public static final String OBJ_id_pda_gender = "1.3.6.1.5.5.7.9.3";
    
    public static final String SN_id_pda_countryOfCitizenship = "id-pda-countryOfCitizenship";
    public static final short NID_id_pda_countryOfCitizenship = 352;
    public static final String OBJ_id_pda_countryOfCitizenship = "1.3.6.1.5.5.7.9.4";
    
    public static final String SN_id_pda_countryOfResidence = "id-pda-countryOfResidence";
    public static final short NID_id_pda_countryOfResidence = 353;
    public static final String OBJ_id_pda_countryOfResidence = "1.3.6.1.5.5.7.9.5";
    
    public static final String SN_id_aca_authenticationInfo = "id-aca-authenticationInfo";
    public static final short NID_id_aca_authenticationInfo = 354;
    public static final String OBJ_id_aca_authenticationInfo = "1.3.6.1.5.5.7.10.1";
    
    public static final String SN_id_aca_accessIdentity = "id-aca-accessIdentity";
    public static final short NID_id_aca_accessIdentity = 355;
    public static final String OBJ_id_aca_accessIdentity = "1.3.6.1.5.5.7.10.2";
    
    public static final String SN_id_aca_chargingIdentity = "id-aca-chargingIdentity";
    public static final short NID_id_aca_chargingIdentity = 356;
    public static final String OBJ_id_aca_chargingIdentity = "1.3.6.1.5.5.7.10.3";
    
    public static final String SN_id_aca_group = "id-aca-group";
    public static final short NID_id_aca_group = 357;
    public static final String OBJ_id_aca_group = "1.3.6.1.5.5.7.10.4";
    
    public static final String SN_id_aca_role = "id-aca-role";
    public static final short NID_id_aca_role = 358;
    public static final String OBJ_id_aca_role = "1.3.6.1.5.5.7.10.5";
    
    public static final String SN_id_aca_encAttrs = "id-aca-encAttrs";
    public static final short NID_id_aca_encAttrs = 399;
    public static final String OBJ_id_aca_encAttrs = "1.3.6.1.5.5.7.10.6";
    
    public static final String SN_id_qcs_pkixQCSyntax_v1 = "id-qcs-pkixQCSyntax-v1";
    public static final short NID_id_qcs_pkixQCSyntax_v1 = 359;
    public static final String OBJ_id_qcs_pkixQCSyntax_v1 = "1.3.6.1.5.5.7.11.1";
    
    public static final String SN_id_cct_crs = "id-cct-crs";
    public static final short NID_id_cct_crs = 360;
    public static final String OBJ_id_cct_crs = "1.3.6.1.5.5.7.12.1";
    
    public static final String SN_id_cct_PKIData = "id-cct-PKIData";
    public static final short NID_id_cct_PKIData = 361;
    public static final String OBJ_id_cct_PKIData = "1.3.6.1.5.5.7.12.2";
    
    public static final String SN_id_cct_PKIResponse = "id-cct-PKIResponse";
    public static final short NID_id_cct_PKIResponse = 362;
    public static final String OBJ_id_cct_PKIResponse = "1.3.6.1.5.5.7.12.3";
    
    public static final String SN_id_ppl_anyLanguage = "id-ppl-anyLanguage";
    public static final String LN_id_ppl_anyLanguage = "Any language";
    public static final short NID_id_ppl_anyLanguage = 664;
    public static final String OBJ_id_ppl_anyLanguage = "1.3.6.1.5.5.7.21.0";
    
    public static final String SN_id_ppl_inheritAll = "id-ppl-inheritAll";
    public static final String LN_id_ppl_inheritAll = "Inherit all";
    public static final short NID_id_ppl_inheritAll = 665;
    public static final String OBJ_id_ppl_inheritAll = "1.3.6.1.5.5.7.21.1";
    
    public static final String SN_Independent = "id-ppl-independent";
    public static final String LN_Independent = "Independent";
    public static final short NID_Independent = 667;
    public static final String OBJ_Independent = "1.3.6.1.5.5.7.21.2";
    
    public static final String SN_ad_OCSP = "OCSP";
    public static final String LN_ad_OCSP = "OCSP";
    public static final short NID_ad_OCSP = 178;
    public static final String OBJ_ad_OCSP = "1.3.6.1.5.5.7.48.1";
    
    public static final String SN_ad_ca_issuers = "caIssuers";
    public static final String LN_ad_ca_issuers = "CA Issuers";
    public static final short NID_ad_ca_issuers = 179;
    public static final String OBJ_ad_ca_issuers = "1.3.6.1.5.5.7.48.2";
    
    public static final String SN_ad_timeStamping = "ad_timestamping";
    public static final String LN_ad_timeStamping = "AD Time Stamping";
    public static final short NID_ad_timeStamping = 363;
    public static final String OBJ_ad_timeStamping = "1.3.6.1.5.5.7.48.3";
    
    public static final String SN_ad_dvcs = "AD_DVCS";
    public static final String LN_ad_dvcs = "ad dvcs";
    public static final short NID_ad_dvcs = 364;
    public static final String OBJ_ad_dvcs = "1.3.6.1.5.5.7.48.4";
    
    public static final String SN_caRepository = "caRepository";
    public static final String LN_caRepository = "CA Repository";
    public static final short NID_caRepository = 785;
    public static final String OBJ_caRepository = "1.3.6.1.5.5.7.48.5";
    
    public static final String OBJ_id_pkix_OCSP = "1.3.6.1.5.5.7.48.1";
    
    public static final String SN_id_pkix_OCSP_basic = "basicOCSPResponse";
    public static final String LN_id_pkix_OCSP_basic = "Basic OCSP Response";
    public static final short NID_id_pkix_OCSP_basic = 365;
    public static final String OBJ_id_pkix_OCSP_basic = "1.3.6.1.5.5.7.48.1.1";
    
    public static final String SN_id_pkix_OCSP_Nonce = "Nonce";
    public static final String LN_id_pkix_OCSP_Nonce = "OCSP Nonce";
    public static final short NID_id_pkix_OCSP_Nonce = 366;
    public static final String OBJ_id_pkix_OCSP_Nonce = "1.3.6.1.5.5.7.48.1.2";
    
    public static final String SN_id_pkix_OCSP_CrlID = "CrlID";
    public static final String LN_id_pkix_OCSP_CrlID = "OCSP CRL ID";
    public static final short NID_id_pkix_OCSP_CrlID = 367;
    public static final String OBJ_id_pkix_OCSP_CrlID = "1.3.6.1.5.5.7.48.1.3";
    
    public static final String SN_id_pkix_OCSP_acceptableResponses = "acceptableResponses";
    public static final String LN_id_pkix_OCSP_acceptableResponses = "Acceptable OCSP Responses";
    public static final short NID_id_pkix_OCSP_acceptableResponses = 368;
    public static final String OBJ_id_pkix_OCSP_acceptableResponses = "1.3.6.1.5.5.7.48.1.4";
    
    public static final String SN_id_pkix_OCSP_noCheck = "noCheck";
    public static final String LN_id_pkix_OCSP_noCheck = "OCSP No Check";
    public static final short NID_id_pkix_OCSP_noCheck = 369;
    public static final String OBJ_id_pkix_OCSP_noCheck = "1.3.6.1.5.5.7.48.1.5";
    
    public static final String SN_id_pkix_OCSP_archiveCutoff = "archiveCutoff";
    public static final String LN_id_pkix_OCSP_archiveCutoff = "OCSP Archive Cutoff";
    public static final short NID_id_pkix_OCSP_archiveCutoff = 370;
    public static final String OBJ_id_pkix_OCSP_archiveCutoff = "1.3.6.1.5.5.7.48.1.6";
    
    public static final String SN_id_pkix_OCSP_serviceLocator = "serviceLocator";
    public static final String LN_id_pkix_OCSP_serviceLocator = "OCSP Service Locator";
    public static final short NID_id_pkix_OCSP_serviceLocator = 371;
    public static final String OBJ_id_pkix_OCSP_serviceLocator = "1.3.6.1.5.5.7.48.1.7";
    
    public static final String SN_id_pkix_OCSP_extendedStatus = "extendedStatus";
    public static final String LN_id_pkix_OCSP_extendedStatus = "Extended OCSP Status";
    public static final short NID_id_pkix_OCSP_extendedStatus = 372;
    public static final String OBJ_id_pkix_OCSP_extendedStatus = "1.3.6.1.5.5.7.48.1.8";
    
    public static final String SN_id_pkix_OCSP_valid = "valid";
    public static final short NID_id_pkix_OCSP_valid = 373;
    public static final String OBJ_id_pkix_OCSP_valid = "1.3.6.1.5.5.7.48.1.9";
    
    public static final String SN_id_pkix_OCSP_path = "path";
    public static final short NID_id_pkix_OCSP_path = 374;
    public static final String OBJ_id_pkix_OCSP_path = "1.3.6.1.5.5.7.48.1.10";
    
    public static final String SN_id_pkix_OCSP_trustRoot = "trustRoot";
    public static final String LN_id_pkix_OCSP_trustRoot = "Trust Root";
    public static final short NID_id_pkix_OCSP_trustRoot = 375;
    public static final String OBJ_id_pkix_OCSP_trustRoot = "1.3.6.1.5.5.7.48.1.11";
    
    public static final String SN_algorithm = "algorithm";
    public static final String LN_algorithm = "algorithm";
    public static final short NID_algorithm = 376;
    public static final String OBJ_algorithm = "1.3.14.3.2";
    
    public static final String SN_md5WithRSA = "RSA-NP-MD5";
    public static final String LN_md5WithRSA = "md5WithRSA";
    public static final short NID_md5WithRSA = 104;
    public static final String OBJ_md5WithRSA = "1.3.14.3.2.3";
    
    public static final String SN_des_ecb = "DES-ECB";
    public static final String LN_des_ecb = "des-ecb";
    public static final short NID_des_ecb = 29;
    public static final String OBJ_des_ecb = "1.3.14.3.2.6";
    
    public static final String SN_des_cbc = "DES-CBC";
    public static final String LN_des_cbc = "des-cbc";
    public static final short NID_des_cbc = 31;
    public static final String OBJ_des_cbc = "1.3.14.3.2.7";
    
    public static final String SN_des_ofb64 = "DES-OFB";
    public static final String LN_des_ofb64 = "des-ofb";
    public static final short NID_des_ofb64 = 45;
    public static final String OBJ_des_ofb64 = "1.3.14.3.2.8";
    
    public static final String SN_des_cfb64 = "DES-CFB";
    public static final String LN_des_cfb64 = "des-cfb";
    public static final short NID_des_cfb64 = 30;
    public static final String OBJ_des_cfb64 = "1.3.14.3.2.9";
    
    public static final String SN_rsaSignature = "rsaSignature";
    public static final short NID_rsaSignature = 377;
    public static final String OBJ_rsaSignature = "1.3.14.3.2.11";
    
    public static final String SN_dsa_2 = "DSA-old";
    public static final String LN_dsa_2 = "dsaEncryption-old";
    public static final short NID_dsa_2 = 67;
    public static final String OBJ_dsa_2 = "1.3.14.3.2.12";
    
    public static final String SN_dsaWithSHA = "DSA-SHA";
    public static final String LN_dsaWithSHA = "dsaWithSHA";
    public static final short NID_dsaWithSHA = 66;
    public static final String OBJ_dsaWithSHA = "1.3.14.3.2.13";
    
    public static final String SN_shaWithRSAEncryption = "RSA-SHA";
    public static final String LN_shaWithRSAEncryption = "shaWithRSAEncryption";
    public static final short NID_shaWithRSAEncryption = 42;
    public static final String OBJ_shaWithRSAEncryption = "1.3.14.3.2.15";
    
    public static final String SN_des_ede_ecb = "DES-EDE";
    public static final String LN_des_ede_ecb = "des-ede";
    public static final short NID_des_ede_ecb = 32;
    public static final String OBJ_des_ede_ecb = "1.3.14.3.2.17";
    
    public static final String SN_des_ede3_ecb = "DES-EDE3";
    public static final String LN_des_ede3_ecb = "des-ede3";
    public static final short NID_des_ede3_ecb = 33;
    
    public static final String SN_des_ede_cbc = "DES-EDE-CBC";
    public static final String LN_des_ede_cbc = "des-ede-cbc";
    public static final short NID_des_ede_cbc = 43;
    
    public static final String SN_des_ede_cfb64 = "DES-EDE-CFB";
    public static final String LN_des_ede_cfb64 = "des-ede-cfb";
    public static final short NID_des_ede_cfb64 = 60;
    
    public static final String SN_des_ede3_cfb64 = "DES-EDE3-CFB";
    public static final String LN_des_ede3_cfb64 = "des-ede3-cfb";
    public static final short NID_des_ede3_cfb64 = 61;
    
    public static final String SN_des_ede_ofb64 = "DES-EDE-OFB";
    public static final String LN_des_ede_ofb64 = "des-ede-ofb";
    public static final short NID_des_ede_ofb64 = 62;
    
    public static final String SN_des_ede3_ofb64 = "DES-EDE3-OFB";
    public static final String LN_des_ede3_ofb64 = "des-ede3-ofb";
    public static final short NID_des_ede3_ofb64 = 63;
    
    public static final String SN_desx_cbc = "DESX-CBC";
    public static final String LN_desx_cbc = "desx-cbc";
    public static final short NID_desx_cbc = 80;
    
    public static final String SN_sha = "SHA";
    public static final String LN_sha = "sha";
    public static final short NID_sha = 41;
    public static final String OBJ_sha = "1.3.14.3.2.18";
    
    public static final String SN_sha1 = "SHA1";
    public static final String LN_sha1 = "sha1";
    public static final short NID_sha1 = 64;
    public static final String OBJ_sha1 = "1.3.14.3.2.26";
    
    public static final String SN_dsaWithSHA1_2 = "DSA-SHA1-old";
    public static final String LN_dsaWithSHA1_2 = "dsaWithSHA1-old";
    public static final short NID_dsaWithSHA1_2 = 70;
    public static final String OBJ_dsaWithSHA1_2 = "1.3.14.3.2.27";
    
    public static final String SN_sha1WithRSA = "RSA-SHA1-2";
    public static final String LN_sha1WithRSA = "sha1WithRSA";
    public static final short NID_sha1WithRSA = 115;
    public static final String OBJ_sha1WithRSA = "1.3.14.3.2.29";
    
    public static final String SN_ripemd160 = "RIPEMD160";
    public static final String LN_ripemd160 = "ripemd160";
    public static final short NID_ripemd160 = 117;
    public static final String OBJ_ripemd160 = "1.3.36.3.2.1";
    
    public static final String SN_ripemd160WithRSA = "RSA-RIPEMD160";
    public static final String LN_ripemd160WithRSA = "ripemd160WithRSA";
    public static final short NID_ripemd160WithRSA = 119;
    public static final String OBJ_ripemd160WithRSA = "1.3.36.3.3.1.2";
    
    public static final String SN_sxnet = "SXNetID";
    public static final String LN_sxnet = "Strong Extranet ID";
    public static final short NID_sxnet = 143;
    public static final String OBJ_sxnet = "1.3.101.1.4.1";
    
    public static final String SN_X500 = "X500";
    public static final String LN_X500 = "directory services (X.500)";
    public static final short NID_X500 = 11;
    public static final String OBJ_X500 = "2.5";
    
    public static final String SN_X509 = "X509";
    public static final short NID_X509 = 12;
    public static final String OBJ_X509 = "2.5.4";
    
    public static final String SN_commonName = "CN";
    public static final String LN_commonName = "commonName";
    public static final short NID_commonName = 13;
    public static final String OBJ_commonName = "2.5.4.3";
    
    public static final String SN_surname = "SN";
    public static final String LN_surname = "surname";
    public static final short NID_surname = 100;
    public static final String OBJ_surname = "2.5.4.4";
    
    public static final String LN_serialNumber = "serialNumber";
    public static final short NID_serialNumber = 105;
    public static final String OBJ_serialNumber = "2.5.4.5";
    
    public static final String SN_countryName = "C";
    public static final String LN_countryName = "countryName";
    public static final short NID_countryName = 14;
    public static final String OBJ_countryName = "2.5.4.6";
    
    public static final String SN_localityName = "L";
    public static final String LN_localityName = "localityName";
    public static final short NID_localityName = 15;
    public static final String OBJ_localityName = "2.5.4.7";
    
    public static final String SN_stateOrProvinceName = "ST";
    public static final String LN_stateOrProvinceName = "stateOrProvinceName";
    public static final short NID_stateOrProvinceName = 16;
    public static final String OBJ_stateOrProvinceName = "2.5.4.8";
    
    public static final String SN_streetAddress = "street";
    public static final String LN_streetAddress = "streetAddress";
    public static final short NID_streetAddress = 660;
    public static final String OBJ_streetAddress = "2.5.4.9";
    
    public static final String SN_organizationName = "O";
    public static final String LN_organizationName = "organizationName";
    public static final short NID_organizationName = 17;
    public static final String OBJ_organizationName = "2.5.4.10";
    
    public static final String SN_organizationalUnitName = "OU";
    public static final String LN_organizationalUnitName = "organizationalUnitName";
    public static final short NID_organizationalUnitName = 18;
    public static final String OBJ_organizationalUnitName = "2.5.4.11";
    
    public static final String SN_title = "title";
    public static final String LN_title = "title";
    public static final short NID_title = 106;
    public static final String OBJ_title = "2.5.4.12";
    
    public static final String LN_description = "description";
    public static final short NID_description = 107;
    public static final String OBJ_description = "2.5.4.13";
    
    public static final String LN_searchGuide = "searchGuide";
    public static final short NID_searchGuide = 859;
    public static final String OBJ_searchGuide = "2.5.4.14";
    
    public static final String LN_businessCategory = "businessCategory";
    public static final short NID_businessCategory = 860;
    public static final String OBJ_businessCategory = "2.5.4.15";
    
    public static final String LN_postalAddress = "postalAddress";
    public static final short NID_postalAddress = 861;
    public static final String OBJ_postalAddress = "2.5.4.16";
    
    public static final String LN_postalCode = "postalCode";
    public static final short NID_postalCode = 661;
    public static final String OBJ_postalCode = "2.5.4.17";
    
    public static final String LN_postOfficeBox = "postOfficeBox";
    public static final short NID_postOfficeBox = 862;
    public static final String OBJ_postOfficeBox = "2.5.4.18";
    
    public static final String LN_physicalDeliveryOfficeName = "physicalDeliveryOfficeName";
    public static final short NID_physicalDeliveryOfficeName = 863;
    public static final String OBJ_physicalDeliveryOfficeName = "2.5.4.19";
    
    public static final String LN_telephoneNumber = "telephoneNumber";
    public static final short NID_telephoneNumber = 864;
    public static final String OBJ_telephoneNumber = "2.5.4.20";
    
    public static final String LN_telexNumber = "telexNumber";
    public static final short NID_telexNumber = 865;
    public static final String OBJ_telexNumber = "2.5.4.21";
    
    public static final String LN_teletexTerminalIdentifier = "teletexTerminalIdentifier";
    public static final short NID_teletexTerminalIdentifier = 866;
    public static final String OBJ_teletexTerminalIdentifier = "2.5.4.22";
    
    public static final String LN_facsimileTelephoneNumber = "facsimileTelephoneNumber";
    public static final short NID_facsimileTelephoneNumber = 867;
    public static final String OBJ_facsimileTelephoneNumber = "2.5.4.23";
    
    public static final String LN_x121Address = "x121Address";
    public static final short NID_x121Address = 868;
    public static final String OBJ_x121Address = "2.5.4.24";
    
    public static final String LN_internationaliSDNNumber = "internationaliSDNNumber";
    public static final short NID_internationaliSDNNumber = 869;
    public static final String OBJ_internationaliSDNNumber = "2.5.4.25";
    
    public static final String LN_registeredAddress = "registeredAddress";
    public static final short NID_registeredAddress = 870;
    public static final String OBJ_registeredAddress = "2.5.4.26";
    
    public static final String LN_destinationIndicator = "destinationIndicator";
    public static final short NID_destinationIndicator = 871;
    public static final String OBJ_destinationIndicator = "2.5.4.27";
    
    public static final String LN_preferredDeliveryMethod = "preferredDeliveryMethod";
    public static final short NID_preferredDeliveryMethod = 872;
    public static final String OBJ_preferredDeliveryMethod = "2.5.4.28";
    
    public static final String LN_presentationAddress = "presentationAddress";
    public static final short NID_presentationAddress = 873;
    public static final String OBJ_presentationAddress = "2.5.4.29";
    
    public static final String LN_supportedApplicationContext = "supportedApplicationContext";
    public static final short NID_supportedApplicationContext = 874;
    public static final String OBJ_supportedApplicationContext = "2.5.4.30";
    
    public static final String SN_member = "member";
    public static final short NID_member = 875;
    public static final String OBJ_member = "2.5.4.31";
    
    public static final String SN_owner = "owner";
    public static final short NID_owner = 876;
    public static final String OBJ_owner = "2.5.4.32";
    
    public static final String LN_roleOccupant = "roleOccupant";
    public static final short NID_roleOccupant = 877;
    public static final String OBJ_roleOccupant = "2.5.4.33";
    
    public static final String SN_seeAlso = "seeAlso";
    public static final short NID_seeAlso = 878;
    public static final String OBJ_seeAlso = "2.5.4.34";
    
    public static final String LN_userPassword = "userPassword";
    public static final short NID_userPassword = 879;
    public static final String OBJ_userPassword = "2.5.4.35";
    
    public static final String LN_userCertificate = "userCertificate";
    public static final short NID_userCertificate = 880;
    public static final String OBJ_userCertificate = "2.5.4.36";
    
    public static final String LN_cACertificate = "cACertificate";
    public static final short NID_cACertificate = 881;
    public static final String OBJ_cACertificate = "2.5.4.37";
    
    public static final String LN_authorityRevocationList = "authorityRevocationList";
    public static final short NID_authorityRevocationList = 882;
    public static final String OBJ_authorityRevocationList = "2.5.4.38";
    
    public static final String LN_certificateRevocationList = "certificateRevocationList";
    public static final short NID_certificateRevocationList = 883;
    public static final String OBJ_certificateRevocationList = "2.5.4.39";
    
    public static final String LN_crossCertificatePair = "crossCertificatePair";
    public static final short NID_crossCertificatePair = 884;
    public static final String OBJ_crossCertificatePair = "2.5.4.40";
    
    public static final String SN_name = "name";
    public static final String LN_name = "name";
    public static final short NID_name = 173;
    public static final String OBJ_name = "2.5.4.41";
    
    public static final String SN_givenName = "GN";
    public static final String LN_givenName = "givenName";
    public static final short NID_givenName = 99;
    public static final String OBJ_givenName = "2.5.4.42";
    
    public static final String SN_initials = "initials";
    public static final String LN_initials = "initials";
    public static final short NID_initials = 101;
    public static final String OBJ_initials = "2.5.4.43";
    
    public static final String LN_generationQualifier = "generationQualifier";
    public static final short NID_generationQualifier = 509;
    public static final String OBJ_generationQualifier = "2.5.4.44";
    
    public static final String LN_x500UniqueIdentifier = "x500UniqueIdentifier";
    public static final short NID_x500UniqueIdentifier = 503;
    public static final String OBJ_x500UniqueIdentifier = "2.5.4.45";
    
    public static final String SN_dnQualifier = "dnQualifier";
    public static final String LN_dnQualifier = "dnQualifier";
    public static final short NID_dnQualifier = 174;
    public static final String OBJ_dnQualifier = "2.5.4.46";
    
    public static final String LN_enhancedSearchGuide = "enhancedSearchGuide";
    public static final short NID_enhancedSearchGuide = 885;
    public static final String OBJ_enhancedSearchGuide = "2.5.4.47";
    
    public static final String LN_protocolInformation = "protocolInformation";
    public static final short NID_protocolInformation = 886;
    public static final String OBJ_protocolInformation = "2.5.4.48";
    
    public static final String LN_distinguishedName = "distinguishedName";
    public static final short NID_distinguishedName = 887;
    public static final String OBJ_distinguishedName = "2.5.4.49";
    
    public static final String LN_uniqueMember = "uniqueMember";
    public static final short NID_uniqueMember = 888;
    public static final String OBJ_uniqueMember = "2.5.4.50";
    
    public static final String LN_houseIdentifier = "houseIdentifier";
    public static final short NID_houseIdentifier = 889;
    public static final String OBJ_houseIdentifier = "2.5.4.51";
    
    public static final String LN_supportedAlgorithms = "supportedAlgorithms";
    public static final short NID_supportedAlgorithms = 890;
    public static final String OBJ_supportedAlgorithms = "2.5.4.52";
    
    public static final String LN_deltaRevocationList = "deltaRevocationList";
    public static final short NID_deltaRevocationList = 891;
    public static final String OBJ_deltaRevocationList = "2.5.4.53";
    
    public static final String SN_dmdName = "dmdName";
    public static final short NID_dmdName = 892;
    public static final String OBJ_dmdName = "2.5.4.54";
    
    public static final String LN_pseudonym = "pseudonym";
    public static final short NID_pseudonym = 510;
    public static final String OBJ_pseudonym = "2.5.4.65";
    
    public static final String SN_role = "role";
    public static final String LN_role = "role";
    public static final short NID_role = 400;
    public static final String OBJ_role = "2.5.4.72";
    
    public static final String SN_X500algorithms = "X500algorithms";
    public static final String LN_X500algorithms = "directory services - algorithms";
    public static final short NID_X500algorithms = 378;
    public static final String OBJ_X500algorithms = "2.5.8";
    
    public static final String SN_rsa = "RSA";
    public static final String LN_rsa = "rsa";
    public static final short NID_rsa = 19;
    public static final String OBJ_rsa = "2.5.8.1.1";
    
    public static final String SN_mdc2WithRSA = "RSA-MDC2";
    public static final String LN_mdc2WithRSA = "mdc2WithRSA";
    public static final short NID_mdc2WithRSA = 96;
    public static final String OBJ_mdc2WithRSA = "2.5.8.3.100";
    
    public static final String SN_mdc2 = "MDC2";
    public static final String LN_mdc2 = "mdc2";
    public static final short NID_mdc2 = 95;
    public static final String OBJ_mdc2 = "2.5.8.3.101";
    
    public static final String SN_id_ce = "id-ce";
    public static final short NID_id_ce = 81;
    public static final String OBJ_id_ce = "2.5.29";
    
    public static final String SN_subject_directory_attributes = "subjectDirectoryAttributes";
    public static final String LN_subject_directory_attributes = "X509v3 Subject Directory Attributes";
    public static final short NID_subject_directory_attributes = 769;
    public static final String OBJ_subject_directory_attributes = "2.5.29.9";
    
    public static final String SN_subject_key_identifier = "subjectKeyIdentifier";
    public static final String LN_subject_key_identifier = "X509v3 Subject Key Identifier";
    public static final short NID_subject_key_identifier = 82;
    public static final String OBJ_subject_key_identifier = "2.5.29.14";
    
    public static final String SN_key_usage = "keyUsage";
    public static final String LN_key_usage = "X509v3 Key Usage";
    public static final short NID_key_usage = 83;
    public static final String OBJ_key_usage = "2.5.29.15";
    
    public static final String SN_private_key_usage_period = "privateKeyUsagePeriod";
    public static final String LN_private_key_usage_period = "X509v3 Private Key Usage Period";
    public static final short NID_private_key_usage_period = 84;
    public static final String OBJ_private_key_usage_period = "2.5.29.16";
    
    public static final String SN_subject_alt_name = "subjectAltName";
    public static final String LN_subject_alt_name = "X509v3 Subject Alternative Name";
    public static final short NID_subject_alt_name = 85;
    public static final String OBJ_subject_alt_name = "2.5.29.17";
    
    public static final String SN_issuer_alt_name = "issuerAltName";
    public static final String LN_issuer_alt_name = "X509v3 Issuer Alternative Name";
    public static final short NID_issuer_alt_name = 86;
    public static final String OBJ_issuer_alt_name = "2.5.29.18";
    
    public static final String SN_basic_constraints = "basicConstraints";
    public static final String LN_basic_constraints = "X509v3 Basic Constraints";
    public static final short NID_basic_constraints = 87;
    public static final String OBJ_basic_constraints = "2.5.29.19";
    
    public static final String SN_crl_number = "crlNumber";
    public static final String LN_crl_number = "X509v3 CRL Number";
    public static final short NID_crl_number = 88;
    public static final String OBJ_crl_number = "2.5.29.20";
    
    public static final String SN_crl_reason = "CRLReason";
    public static final String LN_crl_reason = "X509v3 CRL Reason Code";
    public static final short NID_crl_reason = 141;
    public static final String OBJ_crl_reason = "2.5.29.21";
    
    public static final String SN_invalidity_date = "invalidityDate";
    public static final String LN_invalidity_date = "Invalidity Date";
    public static final short NID_invalidity_date = 142;
    public static final String OBJ_invalidity_date = "2.5.29.24";
    
    public static final String SN_delta_crl = "deltaCRL";
    public static final String LN_delta_crl = "X509v3 Delta CRL Indicator";
    public static final short NID_delta_crl = 140;
    public static final String OBJ_delta_crl = "2.5.29.27";
    
    public static final String SN_issuing_distribution_point = "issuingDistributionPoint";
    public static final String LN_issuing_distribution_point = "X509v3 Issuing Distrubution Point";
    public static final short NID_issuing_distribution_point = 770;
    public static final String OBJ_issuing_distribution_point = "2.5.29.28";
    
    public static final String SN_certificate_issuer = "certificateIssuer";
    public static final String LN_certificate_issuer = "X509v3 Certificate Issuer";
    public static final short NID_certificate_issuer = 771;
    public static final String OBJ_certificate_issuer = "2.5.29.29";
    
    public static final String SN_name_constraints = "nameConstraints";
    public static final String LN_name_constraints = "X509v3 Name Constraints";
    public static final short NID_name_constraints = 666;
    public static final String OBJ_name_constraints = "2.5.29.30";
    
    public static final String SN_crl_distribution_points = "crlDistributionPoints";
    public static final String LN_crl_distribution_points = "X509v3 CRL Distribution Points";
    public static final short NID_crl_distribution_points = 103;
    public static final String OBJ_crl_distribution_points = "2.5.29.31";
    
    public static final String SN_certificate_policies = "certificatePolicies";
    public static final String LN_certificate_policies = "X509v3 Certificate Policies";
    public static final short NID_certificate_policies = 89;
    public static final String OBJ_certificate_policies = "2.5.29.32";
    
    public static final String SN_any_policy = "anyPolicy";
    public static final String LN_any_policy = "X509v3 Any Policy";
    public static final short NID_any_policy = 746;
    public static final String OBJ_any_policy = "2.5.29.32.0";
    
    public static final String SN_policy_mappings = "policyMappings";
    public static final String LN_policy_mappings = "X509v3 Policy Mappings";
    public static final short NID_policy_mappings = 747;
    public static final String OBJ_policy_mappings = "2.5.29.33";
    
    public static final String SN_authority_key_identifier = "authorityKeyIdentifier";
    public static final String LN_authority_key_identifier = "X509v3 Authority Key Identifier";
    public static final short NID_authority_key_identifier = 90;
    public static final String OBJ_authority_key_identifier = "2.5.29.35";
    
    public static final String SN_policy_constraints = "policyConstraints";
    public static final String LN_policy_constraints = "X509v3 Policy Constraints";
    public static final short NID_policy_constraints = 401;
    public static final String OBJ_policy_constraints = "2.5.29.36";
    
    public static final String SN_ext_key_usage = "extendedKeyUsage";
    public static final String LN_ext_key_usage = "X509v3 Extended Key Usage";
    public static final short NID_ext_key_usage = 126;
    public static final String OBJ_ext_key_usage = "2.5.29.37";
    
    public static final String SN_freshest_crl = "freshestCRL";
    public static final String LN_freshest_crl = "X509v3 Freshest CRL";
    public static final short NID_freshest_crl = 857;
    public static final String OBJ_freshest_crl = "2.5.29.46";
    
    public static final String SN_inhibit_any_policy = "inhibitAnyPolicy";
    public static final String LN_inhibit_any_policy = "X509v3 Inhibit Any Policy";
    public static final short NID_inhibit_any_policy = 748;
    public static final String OBJ_inhibit_any_policy = "2.5.29.54";
    
    public static final String SN_target_information = "targetInformation";
    public static final String LN_target_information = "X509v3 AC Targeting";
    public static final short NID_target_information = 402;
    public static final String OBJ_target_information = "2.5.29.55";
    
    public static final String SN_no_rev_avail = "noRevAvail";
    public static final String LN_no_rev_avail = "X509v3 No Revocation Available";
    public static final short NID_no_rev_avail = 403;
    public static final String OBJ_no_rev_avail = "2.5.29.56";
    
    public static final String SN_anyExtendedKeyUsage = "anyExtendedKeyUsage";
    public static final String LN_anyExtendedKeyUsage = "Any Extended Key Usage";
    public static final short NID_anyExtendedKeyUsage = 910;
    public static final String OBJ_anyExtendedKeyUsage = "2.5.29.37.0";
    
    public static final String SN_netscape = "Netscape";
    public static final String LN_netscape = "Netscape Communications Corp.";
    public static final short NID_netscape = 57;
    public static final String OBJ_netscape = "2.16.840.1.113730";
    
    public static final String SN_netscape_cert_extension = "nsCertExt";
    public static final String LN_netscape_cert_extension = "Netscape Certificate Extension";
    public static final short NID_netscape_cert_extension = 58;
    public static final String OBJ_netscape_cert_extension = "2.16.840.1.113730.1";
    
    public static final String SN_netscape_data_type = "nsDataType";
    public static final String LN_netscape_data_type = "Netscape Data Type";
    public static final short NID_netscape_data_type = 59;
    public static final String OBJ_netscape_data_type = "2.16.840.1.113730.2";
    
    public static final String SN_netscape_cert_type = "nsCertType";
    public static final String LN_netscape_cert_type = "Netscape Cert Type";
    public static final short NID_netscape_cert_type = 71;
    public static final String OBJ_netscape_cert_type = "2.16.840.1.113730.1.1";
    
    public static final String SN_netscape_base_url = "nsBaseUrl";
    public static final String LN_netscape_base_url = "Netscape Base Url";
    public static final short NID_netscape_base_url = 72;
    public static final String OBJ_netscape_base_url = "2.16.840.1.113730.1.2";
    
    public static final String SN_netscape_revocation_url = "nsRevocationUrl";
    public static final String LN_netscape_revocation_url = "Netscape Revocation Url";
    public static final short NID_netscape_revocation_url = 73;
    public static final String OBJ_netscape_revocation_url = "2.16.840.1.113730.1.3";
    
    public static final String SN_netscape_ca_revocation_url = "nsCaRevocationUrl";
    public static final String LN_netscape_ca_revocation_url = "Netscape CA Revocation Url";
    public static final short NID_netscape_ca_revocation_url = 74;
    public static final String OBJ_netscape_ca_revocation_url = "2.16.840.1.113730.1.4";
    
    public static final String SN_netscape_renewal_url = "nsRenewalUrl";
    public static final String LN_netscape_renewal_url = "Netscape Renewal Url";
    public static final short NID_netscape_renewal_url = 75;
    public static final String OBJ_netscape_renewal_url = "2.16.840.1.113730.1.7";
    
    public static final String SN_netscape_ca_policy_url = "nsCaPolicyUrl";
    public static final String LN_netscape_ca_policy_url = "Netscape CA Policy Url";
    public static final short NID_netscape_ca_policy_url = 76;
    public static final String OBJ_netscape_ca_policy_url = "2.16.840.1.113730.1.8";
    
    public static final String SN_netscape_ssl_server_name = "nsSslServerName";
    public static final String LN_netscape_ssl_server_name = "Netscape SSL Server Name";
    public static final short NID_netscape_ssl_server_name = 77;
    public static final String OBJ_netscape_ssl_server_name = "2.16.840.1.113730.1.12";
    
    public static final String SN_netscape_comment = "nsComment";
    public static final String LN_netscape_comment = "Netscape Comment";
    public static final short NID_netscape_comment = 78;
    public static final String OBJ_netscape_comment = "2.16.840.1.113730.1.13";
    
    public static final String SN_netscape_cert_sequence = "nsCertSequence";
    public static final String LN_netscape_cert_sequence = "Netscape Certificate Sequence";
    public static final short NID_netscape_cert_sequence = 79;
    public static final String OBJ_netscape_cert_sequence = "2.16.840.1.113730.2.5";
    
    public static final String SN_ns_sgc = "nsSGC";
    public static final String LN_ns_sgc = "Netscape Server Gated Crypto";
    public static final short NID_ns_sgc = 139;
    public static final String OBJ_ns_sgc = "2.16.840.1.113730.4.1";
    
    public static final String SN_org = "ORG";
    public static final String LN_org = "org";
    public static final short NID_org = 379;
    public static final String OBJ_org = "1.3";
    
    public static final String SN_dod = "DOD";
    public static final String LN_dod = "dod";
    public static final short NID_dod = 380;
    public static final String OBJ_dod = "1.3.6";
    
    public static final String SN_iana = "IANA";
    public static final String LN_iana = "iana";
    public static final short NID_iana = 381;
    public static final String OBJ_iana = "1.3.6.1";
    
    public static final String OBJ_internet = "1.3.6.1";
    
    public static final String SN_Directory = "directory";
    public static final String LN_Directory = "Directory";
    public static final short NID_Directory = 382;
    public static final String OBJ_Directory = "1.3.6.1.1";
    
    public static final String SN_Management = "mgmt";
    public static final String LN_Management = "Management";
    public static final short NID_Management = 383;
    public static final String OBJ_Management = "1.3.6.1.2";
    
    public static final String SN_Experimental = "experimental";
    public static final String LN_Experimental = "Experimental";
    public static final short NID_Experimental = 384;
    public static final String OBJ_Experimental = "1.3.6.1.3";
    
    public static final String SN_Private = "private";
    public static final String LN_Private = "Private";
    public static final short NID_Private = 385;
    public static final String OBJ_Private = "1.3.6.1.4";
    
    public static final String SN_Security = "security";
    public static final String LN_Security = "Security";
    public static final short NID_Security = 386;
    public static final String OBJ_Security = "1.3.6.1.5";
    
    public static final String SN_SNMPv2 = "snmpv2";
    public static final String LN_SNMPv2 = "SNMPv2";
    public static final short NID_SNMPv2 = 387;
    public static final String OBJ_SNMPv2 = "1.3.6.1.6";
    
    public static final String LN_Mail = "Mail";
    public static final short NID_Mail = 388;
    public static final String OBJ_Mail = "1.3.6.1.7";
    
    public static final String SN_Enterprises = "enterprises";
    public static final String LN_Enterprises = "Enterprises";
    public static final short NID_Enterprises = 389;
    public static final String OBJ_Enterprises = "1.3.6.1.4.1";
    
    public static final String SN_dcObject = "dcobject";
    public static final String LN_dcObject = "dcObject";
    public static final short NID_dcObject = 390;
    public static final String OBJ_dcObject = "1.3.6.1.4.1.1466.344";
    
    public static final String SN_mime_mhs = "mime-mhs";
    public static final String LN_mime_mhs = "MIME MHS";
    public static final short NID_mime_mhs = 504;
    public static final String OBJ_mime_mhs = "1.3.6.1.7.1";
    
    public static final String SN_mime_mhs_headings = "mime-mhs-headings";
    public static final String LN_mime_mhs_headings = "mime-mhs-headings";
    public static final short NID_mime_mhs_headings = 505;
    public static final String OBJ_mime_mhs_headings = "1.3.6.1.7.1.1";
    
    public static final String SN_mime_mhs_bodies = "mime-mhs-bodies";
    public static final String LN_mime_mhs_bodies = "mime-mhs-bodies";
    public static final short NID_mime_mhs_bodies = 506;
    public static final String OBJ_mime_mhs_bodies = "1.3.6.1.7.1.2";
    
    public static final String SN_id_hex_partial_message = "id-hex-partial-message";
    public static final String LN_id_hex_partial_message = "id-hex-partial-message";
    public static final short NID_id_hex_partial_message = 507;
    public static final String OBJ_id_hex_partial_message = "1.3.6.1.7.1.1.1";
    
    public static final String SN_id_hex_multipart_message = "id-hex-multipart-message";
    public static final String LN_id_hex_multipart_message = "id-hex-multipart-message";
    public static final short NID_id_hex_multipart_message = 508;
    public static final String OBJ_id_hex_multipart_message = "1.3.6.1.7.1.1.2";
    
    public static final String SN_rle_compression = "RLE";
    public static final String LN_rle_compression = "run length compression";
    public static final short NID_rle_compression = 124;
    public static final String OBJ_rle_compression = "1.1.1.1.666.1";
    
    public static final String SN_zlib_compression = "ZLIB";
    public static final String LN_zlib_compression = "zlib compression";
    public static final short NID_zlib_compression = 125;
    public static final String OBJ_zlib_compression = "1.2.840.113549.1.9.16.3.8";
    
    public static final String OBJ_csor = "2.16.840.1.101.3";
    
    public static final String OBJ_nistAlgorithms = "2.16.840.1.101.3.4";
    
    public static final String OBJ_aes = "2.16.840.1.101.3.4.1";
    
    public static final String SN_aes_128_ecb = "AES-128-ECB";
    public static final String LN_aes_128_ecb = "aes-128-ecb";
    public static final short NID_aes_128_ecb = 418;
    public static final String OBJ_aes_128_ecb = "2.16.840.1.101.3.4.1.1";
    
    public static final String SN_aes_128_cbc = "AES-128-CBC";
    public static final String LN_aes_128_cbc = "aes-128-cbc";
    public static final short NID_aes_128_cbc = 419;
    public static final String OBJ_aes_128_cbc = "2.16.840.1.101.3.4.1.2";
    
    public static final String SN_aes_128_ofb128 = "AES-128-OFB";
    public static final String LN_aes_128_ofb128 = "aes-128-ofb";
    public static final short NID_aes_128_ofb128 = 420;
    public static final String OBJ_aes_128_ofb128 = "2.16.840.1.101.3.4.1.3";
    
    public static final String SN_aes_128_cfb128 = "AES-128-CFB";
    public static final String LN_aes_128_cfb128 = "aes-128-cfb";
    public static final short NID_aes_128_cfb128 = 421;
    public static final String OBJ_aes_128_cfb128 = "2.16.840.1.101.3.4.1.4";
    
    public static final String SN_id_aes128_wrap = "id-aes128-wrap";
    public static final short NID_id_aes128_wrap = 788;
    public static final String OBJ_id_aes128_wrap = "2.16.840.1.101.3.4.1.5";
    
    public static final String SN_aes_128_gcm = "id-aes128-GCM";
    public static final String LN_aes_128_gcm = "aes-128-gcm";
    public static final short NID_aes_128_gcm = 895;
    public static final String OBJ_aes_128_gcm = "2.16.840.1.101.3.4.1.6";
    
    public static final String SN_aes_128_ccm = "id-aes128-CCM";
    public static final String LN_aes_128_ccm = "aes-128-ccm";
    public static final short NID_aes_128_ccm = 896;
    public static final String OBJ_aes_128_ccm = "2.16.840.1.101.3.4.1.7";
    
    public static final String SN_id_aes128_wrap_pad = "id-aes128-wrap-pad";
    public static final short NID_id_aes128_wrap_pad = 897;
    public static final String OBJ_id_aes128_wrap_pad = "2.16.840.1.101.3.4.1.8";
    
    public static final String SN_aes_192_ecb = "AES-192-ECB";
    public static final String LN_aes_192_ecb = "aes-192-ecb";
    public static final short NID_aes_192_ecb = 422;
    public static final String OBJ_aes_192_ecb = "2.16.840.1.101.3.4.1.21";
    
    public static final String SN_aes_192_cbc = "AES-192-CBC";
    public static final String LN_aes_192_cbc = "aes-192-cbc";
    public static final short NID_aes_192_cbc = 423;
    public static final String OBJ_aes_192_cbc = "2.16.840.1.101.3.4.1.22";
    
    public static final String SN_aes_192_ofb128 = "AES-192-OFB";
    public static final String LN_aes_192_ofb128 = "aes-192-ofb";
    public static final short NID_aes_192_ofb128 = 424;
    public static final String OBJ_aes_192_ofb128 = "2.16.840.1.101.3.4.1.23";
    
    public static final String SN_aes_192_cfb128 = "AES-192-CFB";
    public static final String LN_aes_192_cfb128 = "aes-192-cfb";
    public static final short NID_aes_192_cfb128 = 425;
    public static final String OBJ_aes_192_cfb128 = "2.16.840.1.101.3.4.1.24";
    
    public static final String SN_id_aes192_wrap = "id-aes192-wrap";
    public static final short NID_id_aes192_wrap = 789;
    public static final String OBJ_id_aes192_wrap = "2.16.840.1.101.3.4.1.25";
    
    public static final String SN_aes_192_gcm = "id-aes192-GCM";
    public static final String LN_aes_192_gcm = "aes-192-gcm";
    public static final short NID_aes_192_gcm = 898;
    public static final String OBJ_aes_192_gcm = "2.16.840.1.101.3.4.1.26";
    
    public static final String SN_aes_192_ccm = "id-aes192-CCM";
    public static final String LN_aes_192_ccm = "aes-192-ccm";
    public static final short NID_aes_192_ccm = 899;
    public static final String OBJ_aes_192_ccm = "2.16.840.1.101.3.4.1.27";
    
    public static final String SN_id_aes192_wrap_pad = "id-aes192-wrap-pad";
    public static final short NID_id_aes192_wrap_pad = 900;
    public static final String OBJ_id_aes192_wrap_pad = "2.16.840.1.101.3.4.1.28";
    
    public static final String SN_aes_256_ecb = "AES-256-ECB";
    public static final String LN_aes_256_ecb = "aes-256-ecb";
    public static final short NID_aes_256_ecb = 426;
    public static final String OBJ_aes_256_ecb = "2.16.840.1.101.3.4.1.41";
    
    public static final String SN_aes_256_cbc = "AES-256-CBC";
    public static final String LN_aes_256_cbc = "aes-256-cbc";
    public static final short NID_aes_256_cbc = 427;
    public static final String OBJ_aes_256_cbc = "2.16.840.1.101.3.4.1.42";
    
    public static final String SN_aes_256_ofb128 = "AES-256-OFB";
    public static final String LN_aes_256_ofb128 = "aes-256-ofb";
    public static final short NID_aes_256_ofb128 = 428;
    public static final String OBJ_aes_256_ofb128 = "2.16.840.1.101.3.4.1.43";
    
    public static final String SN_aes_256_cfb128 = "AES-256-CFB";
    public static final String LN_aes_256_cfb128 = "aes-256-cfb";
    public static final short NID_aes_256_cfb128 = 429;
    public static final String OBJ_aes_256_cfb128 = "2.16.840.1.101.3.4.1.44";
    
    public static final String SN_id_aes256_wrap = "id-aes256-wrap";
    public static final short NID_id_aes256_wrap = 790;
    public static final String OBJ_id_aes256_wrap = "2.16.840.1.101.3.4.1.45";
    
    public static final String SN_aes_256_gcm = "id-aes256-GCM";
    public static final String LN_aes_256_gcm = "aes-256-gcm";
    public static final short NID_aes_256_gcm = 901;
    public static final String OBJ_aes_256_gcm = "2.16.840.1.101.3.4.1.46";
    
    public static final String SN_aes_256_ccm = "id-aes256-CCM";
    public static final String LN_aes_256_ccm = "aes-256-ccm";
    public static final short NID_aes_256_ccm = 902;
    public static final String OBJ_aes_256_ccm = "2.16.840.1.101.3.4.1.47";
    
    public static final String SN_id_aes256_wrap_pad = "id-aes256-wrap-pad";
    public static final short NID_id_aes256_wrap_pad = 903;
    public static final String OBJ_id_aes256_wrap_pad = "2.16.840.1.101.3.4.1.48";
    
    public static final String SN_aes_128_cfb1 = "AES-128-CFB1";
    public static final String LN_aes_128_cfb1 = "aes-128-cfb1";
    public static final short NID_aes_128_cfb1 = 650;
    
    public static final String SN_aes_192_cfb1 = "AES-192-CFB1";
    public static final String LN_aes_192_cfb1 = "aes-192-cfb1";
    public static final short NID_aes_192_cfb1 = 651;
    
    public static final String SN_aes_256_cfb1 = "AES-256-CFB1";
    public static final String LN_aes_256_cfb1 = "aes-256-cfb1";
    public static final short NID_aes_256_cfb1 = 652;
    
    public static final String SN_aes_128_cfb8 = "AES-128-CFB8";
    public static final String LN_aes_128_cfb8 = "aes-128-cfb8";
    public static final short NID_aes_128_cfb8 = 653;
    
    public static final String SN_aes_192_cfb8 = "AES-192-CFB8";
    public static final String LN_aes_192_cfb8 = "aes-192-cfb8";
    public static final short NID_aes_192_cfb8 = 654;
    
    public static final String SN_aes_256_cfb8 = "AES-256-CFB8";
    public static final String LN_aes_256_cfb8 = "aes-256-cfb8";
    public static final short NID_aes_256_cfb8 = 655;
    
    public static final String SN_aes_128_ctr = "AES-128-CTR";
    public static final String LN_aes_128_ctr = "aes-128-ctr";
    public static final short NID_aes_128_ctr = 904;
    
    public static final String SN_aes_192_ctr = "AES-192-CTR";
    public static final String LN_aes_192_ctr = "aes-192-ctr";
    public static final short NID_aes_192_ctr = 905;
    
    public static final String SN_aes_256_ctr = "AES-256-CTR";
    public static final String LN_aes_256_ctr = "aes-256-ctr";
    public static final short NID_aes_256_ctr = 906;
    
    public static final String SN_aes_128_xts = "AES-128-XTS";
    public static final String LN_aes_128_xts = "aes-128-xts";
    public static final short NID_aes_128_xts = 913;
    
    public static final String SN_aes_256_xts = "AES-256-XTS";
    public static final String LN_aes_256_xts = "aes-256-xts";
    public static final short NID_aes_256_xts = 914;
    
    public static final String SN_des_cfb1 = "DES-CFB1";
    public static final String LN_des_cfb1 = "des-cfb1";
    public static final short NID_des_cfb1 = 656;
    
    public static final String SN_des_cfb8 = "DES-CFB8";
    public static final String LN_des_cfb8 = "des-cfb8";
    public static final short NID_des_cfb8 = 657;
    
    public static final String SN_des_ede3_cfb1 = "DES-EDE3-CFB1";
    public static final String LN_des_ede3_cfb1 = "des-ede3-cfb1";
    public static final short NID_des_ede3_cfb1 = 658;
    
    public static final String SN_des_ede3_cfb8 = "DES-EDE3-CFB8";
    public static final String LN_des_ede3_cfb8 = "des-ede3-cfb8";
    public static final short NID_des_ede3_cfb8 = 659;
    
    public static final String OBJ_nist_hashalgs = "2.16.840.1.101.3.4.2";
    
    public static final String SN_sha256 = "SHA256";
    public static final String LN_sha256 = "sha256";
    public static final short NID_sha256 = 672;
    public static final String OBJ_sha256 = "2.16.840.1.101.3.4.2.1";
    
    public static final String SN_sha384 = "SHA384";
    public static final String LN_sha384 = "sha384";
    public static final short NID_sha384 = 673;
    public static final String OBJ_sha384 = "2.16.840.1.101.3.4.2.2";
    
    public static final String SN_sha512 = "SHA512";
    public static final String LN_sha512 = "sha512";
    public static final short NID_sha512 = 674;
    public static final String OBJ_sha512 = "2.16.840.1.101.3.4.2.3";
    
    public static final String SN_sha224 = "SHA224";
    public static final String LN_sha224 = "sha224";
    public static final short NID_sha224 = 675;
    public static final String OBJ_sha224 = "2.16.840.1.101.3.4.2.4";
    
    public static final String OBJ_dsa_with_sha2 = "2.16.840.1.101.3.4.3";
    
    public static final String SN_dsa_with_SHA224 = "dsa_with_SHA224";
    public static final short NID_dsa_with_SHA224 = 802;
    public static final String OBJ_dsa_with_SHA224 = "2.16.840.1.101.3.4.3.1";
    
    public static final String SN_dsa_with_SHA256 = "dsa_with_SHA256";
    public static final short NID_dsa_with_SHA256 = 803;
    public static final String OBJ_dsa_with_SHA256 = "2.16.840.1.101.3.4.3.2";
    
    public static final String SN_hold_instruction_code = "holdInstructionCode";
    public static final String LN_hold_instruction_code = "Hold Instruction Code";
    public static final short NID_hold_instruction_code = 430;
    public static final String OBJ_hold_instruction_code = "2.5.29.23";
    
    public static final String OBJ_holdInstruction = "1.2.840.10040.2";
    
    public static final String SN_hold_instruction_none = "holdInstructionNone";
    public static final String LN_hold_instruction_none = "Hold Instruction None";
    public static final short NID_hold_instruction_none = 431;
    public static final String OBJ_hold_instruction_none = "1.2.840.10040.2.1";
    
    public static final String SN_hold_instruction_call_issuer = "holdInstructionCallIssuer";
    public static final String LN_hold_instruction_call_issuer = "Hold Instruction Call Issuer";
    public static final short NID_hold_instruction_call_issuer = 432;
    public static final String OBJ_hold_instruction_call_issuer = "1.2.840.10040.2.2";
    
    public static final String SN_hold_instruction_reject = "holdInstructionReject";
    public static final String LN_hold_instruction_reject = "Hold Instruction Reject";
    public static final short NID_hold_instruction_reject = 433;
    public static final String OBJ_hold_instruction_reject = "1.2.840.10040.2.3";
    
    public static final String SN_data = "data";
    public static final short NID_data = 434;
    public static final String OBJ_data = "0.9";
    
    public static final String SN_pss = "pss";
    public static final short NID_pss = 435;
    public static final String OBJ_pss = "0.9.2342";
    
    public static final String SN_ucl = "ucl";
    public static final short NID_ucl = 436;
    public static final String OBJ_ucl = "0.9.2342.19200300";
    
    public static final String SN_pilot = "pilot";
    public static final short NID_pilot = 437;
    public static final String OBJ_pilot = "0.9.2342.19200300.100";
    
    public static final String LN_pilotAttributeType = "pilotAttributeType";
    public static final short NID_pilotAttributeType = 438;
    public static final String OBJ_pilotAttributeType = "0.9.2342.19200300.100.1";
    
    public static final String LN_pilotAttributeSyntax = "pilotAttributeSyntax";
    public static final short NID_pilotAttributeSyntax = 439;
    public static final String OBJ_pilotAttributeSyntax = "0.9.2342.19200300.100.3";
    
    public static final String LN_pilotObjectClass = "pilotObjectClass";
    public static final short NID_pilotObjectClass = 440;
    public static final String OBJ_pilotObjectClass = "0.9.2342.19200300.100.4";
    
    public static final String LN_pilotGroups = "pilotGroups";
    public static final short NID_pilotGroups = 441;
    public static final String OBJ_pilotGroups = "0.9.2342.19200300.100.10";
    
    public static final String LN_iA5StringSyntax = "iA5StringSyntax";
    public static final short NID_iA5StringSyntax = 442;
    public static final String OBJ_iA5StringSyntax = "0.9.2342.19200300.100.3.4";
    
    public static final String LN_caseIgnoreIA5StringSyntax = "caseIgnoreIA5StringSyntax";
    public static final short NID_caseIgnoreIA5StringSyntax = 443;
    public static final String OBJ_caseIgnoreIA5StringSyntax = "0.9.2342.19200300.100.3.5";
    
    public static final String LN_pilotObject = "pilotObject";
    public static final short NID_pilotObject = 444;
    public static final String OBJ_pilotObject = "0.9.2342.19200300.100.4.3";
    
    public static final String LN_pilotPerson = "pilotPerson";
    public static final short NID_pilotPerson = 445;
    public static final String OBJ_pilotPerson = "0.9.2342.19200300.100.4.4";
    
    public static final String SN_account = "account";
    public static final short NID_account = 446;
    public static final String OBJ_account = "0.9.2342.19200300.100.4.5";
    
    public static final String SN_document = "document";
    public static final short NID_document = 447;
    public static final String OBJ_document = "0.9.2342.19200300.100.4.6";
    
    public static final String SN_room = "room";
    public static final short NID_room = 448;
    public static final String OBJ_room = "0.9.2342.19200300.100.4.7";
    
    public static final String LN_documentSeries = "documentSeries";
    public static final short NID_documentSeries = 449;
    public static final String OBJ_documentSeries = "0.9.2342.19200300.100.4.9";
    
    public static final String SN_Domain = "domain";
    public static final String LN_Domain = "Domain";
    public static final short NID_Domain = 392;
    public static final String OBJ_Domain = "0.9.2342.19200300.100.4.13";
    
    public static final String LN_rFC822localPart = "rFC822localPart";
    public static final short NID_rFC822localPart = 450;
    public static final String OBJ_rFC822localPart = "0.9.2342.19200300.100.4.14";
    
    public static final String LN_dNSDomain = "dNSDomain";
    public static final short NID_dNSDomain = 451;
    public static final String OBJ_dNSDomain = "0.9.2342.19200300.100.4.15";
    
    public static final String LN_domainRelatedObject = "domainRelatedObject";
    public static final short NID_domainRelatedObject = 452;
    public static final String OBJ_domainRelatedObject = "0.9.2342.19200300.100.4.17";
    
    public static final String LN_friendlyCountry = "friendlyCountry";
    public static final short NID_friendlyCountry = 453;
    public static final String OBJ_friendlyCountry = "0.9.2342.19200300.100.4.18";
    
    public static final String LN_simpleSecurityObject = "simpleSecurityObject";
    public static final short NID_simpleSecurityObject = 454;
    public static final String OBJ_simpleSecurityObject = "0.9.2342.19200300.100.4.19";
    
    public static final String LN_pilotOrganization = "pilotOrganization";
    public static final short NID_pilotOrganization = 455;
    public static final String OBJ_pilotOrganization = "0.9.2342.19200300.100.4.20";
    
    public static final String LN_pilotDSA = "pilotDSA";
    public static final short NID_pilotDSA = 456;
    public static final String OBJ_pilotDSA = "0.9.2342.19200300.100.4.21";
    
    public static final String LN_qualityLabelledData = "qualityLabelledData";
    public static final short NID_qualityLabelledData = 457;
    public static final String OBJ_qualityLabelledData = "0.9.2342.19200300.100.4.22";
    
    public static final String SN_userId = "UID";
    public static final String LN_userId = "userId";
    public static final short NID_userId = 458;
    public static final String OBJ_userId = "0.9.2342.19200300.100.1.1";
    
    public static final String LN_textEncodedORAddress = "textEncodedORAddress";
    public static final short NID_textEncodedORAddress = 459;
    public static final String OBJ_textEncodedORAddress = "0.9.2342.19200300.100.1.2";
    
    public static final String SN_rfc822Mailbox = "mail";
    public static final String LN_rfc822Mailbox = "rfc822Mailbox";
    public static final short NID_rfc822Mailbox = 460;
    public static final String OBJ_rfc822Mailbox = "0.9.2342.19200300.100.1.3";
    
    public static final String SN_info = "info";
    public static final short NID_info = 461;
    public static final String OBJ_info = "0.9.2342.19200300.100.1.4";
    
    public static final String LN_favouriteDrink = "favouriteDrink";
    public static final short NID_favouriteDrink = 462;
    public static final String OBJ_favouriteDrink = "0.9.2342.19200300.100.1.5";
    
    public static final String LN_roomNumber = "roomNumber";
    public static final short NID_roomNumber = 463;
    public static final String OBJ_roomNumber = "0.9.2342.19200300.100.1.6";
    
    public static final String SN_photo = "photo";
    public static final short NID_photo = 464;
    public static final String OBJ_photo = "0.9.2342.19200300.100.1.7";
    
    public static final String LN_userClass = "userClass";
    public static final short NID_userClass = 465;
    public static final String OBJ_userClass = "0.9.2342.19200300.100.1.8";
    
    public static final String SN_host = "host";
    public static final short NID_host = 466;
    public static final String OBJ_host = "0.9.2342.19200300.100.1.9";
    
    public static final String SN_manager = "manager";
    public static final short NID_manager = 467;
    public static final String OBJ_manager = "0.9.2342.19200300.100.1.10";
    
    public static final String LN_documentIdentifier = "documentIdentifier";
    public static final short NID_documentIdentifier = 468;
    public static final String OBJ_documentIdentifier = "0.9.2342.19200300.100.1.11";
    
    public static final String LN_documentTitle = "documentTitle";
    public static final short NID_documentTitle = 469;
    public static final String OBJ_documentTitle = "0.9.2342.19200300.100.1.12";
    
    public static final String LN_documentVersion = "documentVersion";
    public static final short NID_documentVersion = 470;
    public static final String OBJ_documentVersion = "0.9.2342.19200300.100.1.13";
    
    public static final String LN_documentAuthor = "documentAuthor";
    public static final short NID_documentAuthor = 471;
    public static final String OBJ_documentAuthor = "0.9.2342.19200300.100.1.14";
    
    public static final String LN_documentLocation = "documentLocation";
    public static final short NID_documentLocation = 472;
    public static final String OBJ_documentLocation = "0.9.2342.19200300.100.1.15";
    
    public static final String LN_homeTelephoneNumber = "homeTelephoneNumber";
    public static final short NID_homeTelephoneNumber = 473;
    public static final String OBJ_homeTelephoneNumber = "0.9.2342.19200300.100.1.20";
    
    public static final String SN_secretary = "secretary";
    public static final short NID_secretary = 474;
    public static final String OBJ_secretary = "0.9.2342.19200300.100.1.21";
    
    public static final String LN_otherMailbox = "otherMailbox";
    public static final short NID_otherMailbox = 475;
    public static final String OBJ_otherMailbox = "0.9.2342.19200300.100.1.22";
    
    public static final String LN_lastModifiedTime = "lastModifiedTime";
    public static final short NID_lastModifiedTime = 476;
    public static final String OBJ_lastModifiedTime = "0.9.2342.19200300.100.1.23";
    
    public static final String LN_lastModifiedBy = "lastModifiedBy";
    public static final short NID_lastModifiedBy = 477;
    public static final String OBJ_lastModifiedBy = "0.9.2342.19200300.100.1.24";
    
    public static final String SN_domainComponent = "DC";
    public static final String LN_domainComponent = "domainComponent";
    public static final short NID_domainComponent = 391;
    public static final String OBJ_domainComponent = "0.9.2342.19200300.100.1.25";
    
    public static final String LN_aRecord = "aRecord";
    public static final short NID_aRecord = 478;
    public static final String OBJ_aRecord = "0.9.2342.19200300.100.1.26";
    
    public static final String LN_pilotAttributeType27 = "pilotAttributeType27";
    public static final short NID_pilotAttributeType27 = 479;
    public static final String OBJ_pilotAttributeType27 = "0.9.2342.19200300.100.1.27";
    
    public static final String LN_mXRecord = "mXRecord";
    public static final short NID_mXRecord = 480;
    public static final String OBJ_mXRecord = "0.9.2342.19200300.100.1.28";
    
    public static final String LN_nSRecord = "nSRecord";
    public static final short NID_nSRecord = 481;
    public static final String OBJ_nSRecord = "0.9.2342.19200300.100.1.29";
    
    public static final String LN_sOARecord = "sOARecord";
    public static final short NID_sOARecord = 482;
    public static final String OBJ_sOARecord = "0.9.2342.19200300.100.1.30";
    
    public static final String LN_cNAMERecord = "cNAMERecord";
    public static final short NID_cNAMERecord = 483;
    public static final String OBJ_cNAMERecord = "0.9.2342.19200300.100.1.31";
    
    public static final String LN_associatedDomain = "associatedDomain";
    public static final short NID_associatedDomain = 484;
    public static final String OBJ_associatedDomain = "0.9.2342.19200300.100.1.37";
    
    public static final String LN_associatedName = "associatedName";
    public static final short NID_associatedName = 485;
    public static final String OBJ_associatedName = "0.9.2342.19200300.100.1.38";
    
    public static final String LN_homePostalAddress = "homePostalAddress";
    public static final short NID_homePostalAddress = 486;
    public static final String OBJ_homePostalAddress = "0.9.2342.19200300.100.1.39";
    
    public static final String LN_personalTitle = "personalTitle";
    public static final short NID_personalTitle = 487;
    public static final String OBJ_personalTitle = "0.9.2342.19200300.100.1.40";
    
    public static final String LN_mobileTelephoneNumber = "mobileTelephoneNumber";
    public static final short NID_mobileTelephoneNumber = 488;
    public static final String OBJ_mobileTelephoneNumber = "0.9.2342.19200300.100.1.41";
    
    public static final String LN_pagerTelephoneNumber = "pagerTelephoneNumber";
    public static final short NID_pagerTelephoneNumber = 489;
    public static final String OBJ_pagerTelephoneNumber = "0.9.2342.19200300.100.1.42";
    
    public static final String LN_friendlyCountryName = "friendlyCountryName";
    public static final short NID_friendlyCountryName = 490;
    public static final String OBJ_friendlyCountryName = "0.9.2342.19200300.100.1.43";
    
    public static final String LN_organizationalStatus = "organizationalStatus";
    public static final short NID_organizationalStatus = 491;
    public static final String OBJ_organizationalStatus = "0.9.2342.19200300.100.1.45";
    
    public static final String LN_janetMailbox = "janetMailbox";
    public static final short NID_janetMailbox = 492;
    public static final String OBJ_janetMailbox = "0.9.2342.19200300.100.1.46";
    
    public static final String LN_mailPreferenceOption = "mailPreferenceOption";
    public static final short NID_mailPreferenceOption = 493;
    public static final String OBJ_mailPreferenceOption = "0.9.2342.19200300.100.1.47";
    
    public static final String LN_buildingName = "buildingName";
    public static final short NID_buildingName = 494;
    public static final String OBJ_buildingName = "0.9.2342.19200300.100.1.48";
    
    public static final String LN_dSAQuality = "dSAQuality";
    public static final short NID_dSAQuality = 495;
    public static final String OBJ_dSAQuality = "0.9.2342.19200300.100.1.49";
    
    public static final String LN_singleLevelQuality = "singleLevelQuality";
    public static final short NID_singleLevelQuality = 496;
    public static final String OBJ_singleLevelQuality = "0.9.2342.19200300.100.1.50";
    
    public static final String LN_subtreeMinimumQuality = "subtreeMinimumQuality";
    public static final short NID_subtreeMinimumQuality = 497;
    public static final String OBJ_subtreeMinimumQuality = "0.9.2342.19200300.100.1.51";
    
    public static final String LN_subtreeMaximumQuality = "subtreeMaximumQuality";
    public static final short NID_subtreeMaximumQuality = 498;
    public static final String OBJ_subtreeMaximumQuality = "0.9.2342.19200300.100.1.52";
    
    public static final String LN_personalSignature = "personalSignature";
    public static final short NID_personalSignature = 499;
    public static final String OBJ_personalSignature = "0.9.2342.19200300.100.1.53";
    
    public static final String LN_dITRedirect = "dITRedirect";
    public static final short NID_dITRedirect = 500;
    public static final String OBJ_dITRedirect = "0.9.2342.19200300.100.1.54";
    
    public static final String SN_audio = "audio";
    public static final short NID_audio = 501;
    public static final String OBJ_audio = "0.9.2342.19200300.100.1.55";
    
    public static final String LN_documentPublisher = "documentPublisher";
    public static final short NID_documentPublisher = 502;
    public static final String OBJ_documentPublisher = "0.9.2342.19200300.100.1.56";
    
    public static final String SN_id_set = "id-set";
    public static final String LN_id_set = "Secure Electronic Transactions";
    public static final short NID_id_set = 512;
    public static final String OBJ_id_set = "2.23.42";
    
    public static final String SN_set_ctype = "set-ctype";
    public static final String LN_set_ctype = "content types";
    public static final short NID_set_ctype = 513;
    public static final String OBJ_set_ctype = "2.23.42.0";
    
    public static final String SN_set_msgExt = "set-msgExt";
    public static final String LN_set_msgExt = "message extensions";
    public static final short NID_set_msgExt = 514;
    public static final String OBJ_set_msgExt = "2.23.42.1";
    
    public static final String SN_set_attr = "set-attr";
    public static final short NID_set_attr = 515;
    public static final String OBJ_set_attr = "2.23.42.3";
    
    public static final String SN_set_policy = "set-policy";
    public static final short NID_set_policy = 516;
    public static final String OBJ_set_policy = "2.23.42.5";
    
    public static final String SN_set_certExt = "set-certExt";
    public static final String LN_set_certExt = "certificate extensions";
    public static final short NID_set_certExt = 517;
    public static final String OBJ_set_certExt = "2.23.42.7";
    
    public static final String SN_set_brand = "set-brand";
    public static final short NID_set_brand = 518;
    public static final String OBJ_set_brand = "2.23.42.8";
    
    public static final String SN_setct_PANData = "setct-PANData";
    public static final short NID_setct_PANData = 519;
    public static final String OBJ_setct_PANData = "2.23.42.0.0";
    
    public static final String SN_setct_PANToken = "setct-PANToken";
    public static final short NID_setct_PANToken = 520;
    public static final String OBJ_setct_PANToken = "2.23.42.0.1";
    
    public static final String SN_setct_PANOnly = "setct-PANOnly";
    public static final short NID_setct_PANOnly = 521;
    public static final String OBJ_setct_PANOnly = "2.23.42.0.2";
    
    public static final String SN_setct_OIData = "setct-OIData";
    public static final short NID_setct_OIData = 522;
    public static final String OBJ_setct_OIData = "2.23.42.0.3";
    
    public static final String SN_setct_PI = "setct-PI";
    public static final short NID_setct_PI = 523;
    public static final String OBJ_setct_PI = "2.23.42.0.4";
    
    public static final String SN_setct_PIData = "setct-PIData";
    public static final short NID_setct_PIData = 524;
    public static final String OBJ_setct_PIData = "2.23.42.0.5";
    
    public static final String SN_setct_PIDataUnsigned = "setct-PIDataUnsigned";
    public static final short NID_setct_PIDataUnsigned = 525;
    public static final String OBJ_setct_PIDataUnsigned = "2.23.42.0.6";
    
    public static final String SN_setct_HODInput = "setct-HODInput";
    public static final short NID_setct_HODInput = 526;
    public static final String OBJ_setct_HODInput = "2.23.42.0.7";
    
    public static final String SN_setct_AuthResBaggage = "setct-AuthResBaggage";
    public static final short NID_setct_AuthResBaggage = 527;
    public static final String OBJ_setct_AuthResBaggage = "2.23.42.0.8";
    
    public static final String SN_setct_AuthRevReqBaggage = "setct-AuthRevReqBaggage";
    public static final short NID_setct_AuthRevReqBaggage = 528;
    public static final String OBJ_setct_AuthRevReqBaggage = "2.23.42.0.9";
    
    public static final String SN_setct_AuthRevResBaggage = "setct-AuthRevResBaggage";
    public static final short NID_setct_AuthRevResBaggage = 529;
    public static final String OBJ_setct_AuthRevResBaggage = "2.23.42.0.10";
    
    public static final String SN_setct_CapTokenSeq = "setct-CapTokenSeq";
    public static final short NID_setct_CapTokenSeq = 530;
    public static final String OBJ_setct_CapTokenSeq = "2.23.42.0.11";
    
    public static final String SN_setct_PInitResData = "setct-PInitResData";
    public static final short NID_setct_PInitResData = 531;
    public static final String OBJ_setct_PInitResData = "2.23.42.0.12";
    
    public static final String SN_setct_PI_TBS = "setct-PI-TBS";
    public static final short NID_setct_PI_TBS = 532;
    public static final String OBJ_setct_PI_TBS = "2.23.42.0.13";
    
    public static final String SN_setct_PResData = "setct-PResData";
    public static final short NID_setct_PResData = 533;
    public static final String OBJ_setct_PResData = "2.23.42.0.14";
    
    public static final String SN_setct_AuthReqTBS = "setct-AuthReqTBS";
    public static final short NID_setct_AuthReqTBS = 534;
    public static final String OBJ_setct_AuthReqTBS = "2.23.42.0.16";
    
    public static final String SN_setct_AuthResTBS = "setct-AuthResTBS";
    public static final short NID_setct_AuthResTBS = 535;
    public static final String OBJ_setct_AuthResTBS = "2.23.42.0.17";
    
    public static final String SN_setct_AuthResTBSX = "setct-AuthResTBSX";
    public static final short NID_setct_AuthResTBSX = 536;
    public static final String OBJ_setct_AuthResTBSX = "2.23.42.0.18";
    
    public static final String SN_setct_AuthTokenTBS = "setct-AuthTokenTBS";
    public static final short NID_setct_AuthTokenTBS = 537;
    public static final String OBJ_setct_AuthTokenTBS = "2.23.42.0.19";
    
    public static final String SN_setct_CapTokenData = "setct-CapTokenData";
    public static final short NID_setct_CapTokenData = 538;
    public static final String OBJ_setct_CapTokenData = "2.23.42.0.20";
    
    public static final String SN_setct_CapTokenTBS = "setct-CapTokenTBS";
    public static final short NID_setct_CapTokenTBS = 539;
    public static final String OBJ_setct_CapTokenTBS = "2.23.42.0.21";
    
    public static final String SN_setct_AcqCardCodeMsg = "setct-AcqCardCodeMsg";
    public static final short NID_setct_AcqCardCodeMsg = 540;
    public static final String OBJ_setct_AcqCardCodeMsg = "2.23.42.0.22";
    
    public static final String SN_setct_AuthRevReqTBS = "setct-AuthRevReqTBS";
    public static final short NID_setct_AuthRevReqTBS = 541;
    public static final String OBJ_setct_AuthRevReqTBS = "2.23.42.0.23";
    
    public static final String SN_setct_AuthRevResData = "setct-AuthRevResData";
    public static final short NID_setct_AuthRevResData = 542;
    public static final String OBJ_setct_AuthRevResData = "2.23.42.0.24";
    
    public static final String SN_setct_AuthRevResTBS = "setct-AuthRevResTBS";
    public static final short NID_setct_AuthRevResTBS = 543;
    public static final String OBJ_setct_AuthRevResTBS = "2.23.42.0.25";
    
    public static final String SN_setct_CapReqTBS = "setct-CapReqTBS";
    public static final short NID_setct_CapReqTBS = 544;
    public static final String OBJ_setct_CapReqTBS = "2.23.42.0.26";
    
    public static final String SN_setct_CapReqTBSX = "setct-CapReqTBSX";
    public static final short NID_setct_CapReqTBSX = 545;
    public static final String OBJ_setct_CapReqTBSX = "2.23.42.0.27";
    
    public static final String SN_setct_CapResData = "setct-CapResData";
    public static final short NID_setct_CapResData = 546;
    public static final String OBJ_setct_CapResData = "2.23.42.0.28";
    
    public static final String SN_setct_CapRevReqTBS = "setct-CapRevReqTBS";
    public static final short NID_setct_CapRevReqTBS = 547;
    public static final String OBJ_setct_CapRevReqTBS = "2.23.42.0.29";
    
    public static final String SN_setct_CapRevReqTBSX = "setct-CapRevReqTBSX";
    public static final short NID_setct_CapRevReqTBSX = 548;
    public static final String OBJ_setct_CapRevReqTBSX = "2.23.42.0.30";
    
    public static final String SN_setct_CapRevResData = "setct-CapRevResData";
    public static final short NID_setct_CapRevResData = 549;
    public static final String OBJ_setct_CapRevResData = "2.23.42.0.31";
    
    public static final String SN_setct_CredReqTBS = "setct-CredReqTBS";
    public static final short NID_setct_CredReqTBS = 550;
    public static final String OBJ_setct_CredReqTBS = "2.23.42.0.32";
    
    public static final String SN_setct_CredReqTBSX = "setct-CredReqTBSX";
    public static final short NID_setct_CredReqTBSX = 551;
    public static final String OBJ_setct_CredReqTBSX = "2.23.42.0.33";
    
    public static final String SN_setct_CredResData = "setct-CredResData";
    public static final short NID_setct_CredResData = 552;
    public static final String OBJ_setct_CredResData = "2.23.42.0.34";
    
    public static final String SN_setct_CredRevReqTBS = "setct-CredRevReqTBS";
    public static final short NID_setct_CredRevReqTBS = 553;
    public static final String OBJ_setct_CredRevReqTBS = "2.23.42.0.35";
    
    public static final String SN_setct_CredRevReqTBSX = "setct-CredRevReqTBSX";
    public static final short NID_setct_CredRevReqTBSX = 554;
    public static final String OBJ_setct_CredRevReqTBSX = "2.23.42.0.36";
    
    public static final String SN_setct_CredRevResData = "setct-CredRevResData";
    public static final short NID_setct_CredRevResData = 555;
    public static final String OBJ_setct_CredRevResData = "2.23.42.0.37";
    
    public static final String SN_setct_PCertReqData = "setct-PCertReqData";
    public static final short NID_setct_PCertReqData = 556;
    public static final String OBJ_setct_PCertReqData = "2.23.42.0.38";
    
    public static final String SN_setct_PCertResTBS = "setct-PCertResTBS";
    public static final short NID_setct_PCertResTBS = 557;
    public static final String OBJ_setct_PCertResTBS = "2.23.42.0.39";
    
    public static final String SN_setct_BatchAdminReqData = "setct-BatchAdminReqData";
    public static final short NID_setct_BatchAdminReqData = 558;
    public static final String OBJ_setct_BatchAdminReqData = "2.23.42.0.40";
    
    public static final String SN_setct_BatchAdminResData = "setct-BatchAdminResData";
    public static final short NID_setct_BatchAdminResData = 559;
    public static final String OBJ_setct_BatchAdminResData = "2.23.42.0.41";
    
    public static final String SN_setct_CardCInitResTBS = "setct-CardCInitResTBS";
    public static final short NID_setct_CardCInitResTBS = 560;
    public static final String OBJ_setct_CardCInitResTBS = "2.23.42.0.42";
    
    public static final String SN_setct_MeAqCInitResTBS = "setct-MeAqCInitResTBS";
    public static final short NID_setct_MeAqCInitResTBS = 561;
    public static final String OBJ_setct_MeAqCInitResTBS = "2.23.42.0.43";
    
    public static final String SN_setct_RegFormResTBS = "setct-RegFormResTBS";
    public static final short NID_setct_RegFormResTBS = 562;
    public static final String OBJ_setct_RegFormResTBS = "2.23.42.0.44";
    
    public static final String SN_setct_CertReqData = "setct-CertReqData";
    public static final short NID_setct_CertReqData = 563;
    public static final String OBJ_setct_CertReqData = "2.23.42.0.45";
    
    public static final String SN_setct_CertReqTBS = "setct-CertReqTBS";
    public static final short NID_setct_CertReqTBS = 564;
    public static final String OBJ_setct_CertReqTBS = "2.23.42.0.46";
    
    public static final String SN_setct_CertResData = "setct-CertResData";
    public static final short NID_setct_CertResData = 565;
    public static final String OBJ_setct_CertResData = "2.23.42.0.47";
    
    public static final String SN_setct_CertInqReqTBS = "setct-CertInqReqTBS";
    public static final short NID_setct_CertInqReqTBS = 566;
    public static final String OBJ_setct_CertInqReqTBS = "2.23.42.0.48";
    
    public static final String SN_setct_ErrorTBS = "setct-ErrorTBS";
    public static final short NID_setct_ErrorTBS = 567;
    public static final String OBJ_setct_ErrorTBS = "2.23.42.0.49";
    
    public static final String SN_setct_PIDualSignedTBE = "setct-PIDualSignedTBE";
    public static final short NID_setct_PIDualSignedTBE = 568;
    public static final String OBJ_setct_PIDualSignedTBE = "2.23.42.0.50";
    
    public static final String SN_setct_PIUnsignedTBE = "setct-PIUnsignedTBE";
    public static final short NID_setct_PIUnsignedTBE = 569;
    public static final String OBJ_setct_PIUnsignedTBE = "2.23.42.0.51";
    
    public static final String SN_setct_AuthReqTBE = "setct-AuthReqTBE";
    public static final short NID_setct_AuthReqTBE = 570;
    public static final String OBJ_setct_AuthReqTBE = "2.23.42.0.52";
    
    public static final String SN_setct_AuthResTBE = "setct-AuthResTBE";
    public static final short NID_setct_AuthResTBE = 571;
    public static final String OBJ_setct_AuthResTBE = "2.23.42.0.53";
    
    public static final String SN_setct_AuthResTBEX = "setct-AuthResTBEX";
    public static final short NID_setct_AuthResTBEX = 572;
    public static final String OBJ_setct_AuthResTBEX = "2.23.42.0.54";
    
    public static final String SN_setct_AuthTokenTBE = "setct-AuthTokenTBE";
    public static final short NID_setct_AuthTokenTBE = 573;
    public static final String OBJ_setct_AuthTokenTBE = "2.23.42.0.55";
    
    public static final String SN_setct_CapTokenTBE = "setct-CapTokenTBE";
    public static final short NID_setct_CapTokenTBE = 574;
    public static final String OBJ_setct_CapTokenTBE = "2.23.42.0.56";
    
    public static final String SN_setct_CapTokenTBEX = "setct-CapTokenTBEX";
    public static final short NID_setct_CapTokenTBEX = 575;
    public static final String OBJ_setct_CapTokenTBEX = "2.23.42.0.57";
    
    public static final String SN_setct_AcqCardCodeMsgTBE = "setct-AcqCardCodeMsgTBE";
    public static final short NID_setct_AcqCardCodeMsgTBE = 576;
    public static final String OBJ_setct_AcqCardCodeMsgTBE = "2.23.42.0.58";
    
    public static final String SN_setct_AuthRevReqTBE = "setct-AuthRevReqTBE";
    public static final short NID_setct_AuthRevReqTBE = 577;
    public static final String OBJ_setct_AuthRevReqTBE = "2.23.42.0.59";
    
    public static final String SN_setct_AuthRevResTBE = "setct-AuthRevResTBE";
    public static final short NID_setct_AuthRevResTBE = 578;
    public static final String OBJ_setct_AuthRevResTBE = "2.23.42.0.60";
    
    public static final String SN_setct_AuthRevResTBEB = "setct-AuthRevResTBEB";
    public static final short NID_setct_AuthRevResTBEB = 579;
    public static final String OBJ_setct_AuthRevResTBEB = "2.23.42.0.61";
    
    public static final String SN_setct_CapReqTBE = "setct-CapReqTBE";
    public static final short NID_setct_CapReqTBE = 580;
    public static final String OBJ_setct_CapReqTBE = "2.23.42.0.62";
    
    public static final String SN_setct_CapReqTBEX = "setct-CapReqTBEX";
    public static final short NID_setct_CapReqTBEX = 581;
    public static final String OBJ_setct_CapReqTBEX = "2.23.42.0.63";
    
    public static final String SN_setct_CapResTBE = "setct-CapResTBE";
    public static final short NID_setct_CapResTBE = 582;
    public static final String OBJ_setct_CapResTBE = "2.23.42.0.64";
    
    public static final String SN_setct_CapRevReqTBE = "setct-CapRevReqTBE";
    public static final short NID_setct_CapRevReqTBE = 583;
    public static final String OBJ_setct_CapRevReqTBE = "2.23.42.0.65";
    
    public static final String SN_setct_CapRevReqTBEX = "setct-CapRevReqTBEX";
    public static final short NID_setct_CapRevReqTBEX = 584;
    public static final String OBJ_setct_CapRevReqTBEX = "2.23.42.0.66";
    
    public static final String SN_setct_CapRevResTBE = "setct-CapRevResTBE";
    public static final short NID_setct_CapRevResTBE = 585;
    public static final String OBJ_setct_CapRevResTBE = "2.23.42.0.67";
    
    public static final String SN_setct_CredReqTBE = "setct-CredReqTBE";
    public static final short NID_setct_CredReqTBE = 586;
    public static final String OBJ_setct_CredReqTBE = "2.23.42.0.68";
    
    public static final String SN_setct_CredReqTBEX = "setct-CredReqTBEX";
    public static final short NID_setct_CredReqTBEX = 587;
    public static final String OBJ_setct_CredReqTBEX = "2.23.42.0.69";
    
    public static final String SN_setct_CredResTBE = "setct-CredResTBE";
    public static final short NID_setct_CredResTBE = 588;
    public static final String OBJ_setct_CredResTBE = "2.23.42.0.70";
    
    public static final String SN_setct_CredRevReqTBE = "setct-CredRevReqTBE";
    public static final short NID_setct_CredRevReqTBE = 589;
    public static final String OBJ_setct_CredRevReqTBE = "2.23.42.0.71";
    
    public static final String SN_setct_CredRevReqTBEX = "setct-CredRevReqTBEX";
    public static final short NID_setct_CredRevReqTBEX = 590;
    public static final String OBJ_setct_CredRevReqTBEX = "2.23.42.0.72";
    
    public static final String SN_setct_CredRevResTBE = "setct-CredRevResTBE";
    public static final short NID_setct_CredRevResTBE = 591;
    public static final String OBJ_setct_CredRevResTBE = "2.23.42.0.73";
    
    public static final String SN_setct_BatchAdminReqTBE = "setct-BatchAdminReqTBE";
    public static final short NID_setct_BatchAdminReqTBE = 592;
    public static final String OBJ_setct_BatchAdminReqTBE = "2.23.42.0.74";
    
    public static final String SN_setct_BatchAdminResTBE = "setct-BatchAdminResTBE";
    public static final short NID_setct_BatchAdminResTBE = 593;
    public static final String OBJ_setct_BatchAdminResTBE = "2.23.42.0.75";
    
    public static final String SN_setct_RegFormReqTBE = "setct-RegFormReqTBE";
    public static final short NID_setct_RegFormReqTBE = 594;
    public static final String OBJ_setct_RegFormReqTBE = "2.23.42.0.76";
    
    public static final String SN_setct_CertReqTBE = "setct-CertReqTBE";
    public static final short NID_setct_CertReqTBE = 595;
    public static final String OBJ_setct_CertReqTBE = "2.23.42.0.77";
    
    public static final String SN_setct_CertReqTBEX = "setct-CertReqTBEX";
    public static final short NID_setct_CertReqTBEX = 596;
    public static final String OBJ_setct_CertReqTBEX = "2.23.42.0.78";
    
    public static final String SN_setct_CertResTBE = "setct-CertResTBE";
    public static final short NID_setct_CertResTBE = 597;
    public static final String OBJ_setct_CertResTBE = "2.23.42.0.79";
    
    public static final String SN_setct_CRLNotificationTBS = "setct-CRLNotificationTBS";
    public static final short NID_setct_CRLNotificationTBS = 598;
    public static final String OBJ_setct_CRLNotificationTBS = "2.23.42.0.80";
    
    public static final String SN_setct_CRLNotificationResTBS = "setct-CRLNotificationResTBS";
    public static final short NID_setct_CRLNotificationResTBS = 599;
    public static final String OBJ_setct_CRLNotificationResTBS = "2.23.42.0.81";
    
    public static final String SN_setct_BCIDistributionTBS = "setct-BCIDistributionTBS";
    public static final short NID_setct_BCIDistributionTBS = 600;
    public static final String OBJ_setct_BCIDistributionTBS = "2.23.42.0.82";
    
    public static final String SN_setext_genCrypt = "setext-genCrypt";
    public static final String LN_setext_genCrypt = "generic cryptogram";
    public static final short NID_setext_genCrypt = 601;
    public static final String OBJ_setext_genCrypt = "2.23.42.1.1";
    
    public static final String SN_setext_miAuth = "setext-miAuth";
    public static final String LN_setext_miAuth = "merchant initiated auth";
    public static final short NID_setext_miAuth = 602;
    public static final String OBJ_setext_miAuth = "2.23.42.1.3";
    
    public static final String SN_setext_pinSecure = "setext-pinSecure";
    public static final short NID_setext_pinSecure = 603;
    public static final String OBJ_setext_pinSecure = "2.23.42.1.4";
    
    public static final String SN_setext_pinAny = "setext-pinAny";
    public static final short NID_setext_pinAny = 604;
    public static final String OBJ_setext_pinAny = "2.23.42.1.5";
    
    public static final String SN_setext_track2 = "setext-track2";
    public static final short NID_setext_track2 = 605;
    public static final String OBJ_setext_track2 = "2.23.42.1.7";
    
    public static final String SN_setext_cv = "setext-cv";
    public static final String LN_setext_cv = "additional verification";
    public static final short NID_setext_cv = 606;
    public static final String OBJ_setext_cv = "2.23.42.1.8";
    
    public static final String SN_set_policy_root = "set-policy-root";
    public static final short NID_set_policy_root = 607;
    public static final String OBJ_set_policy_root = "2.23.42.5.0";
    
    public static final String SN_setCext_hashedRoot = "setCext-hashedRoot";
    public static final short NID_setCext_hashedRoot = 608;
    public static final String OBJ_setCext_hashedRoot = "2.23.42.7.0";
    
    public static final String SN_setCext_certType = "setCext-certType";
    public static final short NID_setCext_certType = 609;
    public static final String OBJ_setCext_certType = "2.23.42.7.1";
    
    public static final String SN_setCext_merchData = "setCext-merchData";
    public static final short NID_setCext_merchData = 610;
    public static final String OBJ_setCext_merchData = "2.23.42.7.2";
    
    public static final String SN_setCext_cCertRequired = "setCext-cCertRequired";
    public static final short NID_setCext_cCertRequired = 611;
    public static final String OBJ_setCext_cCertRequired = "2.23.42.7.3";
    
    public static final String SN_setCext_tunneling = "setCext-tunneling";
    public static final short NID_setCext_tunneling = 612;
    public static final String OBJ_setCext_tunneling = "2.23.42.7.4";
    
    public static final String SN_setCext_setExt = "setCext-setExt";
    public static final short NID_setCext_setExt = 613;
    public static final String OBJ_setCext_setExt = "2.23.42.7.5";
    
    public static final String SN_setCext_setQualf = "setCext-setQualf";
    public static final short NID_setCext_setQualf = 614;
    public static final String OBJ_setCext_setQualf = "2.23.42.7.6";
    
    public static final String SN_setCext_PGWYcapabilities = "setCext-PGWYcapabilities";
    public static final short NID_setCext_PGWYcapabilities = 615;
    public static final String OBJ_setCext_PGWYcapabilities = "2.23.42.7.7";
    
    public static final String SN_setCext_TokenIdentifier = "setCext-TokenIdentifier";
    public static final short NID_setCext_TokenIdentifier = 616;
    public static final String OBJ_setCext_TokenIdentifier = "2.23.42.7.8";
    
    public static final String SN_setCext_Track2Data = "setCext-Track2Data";
    public static final short NID_setCext_Track2Data = 617;
    public static final String OBJ_setCext_Track2Data = "2.23.42.7.9";
    
    public static final String SN_setCext_TokenType = "setCext-TokenType";
    public static final short NID_setCext_TokenType = 618;
    public static final String OBJ_setCext_TokenType = "2.23.42.7.10";
    
    public static final String SN_setCext_IssuerCapabilities = "setCext-IssuerCapabilities";
    public static final short NID_setCext_IssuerCapabilities = 619;
    public static final String OBJ_setCext_IssuerCapabilities = "2.23.42.7.11";
    
    public static final String SN_setAttr_Cert = "setAttr-Cert";
    public static final short NID_setAttr_Cert = 620;
    public static final String OBJ_setAttr_Cert = "2.23.42.3.0";
    
    public static final String SN_setAttr_PGWYcap = "setAttr-PGWYcap";
    public static final String LN_setAttr_PGWYcap = "payment gateway capabilities";
    public static final short NID_setAttr_PGWYcap = 621;
    public static final String OBJ_setAttr_PGWYcap = "2.23.42.3.1";
    
    public static final String SN_setAttr_TokenType = "setAttr-TokenType";
    public static final short NID_setAttr_TokenType = 622;
    public static final String OBJ_setAttr_TokenType = "2.23.42.3.2";
    
    public static final String SN_setAttr_IssCap = "setAttr-IssCap";
    public static final String LN_setAttr_IssCap = "issuer capabilities";
    public static final short NID_setAttr_IssCap = 623;
    public static final String OBJ_setAttr_IssCap = "2.23.42.3.3";
    
    public static final String SN_set_rootKeyThumb = "set-rootKeyThumb";
    public static final short NID_set_rootKeyThumb = 624;
    public static final String OBJ_set_rootKeyThumb = "2.23.42.3.0.0";
    
    public static final String SN_set_addPolicy = "set-addPolicy";
    public static final short NID_set_addPolicy = 625;
    public static final String OBJ_set_addPolicy = "2.23.42.3.0.1";
    
    public static final String SN_setAttr_Token_EMV = "setAttr-Token-EMV";
    public static final short NID_setAttr_Token_EMV = 626;
    public static final String OBJ_setAttr_Token_EMV = "2.23.42.3.2.1";
    
    public static final String SN_setAttr_Token_B0Prime = "setAttr-Token-B0Prime";
    public static final short NID_setAttr_Token_B0Prime = 627;
    public static final String OBJ_setAttr_Token_B0Prime = "2.23.42.3.2.2";
    
    public static final String SN_setAttr_IssCap_CVM = "setAttr-IssCap-CVM";
    public static final short NID_setAttr_IssCap_CVM = 628;
    public static final String OBJ_setAttr_IssCap_CVM = "2.23.42.3.3.3";
    
    public static final String SN_setAttr_IssCap_T2 = "setAttr-IssCap-T2";
    public static final short NID_setAttr_IssCap_T2 = 629;
    public static final String OBJ_setAttr_IssCap_T2 = "2.23.42.3.3.4";
    
    public static final String SN_setAttr_IssCap_Sig = "setAttr-IssCap-Sig";
    public static final short NID_setAttr_IssCap_Sig = 630;
    public static final String OBJ_setAttr_IssCap_Sig = "2.23.42.3.3.5";
    
    public static final String SN_setAttr_GenCryptgrm = "setAttr-GenCryptgrm";
    public static final String LN_setAttr_GenCryptgrm = "generate cryptogram";
    public static final short NID_setAttr_GenCryptgrm = 631;
    public static final String OBJ_setAttr_GenCryptgrm = "2.23.42.3.3.3.1";
    
    public static final String SN_setAttr_T2Enc = "setAttr-T2Enc";
    public static final String LN_setAttr_T2Enc = "encrypted track 2";
    public static final short NID_setAttr_T2Enc = 632;
    public static final String OBJ_setAttr_T2Enc = "2.23.42.3.3.4.1";
    
    public static final String SN_setAttr_T2cleartxt = "setAttr-T2cleartxt";
    public static final String LN_setAttr_T2cleartxt = "cleartext track 2";
    public static final short NID_setAttr_T2cleartxt = 633;
    public static final String OBJ_setAttr_T2cleartxt = "2.23.42.3.3.4.2";
    
    public static final String SN_setAttr_TokICCsig = "setAttr-TokICCsig";
    public static final String LN_setAttr_TokICCsig = "ICC or token signature";
    public static final short NID_setAttr_TokICCsig = 634;
    public static final String OBJ_setAttr_TokICCsig = "2.23.42.3.3.5.1";
    
    public static final String SN_setAttr_SecDevSig = "setAttr-SecDevSig";
    public static final String LN_setAttr_SecDevSig = "secure device signature";
    public static final short NID_setAttr_SecDevSig = 635;
    public static final String OBJ_setAttr_SecDevSig = "2.23.42.3.3.5.2";
    
    public static final String SN_set_brand_IATA_ATA = "set-brand-IATA-ATA";
    public static final short NID_set_brand_IATA_ATA = 636;
    public static final String OBJ_set_brand_IATA_ATA = "2.23.42.8.1";
    
    public static final String SN_set_brand_Diners = "set-brand-Diners";
    public static final short NID_set_brand_Diners = 637;
    public static final String OBJ_set_brand_Diners = "2.23.42.8.30";
    
    public static final String SN_set_brand_AmericanExpress = "set-brand-AmericanExpress";
    public static final short NID_set_brand_AmericanExpress = 638;
    public static final String OBJ_set_brand_AmericanExpress = "2.23.42.8.34";
    
    public static final String SN_set_brand_JCB = "set-brand-JCB";
    public static final short NID_set_brand_JCB = 639;
    public static final String OBJ_set_brand_JCB = "2.23.42.8.35";
    
    public static final String SN_set_brand_Visa = "set-brand-Visa";
    public static final short NID_set_brand_Visa = 640;
    public static final String OBJ_set_brand_Visa = "2.23.42.8.4";
    
    public static final String SN_set_brand_MasterCard = "set-brand-MasterCard";
    public static final short NID_set_brand_MasterCard = 641;
    public static final String OBJ_set_brand_MasterCard = "2.23.42.8.5";
    
    public static final String SN_set_brand_Novus = "set-brand-Novus";
    public static final short NID_set_brand_Novus = 642;
    public static final String OBJ_set_brand_Novus = "2.23.42.8.6011";
    
    public static final String SN_des_cdmf = "DES-CDMF";
    public static final String LN_des_cdmf = "des-cdmf";
    public static final short NID_des_cdmf = 643;
    public static final String OBJ_des_cdmf = "1.2.840.113549.3.10";
    
    public static final String SN_rsaOAEPEncryptionSET = "rsaOAEPEncryptionSET";
    public static final short NID_rsaOAEPEncryptionSET = 644;
    public static final String OBJ_rsaOAEPEncryptionSET = "1.2.840.113549.1.1.6";
    
    public static final String SN_ipsec3 = "Oakley-EC2N-3";
    public static final String LN_ipsec3 = "ipsec3";
    public static final short NID_ipsec3 = 749;
    
    public static final String SN_ipsec4 = "Oakley-EC2N-4";
    public static final String LN_ipsec4 = "ipsec4";
    public static final short NID_ipsec4 = 750;
    
    public static final String SN_whirlpool = "whirlpool";
    public static final short NID_whirlpool = 804;
    public static final String OBJ_whirlpool = "1.0.10118.3.0.55";
    
    public static final String SN_cryptopro = "cryptopro";
    public static final short NID_cryptopro = 805;
    public static final String OBJ_cryptopro = "1.2.643.2.2";
    
    public static final String SN_cryptocom = "cryptocom";
    public static final short NID_cryptocom = 806;
    public static final String OBJ_cryptocom = "1.2.643.2.9";
    
    public static final String SN_id_GostR3411_94_with_GostR3410_2001 = "id-GostR3411-94-with-GostR3410-2001";
    public static final String LN_id_GostR3411_94_with_GostR3410_2001 = "GOST R 34.11-94 with GOST R 34.10-2001";
    public static final short NID_id_GostR3411_94_with_GostR3410_2001 = 807;
    public static final String OBJ_id_GostR3411_94_with_GostR3410_2001 = "1.2.643.2.2.3";
    
    public static final String SN_id_GostR3411_94_with_GostR3410_94 = "id-GostR3411-94-with-GostR3410-94";
    public static final String LN_id_GostR3411_94_with_GostR3410_94 = "GOST R 34.11-94 with GOST R 34.10-94";
    public static final short NID_id_GostR3411_94_with_GostR3410_94 = 808;
    public static final String OBJ_id_GostR3411_94_with_GostR3410_94 = "1.2.643.2.2.4";
    
    public static final String SN_id_GostR3411_94 = "md_gost94";
    public static final String LN_id_GostR3411_94 = "GOST R 34.11-94";
    public static final short NID_id_GostR3411_94 = 809;
    public static final String OBJ_id_GostR3411_94 = "1.2.643.2.2.9";
    
    public static final String SN_id_HMACGostR3411_94 = "id-HMACGostR3411-94";
    public static final String LN_id_HMACGostR3411_94 = "HMAC GOST 34.11-94";
    public static final short NID_id_HMACGostR3411_94 = 810;
    public static final String OBJ_id_HMACGostR3411_94 = "1.2.643.2.2.10";
    
    public static final String SN_id_GostR3410_2001 = "gost2001";
    public static final String LN_id_GostR3410_2001 = "GOST R 34.10-2001";
    public static final short NID_id_GostR3410_2001 = 811;
    public static final String OBJ_id_GostR3410_2001 = "1.2.643.2.2.19";
    
    public static final String SN_id_GostR3410_94 = "gost94";
    public static final String LN_id_GostR3410_94 = "GOST R 34.10-94";
    public static final short NID_id_GostR3410_94 = 812;
    public static final String OBJ_id_GostR3410_94 = "1.2.643.2.2.20";
    
    public static final String SN_id_Gost28147_89 = "gost89";
    public static final String LN_id_Gost28147_89 = "GOST 28147-89";
    public static final short NID_id_Gost28147_89 = 813;
    public static final String OBJ_id_Gost28147_89 = "1.2.643.2.2.21";
    
    public static final String SN_gost89_cnt = "gost89-cnt";
    public static final short NID_gost89_cnt = 814;
    
    public static final String SN_id_Gost28147_89_MAC = "gost-mac";
    public static final String LN_id_Gost28147_89_MAC = "GOST 28147-89 MAC";
    public static final short NID_id_Gost28147_89_MAC = 815;
    public static final String OBJ_id_Gost28147_89_MAC = "1.2.643.2.2.22";
    
    public static final String SN_id_GostR3411_94_prf = "prf-gostr3411-94";
    public static final String LN_id_GostR3411_94_prf = "GOST R 34.11-94 PRF";
    public static final short NID_id_GostR3411_94_prf = 816;
    public static final String OBJ_id_GostR3411_94_prf = "1.2.643.2.2.23";
    
    public static final String SN_id_GostR3410_2001DH = "id-GostR3410-2001DH";
    public static final String LN_id_GostR3410_2001DH = "GOST R 34.10-2001 DH";
    public static final short NID_id_GostR3410_2001DH = 817;
    public static final String OBJ_id_GostR3410_2001DH = "1.2.643.2.2.98";
    
    public static final String SN_id_GostR3410_94DH = "id-GostR3410-94DH";
    public static final String LN_id_GostR3410_94DH = "GOST R 34.10-94 DH";
    public static final short NID_id_GostR3410_94DH = 818;
    public static final String OBJ_id_GostR3410_94DH = "1.2.643.2.2.99";
    
    public static final String SN_id_Gost28147_89_CryptoPro_KeyMeshing = "id-Gost28147-89-CryptoPro-KeyMeshing";
    public static final short NID_id_Gost28147_89_CryptoPro_KeyMeshing = 819;
    public static final String OBJ_id_Gost28147_89_CryptoPro_KeyMeshing = "1.2.643.2.2.14.1";
    
    public static final String SN_id_Gost28147_89_None_KeyMeshing = "id-Gost28147-89-None-KeyMeshing";
    public static final short NID_id_Gost28147_89_None_KeyMeshing = 820;
    public static final String OBJ_id_Gost28147_89_None_KeyMeshing = "1.2.643.2.2.14.0";
    
    public static final String SN_id_GostR3411_94_TestParamSet = "id-GostR3411-94-TestParamSet";
    public static final short NID_id_GostR3411_94_TestParamSet = 821;
    public static final String OBJ_id_GostR3411_94_TestParamSet = "1.2.643.2.2.30.0";
    
    public static final String SN_id_GostR3411_94_CryptoProParamSet = "id-GostR3411-94-CryptoProParamSet";
    public static final short NID_id_GostR3411_94_CryptoProParamSet = 822;
    public static final String OBJ_id_GostR3411_94_CryptoProParamSet = "1.2.643.2.2.30.1";
    
    public static final String SN_id_Gost28147_89_TestParamSet = "id-Gost28147-89-TestParamSet";
    public static final short NID_id_Gost28147_89_TestParamSet = 823;
    public static final String OBJ_id_Gost28147_89_TestParamSet = "1.2.643.2.2.31.0";
    
    public static final String SN_id_Gost28147_89_CryptoPro_A_ParamSet = "id-Gost28147-89-CryptoPro-A-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_A_ParamSet = 824;
    public static final String OBJ_id_Gost28147_89_CryptoPro_A_ParamSet = "1.2.643.2.2.31.1";
    
    public static final String SN_id_Gost28147_89_CryptoPro_B_ParamSet = "id-Gost28147-89-CryptoPro-B-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_B_ParamSet = 825;
    public static final String OBJ_id_Gost28147_89_CryptoPro_B_ParamSet = "1.2.643.2.2.31.2";
    
    public static final String SN_id_Gost28147_89_CryptoPro_C_ParamSet = "id-Gost28147-89-CryptoPro-C-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_C_ParamSet = 826;
    public static final String OBJ_id_Gost28147_89_CryptoPro_C_ParamSet = "1.2.643.2.2.31.3";
    
    public static final String SN_id_Gost28147_89_CryptoPro_D_ParamSet = "id-Gost28147-89-CryptoPro-D-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_D_ParamSet = 827;
    public static final String OBJ_id_Gost28147_89_CryptoPro_D_ParamSet = "1.2.643.2.2.31.4";
    
    public static final String SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = "id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 828;
    public static final String OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = "1.2.643.2.2.31.5";
    
    public static final String SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = "id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 829;
    public static final String OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = "1.2.643.2.2.31.6";
    
    public static final String SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = "id-Gost28147-89-CryptoPro-RIC-1-ParamSet";
    public static final short NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 830;
    public static final String OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = "1.2.643.2.2.31.7";
    
    public static final String SN_id_GostR3410_94_TestParamSet = "id-GostR3410-94-TestParamSet";
    public static final short NID_id_GostR3410_94_TestParamSet = 831;
    public static final String OBJ_id_GostR3410_94_TestParamSet = "1.2.643.2.2.32.0";
    
    public static final String SN_id_GostR3410_94_CryptoPro_A_ParamSet = "id-GostR3410-94-CryptoPro-A-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_A_ParamSet = 832;
    public static final String OBJ_id_GostR3410_94_CryptoPro_A_ParamSet = "1.2.643.2.2.32.2";
    
    public static final String SN_id_GostR3410_94_CryptoPro_B_ParamSet = "id-GostR3410-94-CryptoPro-B-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_B_ParamSet = 833;
    public static final String OBJ_id_GostR3410_94_CryptoPro_B_ParamSet = "1.2.643.2.2.32.3";
    
    public static final String SN_id_GostR3410_94_CryptoPro_C_ParamSet = "id-GostR3410-94-CryptoPro-C-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_C_ParamSet = 834;
    public static final String OBJ_id_GostR3410_94_CryptoPro_C_ParamSet = "1.2.643.2.2.32.4";
    
    public static final String SN_id_GostR3410_94_CryptoPro_D_ParamSet = "id-GostR3410-94-CryptoPro-D-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_D_ParamSet = 835;
    public static final String OBJ_id_GostR3410_94_CryptoPro_D_ParamSet = "1.2.643.2.2.32.5";
    
    public static final String SN_id_GostR3410_94_CryptoPro_XchA_ParamSet = "id-GostR3410-94-CryptoPro-XchA-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_XchA_ParamSet = 836;
    public static final String OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet = "1.2.643.2.2.33.1";
    
    public static final String SN_id_GostR3410_94_CryptoPro_XchB_ParamSet = "id-GostR3410-94-CryptoPro-XchB-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_XchB_ParamSet = 837;
    public static final String OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet = "1.2.643.2.2.33.2";
    
    public static final String SN_id_GostR3410_94_CryptoPro_XchC_ParamSet = "id-GostR3410-94-CryptoPro-XchC-ParamSet";
    public static final short NID_id_GostR3410_94_CryptoPro_XchC_ParamSet = 838;
    public static final String OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet = "1.2.643.2.2.33.3";
    
    public static final String SN_id_GostR3410_2001_TestParamSet = "id-GostR3410-2001-TestParamSet";
    public static final short NID_id_GostR3410_2001_TestParamSet = 839;
    public static final String OBJ_id_GostR3410_2001_TestParamSet = "1.2.643.2.2.35.0";
    
    public static final String SN_id_GostR3410_2001_CryptoPro_A_ParamSet = "id-GostR3410-2001-CryptoPro-A-ParamSet";
    public static final short NID_id_GostR3410_2001_CryptoPro_A_ParamSet = 840;
    public static final String OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet = "1.2.643.2.2.35.1";
    
    public static final String SN_id_GostR3410_2001_CryptoPro_B_ParamSet = "id-GostR3410-2001-CryptoPro-B-ParamSet";
    public static final short NID_id_GostR3410_2001_CryptoPro_B_ParamSet = 841;
    public static final String OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet = "1.2.643.2.2.35.2";
    
    public static final String SN_id_GostR3410_2001_CryptoPro_C_ParamSet = "id-GostR3410-2001-CryptoPro-C-ParamSet";
    public static final short NID_id_GostR3410_2001_CryptoPro_C_ParamSet = 842;
    public static final String OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet = "1.2.643.2.2.35.3";
    
    public static final String SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet = "id-GostR3410-2001-CryptoPro-XchA-ParamSet";
    public static final short NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 843;
    public static final String OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet = "1.2.643.2.2.36.0";
    
    public static final String SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet = "id-GostR3410-2001-CryptoPro-XchB-ParamSet";
    public static final short NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 844;
    public static final String OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet = "1.2.643.2.2.36.1";
    
    public static final String SN_id_GostR3410_94_a = "id-GostR3410-94-a";
    public static final short NID_id_GostR3410_94_a = 845;
    public static final String OBJ_id_GostR3410_94_a = "1.2.643.2.2.20.1";
    
    public static final String SN_id_GostR3410_94_aBis = "id-GostR3410-94-aBis";
    public static final short NID_id_GostR3410_94_aBis = 846;
    public static final String OBJ_id_GostR3410_94_aBis = "1.2.643.2.2.20.2";
    
    public static final String SN_id_GostR3410_94_b = "id-GostR3410-94-b";
    public static final short NID_id_GostR3410_94_b = 847;
    public static final String OBJ_id_GostR3410_94_b = "1.2.643.2.2.20.3";
    
    public static final String SN_id_GostR3410_94_bBis = "id-GostR3410-94-bBis";
    public static final short NID_id_GostR3410_94_bBis = 848;
    public static final String OBJ_id_GostR3410_94_bBis = "1.2.643.2.2.20.4";
    
    public static final String SN_id_Gost28147_89_cc = "id-Gost28147-89-cc";
    public static final String LN_id_Gost28147_89_cc = "GOST 28147-89 Cryptocom ParamSet";
    public static final short NID_id_Gost28147_89_cc = 849;
    public static final String OBJ_id_Gost28147_89_cc = "1.2.643.2.9.1.6.1";
    
    public static final String SN_id_GostR3410_94_cc = "gost94cc";
    public static final String LN_id_GostR3410_94_cc = "GOST 34.10-94 Cryptocom";
    public static final short NID_id_GostR3410_94_cc = 850;
    public static final String OBJ_id_GostR3410_94_cc = "1.2.643.2.9.1.5.3";
    
    public static final String SN_id_GostR3410_2001_cc = "gost2001cc";
    public static final String LN_id_GostR3410_2001_cc = "GOST 34.10-2001 Cryptocom";
    public static final short NID_id_GostR3410_2001_cc = 851;
    public static final String OBJ_id_GostR3410_2001_cc = "1.2.643.2.9.1.5.4";
    
    public static final String SN_id_GostR3411_94_with_GostR3410_94_cc = "id-GostR3411-94-with-GostR3410-94-cc";
    public static final String LN_id_GostR3411_94_with_GostR3410_94_cc = "GOST R 34.11-94 with GOST R 34.10-94 Cryptocom";
    public static final short NID_id_GostR3411_94_with_GostR3410_94_cc = 852;
    public static final String OBJ_id_GostR3411_94_with_GostR3410_94_cc = "1.2.643.2.9.1.3.3";
    
    public static final String SN_id_GostR3411_94_with_GostR3410_2001_cc = "id-GostR3411-94-with-GostR3410-2001-cc";
    public static final String LN_id_GostR3411_94_with_GostR3410_2001_cc = "GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom";
    public static final short NID_id_GostR3411_94_with_GostR3410_2001_cc = 853;
    public static final String OBJ_id_GostR3411_94_with_GostR3410_2001_cc = "1.2.643.2.9.1.3.4";
    
    public static final String SN_id_GostR3410_2001_ParamSet_cc = "id-GostR3410-2001-ParamSet-cc";
    public static final String LN_id_GostR3410_2001_ParamSet_cc = "GOST R 3410-2001 Parameter Set Cryptocom";
    public static final short NID_id_GostR3410_2001_ParamSet_cc = 854;
    public static final String OBJ_id_GostR3410_2001_ParamSet_cc = "1.2.643.2.9.1.8.1";
    
    public static final String SN_camellia_128_cbc = "CAMELLIA-128-CBC";
    public static final String LN_camellia_128_cbc = "camellia-128-cbc";
    public static final short NID_camellia_128_cbc = 751;
    public static final String OBJ_camellia_128_cbc = "1.2.392.200011.61.1.1.1.2";
    
    public static final String SN_camellia_192_cbc = "CAMELLIA-192-CBC";
    public static final String LN_camellia_192_cbc = "camellia-192-cbc";
    public static final short NID_camellia_192_cbc = 752;
    public static final String OBJ_camellia_192_cbc = "1.2.392.200011.61.1.1.1.3";
    
    public static final String SN_camellia_256_cbc = "CAMELLIA-256-CBC";
    public static final String LN_camellia_256_cbc = "camellia-256-cbc";
    public static final short NID_camellia_256_cbc = 753;
    public static final String OBJ_camellia_256_cbc = "1.2.392.200011.61.1.1.1.4";
    
    public static final String SN_id_camellia128_wrap = "id-camellia128-wrap";
    public static final short NID_id_camellia128_wrap = 907;
    public static final String OBJ_id_camellia128_wrap = "1.2.392.200011.61.1.1.3.2";
    
    public static final String SN_id_camellia192_wrap = "id-camellia192-wrap";
    public static final short NID_id_camellia192_wrap = 908;
    public static final String OBJ_id_camellia192_wrap = "1.2.392.200011.61.1.1.3.3";
    
    public static final String SN_id_camellia256_wrap = "id-camellia256-wrap";
    public static final short NID_id_camellia256_wrap = 909;
    public static final String OBJ_id_camellia256_wrap = "1.2.392.200011.61.1.1.3.4";
    
    public static final String OBJ_ntt_ds = "0.3.4401.5";
    
    public static final String OBJ_camellia = "0.3.4401.5.3.1.9";
    
    public static final String SN_camellia_128_ecb = "CAMELLIA-128-ECB";
    public static final String LN_camellia_128_ecb = "camellia-128-ecb";
    public static final short NID_camellia_128_ecb = 754;
    public static final String OBJ_camellia_128_ecb = "0.3.4401.5.3.1.9.1";
    
    public static final String SN_camellia_128_ofb128 = "CAMELLIA-128-OFB";
    public static final String LN_camellia_128_ofb128 = "camellia-128-ofb";
    public static final short NID_camellia_128_ofb128 = 766;
    public static final String OBJ_camellia_128_ofb128 = "0.3.4401.5.3.1.9.3";
    
    public static final String SN_camellia_128_cfb128 = "CAMELLIA-128-CFB";
    public static final String LN_camellia_128_cfb128 = "camellia-128-cfb";
    public static final short NID_camellia_128_cfb128 = 757;
    public static final String OBJ_camellia_128_cfb128 = "0.3.4401.5.3.1.9.4";
    
    public static final String SN_camellia_192_ecb = "CAMELLIA-192-ECB";
    public static final String LN_camellia_192_ecb = "camellia-192-ecb";
    public static final short NID_camellia_192_ecb = 755;
    public static final String OBJ_camellia_192_ecb = "0.3.4401.5.3.1.9.21";
    
    public static final String SN_camellia_192_ofb128 = "CAMELLIA-192-OFB";
    public static final String LN_camellia_192_ofb128 = "camellia-192-ofb";
    public static final short NID_camellia_192_ofb128 = 767;
    public static final String OBJ_camellia_192_ofb128 = "0.3.4401.5.3.1.9.23";
    
    public static final String SN_camellia_192_cfb128 = "CAMELLIA-192-CFB";
    public static final String LN_camellia_192_cfb128 = "camellia-192-cfb";
    public static final short NID_camellia_192_cfb128 = 758;
    public static final String OBJ_camellia_192_cfb128 = "0.3.4401.5.3.1.9.24";
    
    public static final String SN_camellia_256_ecb = "CAMELLIA-256-ECB";
    public static final String LN_camellia_256_ecb = "camellia-256-ecb";
    public static final short NID_camellia_256_ecb = 756;
    public static final String OBJ_camellia_256_ecb = "0.3.4401.5.3.1.9.41";
    
    public static final String SN_camellia_256_ofb128 = "CAMELLIA-256-OFB";
    public static final String LN_camellia_256_ofb128 = "camellia-256-ofb";
    public static final short NID_camellia_256_ofb128 = 768;
    public static final String OBJ_camellia_256_ofb128 = "0.3.4401.5.3.1.9.43";
    
    public static final String SN_camellia_256_cfb128 = "CAMELLIA-256-CFB";
    public static final String LN_camellia_256_cfb128 = "camellia-256-cfb";
    public static final short NID_camellia_256_cfb128 = 759;
    public static final String OBJ_camellia_256_cfb128 = "0.3.4401.5.3.1.9.44";
    
    public static final String SN_camellia_128_cfb1 = "CAMELLIA-128-CFB1";
    public static final String LN_camellia_128_cfb1 = "camellia-128-cfb1";
    public static final short NID_camellia_128_cfb1 = 760;
    
    public static final String SN_camellia_192_cfb1 = "CAMELLIA-192-CFB1";
    public static final String LN_camellia_192_cfb1 = "camellia-192-cfb1";
    public static final short NID_camellia_192_cfb1 = 761;
    
    public static final String SN_camellia_256_cfb1 = "CAMELLIA-256-CFB1";
    public static final String LN_camellia_256_cfb1 = "camellia-256-cfb1";
    public static final short NID_camellia_256_cfb1 = 762;
    
    public static final String SN_camellia_128_cfb8 = "CAMELLIA-128-CFB8";
    public static final String LN_camellia_128_cfb8 = "camellia-128-cfb8";
    public static final short NID_camellia_128_cfb8 = 763;
    
    public static final String SN_camellia_192_cfb8 = "CAMELLIA-192-CFB8";
    public static final String LN_camellia_192_cfb8 = "camellia-192-cfb8";
    public static final short NID_camellia_192_cfb8 = 764;
    
    public static final String SN_camellia_256_cfb8 = "CAMELLIA-256-CFB8";
    public static final String LN_camellia_256_cfb8 = "camellia-256-cfb8";
    public static final short NID_camellia_256_cfb8 = 765;
    
    public static final String SN_kisa = "KISA";
    public static final String LN_kisa = "kisa";
    public static final short NID_kisa = 773;
    public static final String OBJ_kisa = "1.2.410.200004";
    
    public static final String SN_seed_ecb = "SEED-ECB";
    public static final String LN_seed_ecb = "seed-ecb";
    public static final short NID_seed_ecb = 776;
    public static final String OBJ_seed_ecb = "1.2.410.200004.1.3";
    
    public static final String SN_seed_cbc = "SEED-CBC";
    public static final String LN_seed_cbc = "seed-cbc";
    public static final short NID_seed_cbc = 777;
    public static final String OBJ_seed_cbc = "1.2.410.200004.1.4";
    
    public static final String SN_seed_cfb128 = "SEED-CFB";
    public static final String LN_seed_cfb128 = "seed-cfb";
    public static final short NID_seed_cfb128 = 779;
    public static final String OBJ_seed_cfb128 = "1.2.410.200004.1.5";
    
    public static final String SN_seed_ofb128 = "SEED-OFB";
    public static final String LN_seed_ofb128 = "seed-ofb";
    public static final short NID_seed_ofb128 = 778;
    public static final String OBJ_seed_ofb128 = "1.2.410.200004.1.6";
    
    public static final String SN_hmac = "HMAC";
    public static final String LN_hmac = "hmac";
    public static final short NID_hmac = 855;
    
    public static final String SN_cmac = "CMAC";
    public static final String LN_cmac = "cmac";
    public static final short NID_cmac = 894;
    
    public static final String SN_rc4_hmac_md5 = "RC4-HMAC-MD5";
    public static final String LN_rc4_hmac_md5 = "rc4-hmac-md5";
    public static final short NID_rc4_hmac_md5 = 915;
    
    public static final String SN_aes_128_cbc_hmac_sha1 = "AES-128-CBC-HMAC-SHA1";
    public static final String LN_aes_128_cbc_hmac_sha1 = "aes-128-cbc-hmac-sha1";
    public static final short NID_aes_128_cbc_hmac_sha1 = 916;
    
    public static final String SN_aes_192_cbc_hmac_sha1 = "AES-192-CBC-HMAC-SHA1";
    public static final String LN_aes_192_cbc_hmac_sha1 = "aes-192-cbc-hmac-sha1";
    public static final short NID_aes_192_cbc_hmac_sha1 = 917;
    
    public static final String SN_aes_256_cbc_hmac_sha1 = "AES-256-CBC-HMAC-SHA1";
    public static final String LN_aes_256_cbc_hmac_sha1 = "aes-256-cbc-hmac-sha1";
    public static final short NID_aes_256_cbc_hmac_sha1 = 918;
    
    public static final String SN_aes_128_cbc_hmac_sha256 = "AES-128-CBC-HMAC-SHA256";
    public static final String LN_aes_128_cbc_hmac_sha256 = "aes-128-cbc-hmac-sha256";
    public static final short NID_aes_128_cbc_hmac_sha256 = 948;
    
    public static final String SN_aes_192_cbc_hmac_sha256 = "AES-192-CBC-HMAC-SHA256";
    public static final String LN_aes_192_cbc_hmac_sha256 = "aes-192-cbc-hmac-sha256";
    public static final short NID_aes_192_cbc_hmac_sha256 = 949;
    
    public static final String SN_aes_256_cbc_hmac_sha256 = "AES-256-CBC-HMAC-SHA256";
    public static final String LN_aes_256_cbc_hmac_sha256 = "aes-256-cbc-hmac-sha256";
    public static final short NID_aes_256_cbc_hmac_sha256 = 950;
    
    public static final String SN_dhpublicnumber = "dhpublicnumber";
    public static final String LN_dhpublicnumber = "X9.42 DH";
    public static final short NID_dhpublicnumber = 920;
    public static final String OBJ_dhpublicnumber = "1.2.840.10046.2.1";
    
    public static final String SN_brainpoolP160r1 = "brainpoolP160r1";
    public static final short NID_brainpoolP160r1 = 921;
    public static final String OBJ_brainpoolP160r1 = "1.3.36.3.3.2.8.1.1.1";
    
    public static final String SN_brainpoolP160t1 = "brainpoolP160t1";
    public static final short NID_brainpoolP160t1 = 922;
    public static final String OBJ_brainpoolP160t1 = "1.3.36.3.3.2.8.1.1.2";
    
    public static final String SN_brainpoolP192r1 = "brainpoolP192r1";
    public static final short NID_brainpoolP192r1 = 923;
    public static final String OBJ_brainpoolP192r1 = "1.3.36.3.3.2.8.1.1.3";
    
    public static final String SN_brainpoolP192t1 = "brainpoolP192t1";
    public static final short NID_brainpoolP192t1 = 924;
    public static final String OBJ_brainpoolP192t1 = "1.3.36.3.3.2.8.1.1.4";
    
    public static final String SN_brainpoolP224r1 = "brainpoolP224r1";
    public static final short NID_brainpoolP224r1 = 925;
    public static final String OBJ_brainpoolP224r1 = "1.3.36.3.3.2.8.1.1.5";
    
    public static final String SN_brainpoolP224t1 = "brainpoolP224t1";
    public static final short NID_brainpoolP224t1 = 926;
    public static final String OBJ_brainpoolP224t1 = "1.3.36.3.3.2.8.1.1.6";
    
    public static final String SN_brainpoolP256r1 = "brainpoolP256r1";
    public static final short NID_brainpoolP256r1 = 927;
    public static final String OBJ_brainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";
    
    public static final String SN_brainpoolP256t1 = "brainpoolP256t1";
    public static final short NID_brainpoolP256t1 = 928;
    public static final String OBJ_brainpoolP256t1 = "1.3.36.3.3.2.8.1.1.8";
    
    public static final String SN_brainpoolP320r1 = "brainpoolP320r1";
    public static final short NID_brainpoolP320r1 = 929;
    public static final String OBJ_brainpoolP320r1 = "1.3.36.3.3.2.8.1.1.9";
    
    public static final String SN_brainpoolP320t1 = "brainpoolP320t1";
    public static final short NID_brainpoolP320t1 = 930;
    public static final String OBJ_brainpoolP320t1 = "1.3.36.3.3.2.8.1.1.10";
    
    public static final String SN_brainpoolP384r1 = "brainpoolP384r1";
    public static final short NID_brainpoolP384r1 = 931;
    public static final String OBJ_brainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";
    
    public static final String SN_brainpoolP384t1 = "brainpoolP384t1";
    public static final short NID_brainpoolP384t1 = 932;
    public static final String OBJ_brainpoolP384t1 = "1.3.36.3.3.2.8.1.1.12";
    
    public static final String SN_brainpoolP512r1 = "brainpoolP512r1";
    public static final short NID_brainpoolP512r1 = 933;
    public static final String OBJ_brainpoolP512r1 = "1.3.36.3.3.2.8.1.1.13";
    
    public static final String SN_brainpoolP512t1 = "brainpoolP512t1";
    public static final short NID_brainpoolP512t1 = 934;
    public static final String OBJ_brainpoolP512t1 = "1.3.36.3.3.2.8.1.1.14";
    
    public static final String OBJ_x9_63_scheme = "1.3.133.16.840.63.0";
    
    public static final String OBJ_secg_scheme = "1.3.132.1";
    
    public static final String SN_dhSinglePass_stdDH_sha1kdf_scheme = "dhSinglePass-stdDH-sha1kdf-scheme";
    public static final short NID_dhSinglePass_stdDH_sha1kdf_scheme = 936;
    public static final String OBJ_dhSinglePass_stdDH_sha1kdf_scheme = "1.3.133.16.840.63.0.2";
    
    public static final String SN_dhSinglePass_stdDH_sha224kdf_scheme = "dhSinglePass-stdDH-sha224kdf-scheme";
    public static final short NID_dhSinglePass_stdDH_sha224kdf_scheme = 937;
    public static final String OBJ_dhSinglePass_stdDH_sha224kdf_scheme = "1.3.132.1.11.0";
    
    public static final String SN_dhSinglePass_stdDH_sha256kdf_scheme = "dhSinglePass-stdDH-sha256kdf-scheme";
    public static final short NID_dhSinglePass_stdDH_sha256kdf_scheme = 938;
    public static final String OBJ_dhSinglePass_stdDH_sha256kdf_scheme = "1.3.132.1.11.1";
    
    public static final String SN_dhSinglePass_stdDH_sha384kdf_scheme = "dhSinglePass-stdDH-sha384kdf-scheme";
    public static final short NID_dhSinglePass_stdDH_sha384kdf_scheme = 939;
    public static final String OBJ_dhSinglePass_stdDH_sha384kdf_scheme = "1.3.132.1.11.2";
    
    public static final String SN_dhSinglePass_stdDH_sha512kdf_scheme = "dhSinglePass-stdDH-sha512kdf-scheme";
    public static final short NID_dhSinglePass_stdDH_sha512kdf_scheme = 940;
    public static final String OBJ_dhSinglePass_stdDH_sha512kdf_scheme = "1.3.132.1.11.3";
    
    public static final String SN_dhSinglePass_cofactorDH_sha1kdf_scheme = "dhSinglePass-cofactorDH-sha1kdf-scheme";
    public static final short NID_dhSinglePass_cofactorDH_sha1kdf_scheme = 941;
    public static final String OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme = "1.3.133.16.840.63.0.3";
    
    public static final String SN_dhSinglePass_cofactorDH_sha224kdf_scheme = "dhSinglePass-cofactorDH-sha224kdf-scheme";
    public static final short NID_dhSinglePass_cofactorDH_sha224kdf_scheme = 942;
    public static final String OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme = "1.3.132.1.14.0";
    
    public static final String SN_dhSinglePass_cofactorDH_sha256kdf_scheme = "dhSinglePass-cofactorDH-sha256kdf-scheme";
    public static final short NID_dhSinglePass_cofactorDH_sha256kdf_scheme = 943;
    public static final String OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme = "1.3.132.1.14.1";
    
    public static final String SN_dhSinglePass_cofactorDH_sha384kdf_scheme = "dhSinglePass-cofactorDH-sha384kdf-scheme";
    public static final short NID_dhSinglePass_cofactorDH_sha384kdf_scheme = 944;
    public static final String OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme = "1.3.132.1.14.2";
    
    public static final String SN_dhSinglePass_cofactorDH_sha512kdf_scheme = "dhSinglePass-cofactorDH-sha512kdf-scheme";
    public static final short NID_dhSinglePass_cofactorDH_sha512kdf_scheme = 945;
    public static final String OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme = "1.3.132.1.14.3";
    
    public static final String SN_dh_std_kdf = "dh-std-kdf";
    public static final short NID_dh_std_kdf = 946;
    
    public static final String SN_dh_cofactor_kdf = "dh-cofactor-kdf";
    public static final short NID_dh_cofactor_kdf = 947;
    
    public static final String SN_ct_precert_scts = "ct_precert_scts";
    public static final String LN_ct_precert_scts = "CT Precertificate SCTs";
    public static final short NID_ct_precert_scts = 951;
    public static final String OBJ_ct_precert_scts = "1.3.6.1.4.1.11129.2.4.2";
    
    public static final String SN_ct_precert_poison = "ct_precert_poison";
    public static final String LN_ct_precert_poison = "CT Precertificate Poison";
    public static final short NID_ct_precert_poison = 952;
    public static final String OBJ_ct_precert_poison = "1.3.6.1.4.1.11129.2.4.3";
    
    public static final String SN_ct_precert_signer = "ct_precert_signer";
    public static final String LN_ct_precert_signer = "CT Precertificate Signer";
    public static final short NID_ct_precert_signer = 953;
    public static final String OBJ_ct_precert_signer = "1.3.6.1.4.1.11129.2.4.4";
    
    public static final String SN_ct_cert_scts = "ct_cert_scts";
    public static final String LN_ct_cert_scts = "CT Certificate SCTs";
    public static final short NID_ct_cert_scts = 954;
    public static final String OBJ_ct_cert_scts = "1.3.6.1.4.1.11129.2.4.5";
    
    public static final String SN_jurisdictionLocalityName = "jurisdictionL";
    public static final String LN_jurisdictionLocalityName = "jurisdictionLocalityName";
    public static final short NID_jurisdictionLocalityName = 955;
    public static final String OBJ_jurisdictionLocalityName = "1.3.6.1.4.1.311.60.2.1.1";
    
    public static final String SN_jurisdictionStateOrProvinceName = "jurisdictionST";
    public static final String LN_jurisdictionStateOrProvinceName = "jurisdictionStateOrProvinceName";
    public static final short NID_jurisdictionStateOrProvinceName = 956;
    public static final String OBJ_jurisdictionStateOrProvinceName = "1.3.6.1.4.1.311.60.2.1.2";
    
    public static final String SN_jurisdictionCountryName = "jurisdictionC";
    public static final String LN_jurisdictionCountryName = "jurisdictionCountryName";
    public static final short NID_jurisdictionCountryName = 957;
    public static final String OBJ_jurisdictionCountryName = "1.3.6.1.4.1.311.60.2.1.3";
    
    

    private static final HashMap<String, String> SYM_TO_OID = new HashMap<String, String>(1284, 1);
    // if ( sn != null ) SYM_TO_OID.put(sn.toLowerCase(), oid);
    // if ( ln != null ) SYM_TO_OID.put(ln.toLowerCase(), oid);
    static {
        SYM_TO_OID.put( SN_undef.toLowerCase(), OBJ_undef );
        SYM_TO_OID.put( LN_undef.toLowerCase(), OBJ_undef );
        SYM_TO_OID.put( SN_itu_t.toLowerCase(), OBJ_itu_t );
        SYM_TO_OID.put( LN_itu_t.toLowerCase(), OBJ_itu_t );
        SYM_TO_OID.put( SN_iso.toLowerCase(), OBJ_iso );
        SYM_TO_OID.put( LN_iso.toLowerCase(), OBJ_iso );
        SYM_TO_OID.put( SN_joint_iso_itu_t.toLowerCase(), OBJ_joint_iso_itu_t );
        SYM_TO_OID.put( LN_joint_iso_itu_t.toLowerCase(), OBJ_joint_iso_itu_t );
        SYM_TO_OID.put( SN_member_body.toLowerCase(), OBJ_member_body );
        SYM_TO_OID.put( LN_member_body.toLowerCase(), OBJ_member_body );
        SYM_TO_OID.put( SN_identified_organization.toLowerCase(), OBJ_identified_organization );
        SYM_TO_OID.put( SN_hmac_md5.toLowerCase(), OBJ_hmac_md5 );
        SYM_TO_OID.put( LN_hmac_md5.toLowerCase(), OBJ_hmac_md5 );
        SYM_TO_OID.put( SN_hmac_sha1.toLowerCase(), OBJ_hmac_sha1 );
        SYM_TO_OID.put( LN_hmac_sha1.toLowerCase(), OBJ_hmac_sha1 );
        SYM_TO_OID.put( SN_certicom_arc.toLowerCase(), OBJ_certicom_arc );
        SYM_TO_OID.put( SN_international_organizations.toLowerCase(), OBJ_international_organizations );
        SYM_TO_OID.put( LN_international_organizations.toLowerCase(), OBJ_international_organizations );
        SYM_TO_OID.put( SN_wap.toLowerCase(), OBJ_wap );
        SYM_TO_OID.put( SN_wap_wsg.toLowerCase(), OBJ_wap_wsg );
        SYM_TO_OID.put( SN_selected_attribute_types.toLowerCase(), OBJ_selected_attribute_types );
        SYM_TO_OID.put( LN_selected_attribute_types.toLowerCase(), OBJ_selected_attribute_types );
        SYM_TO_OID.put( SN_clearance.toLowerCase(), OBJ_clearance );
        SYM_TO_OID.put( SN_ISO_US.toLowerCase(), OBJ_ISO_US );
        SYM_TO_OID.put( LN_ISO_US.toLowerCase(), OBJ_ISO_US );
        SYM_TO_OID.put( SN_X9_57.toLowerCase(), OBJ_X9_57 );
        SYM_TO_OID.put( LN_X9_57.toLowerCase(), OBJ_X9_57 );
        SYM_TO_OID.put( SN_X9cm.toLowerCase(), OBJ_X9cm );
        SYM_TO_OID.put( LN_X9cm.toLowerCase(), OBJ_X9cm );
        SYM_TO_OID.put( SN_dsa.toLowerCase(), OBJ_dsa );
        SYM_TO_OID.put( LN_dsa.toLowerCase(), OBJ_dsa );
        SYM_TO_OID.put( SN_dsaWithSHA1.toLowerCase(), OBJ_dsaWithSHA1 );
        SYM_TO_OID.put( LN_dsaWithSHA1.toLowerCase(), OBJ_dsaWithSHA1 );
        SYM_TO_OID.put( SN_ansi_X9_62.toLowerCase(), OBJ_ansi_X9_62 );
        SYM_TO_OID.put( LN_ansi_X9_62.toLowerCase(), OBJ_ansi_X9_62 );
        SYM_TO_OID.put( SN_X9_62_prime_field.toLowerCase(), OBJ_X9_62_prime_field );
        SYM_TO_OID.put( SN_X9_62_characteristic_two_field.toLowerCase(), OBJ_X9_62_characteristic_two_field );
        SYM_TO_OID.put( SN_X9_62_id_characteristic_two_basis.toLowerCase(), OBJ_X9_62_id_characteristic_two_basis );
        SYM_TO_OID.put( SN_X9_62_onBasis.toLowerCase(), OBJ_X9_62_onBasis );
        SYM_TO_OID.put( SN_X9_62_tpBasis.toLowerCase(), OBJ_X9_62_tpBasis );
        SYM_TO_OID.put( SN_X9_62_ppBasis.toLowerCase(), OBJ_X9_62_ppBasis );
        SYM_TO_OID.put( SN_X9_62_id_ecPublicKey.toLowerCase(), OBJ_X9_62_id_ecPublicKey );
        SYM_TO_OID.put( SN_X9_62_c2pnb163v1.toLowerCase(), OBJ_X9_62_c2pnb163v1 );
        SYM_TO_OID.put( SN_X9_62_c2pnb163v2.toLowerCase(), OBJ_X9_62_c2pnb163v2 );
        SYM_TO_OID.put( SN_X9_62_c2pnb163v3.toLowerCase(), OBJ_X9_62_c2pnb163v3 );
        SYM_TO_OID.put( SN_X9_62_c2pnb176v1.toLowerCase(), OBJ_X9_62_c2pnb176v1 );
        SYM_TO_OID.put( SN_X9_62_c2tnb191v1.toLowerCase(), OBJ_X9_62_c2tnb191v1 );
        SYM_TO_OID.put( SN_X9_62_c2tnb191v2.toLowerCase(), OBJ_X9_62_c2tnb191v2 );
        SYM_TO_OID.put( SN_X9_62_c2tnb191v3.toLowerCase(), OBJ_X9_62_c2tnb191v3 );
        SYM_TO_OID.put( SN_X9_62_c2onb191v4.toLowerCase(), OBJ_X9_62_c2onb191v4 );
        SYM_TO_OID.put( SN_X9_62_c2onb191v5.toLowerCase(), OBJ_X9_62_c2onb191v5 );
        SYM_TO_OID.put( SN_X9_62_c2pnb208w1.toLowerCase(), OBJ_X9_62_c2pnb208w1 );
        SYM_TO_OID.put( SN_X9_62_c2tnb239v1.toLowerCase(), OBJ_X9_62_c2tnb239v1 );
        SYM_TO_OID.put( SN_X9_62_c2tnb239v2.toLowerCase(), OBJ_X9_62_c2tnb239v2 );
        SYM_TO_OID.put( SN_X9_62_c2tnb239v3.toLowerCase(), OBJ_X9_62_c2tnb239v3 );
        SYM_TO_OID.put( SN_X9_62_c2onb239v4.toLowerCase(), OBJ_X9_62_c2onb239v4 );
        SYM_TO_OID.put( SN_X9_62_c2onb239v5.toLowerCase(), OBJ_X9_62_c2onb239v5 );
        SYM_TO_OID.put( SN_X9_62_c2pnb272w1.toLowerCase(), OBJ_X9_62_c2pnb272w1 );
        SYM_TO_OID.put( SN_X9_62_c2pnb304w1.toLowerCase(), OBJ_X9_62_c2pnb304w1 );
        SYM_TO_OID.put( SN_X9_62_c2tnb359v1.toLowerCase(), OBJ_X9_62_c2tnb359v1 );
        SYM_TO_OID.put( SN_X9_62_c2pnb368w1.toLowerCase(), OBJ_X9_62_c2pnb368w1 );
        SYM_TO_OID.put( SN_X9_62_c2tnb431r1.toLowerCase(), OBJ_X9_62_c2tnb431r1 );
        SYM_TO_OID.put( SN_X9_62_prime192v1.toLowerCase(), OBJ_X9_62_prime192v1 );
        SYM_TO_OID.put( SN_X9_62_prime192v2.toLowerCase(), OBJ_X9_62_prime192v2 );
        SYM_TO_OID.put( SN_X9_62_prime192v3.toLowerCase(), OBJ_X9_62_prime192v3 );
        SYM_TO_OID.put( SN_X9_62_prime239v1.toLowerCase(), OBJ_X9_62_prime239v1 );
        SYM_TO_OID.put( SN_X9_62_prime239v2.toLowerCase(), OBJ_X9_62_prime239v2 );
        SYM_TO_OID.put( SN_X9_62_prime239v3.toLowerCase(), OBJ_X9_62_prime239v3 );
        SYM_TO_OID.put( SN_X9_62_prime256v1.toLowerCase(), OBJ_X9_62_prime256v1 );
        SYM_TO_OID.put( SN_ecdsa_with_SHA1.toLowerCase(), OBJ_ecdsa_with_SHA1 );
        SYM_TO_OID.put( SN_ecdsa_with_Recommended.toLowerCase(), OBJ_ecdsa_with_Recommended );
        SYM_TO_OID.put( SN_ecdsa_with_Specified.toLowerCase(), OBJ_ecdsa_with_Specified );
        SYM_TO_OID.put( SN_ecdsa_with_SHA224.toLowerCase(), OBJ_ecdsa_with_SHA224 );
        SYM_TO_OID.put( SN_ecdsa_with_SHA256.toLowerCase(), OBJ_ecdsa_with_SHA256 );
        SYM_TO_OID.put( SN_ecdsa_with_SHA384.toLowerCase(), OBJ_ecdsa_with_SHA384 );
        SYM_TO_OID.put( SN_ecdsa_with_SHA512.toLowerCase(), OBJ_ecdsa_with_SHA512 );
        SYM_TO_OID.put( SN_secp112r1.toLowerCase(), OBJ_secp112r1 );
        SYM_TO_OID.put( SN_secp112r2.toLowerCase(), OBJ_secp112r2 );
        SYM_TO_OID.put( SN_secp128r1.toLowerCase(), OBJ_secp128r1 );
        SYM_TO_OID.put( SN_secp128r2.toLowerCase(), OBJ_secp128r2 );
        SYM_TO_OID.put( SN_secp160k1.toLowerCase(), OBJ_secp160k1 );
        SYM_TO_OID.put( SN_secp160r1.toLowerCase(), OBJ_secp160r1 );
        SYM_TO_OID.put( SN_secp160r2.toLowerCase(), OBJ_secp160r2 );
        SYM_TO_OID.put( SN_secp192k1.toLowerCase(), OBJ_secp192k1 );
        SYM_TO_OID.put( SN_secp224k1.toLowerCase(), OBJ_secp224k1 );
        SYM_TO_OID.put( SN_secp224r1.toLowerCase(), OBJ_secp224r1 );
        SYM_TO_OID.put( SN_secp256k1.toLowerCase(), OBJ_secp256k1 );
        SYM_TO_OID.put( SN_secp384r1.toLowerCase(), OBJ_secp384r1 );
        SYM_TO_OID.put( SN_secp521r1.toLowerCase(), OBJ_secp521r1 );
        SYM_TO_OID.put( SN_sect113r1.toLowerCase(), OBJ_sect113r1 );
        SYM_TO_OID.put( SN_sect113r2.toLowerCase(), OBJ_sect113r2 );
        SYM_TO_OID.put( SN_sect131r1.toLowerCase(), OBJ_sect131r1 );
        SYM_TO_OID.put( SN_sect131r2.toLowerCase(), OBJ_sect131r2 );
        SYM_TO_OID.put( SN_sect163k1.toLowerCase(), OBJ_sect163k1 );
        SYM_TO_OID.put( SN_sect163r1.toLowerCase(), OBJ_sect163r1 );
        SYM_TO_OID.put( SN_sect163r2.toLowerCase(), OBJ_sect163r2 );
        SYM_TO_OID.put( SN_sect193r1.toLowerCase(), OBJ_sect193r1 );
        SYM_TO_OID.put( SN_sect193r2.toLowerCase(), OBJ_sect193r2 );
        SYM_TO_OID.put( SN_sect233k1.toLowerCase(), OBJ_sect233k1 );
        SYM_TO_OID.put( SN_sect233r1.toLowerCase(), OBJ_sect233r1 );
        SYM_TO_OID.put( SN_sect239k1.toLowerCase(), OBJ_sect239k1 );
        SYM_TO_OID.put( SN_sect283k1.toLowerCase(), OBJ_sect283k1 );
        SYM_TO_OID.put( SN_sect283r1.toLowerCase(), OBJ_sect283r1 );
        SYM_TO_OID.put( SN_sect409k1.toLowerCase(), OBJ_sect409k1 );
        SYM_TO_OID.put( SN_sect409r1.toLowerCase(), OBJ_sect409r1 );
        SYM_TO_OID.put( SN_sect571k1.toLowerCase(), OBJ_sect571k1 );
        SYM_TO_OID.put( SN_sect571r1.toLowerCase(), OBJ_sect571r1 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls1.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls1 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls3.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls3 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls4.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls4 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls5.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls5 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls6.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls6 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls7.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls7 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls8.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls8 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls9.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls9 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls10.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls10 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls11.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls11 );
        SYM_TO_OID.put( SN_wap_wsg_idm_ecid_wtls12.toLowerCase(), OBJ_wap_wsg_idm_ecid_wtls12 );
        SYM_TO_OID.put( SN_cast5_cbc.toLowerCase(), OBJ_cast5_cbc );
        SYM_TO_OID.put( LN_cast5_cbc.toLowerCase(), OBJ_cast5_cbc );
        SYM_TO_OID.put( LN_pbeWithMD5AndCast5_CBC.toLowerCase(), OBJ_pbeWithMD5AndCast5_CBC );
        SYM_TO_OID.put( SN_id_PasswordBasedMAC.toLowerCase(), OBJ_id_PasswordBasedMAC );
        SYM_TO_OID.put( LN_id_PasswordBasedMAC.toLowerCase(), OBJ_id_PasswordBasedMAC );
        SYM_TO_OID.put( SN_id_DHBasedMac.toLowerCase(), OBJ_id_DHBasedMac );
        SYM_TO_OID.put( LN_id_DHBasedMac.toLowerCase(), OBJ_id_DHBasedMac );
        SYM_TO_OID.put( SN_rsadsi.toLowerCase(), OBJ_rsadsi );
        SYM_TO_OID.put( LN_rsadsi.toLowerCase(), OBJ_rsadsi );
        SYM_TO_OID.put( SN_pkcs.toLowerCase(), OBJ_pkcs );
        SYM_TO_OID.put( LN_pkcs.toLowerCase(), OBJ_pkcs );
        SYM_TO_OID.put( SN_pkcs1.toLowerCase(), OBJ_pkcs1 );
        SYM_TO_OID.put( LN_rsaEncryption.toLowerCase(), OBJ_rsaEncryption );
        SYM_TO_OID.put( SN_md2WithRSAEncryption.toLowerCase(), OBJ_md2WithRSAEncryption );
        SYM_TO_OID.put( LN_md2WithRSAEncryption.toLowerCase(), OBJ_md2WithRSAEncryption );
        SYM_TO_OID.put( SN_md4WithRSAEncryption.toLowerCase(), OBJ_md4WithRSAEncryption );
        SYM_TO_OID.put( LN_md4WithRSAEncryption.toLowerCase(), OBJ_md4WithRSAEncryption );
        SYM_TO_OID.put( SN_md5WithRSAEncryption.toLowerCase(), OBJ_md5WithRSAEncryption );
        SYM_TO_OID.put( LN_md5WithRSAEncryption.toLowerCase(), OBJ_md5WithRSAEncryption );
        SYM_TO_OID.put( SN_sha1WithRSAEncryption.toLowerCase(), OBJ_sha1WithRSAEncryption );
        SYM_TO_OID.put( LN_sha1WithRSAEncryption.toLowerCase(), OBJ_sha1WithRSAEncryption );
        SYM_TO_OID.put( SN_rsaesOaep.toLowerCase(), OBJ_rsaesOaep );
        SYM_TO_OID.put( LN_rsaesOaep.toLowerCase(), OBJ_rsaesOaep );
        SYM_TO_OID.put( SN_mgf1.toLowerCase(), OBJ_mgf1 );
        SYM_TO_OID.put( LN_mgf1.toLowerCase(), OBJ_mgf1 );
        SYM_TO_OID.put( SN_pSpecified.toLowerCase(), OBJ_pSpecified );
        SYM_TO_OID.put( LN_pSpecified.toLowerCase(), OBJ_pSpecified );
        SYM_TO_OID.put( SN_rsassaPss.toLowerCase(), OBJ_rsassaPss );
        SYM_TO_OID.put( LN_rsassaPss.toLowerCase(), OBJ_rsassaPss );
        SYM_TO_OID.put( SN_sha256WithRSAEncryption.toLowerCase(), OBJ_sha256WithRSAEncryption );
        SYM_TO_OID.put( LN_sha256WithRSAEncryption.toLowerCase(), OBJ_sha256WithRSAEncryption );
        SYM_TO_OID.put( SN_sha384WithRSAEncryption.toLowerCase(), OBJ_sha384WithRSAEncryption );
        SYM_TO_OID.put( LN_sha384WithRSAEncryption.toLowerCase(), OBJ_sha384WithRSAEncryption );
        SYM_TO_OID.put( SN_sha512WithRSAEncryption.toLowerCase(), OBJ_sha512WithRSAEncryption );
        SYM_TO_OID.put( LN_sha512WithRSAEncryption.toLowerCase(), OBJ_sha512WithRSAEncryption );
        SYM_TO_OID.put( SN_sha224WithRSAEncryption.toLowerCase(), OBJ_sha224WithRSAEncryption );
        SYM_TO_OID.put( LN_sha224WithRSAEncryption.toLowerCase(), OBJ_sha224WithRSAEncryption );
        SYM_TO_OID.put( SN_pkcs3.toLowerCase(), OBJ_pkcs3 );
        SYM_TO_OID.put( LN_dhKeyAgreement.toLowerCase(), OBJ_dhKeyAgreement );
        SYM_TO_OID.put( SN_pkcs5.toLowerCase(), OBJ_pkcs5 );
        SYM_TO_OID.put( SN_pbeWithMD2AndDES_CBC.toLowerCase(), OBJ_pbeWithMD2AndDES_CBC );
        SYM_TO_OID.put( LN_pbeWithMD2AndDES_CBC.toLowerCase(), OBJ_pbeWithMD2AndDES_CBC );
        SYM_TO_OID.put( SN_pbeWithMD5AndDES_CBC.toLowerCase(), OBJ_pbeWithMD5AndDES_CBC );
        SYM_TO_OID.put( LN_pbeWithMD5AndDES_CBC.toLowerCase(), OBJ_pbeWithMD5AndDES_CBC );
        SYM_TO_OID.put( SN_pbeWithMD2AndRC2_CBC.toLowerCase(), OBJ_pbeWithMD2AndRC2_CBC );
        SYM_TO_OID.put( LN_pbeWithMD2AndRC2_CBC.toLowerCase(), OBJ_pbeWithMD2AndRC2_CBC );
        SYM_TO_OID.put( SN_pbeWithMD5AndRC2_CBC.toLowerCase(), OBJ_pbeWithMD5AndRC2_CBC );
        SYM_TO_OID.put( LN_pbeWithMD5AndRC2_CBC.toLowerCase(), OBJ_pbeWithMD5AndRC2_CBC );
        SYM_TO_OID.put( SN_pbeWithSHA1AndDES_CBC.toLowerCase(), OBJ_pbeWithSHA1AndDES_CBC );
        SYM_TO_OID.put( LN_pbeWithSHA1AndDES_CBC.toLowerCase(), OBJ_pbeWithSHA1AndDES_CBC );
        SYM_TO_OID.put( SN_pbeWithSHA1AndRC2_CBC.toLowerCase(), OBJ_pbeWithSHA1AndRC2_CBC );
        SYM_TO_OID.put( LN_pbeWithSHA1AndRC2_CBC.toLowerCase(), OBJ_pbeWithSHA1AndRC2_CBC );
        SYM_TO_OID.put( LN_id_pbkdf2.toLowerCase(), OBJ_id_pbkdf2 );
        SYM_TO_OID.put( LN_pbes2.toLowerCase(), OBJ_pbes2 );
        SYM_TO_OID.put( LN_pbmac1.toLowerCase(), OBJ_pbmac1 );
        SYM_TO_OID.put( SN_pkcs7.toLowerCase(), OBJ_pkcs7 );
        SYM_TO_OID.put( LN_pkcs7_data.toLowerCase(), OBJ_pkcs7_data );
        SYM_TO_OID.put( LN_pkcs7_signed.toLowerCase(), OBJ_pkcs7_signed );
        SYM_TO_OID.put( LN_pkcs7_enveloped.toLowerCase(), OBJ_pkcs7_enveloped );
        SYM_TO_OID.put( LN_pkcs7_signedAndEnveloped.toLowerCase(), OBJ_pkcs7_signedAndEnveloped );
        SYM_TO_OID.put( LN_pkcs7_digest.toLowerCase(), OBJ_pkcs7_digest );
        SYM_TO_OID.put( LN_pkcs7_encrypted.toLowerCase(), OBJ_pkcs7_encrypted );
        SYM_TO_OID.put( SN_pkcs9.toLowerCase(), OBJ_pkcs9 );
        SYM_TO_OID.put( LN_pkcs9_emailAddress.toLowerCase(), OBJ_pkcs9_emailAddress );
        SYM_TO_OID.put( LN_pkcs9_unstructuredName.toLowerCase(), OBJ_pkcs9_unstructuredName );
        SYM_TO_OID.put( LN_pkcs9_contentType.toLowerCase(), OBJ_pkcs9_contentType );
        SYM_TO_OID.put( LN_pkcs9_messageDigest.toLowerCase(), OBJ_pkcs9_messageDigest );
        SYM_TO_OID.put( LN_pkcs9_signingTime.toLowerCase(), OBJ_pkcs9_signingTime );
        SYM_TO_OID.put( LN_pkcs9_countersignature.toLowerCase(), OBJ_pkcs9_countersignature );
        SYM_TO_OID.put( LN_pkcs9_challengePassword.toLowerCase(), OBJ_pkcs9_challengePassword );
        SYM_TO_OID.put( LN_pkcs9_unstructuredAddress.toLowerCase(), OBJ_pkcs9_unstructuredAddress );
        SYM_TO_OID.put( LN_pkcs9_extCertAttributes.toLowerCase(), OBJ_pkcs9_extCertAttributes );
        SYM_TO_OID.put( SN_ext_req.toLowerCase(), OBJ_ext_req );
        SYM_TO_OID.put( LN_ext_req.toLowerCase(), OBJ_ext_req );
        SYM_TO_OID.put( SN_SMIMECapabilities.toLowerCase(), OBJ_SMIMECapabilities );
        SYM_TO_OID.put( LN_SMIMECapabilities.toLowerCase(), OBJ_SMIMECapabilities );
        SYM_TO_OID.put( SN_SMIME.toLowerCase(), OBJ_SMIME );
        SYM_TO_OID.put( LN_SMIME.toLowerCase(), OBJ_SMIME );
        SYM_TO_OID.put( SN_id_smime_mod.toLowerCase(), OBJ_id_smime_mod );
        SYM_TO_OID.put( SN_id_smime_ct.toLowerCase(), OBJ_id_smime_ct );
        SYM_TO_OID.put( SN_id_smime_aa.toLowerCase(), OBJ_id_smime_aa );
        SYM_TO_OID.put( SN_id_smime_alg.toLowerCase(), OBJ_id_smime_alg );
        SYM_TO_OID.put( SN_id_smime_cd.toLowerCase(), OBJ_id_smime_cd );
        SYM_TO_OID.put( SN_id_smime_spq.toLowerCase(), OBJ_id_smime_spq );
        SYM_TO_OID.put( SN_id_smime_cti.toLowerCase(), OBJ_id_smime_cti );
        SYM_TO_OID.put( SN_id_smime_mod_cms.toLowerCase(), OBJ_id_smime_mod_cms );
        SYM_TO_OID.put( SN_id_smime_mod_ess.toLowerCase(), OBJ_id_smime_mod_ess );
        SYM_TO_OID.put( SN_id_smime_mod_oid.toLowerCase(), OBJ_id_smime_mod_oid );
        SYM_TO_OID.put( SN_id_smime_mod_msg_v3.toLowerCase(), OBJ_id_smime_mod_msg_v3 );
        SYM_TO_OID.put( SN_id_smime_mod_ets_eSignature_88.toLowerCase(), OBJ_id_smime_mod_ets_eSignature_88 );
        SYM_TO_OID.put( SN_id_smime_mod_ets_eSignature_97.toLowerCase(), OBJ_id_smime_mod_ets_eSignature_97 );
        SYM_TO_OID.put( SN_id_smime_mod_ets_eSigPolicy_88.toLowerCase(), OBJ_id_smime_mod_ets_eSigPolicy_88 );
        SYM_TO_OID.put( SN_id_smime_mod_ets_eSigPolicy_97.toLowerCase(), OBJ_id_smime_mod_ets_eSigPolicy_97 );
        SYM_TO_OID.put( SN_id_smime_ct_receipt.toLowerCase(), OBJ_id_smime_ct_receipt );
        SYM_TO_OID.put( SN_id_smime_ct_authData.toLowerCase(), OBJ_id_smime_ct_authData );
        SYM_TO_OID.put( SN_id_smime_ct_publishCert.toLowerCase(), OBJ_id_smime_ct_publishCert );
        SYM_TO_OID.put( SN_id_smime_ct_TSTInfo.toLowerCase(), OBJ_id_smime_ct_TSTInfo );
        SYM_TO_OID.put( SN_id_smime_ct_TDTInfo.toLowerCase(), OBJ_id_smime_ct_TDTInfo );
        SYM_TO_OID.put( SN_id_smime_ct_contentInfo.toLowerCase(), OBJ_id_smime_ct_contentInfo );
        SYM_TO_OID.put( SN_id_smime_ct_DVCSRequestData.toLowerCase(), OBJ_id_smime_ct_DVCSRequestData );
        SYM_TO_OID.put( SN_id_smime_ct_DVCSResponseData.toLowerCase(), OBJ_id_smime_ct_DVCSResponseData );
        SYM_TO_OID.put( SN_id_smime_ct_compressedData.toLowerCase(), OBJ_id_smime_ct_compressedData );
        SYM_TO_OID.put( SN_id_ct_asciiTextWithCRLF.toLowerCase(), OBJ_id_ct_asciiTextWithCRLF );
        SYM_TO_OID.put( SN_id_smime_aa_receiptRequest.toLowerCase(), OBJ_id_smime_aa_receiptRequest );
        SYM_TO_OID.put( SN_id_smime_aa_securityLabel.toLowerCase(), OBJ_id_smime_aa_securityLabel );
        SYM_TO_OID.put( SN_id_smime_aa_mlExpandHistory.toLowerCase(), OBJ_id_smime_aa_mlExpandHistory );
        SYM_TO_OID.put( SN_id_smime_aa_contentHint.toLowerCase(), OBJ_id_smime_aa_contentHint );
        SYM_TO_OID.put( SN_id_smime_aa_msgSigDigest.toLowerCase(), OBJ_id_smime_aa_msgSigDigest );
        SYM_TO_OID.put( SN_id_smime_aa_encapContentType.toLowerCase(), OBJ_id_smime_aa_encapContentType );
        SYM_TO_OID.put( SN_id_smime_aa_contentIdentifier.toLowerCase(), OBJ_id_smime_aa_contentIdentifier );
        SYM_TO_OID.put( SN_id_smime_aa_macValue.toLowerCase(), OBJ_id_smime_aa_macValue );
        SYM_TO_OID.put( SN_id_smime_aa_equivalentLabels.toLowerCase(), OBJ_id_smime_aa_equivalentLabels );
        SYM_TO_OID.put( SN_id_smime_aa_contentReference.toLowerCase(), OBJ_id_smime_aa_contentReference );
        SYM_TO_OID.put( SN_id_smime_aa_encrypKeyPref.toLowerCase(), OBJ_id_smime_aa_encrypKeyPref );
        SYM_TO_OID.put( SN_id_smime_aa_signingCertificate.toLowerCase(), OBJ_id_smime_aa_signingCertificate );
        SYM_TO_OID.put( SN_id_smime_aa_smimeEncryptCerts.toLowerCase(), OBJ_id_smime_aa_smimeEncryptCerts );
        SYM_TO_OID.put( SN_id_smime_aa_timeStampToken.toLowerCase(), OBJ_id_smime_aa_timeStampToken );
        SYM_TO_OID.put( SN_id_smime_aa_ets_sigPolicyId.toLowerCase(), OBJ_id_smime_aa_ets_sigPolicyId );
        SYM_TO_OID.put( SN_id_smime_aa_ets_commitmentType.toLowerCase(), OBJ_id_smime_aa_ets_commitmentType );
        SYM_TO_OID.put( SN_id_smime_aa_ets_signerLocation.toLowerCase(), OBJ_id_smime_aa_ets_signerLocation );
        SYM_TO_OID.put( SN_id_smime_aa_ets_signerAttr.toLowerCase(), OBJ_id_smime_aa_ets_signerAttr );
        SYM_TO_OID.put( SN_id_smime_aa_ets_otherSigCert.toLowerCase(), OBJ_id_smime_aa_ets_otherSigCert );
        SYM_TO_OID.put( SN_id_smime_aa_ets_contentTimestamp.toLowerCase(), OBJ_id_smime_aa_ets_contentTimestamp );
        SYM_TO_OID.put( SN_id_smime_aa_ets_CertificateRefs.toLowerCase(), OBJ_id_smime_aa_ets_CertificateRefs );
        SYM_TO_OID.put( SN_id_smime_aa_ets_RevocationRefs.toLowerCase(), OBJ_id_smime_aa_ets_RevocationRefs );
        SYM_TO_OID.put( SN_id_smime_aa_ets_certValues.toLowerCase(), OBJ_id_smime_aa_ets_certValues );
        SYM_TO_OID.put( SN_id_smime_aa_ets_revocationValues.toLowerCase(), OBJ_id_smime_aa_ets_revocationValues );
        SYM_TO_OID.put( SN_id_smime_aa_ets_escTimeStamp.toLowerCase(), OBJ_id_smime_aa_ets_escTimeStamp );
        SYM_TO_OID.put( SN_id_smime_aa_ets_certCRLTimestamp.toLowerCase(), OBJ_id_smime_aa_ets_certCRLTimestamp );
        SYM_TO_OID.put( SN_id_smime_aa_ets_archiveTimeStamp.toLowerCase(), OBJ_id_smime_aa_ets_archiveTimeStamp );
        SYM_TO_OID.put( SN_id_smime_aa_signatureType.toLowerCase(), OBJ_id_smime_aa_signatureType );
        SYM_TO_OID.put( SN_id_smime_aa_dvcs_dvc.toLowerCase(), OBJ_id_smime_aa_dvcs_dvc );
        SYM_TO_OID.put( SN_id_smime_alg_ESDHwith3DES.toLowerCase(), OBJ_id_smime_alg_ESDHwith3DES );
        SYM_TO_OID.put( SN_id_smime_alg_ESDHwithRC2.toLowerCase(), OBJ_id_smime_alg_ESDHwithRC2 );
        SYM_TO_OID.put( SN_id_smime_alg_3DESwrap.toLowerCase(), OBJ_id_smime_alg_3DESwrap );
        SYM_TO_OID.put( SN_id_smime_alg_RC2wrap.toLowerCase(), OBJ_id_smime_alg_RC2wrap );
        SYM_TO_OID.put( SN_id_smime_alg_ESDH.toLowerCase(), OBJ_id_smime_alg_ESDH );
        SYM_TO_OID.put( SN_id_smime_alg_CMS3DESwrap.toLowerCase(), OBJ_id_smime_alg_CMS3DESwrap );
        SYM_TO_OID.put( SN_id_smime_alg_CMSRC2wrap.toLowerCase(), OBJ_id_smime_alg_CMSRC2wrap );
        SYM_TO_OID.put( SN_id_alg_PWRI_KEK.toLowerCase(), OBJ_id_alg_PWRI_KEK );
        SYM_TO_OID.put( SN_id_smime_cd_ldap.toLowerCase(), OBJ_id_smime_cd_ldap );
        SYM_TO_OID.put( SN_id_smime_spq_ets_sqt_uri.toLowerCase(), OBJ_id_smime_spq_ets_sqt_uri );
        SYM_TO_OID.put( SN_id_smime_spq_ets_sqt_unotice.toLowerCase(), OBJ_id_smime_spq_ets_sqt_unotice );
        SYM_TO_OID.put( SN_id_smime_cti_ets_proofOfOrigin.toLowerCase(), OBJ_id_smime_cti_ets_proofOfOrigin );
        SYM_TO_OID.put( SN_id_smime_cti_ets_proofOfReceipt.toLowerCase(), OBJ_id_smime_cti_ets_proofOfReceipt );
        SYM_TO_OID.put( SN_id_smime_cti_ets_proofOfDelivery.toLowerCase(), OBJ_id_smime_cti_ets_proofOfDelivery );
        SYM_TO_OID.put( SN_id_smime_cti_ets_proofOfSender.toLowerCase(), OBJ_id_smime_cti_ets_proofOfSender );
        SYM_TO_OID.put( SN_id_smime_cti_ets_proofOfApproval.toLowerCase(), OBJ_id_smime_cti_ets_proofOfApproval );
        SYM_TO_OID.put( SN_id_smime_cti_ets_proofOfCreation.toLowerCase(), OBJ_id_smime_cti_ets_proofOfCreation );
        SYM_TO_OID.put( LN_friendlyName.toLowerCase(), OBJ_friendlyName );
        SYM_TO_OID.put( LN_localKeyID.toLowerCase(), OBJ_localKeyID );
        SYM_TO_OID.put( SN_ms_csp_name.toLowerCase(), OBJ_ms_csp_name );
        SYM_TO_OID.put( LN_ms_csp_name.toLowerCase(), OBJ_ms_csp_name );
        SYM_TO_OID.put( SN_LocalKeySet.toLowerCase(), OBJ_LocalKeySet );
        SYM_TO_OID.put( LN_LocalKeySet.toLowerCase(), OBJ_LocalKeySet );
        SYM_TO_OID.put( LN_x509Certificate.toLowerCase(), OBJ_x509Certificate );
        SYM_TO_OID.put( LN_sdsiCertificate.toLowerCase(), OBJ_sdsiCertificate );
        SYM_TO_OID.put( LN_x509Crl.toLowerCase(), OBJ_x509Crl );
        SYM_TO_OID.put( SN_pbe_WithSHA1And128BitRC4.toLowerCase(), OBJ_pbe_WithSHA1And128BitRC4 );
        SYM_TO_OID.put( LN_pbe_WithSHA1And128BitRC4.toLowerCase(), OBJ_pbe_WithSHA1And128BitRC4 );
        SYM_TO_OID.put( SN_pbe_WithSHA1And40BitRC4.toLowerCase(), OBJ_pbe_WithSHA1And40BitRC4 );
        SYM_TO_OID.put( LN_pbe_WithSHA1And40BitRC4.toLowerCase(), OBJ_pbe_WithSHA1And40BitRC4 );
        SYM_TO_OID.put( SN_pbe_WithSHA1And3_Key_TripleDES_CBC.toLowerCase(), OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC );
        SYM_TO_OID.put( LN_pbe_WithSHA1And3_Key_TripleDES_CBC.toLowerCase(), OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC );
        SYM_TO_OID.put( SN_pbe_WithSHA1And2_Key_TripleDES_CBC.toLowerCase(), OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC );
        SYM_TO_OID.put( LN_pbe_WithSHA1And2_Key_TripleDES_CBC.toLowerCase(), OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC );
        SYM_TO_OID.put( SN_pbe_WithSHA1And128BitRC2_CBC.toLowerCase(), OBJ_pbe_WithSHA1And128BitRC2_CBC );
        SYM_TO_OID.put( LN_pbe_WithSHA1And128BitRC2_CBC.toLowerCase(), OBJ_pbe_WithSHA1And128BitRC2_CBC );
        SYM_TO_OID.put( SN_pbe_WithSHA1And40BitRC2_CBC.toLowerCase(), OBJ_pbe_WithSHA1And40BitRC2_CBC );
        SYM_TO_OID.put( LN_pbe_WithSHA1And40BitRC2_CBC.toLowerCase(), OBJ_pbe_WithSHA1And40BitRC2_CBC );
        SYM_TO_OID.put( LN_keyBag.toLowerCase(), OBJ_keyBag );
        SYM_TO_OID.put( LN_pkcs8ShroudedKeyBag.toLowerCase(), OBJ_pkcs8ShroudedKeyBag );
        SYM_TO_OID.put( LN_certBag.toLowerCase(), OBJ_certBag );
        SYM_TO_OID.put( LN_crlBag.toLowerCase(), OBJ_crlBag );
        SYM_TO_OID.put( LN_secretBag.toLowerCase(), OBJ_secretBag );
        SYM_TO_OID.put( LN_safeContentsBag.toLowerCase(), OBJ_safeContentsBag );
        SYM_TO_OID.put( SN_md2.toLowerCase(), OBJ_md2 );
        SYM_TO_OID.put( LN_md2.toLowerCase(), OBJ_md2 );
        SYM_TO_OID.put( SN_md4.toLowerCase(), OBJ_md4 );
        SYM_TO_OID.put( LN_md4.toLowerCase(), OBJ_md4 );
        SYM_TO_OID.put( SN_md5.toLowerCase(), OBJ_md5 );
        SYM_TO_OID.put( LN_md5.toLowerCase(), OBJ_md5 );
        SYM_TO_OID.put( LN_hmacWithMD5.toLowerCase(), OBJ_hmacWithMD5 );
        SYM_TO_OID.put( LN_hmacWithSHA1.toLowerCase(), OBJ_hmacWithSHA1 );
        SYM_TO_OID.put( LN_hmacWithSHA224.toLowerCase(), OBJ_hmacWithSHA224 );
        SYM_TO_OID.put( LN_hmacWithSHA256.toLowerCase(), OBJ_hmacWithSHA256 );
        SYM_TO_OID.put( LN_hmacWithSHA384.toLowerCase(), OBJ_hmacWithSHA384 );
        SYM_TO_OID.put( LN_hmacWithSHA512.toLowerCase(), OBJ_hmacWithSHA512 );
        SYM_TO_OID.put( SN_rc2_cbc.toLowerCase(), OBJ_rc2_cbc );
        SYM_TO_OID.put( LN_rc2_cbc.toLowerCase(), OBJ_rc2_cbc );
        SYM_TO_OID.put( SN_rc4.toLowerCase(), OBJ_rc4 );
        SYM_TO_OID.put( LN_rc4.toLowerCase(), OBJ_rc4 );
        SYM_TO_OID.put( SN_des_ede3_cbc.toLowerCase(), OBJ_des_ede3_cbc );
        SYM_TO_OID.put( LN_des_ede3_cbc.toLowerCase(), OBJ_des_ede3_cbc );
        SYM_TO_OID.put( SN_rc5_cbc.toLowerCase(), OBJ_rc5_cbc );
        SYM_TO_OID.put( LN_rc5_cbc.toLowerCase(), OBJ_rc5_cbc );
        SYM_TO_OID.put( SN_ms_ext_req.toLowerCase(), OBJ_ms_ext_req );
        SYM_TO_OID.put( LN_ms_ext_req.toLowerCase(), OBJ_ms_ext_req );
        SYM_TO_OID.put( SN_ms_code_ind.toLowerCase(), OBJ_ms_code_ind );
        SYM_TO_OID.put( LN_ms_code_ind.toLowerCase(), OBJ_ms_code_ind );
        SYM_TO_OID.put( SN_ms_code_com.toLowerCase(), OBJ_ms_code_com );
        SYM_TO_OID.put( LN_ms_code_com.toLowerCase(), OBJ_ms_code_com );
        SYM_TO_OID.put( SN_ms_ctl_sign.toLowerCase(), OBJ_ms_ctl_sign );
        SYM_TO_OID.put( LN_ms_ctl_sign.toLowerCase(), OBJ_ms_ctl_sign );
        SYM_TO_OID.put( SN_ms_sgc.toLowerCase(), OBJ_ms_sgc );
        SYM_TO_OID.put( LN_ms_sgc.toLowerCase(), OBJ_ms_sgc );
        SYM_TO_OID.put( SN_ms_efs.toLowerCase(), OBJ_ms_efs );
        SYM_TO_OID.put( LN_ms_efs.toLowerCase(), OBJ_ms_efs );
        SYM_TO_OID.put( SN_ms_smartcard_login.toLowerCase(), OBJ_ms_smartcard_login );
        SYM_TO_OID.put( LN_ms_smartcard_login.toLowerCase(), OBJ_ms_smartcard_login );
        SYM_TO_OID.put( SN_ms_upn.toLowerCase(), OBJ_ms_upn );
        SYM_TO_OID.put( LN_ms_upn.toLowerCase(), OBJ_ms_upn );
        SYM_TO_OID.put( SN_idea_cbc.toLowerCase(), OBJ_idea_cbc );
        SYM_TO_OID.put( LN_idea_cbc.toLowerCase(), OBJ_idea_cbc );
        SYM_TO_OID.put( SN_bf_cbc.toLowerCase(), OBJ_bf_cbc );
        SYM_TO_OID.put( LN_bf_cbc.toLowerCase(), OBJ_bf_cbc );
        SYM_TO_OID.put( SN_id_pkix.toLowerCase(), OBJ_id_pkix );
        SYM_TO_OID.put( SN_id_pkix_mod.toLowerCase(), OBJ_id_pkix_mod );
        SYM_TO_OID.put( SN_id_pe.toLowerCase(), OBJ_id_pe );
        SYM_TO_OID.put( SN_id_qt.toLowerCase(), OBJ_id_qt );
        SYM_TO_OID.put( SN_id_kp.toLowerCase(), OBJ_id_kp );
        SYM_TO_OID.put( SN_id_it.toLowerCase(), OBJ_id_it );
        SYM_TO_OID.put( SN_id_pkip.toLowerCase(), OBJ_id_pkip );
        SYM_TO_OID.put( SN_id_alg.toLowerCase(), OBJ_id_alg );
        SYM_TO_OID.put( SN_id_cmc.toLowerCase(), OBJ_id_cmc );
        SYM_TO_OID.put( SN_id_on.toLowerCase(), OBJ_id_on );
        SYM_TO_OID.put( SN_id_pda.toLowerCase(), OBJ_id_pda );
        SYM_TO_OID.put( SN_id_aca.toLowerCase(), OBJ_id_aca );
        SYM_TO_OID.put( SN_id_qcs.toLowerCase(), OBJ_id_qcs );
        SYM_TO_OID.put( SN_id_cct.toLowerCase(), OBJ_id_cct );
        SYM_TO_OID.put( SN_id_ppl.toLowerCase(), OBJ_id_ppl );
        SYM_TO_OID.put( SN_id_ad.toLowerCase(), OBJ_id_ad );
        SYM_TO_OID.put( SN_id_pkix1_explicit_88.toLowerCase(), OBJ_id_pkix1_explicit_88 );
        SYM_TO_OID.put( SN_id_pkix1_implicit_88.toLowerCase(), OBJ_id_pkix1_implicit_88 );
        SYM_TO_OID.put( SN_id_pkix1_explicit_93.toLowerCase(), OBJ_id_pkix1_explicit_93 );
        SYM_TO_OID.put( SN_id_pkix1_implicit_93.toLowerCase(), OBJ_id_pkix1_implicit_93 );
        SYM_TO_OID.put( SN_id_mod_crmf.toLowerCase(), OBJ_id_mod_crmf );
        SYM_TO_OID.put( SN_id_mod_cmc.toLowerCase(), OBJ_id_mod_cmc );
        SYM_TO_OID.put( SN_id_mod_kea_profile_88.toLowerCase(), OBJ_id_mod_kea_profile_88 );
        SYM_TO_OID.put( SN_id_mod_kea_profile_93.toLowerCase(), OBJ_id_mod_kea_profile_93 );
        SYM_TO_OID.put( SN_id_mod_cmp.toLowerCase(), OBJ_id_mod_cmp );
        SYM_TO_OID.put( SN_id_mod_qualified_cert_88.toLowerCase(), OBJ_id_mod_qualified_cert_88 );
        SYM_TO_OID.put( SN_id_mod_qualified_cert_93.toLowerCase(), OBJ_id_mod_qualified_cert_93 );
        SYM_TO_OID.put( SN_id_mod_attribute_cert.toLowerCase(), OBJ_id_mod_attribute_cert );
        SYM_TO_OID.put( SN_id_mod_timestamp_protocol.toLowerCase(), OBJ_id_mod_timestamp_protocol );
        SYM_TO_OID.put( SN_id_mod_ocsp.toLowerCase(), OBJ_id_mod_ocsp );
        SYM_TO_OID.put( SN_id_mod_dvcs.toLowerCase(), OBJ_id_mod_dvcs );
        SYM_TO_OID.put( SN_id_mod_cmp2000.toLowerCase(), OBJ_id_mod_cmp2000 );
        SYM_TO_OID.put( SN_info_access.toLowerCase(), OBJ_info_access );
        SYM_TO_OID.put( LN_info_access.toLowerCase(), OBJ_info_access );
        SYM_TO_OID.put( SN_biometricInfo.toLowerCase(), OBJ_biometricInfo );
        SYM_TO_OID.put( LN_biometricInfo.toLowerCase(), OBJ_biometricInfo );
        SYM_TO_OID.put( SN_qcStatements.toLowerCase(), OBJ_qcStatements );
        SYM_TO_OID.put( SN_ac_auditEntity.toLowerCase(), OBJ_ac_auditEntity );
        SYM_TO_OID.put( SN_ac_targeting.toLowerCase(), OBJ_ac_targeting );
        SYM_TO_OID.put( SN_aaControls.toLowerCase(), OBJ_aaControls );
        SYM_TO_OID.put( SN_sbgp_ipAddrBlock.toLowerCase(), OBJ_sbgp_ipAddrBlock );
        SYM_TO_OID.put( SN_sbgp_autonomousSysNum.toLowerCase(), OBJ_sbgp_autonomousSysNum );
        SYM_TO_OID.put( SN_sbgp_routerIdentifier.toLowerCase(), OBJ_sbgp_routerIdentifier );
        SYM_TO_OID.put( SN_ac_proxying.toLowerCase(), OBJ_ac_proxying );
        SYM_TO_OID.put( SN_sinfo_access.toLowerCase(), OBJ_sinfo_access );
        SYM_TO_OID.put( LN_sinfo_access.toLowerCase(), OBJ_sinfo_access );
        SYM_TO_OID.put( SN_proxyCertInfo.toLowerCase(), OBJ_proxyCertInfo );
        SYM_TO_OID.put( LN_proxyCertInfo.toLowerCase(), OBJ_proxyCertInfo );
        SYM_TO_OID.put( SN_id_qt_cps.toLowerCase(), OBJ_id_qt_cps );
        SYM_TO_OID.put( LN_id_qt_cps.toLowerCase(), OBJ_id_qt_cps );
        SYM_TO_OID.put( SN_id_qt_unotice.toLowerCase(), OBJ_id_qt_unotice );
        SYM_TO_OID.put( LN_id_qt_unotice.toLowerCase(), OBJ_id_qt_unotice );
        SYM_TO_OID.put( SN_textNotice.toLowerCase(), OBJ_textNotice );
        SYM_TO_OID.put( SN_server_auth.toLowerCase(), OBJ_server_auth );
        SYM_TO_OID.put( LN_server_auth.toLowerCase(), OBJ_server_auth );
        SYM_TO_OID.put( SN_client_auth.toLowerCase(), OBJ_client_auth );
        SYM_TO_OID.put( LN_client_auth.toLowerCase(), OBJ_client_auth );
        SYM_TO_OID.put( SN_code_sign.toLowerCase(), OBJ_code_sign );
        SYM_TO_OID.put( LN_code_sign.toLowerCase(), OBJ_code_sign );
        SYM_TO_OID.put( SN_email_protect.toLowerCase(), OBJ_email_protect );
        SYM_TO_OID.put( LN_email_protect.toLowerCase(), OBJ_email_protect );
        SYM_TO_OID.put( SN_ipsecEndSystem.toLowerCase(), OBJ_ipsecEndSystem );
        SYM_TO_OID.put( LN_ipsecEndSystem.toLowerCase(), OBJ_ipsecEndSystem );
        SYM_TO_OID.put( SN_ipsecTunnel.toLowerCase(), OBJ_ipsecTunnel );
        SYM_TO_OID.put( LN_ipsecTunnel.toLowerCase(), OBJ_ipsecTunnel );
        SYM_TO_OID.put( SN_ipsecUser.toLowerCase(), OBJ_ipsecUser );
        SYM_TO_OID.put( LN_ipsecUser.toLowerCase(), OBJ_ipsecUser );
        SYM_TO_OID.put( SN_time_stamp.toLowerCase(), OBJ_time_stamp );
        SYM_TO_OID.put( LN_time_stamp.toLowerCase(), OBJ_time_stamp );
        SYM_TO_OID.put( SN_OCSP_sign.toLowerCase(), OBJ_OCSP_sign );
        SYM_TO_OID.put( LN_OCSP_sign.toLowerCase(), OBJ_OCSP_sign );
        SYM_TO_OID.put( SN_dvcs.toLowerCase(), OBJ_dvcs );
        SYM_TO_OID.put( LN_dvcs.toLowerCase(), OBJ_dvcs );
        SYM_TO_OID.put( SN_id_it_caProtEncCert.toLowerCase(), OBJ_id_it_caProtEncCert );
        SYM_TO_OID.put( SN_id_it_signKeyPairTypes.toLowerCase(), OBJ_id_it_signKeyPairTypes );
        SYM_TO_OID.put( SN_id_it_encKeyPairTypes.toLowerCase(), OBJ_id_it_encKeyPairTypes );
        SYM_TO_OID.put( SN_id_it_preferredSymmAlg.toLowerCase(), OBJ_id_it_preferredSymmAlg );
        SYM_TO_OID.put( SN_id_it_caKeyUpdateInfo.toLowerCase(), OBJ_id_it_caKeyUpdateInfo );
        SYM_TO_OID.put( SN_id_it_currentCRL.toLowerCase(), OBJ_id_it_currentCRL );
        SYM_TO_OID.put( SN_id_it_unsupportedOIDs.toLowerCase(), OBJ_id_it_unsupportedOIDs );
        SYM_TO_OID.put( SN_id_it_subscriptionRequest.toLowerCase(), OBJ_id_it_subscriptionRequest );
        SYM_TO_OID.put( SN_id_it_subscriptionResponse.toLowerCase(), OBJ_id_it_subscriptionResponse );
        SYM_TO_OID.put( SN_id_it_keyPairParamReq.toLowerCase(), OBJ_id_it_keyPairParamReq );
        SYM_TO_OID.put( SN_id_it_keyPairParamRep.toLowerCase(), OBJ_id_it_keyPairParamRep );
        SYM_TO_OID.put( SN_id_it_revPassphrase.toLowerCase(), OBJ_id_it_revPassphrase );
        SYM_TO_OID.put( SN_id_it_implicitConfirm.toLowerCase(), OBJ_id_it_implicitConfirm );
        SYM_TO_OID.put( SN_id_it_confirmWaitTime.toLowerCase(), OBJ_id_it_confirmWaitTime );
        SYM_TO_OID.put( SN_id_it_origPKIMessage.toLowerCase(), OBJ_id_it_origPKIMessage );
        SYM_TO_OID.put( SN_id_it_suppLangTags.toLowerCase(), OBJ_id_it_suppLangTags );
        SYM_TO_OID.put( SN_id_regCtrl.toLowerCase(), OBJ_id_regCtrl );
        SYM_TO_OID.put( SN_id_regInfo.toLowerCase(), OBJ_id_regInfo );
        SYM_TO_OID.put( SN_id_regCtrl_regToken.toLowerCase(), OBJ_id_regCtrl_regToken );
        SYM_TO_OID.put( SN_id_regCtrl_authenticator.toLowerCase(), OBJ_id_regCtrl_authenticator );
        SYM_TO_OID.put( SN_id_regCtrl_pkiPublicationInfo.toLowerCase(), OBJ_id_regCtrl_pkiPublicationInfo );
        SYM_TO_OID.put( SN_id_regCtrl_pkiArchiveOptions.toLowerCase(), OBJ_id_regCtrl_pkiArchiveOptions );
        SYM_TO_OID.put( SN_id_regCtrl_oldCertID.toLowerCase(), OBJ_id_regCtrl_oldCertID );
        SYM_TO_OID.put( SN_id_regCtrl_protocolEncrKey.toLowerCase(), OBJ_id_regCtrl_protocolEncrKey );
        SYM_TO_OID.put( SN_id_regInfo_utf8Pairs.toLowerCase(), OBJ_id_regInfo_utf8Pairs );
        SYM_TO_OID.put( SN_id_regInfo_certReq.toLowerCase(), OBJ_id_regInfo_certReq );
        SYM_TO_OID.put( SN_id_alg_des40.toLowerCase(), OBJ_id_alg_des40 );
        SYM_TO_OID.put( SN_id_alg_noSignature.toLowerCase(), OBJ_id_alg_noSignature );
        SYM_TO_OID.put( SN_id_alg_dh_sig_hmac_sha1.toLowerCase(), OBJ_id_alg_dh_sig_hmac_sha1 );
        SYM_TO_OID.put( SN_id_alg_dh_pop.toLowerCase(), OBJ_id_alg_dh_pop );
        SYM_TO_OID.put( SN_id_cmc_statusInfo.toLowerCase(), OBJ_id_cmc_statusInfo );
        SYM_TO_OID.put( SN_id_cmc_identification.toLowerCase(), OBJ_id_cmc_identification );
        SYM_TO_OID.put( SN_id_cmc_identityProof.toLowerCase(), OBJ_id_cmc_identityProof );
        SYM_TO_OID.put( SN_id_cmc_dataReturn.toLowerCase(), OBJ_id_cmc_dataReturn );
        SYM_TO_OID.put( SN_id_cmc_transactionId.toLowerCase(), OBJ_id_cmc_transactionId );
        SYM_TO_OID.put( SN_id_cmc_senderNonce.toLowerCase(), OBJ_id_cmc_senderNonce );
        SYM_TO_OID.put( SN_id_cmc_recipientNonce.toLowerCase(), OBJ_id_cmc_recipientNonce );
        SYM_TO_OID.put( SN_id_cmc_addExtensions.toLowerCase(), OBJ_id_cmc_addExtensions );
        SYM_TO_OID.put( SN_id_cmc_encryptedPOP.toLowerCase(), OBJ_id_cmc_encryptedPOP );
        SYM_TO_OID.put( SN_id_cmc_decryptedPOP.toLowerCase(), OBJ_id_cmc_decryptedPOP );
        SYM_TO_OID.put( SN_id_cmc_lraPOPWitness.toLowerCase(), OBJ_id_cmc_lraPOPWitness );
        SYM_TO_OID.put( SN_id_cmc_getCert.toLowerCase(), OBJ_id_cmc_getCert );
        SYM_TO_OID.put( SN_id_cmc_getCRL.toLowerCase(), OBJ_id_cmc_getCRL );
        SYM_TO_OID.put( SN_id_cmc_revokeRequest.toLowerCase(), OBJ_id_cmc_revokeRequest );
        SYM_TO_OID.put( SN_id_cmc_regInfo.toLowerCase(), OBJ_id_cmc_regInfo );
        SYM_TO_OID.put( SN_id_cmc_responseInfo.toLowerCase(), OBJ_id_cmc_responseInfo );
        SYM_TO_OID.put( SN_id_cmc_queryPending.toLowerCase(), OBJ_id_cmc_queryPending );
        SYM_TO_OID.put( SN_id_cmc_popLinkRandom.toLowerCase(), OBJ_id_cmc_popLinkRandom );
        SYM_TO_OID.put( SN_id_cmc_popLinkWitness.toLowerCase(), OBJ_id_cmc_popLinkWitness );
        SYM_TO_OID.put( SN_id_cmc_confirmCertAcceptance.toLowerCase(), OBJ_id_cmc_confirmCertAcceptance );
        SYM_TO_OID.put( SN_id_on_personalData.toLowerCase(), OBJ_id_on_personalData );
        SYM_TO_OID.put( SN_id_on_permanentIdentifier.toLowerCase(), OBJ_id_on_permanentIdentifier );
        SYM_TO_OID.put( LN_id_on_permanentIdentifier.toLowerCase(), OBJ_id_on_permanentIdentifier );
        SYM_TO_OID.put( SN_id_pda_dateOfBirth.toLowerCase(), OBJ_id_pda_dateOfBirth );
        SYM_TO_OID.put( SN_id_pda_placeOfBirth.toLowerCase(), OBJ_id_pda_placeOfBirth );
        SYM_TO_OID.put( SN_id_pda_gender.toLowerCase(), OBJ_id_pda_gender );
        SYM_TO_OID.put( SN_id_pda_countryOfCitizenship.toLowerCase(), OBJ_id_pda_countryOfCitizenship );
        SYM_TO_OID.put( SN_id_pda_countryOfResidence.toLowerCase(), OBJ_id_pda_countryOfResidence );
        SYM_TO_OID.put( SN_id_aca_authenticationInfo.toLowerCase(), OBJ_id_aca_authenticationInfo );
        SYM_TO_OID.put( SN_id_aca_accessIdentity.toLowerCase(), OBJ_id_aca_accessIdentity );
        SYM_TO_OID.put( SN_id_aca_chargingIdentity.toLowerCase(), OBJ_id_aca_chargingIdentity );
        SYM_TO_OID.put( SN_id_aca_group.toLowerCase(), OBJ_id_aca_group );
        SYM_TO_OID.put( SN_id_aca_role.toLowerCase(), OBJ_id_aca_role );
        SYM_TO_OID.put( SN_id_aca_encAttrs.toLowerCase(), OBJ_id_aca_encAttrs );
        SYM_TO_OID.put( SN_id_qcs_pkixQCSyntax_v1.toLowerCase(), OBJ_id_qcs_pkixQCSyntax_v1 );
        SYM_TO_OID.put( SN_id_cct_crs.toLowerCase(), OBJ_id_cct_crs );
        SYM_TO_OID.put( SN_id_cct_PKIData.toLowerCase(), OBJ_id_cct_PKIData );
        SYM_TO_OID.put( SN_id_cct_PKIResponse.toLowerCase(), OBJ_id_cct_PKIResponse );
        SYM_TO_OID.put( SN_id_ppl_anyLanguage.toLowerCase(), OBJ_id_ppl_anyLanguage );
        SYM_TO_OID.put( LN_id_ppl_anyLanguage.toLowerCase(), OBJ_id_ppl_anyLanguage );
        SYM_TO_OID.put( SN_id_ppl_inheritAll.toLowerCase(), OBJ_id_ppl_inheritAll );
        SYM_TO_OID.put( LN_id_ppl_inheritAll.toLowerCase(), OBJ_id_ppl_inheritAll );
        SYM_TO_OID.put( SN_Independent.toLowerCase(), OBJ_Independent );
        SYM_TO_OID.put( LN_Independent.toLowerCase(), OBJ_Independent );
        SYM_TO_OID.put( SN_ad_OCSP.toLowerCase(), OBJ_ad_OCSP );
        SYM_TO_OID.put( LN_ad_OCSP.toLowerCase(), OBJ_ad_OCSP );
        SYM_TO_OID.put( SN_ad_ca_issuers.toLowerCase(), OBJ_ad_ca_issuers );
        SYM_TO_OID.put( LN_ad_ca_issuers.toLowerCase(), OBJ_ad_ca_issuers );
        SYM_TO_OID.put( SN_ad_timeStamping.toLowerCase(), OBJ_ad_timeStamping );
        SYM_TO_OID.put( LN_ad_timeStamping.toLowerCase(), OBJ_ad_timeStamping );
        SYM_TO_OID.put( SN_ad_dvcs.toLowerCase(), OBJ_ad_dvcs );
        SYM_TO_OID.put( LN_ad_dvcs.toLowerCase(), OBJ_ad_dvcs );
        SYM_TO_OID.put( SN_caRepository.toLowerCase(), OBJ_caRepository );
        SYM_TO_OID.put( LN_caRepository.toLowerCase(), OBJ_caRepository );
        SYM_TO_OID.put( SN_id_pkix_OCSP_basic.toLowerCase(), OBJ_id_pkix_OCSP_basic );
        SYM_TO_OID.put( LN_id_pkix_OCSP_basic.toLowerCase(), OBJ_id_pkix_OCSP_basic );
        SYM_TO_OID.put( SN_id_pkix_OCSP_Nonce.toLowerCase(), OBJ_id_pkix_OCSP_Nonce );
        SYM_TO_OID.put( LN_id_pkix_OCSP_Nonce.toLowerCase(), OBJ_id_pkix_OCSP_Nonce );
        SYM_TO_OID.put( SN_id_pkix_OCSP_CrlID.toLowerCase(), OBJ_id_pkix_OCSP_CrlID );
        SYM_TO_OID.put( LN_id_pkix_OCSP_CrlID.toLowerCase(), OBJ_id_pkix_OCSP_CrlID );
        SYM_TO_OID.put( SN_id_pkix_OCSP_acceptableResponses.toLowerCase(), OBJ_id_pkix_OCSP_acceptableResponses );
        SYM_TO_OID.put( LN_id_pkix_OCSP_acceptableResponses.toLowerCase(), OBJ_id_pkix_OCSP_acceptableResponses );
        SYM_TO_OID.put( SN_id_pkix_OCSP_noCheck.toLowerCase(), OBJ_id_pkix_OCSP_noCheck );
        SYM_TO_OID.put( LN_id_pkix_OCSP_noCheck.toLowerCase(), OBJ_id_pkix_OCSP_noCheck );
        SYM_TO_OID.put( SN_id_pkix_OCSP_archiveCutoff.toLowerCase(), OBJ_id_pkix_OCSP_archiveCutoff );
        SYM_TO_OID.put( LN_id_pkix_OCSP_archiveCutoff.toLowerCase(), OBJ_id_pkix_OCSP_archiveCutoff );
        SYM_TO_OID.put( SN_id_pkix_OCSP_serviceLocator.toLowerCase(), OBJ_id_pkix_OCSP_serviceLocator );
        SYM_TO_OID.put( LN_id_pkix_OCSP_serviceLocator.toLowerCase(), OBJ_id_pkix_OCSP_serviceLocator );
        SYM_TO_OID.put( SN_id_pkix_OCSP_extendedStatus.toLowerCase(), OBJ_id_pkix_OCSP_extendedStatus );
        SYM_TO_OID.put( LN_id_pkix_OCSP_extendedStatus.toLowerCase(), OBJ_id_pkix_OCSP_extendedStatus );
        SYM_TO_OID.put( SN_id_pkix_OCSP_valid.toLowerCase(), OBJ_id_pkix_OCSP_valid );
        SYM_TO_OID.put( SN_id_pkix_OCSP_path.toLowerCase(), OBJ_id_pkix_OCSP_path );
        SYM_TO_OID.put( SN_id_pkix_OCSP_trustRoot.toLowerCase(), OBJ_id_pkix_OCSP_trustRoot );
        SYM_TO_OID.put( LN_id_pkix_OCSP_trustRoot.toLowerCase(), OBJ_id_pkix_OCSP_trustRoot );
        SYM_TO_OID.put( SN_algorithm.toLowerCase(), OBJ_algorithm );
        SYM_TO_OID.put( LN_algorithm.toLowerCase(), OBJ_algorithm );
        SYM_TO_OID.put( SN_md5WithRSA.toLowerCase(), OBJ_md5WithRSA );
        SYM_TO_OID.put( LN_md5WithRSA.toLowerCase(), OBJ_md5WithRSA );
        SYM_TO_OID.put( SN_des_ecb.toLowerCase(), OBJ_des_ecb );
        SYM_TO_OID.put( LN_des_ecb.toLowerCase(), OBJ_des_ecb );
        SYM_TO_OID.put( SN_des_cbc.toLowerCase(), OBJ_des_cbc );
        SYM_TO_OID.put( LN_des_cbc.toLowerCase(), OBJ_des_cbc );
        SYM_TO_OID.put( SN_des_ofb64.toLowerCase(), OBJ_des_ofb64 );
        SYM_TO_OID.put( LN_des_ofb64.toLowerCase(), OBJ_des_ofb64 );
        SYM_TO_OID.put( SN_des_cfb64.toLowerCase(), OBJ_des_cfb64 );
        SYM_TO_OID.put( LN_des_cfb64.toLowerCase(), OBJ_des_cfb64 );
        SYM_TO_OID.put( SN_rsaSignature.toLowerCase(), OBJ_rsaSignature );
        SYM_TO_OID.put( SN_dsa_2.toLowerCase(), OBJ_dsa_2 );
        SYM_TO_OID.put( LN_dsa_2.toLowerCase(), OBJ_dsa_2 );
        SYM_TO_OID.put( SN_dsaWithSHA.toLowerCase(), OBJ_dsaWithSHA );
        SYM_TO_OID.put( LN_dsaWithSHA.toLowerCase(), OBJ_dsaWithSHA );
        SYM_TO_OID.put( SN_shaWithRSAEncryption.toLowerCase(), OBJ_shaWithRSAEncryption );
        SYM_TO_OID.put( LN_shaWithRSAEncryption.toLowerCase(), OBJ_shaWithRSAEncryption );
        SYM_TO_OID.put( SN_des_ede_ecb.toLowerCase(), OBJ_des_ede_ecb );
        SYM_TO_OID.put( LN_des_ede_ecb.toLowerCase(), OBJ_des_ede_ecb );
        SYM_TO_OID.put( SN_sha.toLowerCase(), OBJ_sha );
        SYM_TO_OID.put( LN_sha.toLowerCase(), OBJ_sha );
        SYM_TO_OID.put( SN_sha1.toLowerCase(), OBJ_sha1 );
        SYM_TO_OID.put( LN_sha1.toLowerCase(), OBJ_sha1 );
        SYM_TO_OID.put( SN_dsaWithSHA1_2.toLowerCase(), OBJ_dsaWithSHA1_2 );
        SYM_TO_OID.put( LN_dsaWithSHA1_2.toLowerCase(), OBJ_dsaWithSHA1_2 );
        SYM_TO_OID.put( SN_sha1WithRSA.toLowerCase(), OBJ_sha1WithRSA );
        SYM_TO_OID.put( LN_sha1WithRSA.toLowerCase(), OBJ_sha1WithRSA );
        SYM_TO_OID.put( SN_ripemd160.toLowerCase(), OBJ_ripemd160 );
        SYM_TO_OID.put( LN_ripemd160.toLowerCase(), OBJ_ripemd160 );
        SYM_TO_OID.put( SN_ripemd160WithRSA.toLowerCase(), OBJ_ripemd160WithRSA );
        SYM_TO_OID.put( LN_ripemd160WithRSA.toLowerCase(), OBJ_ripemd160WithRSA );
        SYM_TO_OID.put( SN_sxnet.toLowerCase(), OBJ_sxnet );
        SYM_TO_OID.put( LN_sxnet.toLowerCase(), OBJ_sxnet );
        SYM_TO_OID.put( SN_X500.toLowerCase(), OBJ_X500 );
        SYM_TO_OID.put( LN_X500.toLowerCase(), OBJ_X500 );
        SYM_TO_OID.put( SN_X509.toLowerCase(), OBJ_X509 );
        SYM_TO_OID.put( SN_commonName.toLowerCase(), OBJ_commonName );
        SYM_TO_OID.put( LN_commonName.toLowerCase(), OBJ_commonName );
        SYM_TO_OID.put( SN_surname.toLowerCase(), OBJ_surname );
        SYM_TO_OID.put( LN_surname.toLowerCase(), OBJ_surname );
        SYM_TO_OID.put( LN_serialNumber.toLowerCase(), OBJ_serialNumber );
        SYM_TO_OID.put( SN_countryName.toLowerCase(), OBJ_countryName );
        SYM_TO_OID.put( LN_countryName.toLowerCase(), OBJ_countryName );
        SYM_TO_OID.put( SN_localityName.toLowerCase(), OBJ_localityName );
        SYM_TO_OID.put( LN_localityName.toLowerCase(), OBJ_localityName );
        SYM_TO_OID.put( SN_stateOrProvinceName.toLowerCase(), OBJ_stateOrProvinceName );
        SYM_TO_OID.put( LN_stateOrProvinceName.toLowerCase(), OBJ_stateOrProvinceName );
        SYM_TO_OID.put( SN_streetAddress.toLowerCase(), OBJ_streetAddress );
        SYM_TO_OID.put( LN_streetAddress.toLowerCase(), OBJ_streetAddress );
        SYM_TO_OID.put( SN_organizationName.toLowerCase(), OBJ_organizationName );
        SYM_TO_OID.put( LN_organizationName.toLowerCase(), OBJ_organizationName );
        SYM_TO_OID.put( SN_organizationalUnitName.toLowerCase(), OBJ_organizationalUnitName );
        SYM_TO_OID.put( LN_organizationalUnitName.toLowerCase(), OBJ_organizationalUnitName );
        SYM_TO_OID.put( SN_title.toLowerCase(), OBJ_title );
        SYM_TO_OID.put( LN_title.toLowerCase(), OBJ_title );
        SYM_TO_OID.put( LN_description.toLowerCase(), OBJ_description );
        SYM_TO_OID.put( LN_searchGuide.toLowerCase(), OBJ_searchGuide );
        SYM_TO_OID.put( LN_businessCategory.toLowerCase(), OBJ_businessCategory );
        SYM_TO_OID.put( LN_postalAddress.toLowerCase(), OBJ_postalAddress );
        SYM_TO_OID.put( LN_postalCode.toLowerCase(), OBJ_postalCode );
        SYM_TO_OID.put( LN_postOfficeBox.toLowerCase(), OBJ_postOfficeBox );
        SYM_TO_OID.put( LN_physicalDeliveryOfficeName.toLowerCase(), OBJ_physicalDeliveryOfficeName );
        SYM_TO_OID.put( LN_telephoneNumber.toLowerCase(), OBJ_telephoneNumber );
        SYM_TO_OID.put( LN_telexNumber.toLowerCase(), OBJ_telexNumber );
        SYM_TO_OID.put( LN_teletexTerminalIdentifier.toLowerCase(), OBJ_teletexTerminalIdentifier );
        SYM_TO_OID.put( LN_facsimileTelephoneNumber.toLowerCase(), OBJ_facsimileTelephoneNumber );
        SYM_TO_OID.put( LN_x121Address.toLowerCase(), OBJ_x121Address );
        SYM_TO_OID.put( LN_internationaliSDNNumber.toLowerCase(), OBJ_internationaliSDNNumber );
        SYM_TO_OID.put( LN_registeredAddress.toLowerCase(), OBJ_registeredAddress );
        SYM_TO_OID.put( LN_destinationIndicator.toLowerCase(), OBJ_destinationIndicator );
        SYM_TO_OID.put( LN_preferredDeliveryMethod.toLowerCase(), OBJ_preferredDeliveryMethod );
        SYM_TO_OID.put( LN_presentationAddress.toLowerCase(), OBJ_presentationAddress );
        SYM_TO_OID.put( LN_supportedApplicationContext.toLowerCase(), OBJ_supportedApplicationContext );
        SYM_TO_OID.put( SN_member.toLowerCase(), OBJ_member );
        SYM_TO_OID.put( SN_owner.toLowerCase(), OBJ_owner );
        SYM_TO_OID.put( LN_roleOccupant.toLowerCase(), OBJ_roleOccupant );
        SYM_TO_OID.put( SN_seeAlso.toLowerCase(), OBJ_seeAlso );
        SYM_TO_OID.put( LN_userPassword.toLowerCase(), OBJ_userPassword );
        SYM_TO_OID.put( LN_userCertificate.toLowerCase(), OBJ_userCertificate );
        SYM_TO_OID.put( LN_cACertificate.toLowerCase(), OBJ_cACertificate );
        SYM_TO_OID.put( LN_authorityRevocationList.toLowerCase(), OBJ_authorityRevocationList );
        SYM_TO_OID.put( LN_certificateRevocationList.toLowerCase(), OBJ_certificateRevocationList );
        SYM_TO_OID.put( LN_crossCertificatePair.toLowerCase(), OBJ_crossCertificatePair );
        SYM_TO_OID.put( SN_name.toLowerCase(), OBJ_name );
        SYM_TO_OID.put( LN_name.toLowerCase(), OBJ_name );
        SYM_TO_OID.put( SN_givenName.toLowerCase(), OBJ_givenName );
        SYM_TO_OID.put( LN_givenName.toLowerCase(), OBJ_givenName );
        SYM_TO_OID.put( SN_initials.toLowerCase(), OBJ_initials );
        SYM_TO_OID.put( LN_initials.toLowerCase(), OBJ_initials );
        SYM_TO_OID.put( LN_generationQualifier.toLowerCase(), OBJ_generationQualifier );
        SYM_TO_OID.put( LN_x500UniqueIdentifier.toLowerCase(), OBJ_x500UniqueIdentifier );
        SYM_TO_OID.put( SN_dnQualifier.toLowerCase(), OBJ_dnQualifier );
        SYM_TO_OID.put( LN_dnQualifier.toLowerCase(), OBJ_dnQualifier );
        SYM_TO_OID.put( LN_enhancedSearchGuide.toLowerCase(), OBJ_enhancedSearchGuide );
        SYM_TO_OID.put( LN_protocolInformation.toLowerCase(), OBJ_protocolInformation );
        SYM_TO_OID.put( LN_distinguishedName.toLowerCase(), OBJ_distinguishedName );
        SYM_TO_OID.put( LN_uniqueMember.toLowerCase(), OBJ_uniqueMember );
        SYM_TO_OID.put( LN_houseIdentifier.toLowerCase(), OBJ_houseIdentifier );
        SYM_TO_OID.put( LN_supportedAlgorithms.toLowerCase(), OBJ_supportedAlgorithms );
        SYM_TO_OID.put( LN_deltaRevocationList.toLowerCase(), OBJ_deltaRevocationList );
        SYM_TO_OID.put( SN_dmdName.toLowerCase(), OBJ_dmdName );
        SYM_TO_OID.put( LN_pseudonym.toLowerCase(), OBJ_pseudonym );
        SYM_TO_OID.put( SN_role.toLowerCase(), OBJ_role );
        SYM_TO_OID.put( LN_role.toLowerCase(), OBJ_role );
        SYM_TO_OID.put( SN_X500algorithms.toLowerCase(), OBJ_X500algorithms );
        SYM_TO_OID.put( LN_X500algorithms.toLowerCase(), OBJ_X500algorithms );
        SYM_TO_OID.put( SN_rsa.toLowerCase(), OBJ_rsa );
        SYM_TO_OID.put( LN_rsa.toLowerCase(), OBJ_rsa );
        SYM_TO_OID.put( SN_mdc2WithRSA.toLowerCase(), OBJ_mdc2WithRSA );
        SYM_TO_OID.put( LN_mdc2WithRSA.toLowerCase(), OBJ_mdc2WithRSA );
        SYM_TO_OID.put( SN_mdc2.toLowerCase(), OBJ_mdc2 );
        SYM_TO_OID.put( LN_mdc2.toLowerCase(), OBJ_mdc2 );
        SYM_TO_OID.put( SN_id_ce.toLowerCase(), OBJ_id_ce );
        SYM_TO_OID.put( SN_subject_directory_attributes.toLowerCase(), OBJ_subject_directory_attributes );
        SYM_TO_OID.put( LN_subject_directory_attributes.toLowerCase(), OBJ_subject_directory_attributes );
        SYM_TO_OID.put( SN_subject_key_identifier.toLowerCase(), OBJ_subject_key_identifier );
        SYM_TO_OID.put( LN_subject_key_identifier.toLowerCase(), OBJ_subject_key_identifier );
        SYM_TO_OID.put( SN_key_usage.toLowerCase(), OBJ_key_usage );
        SYM_TO_OID.put( LN_key_usage.toLowerCase(), OBJ_key_usage );
        SYM_TO_OID.put( SN_private_key_usage_period.toLowerCase(), OBJ_private_key_usage_period );
        SYM_TO_OID.put( LN_private_key_usage_period.toLowerCase(), OBJ_private_key_usage_period );
        SYM_TO_OID.put( SN_subject_alt_name.toLowerCase(), OBJ_subject_alt_name );
        SYM_TO_OID.put( LN_subject_alt_name.toLowerCase(), OBJ_subject_alt_name );
        SYM_TO_OID.put( SN_issuer_alt_name.toLowerCase(), OBJ_issuer_alt_name );
        SYM_TO_OID.put( LN_issuer_alt_name.toLowerCase(), OBJ_issuer_alt_name );
        SYM_TO_OID.put( SN_basic_constraints.toLowerCase(), OBJ_basic_constraints );
        SYM_TO_OID.put( LN_basic_constraints.toLowerCase(), OBJ_basic_constraints );
        SYM_TO_OID.put( SN_crl_number.toLowerCase(), OBJ_crl_number );
        SYM_TO_OID.put( LN_crl_number.toLowerCase(), OBJ_crl_number );
        SYM_TO_OID.put( SN_crl_reason.toLowerCase(), OBJ_crl_reason );
        SYM_TO_OID.put( LN_crl_reason.toLowerCase(), OBJ_crl_reason );
        SYM_TO_OID.put( SN_invalidity_date.toLowerCase(), OBJ_invalidity_date );
        SYM_TO_OID.put( LN_invalidity_date.toLowerCase(), OBJ_invalidity_date );
        SYM_TO_OID.put( SN_delta_crl.toLowerCase(), OBJ_delta_crl );
        SYM_TO_OID.put( LN_delta_crl.toLowerCase(), OBJ_delta_crl );
        SYM_TO_OID.put( SN_issuing_distribution_point.toLowerCase(), OBJ_issuing_distribution_point );
        SYM_TO_OID.put( LN_issuing_distribution_point.toLowerCase(), OBJ_issuing_distribution_point );
        SYM_TO_OID.put( SN_certificate_issuer.toLowerCase(), OBJ_certificate_issuer );
        SYM_TO_OID.put( LN_certificate_issuer.toLowerCase(), OBJ_certificate_issuer );
        SYM_TO_OID.put( SN_name_constraints.toLowerCase(), OBJ_name_constraints );
        SYM_TO_OID.put( LN_name_constraints.toLowerCase(), OBJ_name_constraints );
        SYM_TO_OID.put( SN_crl_distribution_points.toLowerCase(), OBJ_crl_distribution_points );
        SYM_TO_OID.put( LN_crl_distribution_points.toLowerCase(), OBJ_crl_distribution_points );
        SYM_TO_OID.put( SN_certificate_policies.toLowerCase(), OBJ_certificate_policies );
        SYM_TO_OID.put( LN_certificate_policies.toLowerCase(), OBJ_certificate_policies );
        SYM_TO_OID.put( SN_any_policy.toLowerCase(), OBJ_any_policy );
        SYM_TO_OID.put( LN_any_policy.toLowerCase(), OBJ_any_policy );
        SYM_TO_OID.put( SN_policy_mappings.toLowerCase(), OBJ_policy_mappings );
        SYM_TO_OID.put( LN_policy_mappings.toLowerCase(), OBJ_policy_mappings );
        SYM_TO_OID.put( SN_authority_key_identifier.toLowerCase(), OBJ_authority_key_identifier );
        SYM_TO_OID.put( LN_authority_key_identifier.toLowerCase(), OBJ_authority_key_identifier );
        SYM_TO_OID.put( SN_policy_constraints.toLowerCase(), OBJ_policy_constraints );
        SYM_TO_OID.put( LN_policy_constraints.toLowerCase(), OBJ_policy_constraints );
        SYM_TO_OID.put( SN_ext_key_usage.toLowerCase(), OBJ_ext_key_usage );
        SYM_TO_OID.put( LN_ext_key_usage.toLowerCase(), OBJ_ext_key_usage );
        SYM_TO_OID.put( SN_freshest_crl.toLowerCase(), OBJ_freshest_crl );
        SYM_TO_OID.put( LN_freshest_crl.toLowerCase(), OBJ_freshest_crl );
        SYM_TO_OID.put( SN_inhibit_any_policy.toLowerCase(), OBJ_inhibit_any_policy );
        SYM_TO_OID.put( LN_inhibit_any_policy.toLowerCase(), OBJ_inhibit_any_policy );
        SYM_TO_OID.put( SN_target_information.toLowerCase(), OBJ_target_information );
        SYM_TO_OID.put( LN_target_information.toLowerCase(), OBJ_target_information );
        SYM_TO_OID.put( SN_no_rev_avail.toLowerCase(), OBJ_no_rev_avail );
        SYM_TO_OID.put( LN_no_rev_avail.toLowerCase(), OBJ_no_rev_avail );
        SYM_TO_OID.put( SN_anyExtendedKeyUsage.toLowerCase(), OBJ_anyExtendedKeyUsage );
        SYM_TO_OID.put( LN_anyExtendedKeyUsage.toLowerCase(), OBJ_anyExtendedKeyUsage );
        SYM_TO_OID.put( SN_netscape.toLowerCase(), OBJ_netscape );
        SYM_TO_OID.put( LN_netscape.toLowerCase(), OBJ_netscape );
        SYM_TO_OID.put( SN_netscape_cert_extension.toLowerCase(), OBJ_netscape_cert_extension );
        SYM_TO_OID.put( LN_netscape_cert_extension.toLowerCase(), OBJ_netscape_cert_extension );
        SYM_TO_OID.put( SN_netscape_data_type.toLowerCase(), OBJ_netscape_data_type );
        SYM_TO_OID.put( LN_netscape_data_type.toLowerCase(), OBJ_netscape_data_type );
        SYM_TO_OID.put( SN_netscape_cert_type.toLowerCase(), OBJ_netscape_cert_type );
        SYM_TO_OID.put( LN_netscape_cert_type.toLowerCase(), OBJ_netscape_cert_type );
        SYM_TO_OID.put( SN_netscape_base_url.toLowerCase(), OBJ_netscape_base_url );
        SYM_TO_OID.put( LN_netscape_base_url.toLowerCase(), OBJ_netscape_base_url );
        SYM_TO_OID.put( SN_netscape_revocation_url.toLowerCase(), OBJ_netscape_revocation_url );
        SYM_TO_OID.put( LN_netscape_revocation_url.toLowerCase(), OBJ_netscape_revocation_url );
        SYM_TO_OID.put( SN_netscape_ca_revocation_url.toLowerCase(), OBJ_netscape_ca_revocation_url );
        SYM_TO_OID.put( LN_netscape_ca_revocation_url.toLowerCase(), OBJ_netscape_ca_revocation_url );
        SYM_TO_OID.put( SN_netscape_renewal_url.toLowerCase(), OBJ_netscape_renewal_url );
        SYM_TO_OID.put( LN_netscape_renewal_url.toLowerCase(), OBJ_netscape_renewal_url );
        SYM_TO_OID.put( SN_netscape_ca_policy_url.toLowerCase(), OBJ_netscape_ca_policy_url );
        SYM_TO_OID.put( LN_netscape_ca_policy_url.toLowerCase(), OBJ_netscape_ca_policy_url );
        SYM_TO_OID.put( SN_netscape_ssl_server_name.toLowerCase(), OBJ_netscape_ssl_server_name );
        SYM_TO_OID.put( LN_netscape_ssl_server_name.toLowerCase(), OBJ_netscape_ssl_server_name );
        SYM_TO_OID.put( SN_netscape_comment.toLowerCase(), OBJ_netscape_comment );
        SYM_TO_OID.put( LN_netscape_comment.toLowerCase(), OBJ_netscape_comment );
        SYM_TO_OID.put( SN_netscape_cert_sequence.toLowerCase(), OBJ_netscape_cert_sequence );
        SYM_TO_OID.put( LN_netscape_cert_sequence.toLowerCase(), OBJ_netscape_cert_sequence );
        SYM_TO_OID.put( SN_ns_sgc.toLowerCase(), OBJ_ns_sgc );
        SYM_TO_OID.put( LN_ns_sgc.toLowerCase(), OBJ_ns_sgc );
        SYM_TO_OID.put( SN_org.toLowerCase(), OBJ_org );
        SYM_TO_OID.put( LN_org.toLowerCase(), OBJ_org );
        SYM_TO_OID.put( SN_dod.toLowerCase(), OBJ_dod );
        SYM_TO_OID.put( LN_dod.toLowerCase(), OBJ_dod );
        SYM_TO_OID.put( SN_iana.toLowerCase(), OBJ_iana );
        SYM_TO_OID.put( LN_iana.toLowerCase(), OBJ_iana );
        SYM_TO_OID.put( SN_Directory.toLowerCase(), OBJ_Directory );
        SYM_TO_OID.put( LN_Directory.toLowerCase(), OBJ_Directory );
        SYM_TO_OID.put( SN_Management.toLowerCase(), OBJ_Management );
        SYM_TO_OID.put( LN_Management.toLowerCase(), OBJ_Management );
        SYM_TO_OID.put( SN_Experimental.toLowerCase(), OBJ_Experimental );
        SYM_TO_OID.put( LN_Experimental.toLowerCase(), OBJ_Experimental );
        SYM_TO_OID.put( SN_Private.toLowerCase(), OBJ_Private );
        SYM_TO_OID.put( LN_Private.toLowerCase(), OBJ_Private );
        SYM_TO_OID.put( SN_Security.toLowerCase(), OBJ_Security );
        SYM_TO_OID.put( LN_Security.toLowerCase(), OBJ_Security );
        SYM_TO_OID.put( SN_SNMPv2.toLowerCase(), OBJ_SNMPv2 );
        SYM_TO_OID.put( LN_SNMPv2.toLowerCase(), OBJ_SNMPv2 );
        SYM_TO_OID.put( LN_Mail.toLowerCase(), OBJ_Mail );
        SYM_TO_OID.put( SN_Enterprises.toLowerCase(), OBJ_Enterprises );
        SYM_TO_OID.put( LN_Enterprises.toLowerCase(), OBJ_Enterprises );
        SYM_TO_OID.put( SN_dcObject.toLowerCase(), OBJ_dcObject );
        SYM_TO_OID.put( LN_dcObject.toLowerCase(), OBJ_dcObject );
        SYM_TO_OID.put( SN_mime_mhs.toLowerCase(), OBJ_mime_mhs );
        SYM_TO_OID.put( LN_mime_mhs.toLowerCase(), OBJ_mime_mhs );
        SYM_TO_OID.put( SN_mime_mhs_headings.toLowerCase(), OBJ_mime_mhs_headings );
        SYM_TO_OID.put( LN_mime_mhs_headings.toLowerCase(), OBJ_mime_mhs_headings );
        SYM_TO_OID.put( SN_mime_mhs_bodies.toLowerCase(), OBJ_mime_mhs_bodies );
        SYM_TO_OID.put( LN_mime_mhs_bodies.toLowerCase(), OBJ_mime_mhs_bodies );
        SYM_TO_OID.put( SN_id_hex_partial_message.toLowerCase(), OBJ_id_hex_partial_message );
        SYM_TO_OID.put( LN_id_hex_partial_message.toLowerCase(), OBJ_id_hex_partial_message );
        SYM_TO_OID.put( SN_id_hex_multipart_message.toLowerCase(), OBJ_id_hex_multipart_message );
        SYM_TO_OID.put( LN_id_hex_multipart_message.toLowerCase(), OBJ_id_hex_multipart_message );
        SYM_TO_OID.put( SN_rle_compression.toLowerCase(), OBJ_rle_compression );
        SYM_TO_OID.put( LN_rle_compression.toLowerCase(), OBJ_rle_compression );
        SYM_TO_OID.put( SN_zlib_compression.toLowerCase(), OBJ_zlib_compression );
        SYM_TO_OID.put( LN_zlib_compression.toLowerCase(), OBJ_zlib_compression );
        SYM_TO_OID.put( SN_aes_128_ecb.toLowerCase(), OBJ_aes_128_ecb );
        SYM_TO_OID.put( LN_aes_128_ecb.toLowerCase(), OBJ_aes_128_ecb );
        SYM_TO_OID.put( SN_aes_128_cbc.toLowerCase(), OBJ_aes_128_cbc );
        SYM_TO_OID.put( LN_aes_128_cbc.toLowerCase(), OBJ_aes_128_cbc );
        SYM_TO_OID.put( SN_aes_128_ofb128.toLowerCase(), OBJ_aes_128_ofb128 );
        SYM_TO_OID.put( LN_aes_128_ofb128.toLowerCase(), OBJ_aes_128_ofb128 );
        SYM_TO_OID.put( SN_aes_128_cfb128.toLowerCase(), OBJ_aes_128_cfb128 );
        SYM_TO_OID.put( LN_aes_128_cfb128.toLowerCase(), OBJ_aes_128_cfb128 );
        SYM_TO_OID.put( SN_id_aes128_wrap.toLowerCase(), OBJ_id_aes128_wrap );
        SYM_TO_OID.put( SN_aes_128_gcm.toLowerCase(), OBJ_aes_128_gcm );
        SYM_TO_OID.put( LN_aes_128_gcm.toLowerCase(), OBJ_aes_128_gcm );
        SYM_TO_OID.put( SN_aes_128_ccm.toLowerCase(), OBJ_aes_128_ccm );
        SYM_TO_OID.put( LN_aes_128_ccm.toLowerCase(), OBJ_aes_128_ccm );
        SYM_TO_OID.put( SN_id_aes128_wrap_pad.toLowerCase(), OBJ_id_aes128_wrap_pad );
        SYM_TO_OID.put( SN_aes_192_ecb.toLowerCase(), OBJ_aes_192_ecb );
        SYM_TO_OID.put( LN_aes_192_ecb.toLowerCase(), OBJ_aes_192_ecb );
        SYM_TO_OID.put( SN_aes_192_cbc.toLowerCase(), OBJ_aes_192_cbc );
        SYM_TO_OID.put( LN_aes_192_cbc.toLowerCase(), OBJ_aes_192_cbc );
        SYM_TO_OID.put( SN_aes_192_ofb128.toLowerCase(), OBJ_aes_192_ofb128 );
        SYM_TO_OID.put( LN_aes_192_ofb128.toLowerCase(), OBJ_aes_192_ofb128 );
        SYM_TO_OID.put( SN_aes_192_cfb128.toLowerCase(), OBJ_aes_192_cfb128 );
        SYM_TO_OID.put( LN_aes_192_cfb128.toLowerCase(), OBJ_aes_192_cfb128 );
        SYM_TO_OID.put( SN_id_aes192_wrap.toLowerCase(), OBJ_id_aes192_wrap );
        SYM_TO_OID.put( SN_aes_192_gcm.toLowerCase(), OBJ_aes_192_gcm );
        SYM_TO_OID.put( LN_aes_192_gcm.toLowerCase(), OBJ_aes_192_gcm );
        SYM_TO_OID.put( SN_aes_192_ccm.toLowerCase(), OBJ_aes_192_ccm );
        SYM_TO_OID.put( LN_aes_192_ccm.toLowerCase(), OBJ_aes_192_ccm );
        SYM_TO_OID.put( SN_id_aes192_wrap_pad.toLowerCase(), OBJ_id_aes192_wrap_pad );
        SYM_TO_OID.put( SN_aes_256_ecb.toLowerCase(), OBJ_aes_256_ecb );
        SYM_TO_OID.put( LN_aes_256_ecb.toLowerCase(), OBJ_aes_256_ecb );
        SYM_TO_OID.put( SN_aes_256_cbc.toLowerCase(), OBJ_aes_256_cbc );
        SYM_TO_OID.put( LN_aes_256_cbc.toLowerCase(), OBJ_aes_256_cbc );
        SYM_TO_OID.put( SN_aes_256_ofb128.toLowerCase(), OBJ_aes_256_ofb128 );
        SYM_TO_OID.put( LN_aes_256_ofb128.toLowerCase(), OBJ_aes_256_ofb128 );
        SYM_TO_OID.put( SN_aes_256_cfb128.toLowerCase(), OBJ_aes_256_cfb128 );
        SYM_TO_OID.put( LN_aes_256_cfb128.toLowerCase(), OBJ_aes_256_cfb128 );
        SYM_TO_OID.put( SN_id_aes256_wrap.toLowerCase(), OBJ_id_aes256_wrap );
        SYM_TO_OID.put( SN_aes_256_gcm.toLowerCase(), OBJ_aes_256_gcm );
        SYM_TO_OID.put( LN_aes_256_gcm.toLowerCase(), OBJ_aes_256_gcm );
        SYM_TO_OID.put( SN_aes_256_ccm.toLowerCase(), OBJ_aes_256_ccm );
        SYM_TO_OID.put( LN_aes_256_ccm.toLowerCase(), OBJ_aes_256_ccm );
        SYM_TO_OID.put( SN_id_aes256_wrap_pad.toLowerCase(), OBJ_id_aes256_wrap_pad );
        SYM_TO_OID.put( SN_sha256.toLowerCase(), OBJ_sha256 );
        SYM_TO_OID.put( LN_sha256.toLowerCase(), OBJ_sha256 );
        SYM_TO_OID.put( SN_sha384.toLowerCase(), OBJ_sha384 );
        SYM_TO_OID.put( LN_sha384.toLowerCase(), OBJ_sha384 );
        SYM_TO_OID.put( SN_sha512.toLowerCase(), OBJ_sha512 );
        SYM_TO_OID.put( LN_sha512.toLowerCase(), OBJ_sha512 );
        SYM_TO_OID.put( SN_sha224.toLowerCase(), OBJ_sha224 );
        SYM_TO_OID.put( LN_sha224.toLowerCase(), OBJ_sha224 );
        SYM_TO_OID.put( SN_dsa_with_SHA224.toLowerCase(), OBJ_dsa_with_SHA224 );
        SYM_TO_OID.put( SN_dsa_with_SHA256.toLowerCase(), OBJ_dsa_with_SHA256 );
        SYM_TO_OID.put( SN_hold_instruction_code.toLowerCase(), OBJ_hold_instruction_code );
        SYM_TO_OID.put( LN_hold_instruction_code.toLowerCase(), OBJ_hold_instruction_code );
        SYM_TO_OID.put( SN_hold_instruction_none.toLowerCase(), OBJ_hold_instruction_none );
        SYM_TO_OID.put( LN_hold_instruction_none.toLowerCase(), OBJ_hold_instruction_none );
        SYM_TO_OID.put( SN_hold_instruction_call_issuer.toLowerCase(), OBJ_hold_instruction_call_issuer );
        SYM_TO_OID.put( LN_hold_instruction_call_issuer.toLowerCase(), OBJ_hold_instruction_call_issuer );
        SYM_TO_OID.put( SN_hold_instruction_reject.toLowerCase(), OBJ_hold_instruction_reject );
        SYM_TO_OID.put( LN_hold_instruction_reject.toLowerCase(), OBJ_hold_instruction_reject );
        SYM_TO_OID.put( SN_data.toLowerCase(), OBJ_data );
        SYM_TO_OID.put( SN_pss.toLowerCase(), OBJ_pss );
        SYM_TO_OID.put( SN_ucl.toLowerCase(), OBJ_ucl );
        SYM_TO_OID.put( SN_pilot.toLowerCase(), OBJ_pilot );
        SYM_TO_OID.put( LN_pilotAttributeType.toLowerCase(), OBJ_pilotAttributeType );
        SYM_TO_OID.put( LN_pilotAttributeSyntax.toLowerCase(), OBJ_pilotAttributeSyntax );
        SYM_TO_OID.put( LN_pilotObjectClass.toLowerCase(), OBJ_pilotObjectClass );
        SYM_TO_OID.put( LN_pilotGroups.toLowerCase(), OBJ_pilotGroups );
        SYM_TO_OID.put( LN_iA5StringSyntax.toLowerCase(), OBJ_iA5StringSyntax );
        SYM_TO_OID.put( LN_caseIgnoreIA5StringSyntax.toLowerCase(), OBJ_caseIgnoreIA5StringSyntax );
        SYM_TO_OID.put( LN_pilotObject.toLowerCase(), OBJ_pilotObject );
        SYM_TO_OID.put( LN_pilotPerson.toLowerCase(), OBJ_pilotPerson );
        SYM_TO_OID.put( SN_account.toLowerCase(), OBJ_account );
        SYM_TO_OID.put( SN_document.toLowerCase(), OBJ_document );
        SYM_TO_OID.put( SN_room.toLowerCase(), OBJ_room );
        SYM_TO_OID.put( LN_documentSeries.toLowerCase(), OBJ_documentSeries );
        SYM_TO_OID.put( SN_Domain.toLowerCase(), OBJ_Domain );
        SYM_TO_OID.put( LN_Domain.toLowerCase(), OBJ_Domain );
        SYM_TO_OID.put( LN_rFC822localPart.toLowerCase(), OBJ_rFC822localPart );
        SYM_TO_OID.put( LN_dNSDomain.toLowerCase(), OBJ_dNSDomain );
        SYM_TO_OID.put( LN_domainRelatedObject.toLowerCase(), OBJ_domainRelatedObject );
        SYM_TO_OID.put( LN_friendlyCountry.toLowerCase(), OBJ_friendlyCountry );
        SYM_TO_OID.put( LN_simpleSecurityObject.toLowerCase(), OBJ_simpleSecurityObject );
        SYM_TO_OID.put( LN_pilotOrganization.toLowerCase(), OBJ_pilotOrganization );
        SYM_TO_OID.put( LN_pilotDSA.toLowerCase(), OBJ_pilotDSA );
        SYM_TO_OID.put( LN_qualityLabelledData.toLowerCase(), OBJ_qualityLabelledData );
        SYM_TO_OID.put( SN_userId.toLowerCase(), OBJ_userId );
        SYM_TO_OID.put( LN_userId.toLowerCase(), OBJ_userId );
        SYM_TO_OID.put( LN_textEncodedORAddress.toLowerCase(), OBJ_textEncodedORAddress );
        SYM_TO_OID.put( SN_rfc822Mailbox.toLowerCase(), OBJ_rfc822Mailbox );
        SYM_TO_OID.put( LN_rfc822Mailbox.toLowerCase(), OBJ_rfc822Mailbox );
        SYM_TO_OID.put( SN_info.toLowerCase(), OBJ_info );
        SYM_TO_OID.put( LN_favouriteDrink.toLowerCase(), OBJ_favouriteDrink );
        SYM_TO_OID.put( LN_roomNumber.toLowerCase(), OBJ_roomNumber );
        SYM_TO_OID.put( SN_photo.toLowerCase(), OBJ_photo );
        SYM_TO_OID.put( LN_userClass.toLowerCase(), OBJ_userClass );
        SYM_TO_OID.put( SN_host.toLowerCase(), OBJ_host );
        SYM_TO_OID.put( SN_manager.toLowerCase(), OBJ_manager );
        SYM_TO_OID.put( LN_documentIdentifier.toLowerCase(), OBJ_documentIdentifier );
        SYM_TO_OID.put( LN_documentTitle.toLowerCase(), OBJ_documentTitle );
        SYM_TO_OID.put( LN_documentVersion.toLowerCase(), OBJ_documentVersion );
        SYM_TO_OID.put( LN_documentAuthor.toLowerCase(), OBJ_documentAuthor );
        SYM_TO_OID.put( LN_documentLocation.toLowerCase(), OBJ_documentLocation );
        SYM_TO_OID.put( LN_homeTelephoneNumber.toLowerCase(), OBJ_homeTelephoneNumber );
        SYM_TO_OID.put( SN_secretary.toLowerCase(), OBJ_secretary );
        SYM_TO_OID.put( LN_otherMailbox.toLowerCase(), OBJ_otherMailbox );
        SYM_TO_OID.put( LN_lastModifiedTime.toLowerCase(), OBJ_lastModifiedTime );
        SYM_TO_OID.put( LN_lastModifiedBy.toLowerCase(), OBJ_lastModifiedBy );
        SYM_TO_OID.put( SN_domainComponent.toLowerCase(), OBJ_domainComponent );
        SYM_TO_OID.put( LN_domainComponent.toLowerCase(), OBJ_domainComponent );
        SYM_TO_OID.put( LN_aRecord.toLowerCase(), OBJ_aRecord );
        SYM_TO_OID.put( LN_pilotAttributeType27.toLowerCase(), OBJ_pilotAttributeType27 );
        SYM_TO_OID.put( LN_mXRecord.toLowerCase(), OBJ_mXRecord );
        SYM_TO_OID.put( LN_nSRecord.toLowerCase(), OBJ_nSRecord );
        SYM_TO_OID.put( LN_sOARecord.toLowerCase(), OBJ_sOARecord );
        SYM_TO_OID.put( LN_cNAMERecord.toLowerCase(), OBJ_cNAMERecord );
        SYM_TO_OID.put( LN_associatedDomain.toLowerCase(), OBJ_associatedDomain );
        SYM_TO_OID.put( LN_associatedName.toLowerCase(), OBJ_associatedName );
        SYM_TO_OID.put( LN_homePostalAddress.toLowerCase(), OBJ_homePostalAddress );
        SYM_TO_OID.put( LN_personalTitle.toLowerCase(), OBJ_personalTitle );
        SYM_TO_OID.put( LN_mobileTelephoneNumber.toLowerCase(), OBJ_mobileTelephoneNumber );
        SYM_TO_OID.put( LN_pagerTelephoneNumber.toLowerCase(), OBJ_pagerTelephoneNumber );
        SYM_TO_OID.put( LN_friendlyCountryName.toLowerCase(), OBJ_friendlyCountryName );
        SYM_TO_OID.put( LN_organizationalStatus.toLowerCase(), OBJ_organizationalStatus );
        SYM_TO_OID.put( LN_janetMailbox.toLowerCase(), OBJ_janetMailbox );
        SYM_TO_OID.put( LN_mailPreferenceOption.toLowerCase(), OBJ_mailPreferenceOption );
        SYM_TO_OID.put( LN_buildingName.toLowerCase(), OBJ_buildingName );
        SYM_TO_OID.put( LN_dSAQuality.toLowerCase(), OBJ_dSAQuality );
        SYM_TO_OID.put( LN_singleLevelQuality.toLowerCase(), OBJ_singleLevelQuality );
        SYM_TO_OID.put( LN_subtreeMinimumQuality.toLowerCase(), OBJ_subtreeMinimumQuality );
        SYM_TO_OID.put( LN_subtreeMaximumQuality.toLowerCase(), OBJ_subtreeMaximumQuality );
        SYM_TO_OID.put( LN_personalSignature.toLowerCase(), OBJ_personalSignature );
        SYM_TO_OID.put( LN_dITRedirect.toLowerCase(), OBJ_dITRedirect );
        SYM_TO_OID.put( SN_audio.toLowerCase(), OBJ_audio );
        SYM_TO_OID.put( LN_documentPublisher.toLowerCase(), OBJ_documentPublisher );
        SYM_TO_OID.put( SN_id_set.toLowerCase(), OBJ_id_set );
        SYM_TO_OID.put( LN_id_set.toLowerCase(), OBJ_id_set );
        SYM_TO_OID.put( SN_set_ctype.toLowerCase(), OBJ_set_ctype );
        SYM_TO_OID.put( LN_set_ctype.toLowerCase(), OBJ_set_ctype );
        SYM_TO_OID.put( SN_set_msgExt.toLowerCase(), OBJ_set_msgExt );
        SYM_TO_OID.put( LN_set_msgExt.toLowerCase(), OBJ_set_msgExt );
        SYM_TO_OID.put( SN_set_attr.toLowerCase(), OBJ_set_attr );
        SYM_TO_OID.put( SN_set_policy.toLowerCase(), OBJ_set_policy );
        SYM_TO_OID.put( SN_set_certExt.toLowerCase(), OBJ_set_certExt );
        SYM_TO_OID.put( LN_set_certExt.toLowerCase(), OBJ_set_certExt );
        SYM_TO_OID.put( SN_set_brand.toLowerCase(), OBJ_set_brand );
        SYM_TO_OID.put( SN_setct_PANData.toLowerCase(), OBJ_setct_PANData );
        SYM_TO_OID.put( SN_setct_PANToken.toLowerCase(), OBJ_setct_PANToken );
        SYM_TO_OID.put( SN_setct_PANOnly.toLowerCase(), OBJ_setct_PANOnly );
        SYM_TO_OID.put( SN_setct_OIData.toLowerCase(), OBJ_setct_OIData );
        SYM_TO_OID.put( SN_setct_PI.toLowerCase(), OBJ_setct_PI );
        SYM_TO_OID.put( SN_setct_PIData.toLowerCase(), OBJ_setct_PIData );
        SYM_TO_OID.put( SN_setct_PIDataUnsigned.toLowerCase(), OBJ_setct_PIDataUnsigned );
        SYM_TO_OID.put( SN_setct_HODInput.toLowerCase(), OBJ_setct_HODInput );
        SYM_TO_OID.put( SN_setct_AuthResBaggage.toLowerCase(), OBJ_setct_AuthResBaggage );
        SYM_TO_OID.put( SN_setct_AuthRevReqBaggage.toLowerCase(), OBJ_setct_AuthRevReqBaggage );
        SYM_TO_OID.put( SN_setct_AuthRevResBaggage.toLowerCase(), OBJ_setct_AuthRevResBaggage );
        SYM_TO_OID.put( SN_setct_CapTokenSeq.toLowerCase(), OBJ_setct_CapTokenSeq );
        SYM_TO_OID.put( SN_setct_PInitResData.toLowerCase(), OBJ_setct_PInitResData );
        SYM_TO_OID.put( SN_setct_PI_TBS.toLowerCase(), OBJ_setct_PI_TBS );
        SYM_TO_OID.put( SN_setct_PResData.toLowerCase(), OBJ_setct_PResData );
        SYM_TO_OID.put( SN_setct_AuthReqTBS.toLowerCase(), OBJ_setct_AuthReqTBS );
        SYM_TO_OID.put( SN_setct_AuthResTBS.toLowerCase(), OBJ_setct_AuthResTBS );
        SYM_TO_OID.put( SN_setct_AuthResTBSX.toLowerCase(), OBJ_setct_AuthResTBSX );
        SYM_TO_OID.put( SN_setct_AuthTokenTBS.toLowerCase(), OBJ_setct_AuthTokenTBS );
        SYM_TO_OID.put( SN_setct_CapTokenData.toLowerCase(), OBJ_setct_CapTokenData );
        SYM_TO_OID.put( SN_setct_CapTokenTBS.toLowerCase(), OBJ_setct_CapTokenTBS );
        SYM_TO_OID.put( SN_setct_AcqCardCodeMsg.toLowerCase(), OBJ_setct_AcqCardCodeMsg );
        SYM_TO_OID.put( SN_setct_AuthRevReqTBS.toLowerCase(), OBJ_setct_AuthRevReqTBS );
        SYM_TO_OID.put( SN_setct_AuthRevResData.toLowerCase(), OBJ_setct_AuthRevResData );
        SYM_TO_OID.put( SN_setct_AuthRevResTBS.toLowerCase(), OBJ_setct_AuthRevResTBS );
        SYM_TO_OID.put( SN_setct_CapReqTBS.toLowerCase(), OBJ_setct_CapReqTBS );
        SYM_TO_OID.put( SN_setct_CapReqTBSX.toLowerCase(), OBJ_setct_CapReqTBSX );
        SYM_TO_OID.put( SN_setct_CapResData.toLowerCase(), OBJ_setct_CapResData );
        SYM_TO_OID.put( SN_setct_CapRevReqTBS.toLowerCase(), OBJ_setct_CapRevReqTBS );
        SYM_TO_OID.put( SN_setct_CapRevReqTBSX.toLowerCase(), OBJ_setct_CapRevReqTBSX );
        SYM_TO_OID.put( SN_setct_CapRevResData.toLowerCase(), OBJ_setct_CapRevResData );
        SYM_TO_OID.put( SN_setct_CredReqTBS.toLowerCase(), OBJ_setct_CredReqTBS );
        SYM_TO_OID.put( SN_setct_CredReqTBSX.toLowerCase(), OBJ_setct_CredReqTBSX );
        SYM_TO_OID.put( SN_setct_CredResData.toLowerCase(), OBJ_setct_CredResData );
        SYM_TO_OID.put( SN_setct_CredRevReqTBS.toLowerCase(), OBJ_setct_CredRevReqTBS );
        SYM_TO_OID.put( SN_setct_CredRevReqTBSX.toLowerCase(), OBJ_setct_CredRevReqTBSX );
        SYM_TO_OID.put( SN_setct_CredRevResData.toLowerCase(), OBJ_setct_CredRevResData );
        SYM_TO_OID.put( SN_setct_PCertReqData.toLowerCase(), OBJ_setct_PCertReqData );
        SYM_TO_OID.put( SN_setct_PCertResTBS.toLowerCase(), OBJ_setct_PCertResTBS );
        SYM_TO_OID.put( SN_setct_BatchAdminReqData.toLowerCase(), OBJ_setct_BatchAdminReqData );
        SYM_TO_OID.put( SN_setct_BatchAdminResData.toLowerCase(), OBJ_setct_BatchAdminResData );
        SYM_TO_OID.put( SN_setct_CardCInitResTBS.toLowerCase(), OBJ_setct_CardCInitResTBS );
        SYM_TO_OID.put( SN_setct_MeAqCInitResTBS.toLowerCase(), OBJ_setct_MeAqCInitResTBS );
        SYM_TO_OID.put( SN_setct_RegFormResTBS.toLowerCase(), OBJ_setct_RegFormResTBS );
        SYM_TO_OID.put( SN_setct_CertReqData.toLowerCase(), OBJ_setct_CertReqData );
        SYM_TO_OID.put( SN_setct_CertReqTBS.toLowerCase(), OBJ_setct_CertReqTBS );
        SYM_TO_OID.put( SN_setct_CertResData.toLowerCase(), OBJ_setct_CertResData );
        SYM_TO_OID.put( SN_setct_CertInqReqTBS.toLowerCase(), OBJ_setct_CertInqReqTBS );
        SYM_TO_OID.put( SN_setct_ErrorTBS.toLowerCase(), OBJ_setct_ErrorTBS );
        SYM_TO_OID.put( SN_setct_PIDualSignedTBE.toLowerCase(), OBJ_setct_PIDualSignedTBE );
        SYM_TO_OID.put( SN_setct_PIUnsignedTBE.toLowerCase(), OBJ_setct_PIUnsignedTBE );
        SYM_TO_OID.put( SN_setct_AuthReqTBE.toLowerCase(), OBJ_setct_AuthReqTBE );
        SYM_TO_OID.put( SN_setct_AuthResTBE.toLowerCase(), OBJ_setct_AuthResTBE );
        SYM_TO_OID.put( SN_setct_AuthResTBEX.toLowerCase(), OBJ_setct_AuthResTBEX );
        SYM_TO_OID.put( SN_setct_AuthTokenTBE.toLowerCase(), OBJ_setct_AuthTokenTBE );
        SYM_TO_OID.put( SN_setct_CapTokenTBE.toLowerCase(), OBJ_setct_CapTokenTBE );
        SYM_TO_OID.put( SN_setct_CapTokenTBEX.toLowerCase(), OBJ_setct_CapTokenTBEX );
        SYM_TO_OID.put( SN_setct_AcqCardCodeMsgTBE.toLowerCase(), OBJ_setct_AcqCardCodeMsgTBE );
        SYM_TO_OID.put( SN_setct_AuthRevReqTBE.toLowerCase(), OBJ_setct_AuthRevReqTBE );
        SYM_TO_OID.put( SN_setct_AuthRevResTBE.toLowerCase(), OBJ_setct_AuthRevResTBE );
        SYM_TO_OID.put( SN_setct_AuthRevResTBEB.toLowerCase(), OBJ_setct_AuthRevResTBEB );
        SYM_TO_OID.put( SN_setct_CapReqTBE.toLowerCase(), OBJ_setct_CapReqTBE );
        SYM_TO_OID.put( SN_setct_CapReqTBEX.toLowerCase(), OBJ_setct_CapReqTBEX );
        SYM_TO_OID.put( SN_setct_CapResTBE.toLowerCase(), OBJ_setct_CapResTBE );
        SYM_TO_OID.put( SN_setct_CapRevReqTBE.toLowerCase(), OBJ_setct_CapRevReqTBE );
        SYM_TO_OID.put( SN_setct_CapRevReqTBEX.toLowerCase(), OBJ_setct_CapRevReqTBEX );
        SYM_TO_OID.put( SN_setct_CapRevResTBE.toLowerCase(), OBJ_setct_CapRevResTBE );
        SYM_TO_OID.put( SN_setct_CredReqTBE.toLowerCase(), OBJ_setct_CredReqTBE );
        SYM_TO_OID.put( SN_setct_CredReqTBEX.toLowerCase(), OBJ_setct_CredReqTBEX );
        SYM_TO_OID.put( SN_setct_CredResTBE.toLowerCase(), OBJ_setct_CredResTBE );
        SYM_TO_OID.put( SN_setct_CredRevReqTBE.toLowerCase(), OBJ_setct_CredRevReqTBE );
        SYM_TO_OID.put( SN_setct_CredRevReqTBEX.toLowerCase(), OBJ_setct_CredRevReqTBEX );
        SYM_TO_OID.put( SN_setct_CredRevResTBE.toLowerCase(), OBJ_setct_CredRevResTBE );
        SYM_TO_OID.put( SN_setct_BatchAdminReqTBE.toLowerCase(), OBJ_setct_BatchAdminReqTBE );
        SYM_TO_OID.put( SN_setct_BatchAdminResTBE.toLowerCase(), OBJ_setct_BatchAdminResTBE );
        SYM_TO_OID.put( SN_setct_RegFormReqTBE.toLowerCase(), OBJ_setct_RegFormReqTBE );
        SYM_TO_OID.put( SN_setct_CertReqTBE.toLowerCase(), OBJ_setct_CertReqTBE );
        SYM_TO_OID.put( SN_setct_CertReqTBEX.toLowerCase(), OBJ_setct_CertReqTBEX );
        SYM_TO_OID.put( SN_setct_CertResTBE.toLowerCase(), OBJ_setct_CertResTBE );
        SYM_TO_OID.put( SN_setct_CRLNotificationTBS.toLowerCase(), OBJ_setct_CRLNotificationTBS );
        SYM_TO_OID.put( SN_setct_CRLNotificationResTBS.toLowerCase(), OBJ_setct_CRLNotificationResTBS );
        SYM_TO_OID.put( SN_setct_BCIDistributionTBS.toLowerCase(), OBJ_setct_BCIDistributionTBS );
        SYM_TO_OID.put( SN_setext_genCrypt.toLowerCase(), OBJ_setext_genCrypt );
        SYM_TO_OID.put( LN_setext_genCrypt.toLowerCase(), OBJ_setext_genCrypt );
        SYM_TO_OID.put( SN_setext_miAuth.toLowerCase(), OBJ_setext_miAuth );
        SYM_TO_OID.put( LN_setext_miAuth.toLowerCase(), OBJ_setext_miAuth );
        SYM_TO_OID.put( SN_setext_pinSecure.toLowerCase(), OBJ_setext_pinSecure );
        SYM_TO_OID.put( SN_setext_pinAny.toLowerCase(), OBJ_setext_pinAny );
        SYM_TO_OID.put( SN_setext_track2.toLowerCase(), OBJ_setext_track2 );
        SYM_TO_OID.put( SN_setext_cv.toLowerCase(), OBJ_setext_cv );
        SYM_TO_OID.put( LN_setext_cv.toLowerCase(), OBJ_setext_cv );
        SYM_TO_OID.put( SN_set_policy_root.toLowerCase(), OBJ_set_policy_root );
        SYM_TO_OID.put( SN_setCext_hashedRoot.toLowerCase(), OBJ_setCext_hashedRoot );
        SYM_TO_OID.put( SN_setCext_certType.toLowerCase(), OBJ_setCext_certType );
        SYM_TO_OID.put( SN_setCext_merchData.toLowerCase(), OBJ_setCext_merchData );
        SYM_TO_OID.put( SN_setCext_cCertRequired.toLowerCase(), OBJ_setCext_cCertRequired );
        SYM_TO_OID.put( SN_setCext_tunneling.toLowerCase(), OBJ_setCext_tunneling );
        SYM_TO_OID.put( SN_setCext_setExt.toLowerCase(), OBJ_setCext_setExt );
        SYM_TO_OID.put( SN_setCext_setQualf.toLowerCase(), OBJ_setCext_setQualf );
        SYM_TO_OID.put( SN_setCext_PGWYcapabilities.toLowerCase(), OBJ_setCext_PGWYcapabilities );
        SYM_TO_OID.put( SN_setCext_TokenIdentifier.toLowerCase(), OBJ_setCext_TokenIdentifier );
        SYM_TO_OID.put( SN_setCext_Track2Data.toLowerCase(), OBJ_setCext_Track2Data );
        SYM_TO_OID.put( SN_setCext_TokenType.toLowerCase(), OBJ_setCext_TokenType );
        SYM_TO_OID.put( SN_setCext_IssuerCapabilities.toLowerCase(), OBJ_setCext_IssuerCapabilities );
        SYM_TO_OID.put( SN_setAttr_Cert.toLowerCase(), OBJ_setAttr_Cert );
        SYM_TO_OID.put( SN_setAttr_PGWYcap.toLowerCase(), OBJ_setAttr_PGWYcap );
        SYM_TO_OID.put( LN_setAttr_PGWYcap.toLowerCase(), OBJ_setAttr_PGWYcap );
        SYM_TO_OID.put( SN_setAttr_TokenType.toLowerCase(), OBJ_setAttr_TokenType );
        SYM_TO_OID.put( SN_setAttr_IssCap.toLowerCase(), OBJ_setAttr_IssCap );
        SYM_TO_OID.put( LN_setAttr_IssCap.toLowerCase(), OBJ_setAttr_IssCap );
        SYM_TO_OID.put( SN_set_rootKeyThumb.toLowerCase(), OBJ_set_rootKeyThumb );
        SYM_TO_OID.put( SN_set_addPolicy.toLowerCase(), OBJ_set_addPolicy );
        SYM_TO_OID.put( SN_setAttr_Token_EMV.toLowerCase(), OBJ_setAttr_Token_EMV );
        SYM_TO_OID.put( SN_setAttr_Token_B0Prime.toLowerCase(), OBJ_setAttr_Token_B0Prime );
        SYM_TO_OID.put( SN_setAttr_IssCap_CVM.toLowerCase(), OBJ_setAttr_IssCap_CVM );
        SYM_TO_OID.put( SN_setAttr_IssCap_T2.toLowerCase(), OBJ_setAttr_IssCap_T2 );
        SYM_TO_OID.put( SN_setAttr_IssCap_Sig.toLowerCase(), OBJ_setAttr_IssCap_Sig );
        SYM_TO_OID.put( SN_setAttr_GenCryptgrm.toLowerCase(), OBJ_setAttr_GenCryptgrm );
        SYM_TO_OID.put( LN_setAttr_GenCryptgrm.toLowerCase(), OBJ_setAttr_GenCryptgrm );
        SYM_TO_OID.put( SN_setAttr_T2Enc.toLowerCase(), OBJ_setAttr_T2Enc );
        SYM_TO_OID.put( LN_setAttr_T2Enc.toLowerCase(), OBJ_setAttr_T2Enc );
        SYM_TO_OID.put( SN_setAttr_T2cleartxt.toLowerCase(), OBJ_setAttr_T2cleartxt );
        SYM_TO_OID.put( LN_setAttr_T2cleartxt.toLowerCase(), OBJ_setAttr_T2cleartxt );
        SYM_TO_OID.put( SN_setAttr_TokICCsig.toLowerCase(), OBJ_setAttr_TokICCsig );
        SYM_TO_OID.put( LN_setAttr_TokICCsig.toLowerCase(), OBJ_setAttr_TokICCsig );
        SYM_TO_OID.put( SN_setAttr_SecDevSig.toLowerCase(), OBJ_setAttr_SecDevSig );
        SYM_TO_OID.put( LN_setAttr_SecDevSig.toLowerCase(), OBJ_setAttr_SecDevSig );
        SYM_TO_OID.put( SN_set_brand_IATA_ATA.toLowerCase(), OBJ_set_brand_IATA_ATA );
        SYM_TO_OID.put( SN_set_brand_Diners.toLowerCase(), OBJ_set_brand_Diners );
        SYM_TO_OID.put( SN_set_brand_AmericanExpress.toLowerCase(), OBJ_set_brand_AmericanExpress );
        SYM_TO_OID.put( SN_set_brand_JCB.toLowerCase(), OBJ_set_brand_JCB );
        SYM_TO_OID.put( SN_set_brand_Visa.toLowerCase(), OBJ_set_brand_Visa );
        SYM_TO_OID.put( SN_set_brand_MasterCard.toLowerCase(), OBJ_set_brand_MasterCard );
        SYM_TO_OID.put( SN_set_brand_Novus.toLowerCase(), OBJ_set_brand_Novus );
        SYM_TO_OID.put( SN_des_cdmf.toLowerCase(), OBJ_des_cdmf );
        SYM_TO_OID.put( LN_des_cdmf.toLowerCase(), OBJ_des_cdmf );
        SYM_TO_OID.put( SN_rsaOAEPEncryptionSET.toLowerCase(), OBJ_rsaOAEPEncryptionSET );
        SYM_TO_OID.put( SN_whirlpool.toLowerCase(), OBJ_whirlpool );
        SYM_TO_OID.put( SN_cryptopro.toLowerCase(), OBJ_cryptopro );
        SYM_TO_OID.put( SN_cryptocom.toLowerCase(), OBJ_cryptocom );
        SYM_TO_OID.put( SN_id_GostR3411_94_with_GostR3410_2001.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_2001 );
        SYM_TO_OID.put( LN_id_GostR3411_94_with_GostR3410_2001.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_2001 );
        SYM_TO_OID.put( SN_id_GostR3411_94_with_GostR3410_94.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_94 );
        SYM_TO_OID.put( LN_id_GostR3411_94_with_GostR3410_94.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_94 );
        SYM_TO_OID.put( SN_id_GostR3411_94.toLowerCase(), OBJ_id_GostR3411_94 );
        SYM_TO_OID.put( LN_id_GostR3411_94.toLowerCase(), OBJ_id_GostR3411_94 );
        SYM_TO_OID.put( SN_id_HMACGostR3411_94.toLowerCase(), OBJ_id_HMACGostR3411_94 );
        SYM_TO_OID.put( LN_id_HMACGostR3411_94.toLowerCase(), OBJ_id_HMACGostR3411_94 );
        SYM_TO_OID.put( SN_id_GostR3410_2001.toLowerCase(), OBJ_id_GostR3410_2001 );
        SYM_TO_OID.put( LN_id_GostR3410_2001.toLowerCase(), OBJ_id_GostR3410_2001 );
        SYM_TO_OID.put( SN_id_GostR3410_94.toLowerCase(), OBJ_id_GostR3410_94 );
        SYM_TO_OID.put( LN_id_GostR3410_94.toLowerCase(), OBJ_id_GostR3410_94 );
        SYM_TO_OID.put( SN_id_Gost28147_89.toLowerCase(), OBJ_id_Gost28147_89 );
        SYM_TO_OID.put( LN_id_Gost28147_89.toLowerCase(), OBJ_id_Gost28147_89 );
        SYM_TO_OID.put( SN_id_Gost28147_89_MAC.toLowerCase(), OBJ_id_Gost28147_89_MAC );
        SYM_TO_OID.put( LN_id_Gost28147_89_MAC.toLowerCase(), OBJ_id_Gost28147_89_MAC );
        SYM_TO_OID.put( SN_id_GostR3411_94_prf.toLowerCase(), OBJ_id_GostR3411_94_prf );
        SYM_TO_OID.put( LN_id_GostR3411_94_prf.toLowerCase(), OBJ_id_GostR3411_94_prf );
        SYM_TO_OID.put( SN_id_GostR3410_2001DH.toLowerCase(), OBJ_id_GostR3410_2001DH );
        SYM_TO_OID.put( LN_id_GostR3410_2001DH.toLowerCase(), OBJ_id_GostR3410_2001DH );
        SYM_TO_OID.put( SN_id_GostR3410_94DH.toLowerCase(), OBJ_id_GostR3410_94DH );
        SYM_TO_OID.put( LN_id_GostR3410_94DH.toLowerCase(), OBJ_id_GostR3410_94DH );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_KeyMeshing.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_KeyMeshing );
        SYM_TO_OID.put( SN_id_Gost28147_89_None_KeyMeshing.toLowerCase(), OBJ_id_Gost28147_89_None_KeyMeshing );
        SYM_TO_OID.put( SN_id_GostR3411_94_TestParamSet.toLowerCase(), OBJ_id_GostR3411_94_TestParamSet );
        SYM_TO_OID.put( SN_id_GostR3411_94_CryptoProParamSet.toLowerCase(), OBJ_id_GostR3411_94_CryptoProParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_TestParamSet.toLowerCase(), OBJ_id_Gost28147_89_TestParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_A_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_A_ParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_B_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_B_ParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_C_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_C_ParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_D_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_D_ParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet );
        SYM_TO_OID.put( SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet.toLowerCase(), OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_TestParamSet.toLowerCase(), OBJ_id_GostR3410_94_TestParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_A_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_A_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_B_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_B_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_C_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_C_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_D_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_D_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_XchA_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_XchB_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_CryptoPro_XchC_ParamSet.toLowerCase(), OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_2001_TestParamSet.toLowerCase(), OBJ_id_GostR3410_2001_TestParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_2001_CryptoPro_A_ParamSet.toLowerCase(), OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_2001_CryptoPro_B_ParamSet.toLowerCase(), OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_2001_CryptoPro_C_ParamSet.toLowerCase(), OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet.toLowerCase(), OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet.toLowerCase(), OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet );
        SYM_TO_OID.put( SN_id_GostR3410_94_a.toLowerCase(), OBJ_id_GostR3410_94_a );
        SYM_TO_OID.put( SN_id_GostR3410_94_aBis.toLowerCase(), OBJ_id_GostR3410_94_aBis );
        SYM_TO_OID.put( SN_id_GostR3410_94_b.toLowerCase(), OBJ_id_GostR3410_94_b );
        SYM_TO_OID.put( SN_id_GostR3410_94_bBis.toLowerCase(), OBJ_id_GostR3410_94_bBis );
        SYM_TO_OID.put( SN_id_Gost28147_89_cc.toLowerCase(), OBJ_id_Gost28147_89_cc );
        SYM_TO_OID.put( LN_id_Gost28147_89_cc.toLowerCase(), OBJ_id_Gost28147_89_cc );
        SYM_TO_OID.put( SN_id_GostR3410_94_cc.toLowerCase(), OBJ_id_GostR3410_94_cc );
        SYM_TO_OID.put( LN_id_GostR3410_94_cc.toLowerCase(), OBJ_id_GostR3410_94_cc );
        SYM_TO_OID.put( SN_id_GostR3410_2001_cc.toLowerCase(), OBJ_id_GostR3410_2001_cc );
        SYM_TO_OID.put( LN_id_GostR3410_2001_cc.toLowerCase(), OBJ_id_GostR3410_2001_cc );
        SYM_TO_OID.put( SN_id_GostR3411_94_with_GostR3410_94_cc.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_94_cc );
        SYM_TO_OID.put( LN_id_GostR3411_94_with_GostR3410_94_cc.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_94_cc );
        SYM_TO_OID.put( SN_id_GostR3411_94_with_GostR3410_2001_cc.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_2001_cc );
        SYM_TO_OID.put( LN_id_GostR3411_94_with_GostR3410_2001_cc.toLowerCase(), OBJ_id_GostR3411_94_with_GostR3410_2001_cc );
        SYM_TO_OID.put( SN_id_GostR3410_2001_ParamSet_cc.toLowerCase(), OBJ_id_GostR3410_2001_ParamSet_cc );
        SYM_TO_OID.put( LN_id_GostR3410_2001_ParamSet_cc.toLowerCase(), OBJ_id_GostR3410_2001_ParamSet_cc );
        SYM_TO_OID.put( SN_camellia_128_cbc.toLowerCase(), OBJ_camellia_128_cbc );
        SYM_TO_OID.put( LN_camellia_128_cbc.toLowerCase(), OBJ_camellia_128_cbc );
        SYM_TO_OID.put( SN_camellia_192_cbc.toLowerCase(), OBJ_camellia_192_cbc );
        SYM_TO_OID.put( LN_camellia_192_cbc.toLowerCase(), OBJ_camellia_192_cbc );
        SYM_TO_OID.put( SN_camellia_256_cbc.toLowerCase(), OBJ_camellia_256_cbc );
        SYM_TO_OID.put( LN_camellia_256_cbc.toLowerCase(), OBJ_camellia_256_cbc );
        SYM_TO_OID.put( SN_id_camellia128_wrap.toLowerCase(), OBJ_id_camellia128_wrap );
        SYM_TO_OID.put( SN_id_camellia192_wrap.toLowerCase(), OBJ_id_camellia192_wrap );
        SYM_TO_OID.put( SN_id_camellia256_wrap.toLowerCase(), OBJ_id_camellia256_wrap );
        SYM_TO_OID.put( SN_camellia_128_ecb.toLowerCase(), OBJ_camellia_128_ecb );
        SYM_TO_OID.put( LN_camellia_128_ecb.toLowerCase(), OBJ_camellia_128_ecb );
        SYM_TO_OID.put( SN_camellia_128_ofb128.toLowerCase(), OBJ_camellia_128_ofb128 );
        SYM_TO_OID.put( LN_camellia_128_ofb128.toLowerCase(), OBJ_camellia_128_ofb128 );
        SYM_TO_OID.put( SN_camellia_128_cfb128.toLowerCase(), OBJ_camellia_128_cfb128 );
        SYM_TO_OID.put( LN_camellia_128_cfb128.toLowerCase(), OBJ_camellia_128_cfb128 );
        SYM_TO_OID.put( SN_camellia_192_ecb.toLowerCase(), OBJ_camellia_192_ecb );
        SYM_TO_OID.put( LN_camellia_192_ecb.toLowerCase(), OBJ_camellia_192_ecb );
        SYM_TO_OID.put( SN_camellia_192_ofb128.toLowerCase(), OBJ_camellia_192_ofb128 );
        SYM_TO_OID.put( LN_camellia_192_ofb128.toLowerCase(), OBJ_camellia_192_ofb128 );
        SYM_TO_OID.put( SN_camellia_192_cfb128.toLowerCase(), OBJ_camellia_192_cfb128 );
        SYM_TO_OID.put( LN_camellia_192_cfb128.toLowerCase(), OBJ_camellia_192_cfb128 );
        SYM_TO_OID.put( SN_camellia_256_ecb.toLowerCase(), OBJ_camellia_256_ecb );
        SYM_TO_OID.put( LN_camellia_256_ecb.toLowerCase(), OBJ_camellia_256_ecb );
        SYM_TO_OID.put( SN_camellia_256_ofb128.toLowerCase(), OBJ_camellia_256_ofb128 );
        SYM_TO_OID.put( LN_camellia_256_ofb128.toLowerCase(), OBJ_camellia_256_ofb128 );
        SYM_TO_OID.put( SN_camellia_256_cfb128.toLowerCase(), OBJ_camellia_256_cfb128 );
        SYM_TO_OID.put( LN_camellia_256_cfb128.toLowerCase(), OBJ_camellia_256_cfb128 );
        SYM_TO_OID.put( SN_kisa.toLowerCase(), OBJ_kisa );
        SYM_TO_OID.put( LN_kisa.toLowerCase(), OBJ_kisa );
        SYM_TO_OID.put( SN_seed_ecb.toLowerCase(), OBJ_seed_ecb );
        SYM_TO_OID.put( LN_seed_ecb.toLowerCase(), OBJ_seed_ecb );
        SYM_TO_OID.put( SN_seed_cbc.toLowerCase(), OBJ_seed_cbc );
        SYM_TO_OID.put( LN_seed_cbc.toLowerCase(), OBJ_seed_cbc );
        SYM_TO_OID.put( SN_seed_cfb128.toLowerCase(), OBJ_seed_cfb128 );
        SYM_TO_OID.put( LN_seed_cfb128.toLowerCase(), OBJ_seed_cfb128 );
        SYM_TO_OID.put( SN_seed_ofb128.toLowerCase(), OBJ_seed_ofb128 );
        SYM_TO_OID.put( LN_seed_ofb128.toLowerCase(), OBJ_seed_ofb128 );
        SYM_TO_OID.put( SN_dhpublicnumber.toLowerCase(), OBJ_dhpublicnumber );
        SYM_TO_OID.put( LN_dhpublicnumber.toLowerCase(), OBJ_dhpublicnumber );
        SYM_TO_OID.put( SN_brainpoolP160r1.toLowerCase(), OBJ_brainpoolP160r1 );
        SYM_TO_OID.put( SN_brainpoolP160t1.toLowerCase(), OBJ_brainpoolP160t1 );
        SYM_TO_OID.put( SN_brainpoolP192r1.toLowerCase(), OBJ_brainpoolP192r1 );
        SYM_TO_OID.put( SN_brainpoolP192t1.toLowerCase(), OBJ_brainpoolP192t1 );
        SYM_TO_OID.put( SN_brainpoolP224r1.toLowerCase(), OBJ_brainpoolP224r1 );
        SYM_TO_OID.put( SN_brainpoolP224t1.toLowerCase(), OBJ_brainpoolP224t1 );
        SYM_TO_OID.put( SN_brainpoolP256r1.toLowerCase(), OBJ_brainpoolP256r1 );
        SYM_TO_OID.put( SN_brainpoolP256t1.toLowerCase(), OBJ_brainpoolP256t1 );
        SYM_TO_OID.put( SN_brainpoolP320r1.toLowerCase(), OBJ_brainpoolP320r1 );
        SYM_TO_OID.put( SN_brainpoolP320t1.toLowerCase(), OBJ_brainpoolP320t1 );
        SYM_TO_OID.put( SN_brainpoolP384r1.toLowerCase(), OBJ_brainpoolP384r1 );
        SYM_TO_OID.put( SN_brainpoolP384t1.toLowerCase(), OBJ_brainpoolP384t1 );
        SYM_TO_OID.put( SN_brainpoolP512r1.toLowerCase(), OBJ_brainpoolP512r1 );
        SYM_TO_OID.put( SN_brainpoolP512t1.toLowerCase(), OBJ_brainpoolP512t1 );
        SYM_TO_OID.put( SN_dhSinglePass_stdDH_sha1kdf_scheme.toLowerCase(), OBJ_dhSinglePass_stdDH_sha1kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_stdDH_sha224kdf_scheme.toLowerCase(), OBJ_dhSinglePass_stdDH_sha224kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_stdDH_sha256kdf_scheme.toLowerCase(), OBJ_dhSinglePass_stdDH_sha256kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_stdDH_sha384kdf_scheme.toLowerCase(), OBJ_dhSinglePass_stdDH_sha384kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_stdDH_sha512kdf_scheme.toLowerCase(), OBJ_dhSinglePass_stdDH_sha512kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_cofactorDH_sha1kdf_scheme.toLowerCase(), OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_cofactorDH_sha224kdf_scheme.toLowerCase(), OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_cofactorDH_sha256kdf_scheme.toLowerCase(), OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_cofactorDH_sha384kdf_scheme.toLowerCase(), OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme );
        SYM_TO_OID.put( SN_dhSinglePass_cofactorDH_sha512kdf_scheme.toLowerCase(), OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme );
        SYM_TO_OID.put( SN_ct_precert_scts.toLowerCase(), OBJ_ct_precert_scts );
        SYM_TO_OID.put( LN_ct_precert_scts.toLowerCase(), OBJ_ct_precert_scts );
        SYM_TO_OID.put( SN_ct_precert_poison.toLowerCase(), OBJ_ct_precert_poison );
        SYM_TO_OID.put( LN_ct_precert_poison.toLowerCase(), OBJ_ct_precert_poison );
        SYM_TO_OID.put( SN_ct_precert_signer.toLowerCase(), OBJ_ct_precert_signer );
        SYM_TO_OID.put( LN_ct_precert_signer.toLowerCase(), OBJ_ct_precert_signer );
        SYM_TO_OID.put( SN_ct_cert_scts.toLowerCase(), OBJ_ct_cert_scts );
        SYM_TO_OID.put( LN_ct_cert_scts.toLowerCase(), OBJ_ct_cert_scts );
        SYM_TO_OID.put( SN_jurisdictionLocalityName.toLowerCase(), OBJ_jurisdictionLocalityName );
        SYM_TO_OID.put( LN_jurisdictionLocalityName.toLowerCase(), OBJ_jurisdictionLocalityName );
        SYM_TO_OID.put( SN_jurisdictionStateOrProvinceName.toLowerCase(), OBJ_jurisdictionStateOrProvinceName );
        SYM_TO_OID.put( LN_jurisdictionStateOrProvinceName.toLowerCase(), OBJ_jurisdictionStateOrProvinceName );
        SYM_TO_OID.put( SN_jurisdictionCountryName.toLowerCase(), OBJ_jurisdictionCountryName );
        SYM_TO_OID.put( LN_jurisdictionCountryName.toLowerCase(), OBJ_jurisdictionCountryName );
    }
    

    private static final HashMap<String, String> OID_TO_SYM = new HashMap<String, String>(1052, 1);
    // OID_TO_SYM.put(oid, sn == null ? ln : sn) 
    static {
        OID_TO_SYM.put( OBJ_undef, SN_undef );
        OID_TO_SYM.put( OBJ_itu_t, SN_itu_t );
        OID_TO_SYM.put( OBJ_iso, SN_iso );
        OID_TO_SYM.put( OBJ_joint_iso_itu_t, SN_joint_iso_itu_t );
        OID_TO_SYM.put( OBJ_member_body, SN_member_body );
        OID_TO_SYM.put( OBJ_hmac_md5, SN_hmac_md5 );
        OID_TO_SYM.put( OBJ_hmac_sha1, SN_hmac_sha1 );
        OID_TO_SYM.put( OBJ_international_organizations, SN_international_organizations );
        OID_TO_SYM.put( OBJ_selected_attribute_types, SN_selected_attribute_types );
        OID_TO_SYM.put( OBJ_ISO_US, SN_ISO_US );
        OID_TO_SYM.put( OBJ_X9_57, SN_X9_57 );
        OID_TO_SYM.put( OBJ_X9cm, SN_X9cm );
        OID_TO_SYM.put( OBJ_dsa, SN_dsa );
        OID_TO_SYM.put( OBJ_dsaWithSHA1, SN_dsaWithSHA1 );
        OID_TO_SYM.put( OBJ_ansi_X9_62, SN_ansi_X9_62 );
        OID_TO_SYM.put( OBJ_cast5_cbc, SN_cast5_cbc );
        OID_TO_SYM.put( OBJ_pbeWithMD5AndCast5_CBC, LN_pbeWithMD5AndCast5_CBC );
        OID_TO_SYM.put( OBJ_id_PasswordBasedMAC, SN_id_PasswordBasedMAC );
        OID_TO_SYM.put( OBJ_id_DHBasedMac, SN_id_DHBasedMac );
        OID_TO_SYM.put( OBJ_rsadsi, SN_rsadsi );
        OID_TO_SYM.put( OBJ_pkcs, SN_pkcs );
        OID_TO_SYM.put( OBJ_rsaEncryption, LN_rsaEncryption );
        OID_TO_SYM.put( OBJ_md2WithRSAEncryption, SN_md2WithRSAEncryption );
        OID_TO_SYM.put( OBJ_md4WithRSAEncryption, SN_md4WithRSAEncryption );
        OID_TO_SYM.put( OBJ_md5WithRSAEncryption, SN_md5WithRSAEncryption );
        OID_TO_SYM.put( OBJ_sha1WithRSAEncryption, SN_sha1WithRSAEncryption );
        OID_TO_SYM.put( OBJ_rsaesOaep, SN_rsaesOaep );
        OID_TO_SYM.put( OBJ_mgf1, SN_mgf1 );
        OID_TO_SYM.put( OBJ_pSpecified, SN_pSpecified );
        OID_TO_SYM.put( OBJ_rsassaPss, SN_rsassaPss );
        OID_TO_SYM.put( OBJ_sha256WithRSAEncryption, SN_sha256WithRSAEncryption );
        OID_TO_SYM.put( OBJ_sha384WithRSAEncryption, SN_sha384WithRSAEncryption );
        OID_TO_SYM.put( OBJ_sha512WithRSAEncryption, SN_sha512WithRSAEncryption );
        OID_TO_SYM.put( OBJ_sha224WithRSAEncryption, SN_sha224WithRSAEncryption );
        OID_TO_SYM.put( OBJ_dhKeyAgreement, LN_dhKeyAgreement );
        OID_TO_SYM.put( OBJ_pbeWithMD2AndDES_CBC, SN_pbeWithMD2AndDES_CBC );
        OID_TO_SYM.put( OBJ_pbeWithMD5AndDES_CBC, SN_pbeWithMD5AndDES_CBC );
        OID_TO_SYM.put( OBJ_pbeWithMD2AndRC2_CBC, SN_pbeWithMD2AndRC2_CBC );
        OID_TO_SYM.put( OBJ_pbeWithMD5AndRC2_CBC, SN_pbeWithMD5AndRC2_CBC );
        OID_TO_SYM.put( OBJ_pbeWithSHA1AndDES_CBC, SN_pbeWithSHA1AndDES_CBC );
        OID_TO_SYM.put( OBJ_pbeWithSHA1AndRC2_CBC, SN_pbeWithSHA1AndRC2_CBC );
        OID_TO_SYM.put( OBJ_id_pbkdf2, LN_id_pbkdf2 );
        OID_TO_SYM.put( OBJ_pbes2, LN_pbes2 );
        OID_TO_SYM.put( OBJ_pbmac1, LN_pbmac1 );
        OID_TO_SYM.put( OBJ_pkcs7_data, LN_pkcs7_data );
        OID_TO_SYM.put( OBJ_pkcs7_signed, LN_pkcs7_signed );
        OID_TO_SYM.put( OBJ_pkcs7_enveloped, LN_pkcs7_enveloped );
        OID_TO_SYM.put( OBJ_pkcs7_signedAndEnveloped, LN_pkcs7_signedAndEnveloped );
        OID_TO_SYM.put( OBJ_pkcs7_digest, LN_pkcs7_digest );
        OID_TO_SYM.put( OBJ_pkcs7_encrypted, LN_pkcs7_encrypted );
        OID_TO_SYM.put( OBJ_pkcs9_emailAddress, LN_pkcs9_emailAddress );
        OID_TO_SYM.put( OBJ_pkcs9_unstructuredName, LN_pkcs9_unstructuredName );
        OID_TO_SYM.put( OBJ_pkcs9_contentType, LN_pkcs9_contentType );
        OID_TO_SYM.put( OBJ_pkcs9_messageDigest, LN_pkcs9_messageDigest );
        OID_TO_SYM.put( OBJ_pkcs9_signingTime, LN_pkcs9_signingTime );
        OID_TO_SYM.put( OBJ_pkcs9_countersignature, LN_pkcs9_countersignature );
        OID_TO_SYM.put( OBJ_pkcs9_challengePassword, LN_pkcs9_challengePassword );
        OID_TO_SYM.put( OBJ_pkcs9_unstructuredAddress, LN_pkcs9_unstructuredAddress );
        OID_TO_SYM.put( OBJ_pkcs9_extCertAttributes, LN_pkcs9_extCertAttributes );
        OID_TO_SYM.put( OBJ_ext_req, SN_ext_req );
        OID_TO_SYM.put( OBJ_SMIMECapabilities, SN_SMIMECapabilities );
        OID_TO_SYM.put( OBJ_SMIME, SN_SMIME );
        OID_TO_SYM.put( OBJ_friendlyName, LN_friendlyName );
        OID_TO_SYM.put( OBJ_localKeyID, LN_localKeyID );
        OID_TO_SYM.put( OBJ_ms_csp_name, SN_ms_csp_name );
        OID_TO_SYM.put( OBJ_LocalKeySet, SN_LocalKeySet );
        OID_TO_SYM.put( OBJ_x509Certificate, LN_x509Certificate );
        OID_TO_SYM.put( OBJ_sdsiCertificate, LN_sdsiCertificate );
        OID_TO_SYM.put( OBJ_x509Crl, LN_x509Crl );
        OID_TO_SYM.put( OBJ_pbe_WithSHA1And128BitRC4, SN_pbe_WithSHA1And128BitRC4 );
        OID_TO_SYM.put( OBJ_pbe_WithSHA1And40BitRC4, SN_pbe_WithSHA1And40BitRC4 );
        OID_TO_SYM.put( OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC, SN_pbe_WithSHA1And3_Key_TripleDES_CBC );
        OID_TO_SYM.put( OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC, SN_pbe_WithSHA1And2_Key_TripleDES_CBC );
        OID_TO_SYM.put( OBJ_pbe_WithSHA1And128BitRC2_CBC, SN_pbe_WithSHA1And128BitRC2_CBC );
        OID_TO_SYM.put( OBJ_pbe_WithSHA1And40BitRC2_CBC, SN_pbe_WithSHA1And40BitRC2_CBC );
        OID_TO_SYM.put( OBJ_keyBag, LN_keyBag );
        OID_TO_SYM.put( OBJ_pkcs8ShroudedKeyBag, LN_pkcs8ShroudedKeyBag );
        OID_TO_SYM.put( OBJ_certBag, LN_certBag );
        OID_TO_SYM.put( OBJ_crlBag, LN_crlBag );
        OID_TO_SYM.put( OBJ_secretBag, LN_secretBag );
        OID_TO_SYM.put( OBJ_safeContentsBag, LN_safeContentsBag );
        OID_TO_SYM.put( OBJ_md2, SN_md2 );
        OID_TO_SYM.put( OBJ_md4, SN_md4 );
        OID_TO_SYM.put( OBJ_md5, SN_md5 );
        OID_TO_SYM.put( OBJ_hmacWithMD5, LN_hmacWithMD5 );
        OID_TO_SYM.put( OBJ_hmacWithSHA1, LN_hmacWithSHA1 );
        OID_TO_SYM.put( OBJ_hmacWithSHA224, LN_hmacWithSHA224 );
        OID_TO_SYM.put( OBJ_hmacWithSHA256, LN_hmacWithSHA256 );
        OID_TO_SYM.put( OBJ_hmacWithSHA384, LN_hmacWithSHA384 );
        OID_TO_SYM.put( OBJ_hmacWithSHA512, LN_hmacWithSHA512 );
        OID_TO_SYM.put( OBJ_rc2_cbc, SN_rc2_cbc );
        OID_TO_SYM.put( OBJ_rc4, SN_rc4 );
        OID_TO_SYM.put( OBJ_des_ede3_cbc, SN_des_ede3_cbc );
        OID_TO_SYM.put( OBJ_rc5_cbc, SN_rc5_cbc );
        OID_TO_SYM.put( OBJ_ms_ext_req, SN_ms_ext_req );
        OID_TO_SYM.put( OBJ_ms_code_ind, SN_ms_code_ind );
        OID_TO_SYM.put( OBJ_ms_code_com, SN_ms_code_com );
        OID_TO_SYM.put( OBJ_ms_ctl_sign, SN_ms_ctl_sign );
        OID_TO_SYM.put( OBJ_ms_sgc, SN_ms_sgc );
        OID_TO_SYM.put( OBJ_ms_efs, SN_ms_efs );
        OID_TO_SYM.put( OBJ_ms_smartcard_login, SN_ms_smartcard_login );
        OID_TO_SYM.put( OBJ_ms_upn, SN_ms_upn );
        OID_TO_SYM.put( OBJ_idea_cbc, SN_idea_cbc );
        OID_TO_SYM.put( OBJ_bf_cbc, SN_bf_cbc );
        OID_TO_SYM.put( OBJ_info_access, SN_info_access );
        OID_TO_SYM.put( OBJ_biometricInfo, SN_biometricInfo );
        OID_TO_SYM.put( OBJ_sinfo_access, SN_sinfo_access );
        OID_TO_SYM.put( OBJ_proxyCertInfo, SN_proxyCertInfo );
        OID_TO_SYM.put( OBJ_id_qt_cps, SN_id_qt_cps );
        OID_TO_SYM.put( OBJ_id_qt_unotice, SN_id_qt_unotice );
        OID_TO_SYM.put( OBJ_server_auth, SN_server_auth );
        OID_TO_SYM.put( OBJ_client_auth, SN_client_auth );
        OID_TO_SYM.put( OBJ_code_sign, SN_code_sign );
        OID_TO_SYM.put( OBJ_email_protect, SN_email_protect );
        OID_TO_SYM.put( OBJ_ipsecEndSystem, SN_ipsecEndSystem );
        OID_TO_SYM.put( OBJ_ipsecTunnel, SN_ipsecTunnel );
        OID_TO_SYM.put( OBJ_ipsecUser, SN_ipsecUser );
        OID_TO_SYM.put( OBJ_time_stamp, SN_time_stamp );
        OID_TO_SYM.put( OBJ_OCSP_sign, SN_OCSP_sign );
        OID_TO_SYM.put( OBJ_dvcs, SN_dvcs );
        OID_TO_SYM.put( OBJ_id_on_permanentIdentifier, SN_id_on_permanentIdentifier );
        OID_TO_SYM.put( OBJ_id_ppl_anyLanguage, SN_id_ppl_anyLanguage );
        OID_TO_SYM.put( OBJ_id_ppl_inheritAll, SN_id_ppl_inheritAll );
        OID_TO_SYM.put( OBJ_Independent, SN_Independent );
        OID_TO_SYM.put( OBJ_ad_OCSP, SN_ad_OCSP );
        OID_TO_SYM.put( OBJ_ad_ca_issuers, SN_ad_ca_issuers );
        OID_TO_SYM.put( OBJ_ad_timeStamping, SN_ad_timeStamping );
        OID_TO_SYM.put( OBJ_ad_dvcs, SN_ad_dvcs );
        OID_TO_SYM.put( OBJ_caRepository, SN_caRepository );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_basic, SN_id_pkix_OCSP_basic );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_Nonce, SN_id_pkix_OCSP_Nonce );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_CrlID, SN_id_pkix_OCSP_CrlID );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_acceptableResponses, SN_id_pkix_OCSP_acceptableResponses );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_noCheck, SN_id_pkix_OCSP_noCheck );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_archiveCutoff, SN_id_pkix_OCSP_archiveCutoff );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_serviceLocator, SN_id_pkix_OCSP_serviceLocator );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_extendedStatus, SN_id_pkix_OCSP_extendedStatus );
        OID_TO_SYM.put( OBJ_id_pkix_OCSP_trustRoot, SN_id_pkix_OCSP_trustRoot );
        OID_TO_SYM.put( OBJ_algorithm, SN_algorithm );
        OID_TO_SYM.put( OBJ_md5WithRSA, SN_md5WithRSA );
        OID_TO_SYM.put( OBJ_des_ecb, SN_des_ecb );
        OID_TO_SYM.put( OBJ_des_cbc, SN_des_cbc );
        OID_TO_SYM.put( OBJ_des_ofb64, SN_des_ofb64 );
        OID_TO_SYM.put( OBJ_des_cfb64, SN_des_cfb64 );
        OID_TO_SYM.put( OBJ_dsa_2, SN_dsa_2 );
        OID_TO_SYM.put( OBJ_dsaWithSHA, SN_dsaWithSHA );
        OID_TO_SYM.put( OBJ_shaWithRSAEncryption, SN_shaWithRSAEncryption );
        OID_TO_SYM.put( OBJ_des_ede_ecb, SN_des_ede_ecb );
        OID_TO_SYM.put( OBJ_sha, SN_sha );
        OID_TO_SYM.put( OBJ_sha1, SN_sha1 );
        OID_TO_SYM.put( OBJ_dsaWithSHA1_2, SN_dsaWithSHA1_2 );
        OID_TO_SYM.put( OBJ_sha1WithRSA, SN_sha1WithRSA );
        OID_TO_SYM.put( OBJ_ripemd160, SN_ripemd160 );
        OID_TO_SYM.put( OBJ_ripemd160WithRSA, SN_ripemd160WithRSA );
        OID_TO_SYM.put( OBJ_sxnet, SN_sxnet );
        OID_TO_SYM.put( OBJ_X500, SN_X500 );
        OID_TO_SYM.put( OBJ_commonName, SN_commonName );
        OID_TO_SYM.put( OBJ_surname, SN_surname );
        OID_TO_SYM.put( OBJ_serialNumber, LN_serialNumber );
        OID_TO_SYM.put( OBJ_countryName, SN_countryName );
        OID_TO_SYM.put( OBJ_localityName, SN_localityName );
        OID_TO_SYM.put( OBJ_stateOrProvinceName, SN_stateOrProvinceName );
        OID_TO_SYM.put( OBJ_streetAddress, SN_streetAddress );
        OID_TO_SYM.put( OBJ_organizationName, SN_organizationName );
        OID_TO_SYM.put( OBJ_organizationalUnitName, SN_organizationalUnitName );
        OID_TO_SYM.put( OBJ_title, SN_title );
        OID_TO_SYM.put( OBJ_description, LN_description );
        OID_TO_SYM.put( OBJ_searchGuide, LN_searchGuide );
        OID_TO_SYM.put( OBJ_businessCategory, LN_businessCategory );
        OID_TO_SYM.put( OBJ_postalAddress, LN_postalAddress );
        OID_TO_SYM.put( OBJ_postalCode, LN_postalCode );
        OID_TO_SYM.put( OBJ_postOfficeBox, LN_postOfficeBox );
        OID_TO_SYM.put( OBJ_physicalDeliveryOfficeName, LN_physicalDeliveryOfficeName );
        OID_TO_SYM.put( OBJ_telephoneNumber, LN_telephoneNumber );
        OID_TO_SYM.put( OBJ_telexNumber, LN_telexNumber );
        OID_TO_SYM.put( OBJ_teletexTerminalIdentifier, LN_teletexTerminalIdentifier );
        OID_TO_SYM.put( OBJ_facsimileTelephoneNumber, LN_facsimileTelephoneNumber );
        OID_TO_SYM.put( OBJ_x121Address, LN_x121Address );
        OID_TO_SYM.put( OBJ_internationaliSDNNumber, LN_internationaliSDNNumber );
        OID_TO_SYM.put( OBJ_registeredAddress, LN_registeredAddress );
        OID_TO_SYM.put( OBJ_destinationIndicator, LN_destinationIndicator );
        OID_TO_SYM.put( OBJ_preferredDeliveryMethod, LN_preferredDeliveryMethod );
        OID_TO_SYM.put( OBJ_presentationAddress, LN_presentationAddress );
        OID_TO_SYM.put( OBJ_supportedApplicationContext, LN_supportedApplicationContext );
        OID_TO_SYM.put( OBJ_roleOccupant, LN_roleOccupant );
        OID_TO_SYM.put( OBJ_userPassword, LN_userPassword );
        OID_TO_SYM.put( OBJ_userCertificate, LN_userCertificate );
        OID_TO_SYM.put( OBJ_cACertificate, LN_cACertificate );
        OID_TO_SYM.put( OBJ_authorityRevocationList, LN_authorityRevocationList );
        OID_TO_SYM.put( OBJ_certificateRevocationList, LN_certificateRevocationList );
        OID_TO_SYM.put( OBJ_crossCertificatePair, LN_crossCertificatePair );
        OID_TO_SYM.put( OBJ_name, SN_name );
        OID_TO_SYM.put( OBJ_givenName, SN_givenName );
        OID_TO_SYM.put( OBJ_initials, SN_initials );
        OID_TO_SYM.put( OBJ_generationQualifier, LN_generationQualifier );
        OID_TO_SYM.put( OBJ_x500UniqueIdentifier, LN_x500UniqueIdentifier );
        OID_TO_SYM.put( OBJ_dnQualifier, SN_dnQualifier );
        OID_TO_SYM.put( OBJ_enhancedSearchGuide, LN_enhancedSearchGuide );
        OID_TO_SYM.put( OBJ_protocolInformation, LN_protocolInformation );
        OID_TO_SYM.put( OBJ_distinguishedName, LN_distinguishedName );
        OID_TO_SYM.put( OBJ_uniqueMember, LN_uniqueMember );
        OID_TO_SYM.put( OBJ_houseIdentifier, LN_houseIdentifier );
        OID_TO_SYM.put( OBJ_supportedAlgorithms, LN_supportedAlgorithms );
        OID_TO_SYM.put( OBJ_deltaRevocationList, LN_deltaRevocationList );
        OID_TO_SYM.put( OBJ_pseudonym, LN_pseudonym );
        OID_TO_SYM.put( OBJ_role, SN_role );
        OID_TO_SYM.put( OBJ_X500algorithms, SN_X500algorithms );
        OID_TO_SYM.put( OBJ_rsa, SN_rsa );
        OID_TO_SYM.put( OBJ_mdc2WithRSA, SN_mdc2WithRSA );
        OID_TO_SYM.put( OBJ_mdc2, SN_mdc2 );
        OID_TO_SYM.put( OBJ_subject_directory_attributes, SN_subject_directory_attributes );
        OID_TO_SYM.put( OBJ_subject_key_identifier, SN_subject_key_identifier );
        OID_TO_SYM.put( OBJ_key_usage, SN_key_usage );
        OID_TO_SYM.put( OBJ_private_key_usage_period, SN_private_key_usage_period );
        OID_TO_SYM.put( OBJ_subject_alt_name, SN_subject_alt_name );
        OID_TO_SYM.put( OBJ_issuer_alt_name, SN_issuer_alt_name );
        OID_TO_SYM.put( OBJ_basic_constraints, SN_basic_constraints );
        OID_TO_SYM.put( OBJ_crl_number, SN_crl_number );
        OID_TO_SYM.put( OBJ_crl_reason, SN_crl_reason );
        OID_TO_SYM.put( OBJ_invalidity_date, SN_invalidity_date );
        OID_TO_SYM.put( OBJ_delta_crl, SN_delta_crl );
        OID_TO_SYM.put( OBJ_issuing_distribution_point, SN_issuing_distribution_point );
        OID_TO_SYM.put( OBJ_certificate_issuer, SN_certificate_issuer );
        OID_TO_SYM.put( OBJ_name_constraints, SN_name_constraints );
        OID_TO_SYM.put( OBJ_crl_distribution_points, SN_crl_distribution_points );
        OID_TO_SYM.put( OBJ_certificate_policies, SN_certificate_policies );
        OID_TO_SYM.put( OBJ_any_policy, SN_any_policy );
        OID_TO_SYM.put( OBJ_policy_mappings, SN_policy_mappings );
        OID_TO_SYM.put( OBJ_authority_key_identifier, SN_authority_key_identifier );
        OID_TO_SYM.put( OBJ_policy_constraints, SN_policy_constraints );
        OID_TO_SYM.put( OBJ_ext_key_usage, SN_ext_key_usage );
        OID_TO_SYM.put( OBJ_freshest_crl, SN_freshest_crl );
        OID_TO_SYM.put( OBJ_inhibit_any_policy, SN_inhibit_any_policy );
        OID_TO_SYM.put( OBJ_target_information, SN_target_information );
        OID_TO_SYM.put( OBJ_no_rev_avail, SN_no_rev_avail );
        OID_TO_SYM.put( OBJ_anyExtendedKeyUsage, SN_anyExtendedKeyUsage );
        OID_TO_SYM.put( OBJ_netscape, SN_netscape );
        OID_TO_SYM.put( OBJ_netscape_cert_extension, SN_netscape_cert_extension );
        OID_TO_SYM.put( OBJ_netscape_data_type, SN_netscape_data_type );
        OID_TO_SYM.put( OBJ_netscape_cert_type, SN_netscape_cert_type );
        OID_TO_SYM.put( OBJ_netscape_base_url, SN_netscape_base_url );
        OID_TO_SYM.put( OBJ_netscape_revocation_url, SN_netscape_revocation_url );
        OID_TO_SYM.put( OBJ_netscape_ca_revocation_url, SN_netscape_ca_revocation_url );
        OID_TO_SYM.put( OBJ_netscape_renewal_url, SN_netscape_renewal_url );
        OID_TO_SYM.put( OBJ_netscape_ca_policy_url, SN_netscape_ca_policy_url );
        OID_TO_SYM.put( OBJ_netscape_ssl_server_name, SN_netscape_ssl_server_name );
        OID_TO_SYM.put( OBJ_netscape_comment, SN_netscape_comment );
        OID_TO_SYM.put( OBJ_netscape_cert_sequence, SN_netscape_cert_sequence );
        OID_TO_SYM.put( OBJ_ns_sgc, SN_ns_sgc );
        OID_TO_SYM.put( OBJ_org, SN_org );
        OID_TO_SYM.put( OBJ_dod, SN_dod );
        OID_TO_SYM.put( OBJ_iana, SN_iana );
        OID_TO_SYM.put( OBJ_Directory, SN_Directory );
        OID_TO_SYM.put( OBJ_Management, SN_Management );
        OID_TO_SYM.put( OBJ_Experimental, SN_Experimental );
        OID_TO_SYM.put( OBJ_Private, SN_Private );
        OID_TO_SYM.put( OBJ_Security, SN_Security );
        OID_TO_SYM.put( OBJ_SNMPv2, SN_SNMPv2 );
        OID_TO_SYM.put( OBJ_Mail, LN_Mail );
        OID_TO_SYM.put( OBJ_Enterprises, SN_Enterprises );
        OID_TO_SYM.put( OBJ_dcObject, SN_dcObject );
        OID_TO_SYM.put( OBJ_mime_mhs, SN_mime_mhs );
        OID_TO_SYM.put( OBJ_mime_mhs_headings, SN_mime_mhs_headings );
        OID_TO_SYM.put( OBJ_mime_mhs_bodies, SN_mime_mhs_bodies );
        OID_TO_SYM.put( OBJ_id_hex_partial_message, SN_id_hex_partial_message );
        OID_TO_SYM.put( OBJ_id_hex_multipart_message, SN_id_hex_multipart_message );
        OID_TO_SYM.put( OBJ_rle_compression, SN_rle_compression );
        OID_TO_SYM.put( OBJ_zlib_compression, SN_zlib_compression );
        OID_TO_SYM.put( OBJ_aes_128_ecb, SN_aes_128_ecb );
        OID_TO_SYM.put( OBJ_aes_128_cbc, SN_aes_128_cbc );
        OID_TO_SYM.put( OBJ_aes_128_ofb128, SN_aes_128_ofb128 );
        OID_TO_SYM.put( OBJ_aes_128_cfb128, SN_aes_128_cfb128 );
        OID_TO_SYM.put( OBJ_aes_128_gcm, SN_aes_128_gcm );
        OID_TO_SYM.put( OBJ_aes_128_ccm, SN_aes_128_ccm );
        OID_TO_SYM.put( OBJ_aes_192_ecb, SN_aes_192_ecb );
        OID_TO_SYM.put( OBJ_aes_192_cbc, SN_aes_192_cbc );
        OID_TO_SYM.put( OBJ_aes_192_ofb128, SN_aes_192_ofb128 );
        OID_TO_SYM.put( OBJ_aes_192_cfb128, SN_aes_192_cfb128 );
        OID_TO_SYM.put( OBJ_aes_192_gcm, SN_aes_192_gcm );
        OID_TO_SYM.put( OBJ_aes_192_ccm, SN_aes_192_ccm );
        OID_TO_SYM.put( OBJ_aes_256_ecb, SN_aes_256_ecb );
        OID_TO_SYM.put( OBJ_aes_256_cbc, SN_aes_256_cbc );
        OID_TO_SYM.put( OBJ_aes_256_ofb128, SN_aes_256_ofb128 );
        OID_TO_SYM.put( OBJ_aes_256_cfb128, SN_aes_256_cfb128 );
        OID_TO_SYM.put( OBJ_aes_256_gcm, SN_aes_256_gcm );
        OID_TO_SYM.put( OBJ_aes_256_ccm, SN_aes_256_ccm );
        OID_TO_SYM.put( OBJ_sha256, SN_sha256 );
        OID_TO_SYM.put( OBJ_sha384, SN_sha384 );
        OID_TO_SYM.put( OBJ_sha512, SN_sha512 );
        OID_TO_SYM.put( OBJ_sha224, SN_sha224 );
        OID_TO_SYM.put( OBJ_hold_instruction_code, SN_hold_instruction_code );
        OID_TO_SYM.put( OBJ_hold_instruction_none, SN_hold_instruction_none );
        OID_TO_SYM.put( OBJ_hold_instruction_call_issuer, SN_hold_instruction_call_issuer );
        OID_TO_SYM.put( OBJ_hold_instruction_reject, SN_hold_instruction_reject );
        OID_TO_SYM.put( OBJ_pilotAttributeType, LN_pilotAttributeType );
        OID_TO_SYM.put( OBJ_pilotAttributeSyntax, LN_pilotAttributeSyntax );
        OID_TO_SYM.put( OBJ_pilotObjectClass, LN_pilotObjectClass );
        OID_TO_SYM.put( OBJ_pilotGroups, LN_pilotGroups );
        OID_TO_SYM.put( OBJ_iA5StringSyntax, LN_iA5StringSyntax );
        OID_TO_SYM.put( OBJ_caseIgnoreIA5StringSyntax, LN_caseIgnoreIA5StringSyntax );
        OID_TO_SYM.put( OBJ_pilotObject, LN_pilotObject );
        OID_TO_SYM.put( OBJ_pilotPerson, LN_pilotPerson );
        OID_TO_SYM.put( OBJ_documentSeries, LN_documentSeries );
        OID_TO_SYM.put( OBJ_Domain, SN_Domain );
        OID_TO_SYM.put( OBJ_rFC822localPart, LN_rFC822localPart );
        OID_TO_SYM.put( OBJ_dNSDomain, LN_dNSDomain );
        OID_TO_SYM.put( OBJ_domainRelatedObject, LN_domainRelatedObject );
        OID_TO_SYM.put( OBJ_friendlyCountry, LN_friendlyCountry );
        OID_TO_SYM.put( OBJ_simpleSecurityObject, LN_simpleSecurityObject );
        OID_TO_SYM.put( OBJ_pilotOrganization, LN_pilotOrganization );
        OID_TO_SYM.put( OBJ_pilotDSA, LN_pilotDSA );
        OID_TO_SYM.put( OBJ_qualityLabelledData, LN_qualityLabelledData );
        OID_TO_SYM.put( OBJ_userId, SN_userId );
        OID_TO_SYM.put( OBJ_textEncodedORAddress, LN_textEncodedORAddress );
        OID_TO_SYM.put( OBJ_rfc822Mailbox, SN_rfc822Mailbox );
        OID_TO_SYM.put( OBJ_favouriteDrink, LN_favouriteDrink );
        OID_TO_SYM.put( OBJ_roomNumber, LN_roomNumber );
        OID_TO_SYM.put( OBJ_userClass, LN_userClass );
        OID_TO_SYM.put( OBJ_documentIdentifier, LN_documentIdentifier );
        OID_TO_SYM.put( OBJ_documentTitle, LN_documentTitle );
        OID_TO_SYM.put( OBJ_documentVersion, LN_documentVersion );
        OID_TO_SYM.put( OBJ_documentAuthor, LN_documentAuthor );
        OID_TO_SYM.put( OBJ_documentLocation, LN_documentLocation );
        OID_TO_SYM.put( OBJ_homeTelephoneNumber, LN_homeTelephoneNumber );
        OID_TO_SYM.put( OBJ_otherMailbox, LN_otherMailbox );
        OID_TO_SYM.put( OBJ_lastModifiedTime, LN_lastModifiedTime );
        OID_TO_SYM.put( OBJ_lastModifiedBy, LN_lastModifiedBy );
        OID_TO_SYM.put( OBJ_domainComponent, SN_domainComponent );
        OID_TO_SYM.put( OBJ_aRecord, LN_aRecord );
        OID_TO_SYM.put( OBJ_pilotAttributeType27, LN_pilotAttributeType27 );
        OID_TO_SYM.put( OBJ_mXRecord, LN_mXRecord );
        OID_TO_SYM.put( OBJ_nSRecord, LN_nSRecord );
        OID_TO_SYM.put( OBJ_sOARecord, LN_sOARecord );
        OID_TO_SYM.put( OBJ_cNAMERecord, LN_cNAMERecord );
        OID_TO_SYM.put( OBJ_associatedDomain, LN_associatedDomain );
        OID_TO_SYM.put( OBJ_associatedName, LN_associatedName );
        OID_TO_SYM.put( OBJ_homePostalAddress, LN_homePostalAddress );
        OID_TO_SYM.put( OBJ_personalTitle, LN_personalTitle );
        OID_TO_SYM.put( OBJ_mobileTelephoneNumber, LN_mobileTelephoneNumber );
        OID_TO_SYM.put( OBJ_pagerTelephoneNumber, LN_pagerTelephoneNumber );
        OID_TO_SYM.put( OBJ_friendlyCountryName, LN_friendlyCountryName );
        OID_TO_SYM.put( OBJ_organizationalStatus, LN_organizationalStatus );
        OID_TO_SYM.put( OBJ_janetMailbox, LN_janetMailbox );
        OID_TO_SYM.put( OBJ_mailPreferenceOption, LN_mailPreferenceOption );
        OID_TO_SYM.put( OBJ_buildingName, LN_buildingName );
        OID_TO_SYM.put( OBJ_dSAQuality, LN_dSAQuality );
        OID_TO_SYM.put( OBJ_singleLevelQuality, LN_singleLevelQuality );
        OID_TO_SYM.put( OBJ_subtreeMinimumQuality, LN_subtreeMinimumQuality );
        OID_TO_SYM.put( OBJ_subtreeMaximumQuality, LN_subtreeMaximumQuality );
        OID_TO_SYM.put( OBJ_personalSignature, LN_personalSignature );
        OID_TO_SYM.put( OBJ_dITRedirect, LN_dITRedirect );
        OID_TO_SYM.put( OBJ_documentPublisher, LN_documentPublisher );
        OID_TO_SYM.put( OBJ_id_set, SN_id_set );
        OID_TO_SYM.put( OBJ_set_ctype, SN_set_ctype );
        OID_TO_SYM.put( OBJ_set_msgExt, SN_set_msgExt );
        OID_TO_SYM.put( OBJ_set_certExt, SN_set_certExt );
        OID_TO_SYM.put( OBJ_setext_genCrypt, SN_setext_genCrypt );
        OID_TO_SYM.put( OBJ_setext_miAuth, SN_setext_miAuth );
        OID_TO_SYM.put( OBJ_setext_cv, SN_setext_cv );
        OID_TO_SYM.put( OBJ_setAttr_PGWYcap, SN_setAttr_PGWYcap );
        OID_TO_SYM.put( OBJ_setAttr_IssCap, SN_setAttr_IssCap );
        OID_TO_SYM.put( OBJ_setAttr_GenCryptgrm, SN_setAttr_GenCryptgrm );
        OID_TO_SYM.put( OBJ_setAttr_T2Enc, SN_setAttr_T2Enc );
        OID_TO_SYM.put( OBJ_setAttr_T2cleartxt, SN_setAttr_T2cleartxt );
        OID_TO_SYM.put( OBJ_setAttr_TokICCsig, SN_setAttr_TokICCsig );
        OID_TO_SYM.put( OBJ_setAttr_SecDevSig, SN_setAttr_SecDevSig );
        OID_TO_SYM.put( OBJ_des_cdmf, SN_des_cdmf );
        OID_TO_SYM.put( OBJ_id_GostR3411_94_with_GostR3410_2001, SN_id_GostR3411_94_with_GostR3410_2001 );
        OID_TO_SYM.put( OBJ_id_GostR3411_94_with_GostR3410_94, SN_id_GostR3411_94_with_GostR3410_94 );
        OID_TO_SYM.put( OBJ_id_GostR3411_94, SN_id_GostR3411_94 );
        OID_TO_SYM.put( OBJ_id_HMACGostR3411_94, SN_id_HMACGostR3411_94 );
        OID_TO_SYM.put( OBJ_id_GostR3410_2001, SN_id_GostR3410_2001 );
        OID_TO_SYM.put( OBJ_id_GostR3410_94, SN_id_GostR3410_94 );
        OID_TO_SYM.put( OBJ_id_Gost28147_89, SN_id_Gost28147_89 );
        OID_TO_SYM.put( OBJ_id_Gost28147_89_MAC, SN_id_Gost28147_89_MAC );
        OID_TO_SYM.put( OBJ_id_GostR3411_94_prf, SN_id_GostR3411_94_prf );
        OID_TO_SYM.put( OBJ_id_GostR3410_2001DH, SN_id_GostR3410_2001DH );
        OID_TO_SYM.put( OBJ_id_GostR3410_94DH, SN_id_GostR3410_94DH );
        OID_TO_SYM.put( OBJ_id_Gost28147_89_cc, SN_id_Gost28147_89_cc );
        OID_TO_SYM.put( OBJ_id_GostR3410_94_cc, SN_id_GostR3410_94_cc );
        OID_TO_SYM.put( OBJ_id_GostR3410_2001_cc, SN_id_GostR3410_2001_cc );
        OID_TO_SYM.put( OBJ_id_GostR3411_94_with_GostR3410_94_cc, SN_id_GostR3411_94_with_GostR3410_94_cc );
        OID_TO_SYM.put( OBJ_id_GostR3411_94_with_GostR3410_2001_cc, SN_id_GostR3411_94_with_GostR3410_2001_cc );
        OID_TO_SYM.put( OBJ_id_GostR3410_2001_ParamSet_cc, SN_id_GostR3410_2001_ParamSet_cc );
        OID_TO_SYM.put( OBJ_camellia_128_cbc, SN_camellia_128_cbc );
        OID_TO_SYM.put( OBJ_camellia_192_cbc, SN_camellia_192_cbc );
        OID_TO_SYM.put( OBJ_camellia_256_cbc, SN_camellia_256_cbc );
        OID_TO_SYM.put( OBJ_camellia_128_ecb, SN_camellia_128_ecb );
        OID_TO_SYM.put( OBJ_camellia_128_ofb128, SN_camellia_128_ofb128 );
        OID_TO_SYM.put( OBJ_camellia_128_cfb128, SN_camellia_128_cfb128 );
        OID_TO_SYM.put( OBJ_camellia_192_ecb, SN_camellia_192_ecb );
        OID_TO_SYM.put( OBJ_camellia_192_ofb128, SN_camellia_192_ofb128 );
        OID_TO_SYM.put( OBJ_camellia_192_cfb128, SN_camellia_192_cfb128 );
        OID_TO_SYM.put( OBJ_camellia_256_ecb, SN_camellia_256_ecb );
        OID_TO_SYM.put( OBJ_camellia_256_ofb128, SN_camellia_256_ofb128 );
        OID_TO_SYM.put( OBJ_camellia_256_cfb128, SN_camellia_256_cfb128 );
        OID_TO_SYM.put( OBJ_kisa, SN_kisa );
        OID_TO_SYM.put( OBJ_seed_ecb, SN_seed_ecb );
        OID_TO_SYM.put( OBJ_seed_cbc, SN_seed_cbc );
        OID_TO_SYM.put( OBJ_seed_cfb128, SN_seed_cfb128 );
        OID_TO_SYM.put( OBJ_seed_ofb128, SN_seed_ofb128 );
        OID_TO_SYM.put( OBJ_dhpublicnumber, SN_dhpublicnumber );
        OID_TO_SYM.put( OBJ_ct_precert_scts, SN_ct_precert_scts );
        OID_TO_SYM.put( OBJ_ct_precert_poison, SN_ct_precert_poison );
        OID_TO_SYM.put( OBJ_ct_precert_signer, SN_ct_precert_signer );
        OID_TO_SYM.put( OBJ_ct_cert_scts, SN_ct_cert_scts );
        OID_TO_SYM.put( OBJ_jurisdictionLocalityName, SN_jurisdictionLocalityName );
        OID_TO_SYM.put( OBJ_jurisdictionStateOrProvinceName, SN_jurisdictionStateOrProvinceName );
        OID_TO_SYM.put( OBJ_jurisdictionCountryName, SN_jurisdictionCountryName );
    }
    

    private static final HashMap<String, Integer> OID_TO_NID = new HashMap<String, Integer>(1052, 1);
    static {
        OID_TO_NID.put( OBJ_undef, Integer.valueOf( NID_undef ) );
        OID_TO_NID.put( OBJ_itu_t, Integer.valueOf( NID_itu_t ) );
        OID_TO_NID.put( OBJ_ccitt, Integer.valueOf( NID_ccitt ) );
        OID_TO_NID.put( OBJ_iso, Integer.valueOf( NID_iso ) );
        OID_TO_NID.put( OBJ_joint_iso_itu_t, Integer.valueOf( NID_joint_iso_itu_t ) );
        OID_TO_NID.put( OBJ_joint_iso_ccitt, Integer.valueOf( NID_joint_iso_ccitt ) );
        OID_TO_NID.put( OBJ_member_body, Integer.valueOf( NID_member_body ) );
        OID_TO_NID.put( OBJ_identified_organization, Integer.valueOf( NID_identified_organization ) );
        OID_TO_NID.put( OBJ_hmac_md5, Integer.valueOf( NID_hmac_md5 ) );
        OID_TO_NID.put( OBJ_hmac_sha1, Integer.valueOf( NID_hmac_sha1 ) );
        OID_TO_NID.put( OBJ_certicom_arc, Integer.valueOf( NID_certicom_arc ) );
        OID_TO_NID.put( OBJ_international_organizations, Integer.valueOf( NID_international_organizations ) );
        OID_TO_NID.put( OBJ_wap, Integer.valueOf( NID_wap ) );
        OID_TO_NID.put( OBJ_wap_wsg, Integer.valueOf( NID_wap_wsg ) );
        OID_TO_NID.put( OBJ_selected_attribute_types, Integer.valueOf( NID_selected_attribute_types ) );
        OID_TO_NID.put( OBJ_clearance, Integer.valueOf( NID_clearance ) );
        OID_TO_NID.put( OBJ_ISO_US, Integer.valueOf( NID_ISO_US ) );
        OID_TO_NID.put( OBJ_X9_57, Integer.valueOf( NID_X9_57 ) );
        OID_TO_NID.put( OBJ_X9cm, Integer.valueOf( NID_X9cm ) );
        OID_TO_NID.put( OBJ_dsa, Integer.valueOf( NID_dsa ) );
        OID_TO_NID.put( OBJ_dsaWithSHA1, Integer.valueOf( NID_dsaWithSHA1 ) );
        OID_TO_NID.put( OBJ_ansi_X9_62, Integer.valueOf( NID_ansi_X9_62 ) );
        OID_TO_NID.put( OBJ_X9_62_prime_field, Integer.valueOf( NID_X9_62_prime_field ) );
        OID_TO_NID.put( OBJ_X9_62_characteristic_two_field, Integer.valueOf( NID_X9_62_characteristic_two_field ) );
        OID_TO_NID.put( OBJ_X9_62_id_characteristic_two_basis, Integer.valueOf( NID_X9_62_id_characteristic_two_basis ) );
        OID_TO_NID.put( OBJ_X9_62_onBasis, Integer.valueOf( NID_X9_62_onBasis ) );
        OID_TO_NID.put( OBJ_X9_62_tpBasis, Integer.valueOf( NID_X9_62_tpBasis ) );
        OID_TO_NID.put( OBJ_X9_62_ppBasis, Integer.valueOf( NID_X9_62_ppBasis ) );
        OID_TO_NID.put( OBJ_X9_62_id_ecPublicKey, Integer.valueOf( NID_X9_62_id_ecPublicKey ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb163v1, Integer.valueOf( NID_X9_62_c2pnb163v1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb163v2, Integer.valueOf( NID_X9_62_c2pnb163v2 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb163v3, Integer.valueOf( NID_X9_62_c2pnb163v3 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb176v1, Integer.valueOf( NID_X9_62_c2pnb176v1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb191v1, Integer.valueOf( NID_X9_62_c2tnb191v1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb191v2, Integer.valueOf( NID_X9_62_c2tnb191v2 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb191v3, Integer.valueOf( NID_X9_62_c2tnb191v3 ) );
        OID_TO_NID.put( OBJ_X9_62_c2onb191v4, Integer.valueOf( NID_X9_62_c2onb191v4 ) );
        OID_TO_NID.put( OBJ_X9_62_c2onb191v5, Integer.valueOf( NID_X9_62_c2onb191v5 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb208w1, Integer.valueOf( NID_X9_62_c2pnb208w1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb239v1, Integer.valueOf( NID_X9_62_c2tnb239v1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb239v2, Integer.valueOf( NID_X9_62_c2tnb239v2 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb239v3, Integer.valueOf( NID_X9_62_c2tnb239v3 ) );
        OID_TO_NID.put( OBJ_X9_62_c2onb239v4, Integer.valueOf( NID_X9_62_c2onb239v4 ) );
        OID_TO_NID.put( OBJ_X9_62_c2onb239v5, Integer.valueOf( NID_X9_62_c2onb239v5 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb272w1, Integer.valueOf( NID_X9_62_c2pnb272w1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb304w1, Integer.valueOf( NID_X9_62_c2pnb304w1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb359v1, Integer.valueOf( NID_X9_62_c2tnb359v1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2pnb368w1, Integer.valueOf( NID_X9_62_c2pnb368w1 ) );
        OID_TO_NID.put( OBJ_X9_62_c2tnb431r1, Integer.valueOf( NID_X9_62_c2tnb431r1 ) );
        OID_TO_NID.put( OBJ_X9_62_prime192v1, Integer.valueOf( NID_X9_62_prime192v1 ) );
        OID_TO_NID.put( OBJ_X9_62_prime192v2, Integer.valueOf( NID_X9_62_prime192v2 ) );
        OID_TO_NID.put( OBJ_X9_62_prime192v3, Integer.valueOf( NID_X9_62_prime192v3 ) );
        OID_TO_NID.put( OBJ_X9_62_prime239v1, Integer.valueOf( NID_X9_62_prime239v1 ) );
        OID_TO_NID.put( OBJ_X9_62_prime239v2, Integer.valueOf( NID_X9_62_prime239v2 ) );
        OID_TO_NID.put( OBJ_X9_62_prime239v3, Integer.valueOf( NID_X9_62_prime239v3 ) );
        OID_TO_NID.put( OBJ_X9_62_prime256v1, Integer.valueOf( NID_X9_62_prime256v1 ) );
        OID_TO_NID.put( OBJ_ecdsa_with_SHA1, Integer.valueOf( NID_ecdsa_with_SHA1 ) );
        OID_TO_NID.put( OBJ_ecdsa_with_Recommended, Integer.valueOf( NID_ecdsa_with_Recommended ) );
        OID_TO_NID.put( OBJ_ecdsa_with_Specified, Integer.valueOf( NID_ecdsa_with_Specified ) );
        OID_TO_NID.put( OBJ_ecdsa_with_SHA224, Integer.valueOf( NID_ecdsa_with_SHA224 ) );
        OID_TO_NID.put( OBJ_ecdsa_with_SHA256, Integer.valueOf( NID_ecdsa_with_SHA256 ) );
        OID_TO_NID.put( OBJ_ecdsa_with_SHA384, Integer.valueOf( NID_ecdsa_with_SHA384 ) );
        OID_TO_NID.put( OBJ_ecdsa_with_SHA512, Integer.valueOf( NID_ecdsa_with_SHA512 ) );
        OID_TO_NID.put( OBJ_secp112r1, Integer.valueOf( NID_secp112r1 ) );
        OID_TO_NID.put( OBJ_secp112r2, Integer.valueOf( NID_secp112r2 ) );
        OID_TO_NID.put( OBJ_secp128r1, Integer.valueOf( NID_secp128r1 ) );
        OID_TO_NID.put( OBJ_secp128r2, Integer.valueOf( NID_secp128r2 ) );
        OID_TO_NID.put( OBJ_secp160k1, Integer.valueOf( NID_secp160k1 ) );
        OID_TO_NID.put( OBJ_secp160r1, Integer.valueOf( NID_secp160r1 ) );
        OID_TO_NID.put( OBJ_secp160r2, Integer.valueOf( NID_secp160r2 ) );
        OID_TO_NID.put( OBJ_secp192k1, Integer.valueOf( NID_secp192k1 ) );
        OID_TO_NID.put( OBJ_secp224k1, Integer.valueOf( NID_secp224k1 ) );
        OID_TO_NID.put( OBJ_secp224r1, Integer.valueOf( NID_secp224r1 ) );
        OID_TO_NID.put( OBJ_secp256k1, Integer.valueOf( NID_secp256k1 ) );
        OID_TO_NID.put( OBJ_secp384r1, Integer.valueOf( NID_secp384r1 ) );
        OID_TO_NID.put( OBJ_secp521r1, Integer.valueOf( NID_secp521r1 ) );
        OID_TO_NID.put( OBJ_sect113r1, Integer.valueOf( NID_sect113r1 ) );
        OID_TO_NID.put( OBJ_sect113r2, Integer.valueOf( NID_sect113r2 ) );
        OID_TO_NID.put( OBJ_sect131r1, Integer.valueOf( NID_sect131r1 ) );
        OID_TO_NID.put( OBJ_sect131r2, Integer.valueOf( NID_sect131r2 ) );
        OID_TO_NID.put( OBJ_sect163k1, Integer.valueOf( NID_sect163k1 ) );
        OID_TO_NID.put( OBJ_sect163r1, Integer.valueOf( NID_sect163r1 ) );
        OID_TO_NID.put( OBJ_sect163r2, Integer.valueOf( NID_sect163r2 ) );
        OID_TO_NID.put( OBJ_sect193r1, Integer.valueOf( NID_sect193r1 ) );
        OID_TO_NID.put( OBJ_sect193r2, Integer.valueOf( NID_sect193r2 ) );
        OID_TO_NID.put( OBJ_sect233k1, Integer.valueOf( NID_sect233k1 ) );
        OID_TO_NID.put( OBJ_sect233r1, Integer.valueOf( NID_sect233r1 ) );
        OID_TO_NID.put( OBJ_sect239k1, Integer.valueOf( NID_sect239k1 ) );
        OID_TO_NID.put( OBJ_sect283k1, Integer.valueOf( NID_sect283k1 ) );
        OID_TO_NID.put( OBJ_sect283r1, Integer.valueOf( NID_sect283r1 ) );
        OID_TO_NID.put( OBJ_sect409k1, Integer.valueOf( NID_sect409k1 ) );
        OID_TO_NID.put( OBJ_sect409r1, Integer.valueOf( NID_sect409r1 ) );
        OID_TO_NID.put( OBJ_sect571k1, Integer.valueOf( NID_sect571k1 ) );
        OID_TO_NID.put( OBJ_sect571r1, Integer.valueOf( NID_sect571r1 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls1, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls1 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls3, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls3 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls4, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls4 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls5, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls5 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls6, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls6 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls7, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls7 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls8, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls8 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls9, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls9 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls10, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls10 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls11, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls11 ) );
        OID_TO_NID.put( OBJ_wap_wsg_idm_ecid_wtls12, Integer.valueOf( NID_wap_wsg_idm_ecid_wtls12 ) );
        OID_TO_NID.put( OBJ_cast5_cbc, Integer.valueOf( NID_cast5_cbc ) );
        OID_TO_NID.put( OBJ_pbeWithMD5AndCast5_CBC, Integer.valueOf( NID_pbeWithMD5AndCast5_CBC ) );
        OID_TO_NID.put( OBJ_id_PasswordBasedMAC, Integer.valueOf( NID_id_PasswordBasedMAC ) );
        OID_TO_NID.put( OBJ_id_DHBasedMac, Integer.valueOf( NID_id_DHBasedMac ) );
        OID_TO_NID.put( OBJ_rsadsi, Integer.valueOf( NID_rsadsi ) );
        OID_TO_NID.put( OBJ_pkcs, Integer.valueOf( NID_pkcs ) );
        OID_TO_NID.put( OBJ_pkcs1, Integer.valueOf( NID_pkcs1 ) );
        OID_TO_NID.put( OBJ_rsaEncryption, Integer.valueOf( NID_rsaEncryption ) );
        OID_TO_NID.put( OBJ_md2WithRSAEncryption, Integer.valueOf( NID_md2WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_md4WithRSAEncryption, Integer.valueOf( NID_md4WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_md5WithRSAEncryption, Integer.valueOf( NID_md5WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_sha1WithRSAEncryption, Integer.valueOf( NID_sha1WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_rsaesOaep, Integer.valueOf( NID_rsaesOaep ) );
        OID_TO_NID.put( OBJ_mgf1, Integer.valueOf( NID_mgf1 ) );
        OID_TO_NID.put( OBJ_pSpecified, Integer.valueOf( NID_pSpecified ) );
        OID_TO_NID.put( OBJ_rsassaPss, Integer.valueOf( NID_rsassaPss ) );
        OID_TO_NID.put( OBJ_sha256WithRSAEncryption, Integer.valueOf( NID_sha256WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_sha384WithRSAEncryption, Integer.valueOf( NID_sha384WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_sha512WithRSAEncryption, Integer.valueOf( NID_sha512WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_sha224WithRSAEncryption, Integer.valueOf( NID_sha224WithRSAEncryption ) );
        OID_TO_NID.put( OBJ_pkcs3, Integer.valueOf( NID_pkcs3 ) );
        OID_TO_NID.put( OBJ_dhKeyAgreement, Integer.valueOf( NID_dhKeyAgreement ) );
        OID_TO_NID.put( OBJ_pkcs5, Integer.valueOf( NID_pkcs5 ) );
        OID_TO_NID.put( OBJ_pbeWithMD2AndDES_CBC, Integer.valueOf( NID_pbeWithMD2AndDES_CBC ) );
        OID_TO_NID.put( OBJ_pbeWithMD5AndDES_CBC, Integer.valueOf( NID_pbeWithMD5AndDES_CBC ) );
        OID_TO_NID.put( OBJ_pbeWithMD2AndRC2_CBC, Integer.valueOf( NID_pbeWithMD2AndRC2_CBC ) );
        OID_TO_NID.put( OBJ_pbeWithMD5AndRC2_CBC, Integer.valueOf( NID_pbeWithMD5AndRC2_CBC ) );
        OID_TO_NID.put( OBJ_pbeWithSHA1AndDES_CBC, Integer.valueOf( NID_pbeWithSHA1AndDES_CBC ) );
        OID_TO_NID.put( OBJ_pbeWithSHA1AndRC2_CBC, Integer.valueOf( NID_pbeWithSHA1AndRC2_CBC ) );
        OID_TO_NID.put( OBJ_id_pbkdf2, Integer.valueOf( NID_id_pbkdf2 ) );
        OID_TO_NID.put( OBJ_pbes2, Integer.valueOf( NID_pbes2 ) );
        OID_TO_NID.put( OBJ_pbmac1, Integer.valueOf( NID_pbmac1 ) );
        OID_TO_NID.put( OBJ_pkcs7, Integer.valueOf( NID_pkcs7 ) );
        OID_TO_NID.put( OBJ_pkcs7_data, Integer.valueOf( NID_pkcs7_data ) );
        OID_TO_NID.put( OBJ_pkcs7_signed, Integer.valueOf( NID_pkcs7_signed ) );
        OID_TO_NID.put( OBJ_pkcs7_enveloped, Integer.valueOf( NID_pkcs7_enveloped ) );
        OID_TO_NID.put( OBJ_pkcs7_signedAndEnveloped, Integer.valueOf( NID_pkcs7_signedAndEnveloped ) );
        OID_TO_NID.put( OBJ_pkcs7_digest, Integer.valueOf( NID_pkcs7_digest ) );
        OID_TO_NID.put( OBJ_pkcs7_encrypted, Integer.valueOf( NID_pkcs7_encrypted ) );
        OID_TO_NID.put( OBJ_pkcs9, Integer.valueOf( NID_pkcs9 ) );
        OID_TO_NID.put( OBJ_pkcs9_emailAddress, Integer.valueOf( NID_pkcs9_emailAddress ) );
        OID_TO_NID.put( OBJ_pkcs9_unstructuredName, Integer.valueOf( NID_pkcs9_unstructuredName ) );
        OID_TO_NID.put( OBJ_pkcs9_contentType, Integer.valueOf( NID_pkcs9_contentType ) );
        OID_TO_NID.put( OBJ_pkcs9_messageDigest, Integer.valueOf( NID_pkcs9_messageDigest ) );
        OID_TO_NID.put( OBJ_pkcs9_signingTime, Integer.valueOf( NID_pkcs9_signingTime ) );
        OID_TO_NID.put( OBJ_pkcs9_countersignature, Integer.valueOf( NID_pkcs9_countersignature ) );
        OID_TO_NID.put( OBJ_pkcs9_challengePassword, Integer.valueOf( NID_pkcs9_challengePassword ) );
        OID_TO_NID.put( OBJ_pkcs9_unstructuredAddress, Integer.valueOf( NID_pkcs9_unstructuredAddress ) );
        OID_TO_NID.put( OBJ_pkcs9_extCertAttributes, Integer.valueOf( NID_pkcs9_extCertAttributes ) );
        OID_TO_NID.put( OBJ_ext_req, Integer.valueOf( NID_ext_req ) );
        OID_TO_NID.put( OBJ_SMIMECapabilities, Integer.valueOf( NID_SMIMECapabilities ) );
        OID_TO_NID.put( OBJ_SMIME, Integer.valueOf( NID_SMIME ) );
        OID_TO_NID.put( OBJ_id_smime_mod, Integer.valueOf( NID_id_smime_mod ) );
        OID_TO_NID.put( OBJ_id_smime_ct, Integer.valueOf( NID_id_smime_ct ) );
        OID_TO_NID.put( OBJ_id_smime_aa, Integer.valueOf( NID_id_smime_aa ) );
        OID_TO_NID.put( OBJ_id_smime_alg, Integer.valueOf( NID_id_smime_alg ) );
        OID_TO_NID.put( OBJ_id_smime_cd, Integer.valueOf( NID_id_smime_cd ) );
        OID_TO_NID.put( OBJ_id_smime_spq, Integer.valueOf( NID_id_smime_spq ) );
        OID_TO_NID.put( OBJ_id_smime_cti, Integer.valueOf( NID_id_smime_cti ) );
        OID_TO_NID.put( OBJ_id_smime_mod_cms, Integer.valueOf( NID_id_smime_mod_cms ) );
        OID_TO_NID.put( OBJ_id_smime_mod_ess, Integer.valueOf( NID_id_smime_mod_ess ) );
        OID_TO_NID.put( OBJ_id_smime_mod_oid, Integer.valueOf( NID_id_smime_mod_oid ) );
        OID_TO_NID.put( OBJ_id_smime_mod_msg_v3, Integer.valueOf( NID_id_smime_mod_msg_v3 ) );
        OID_TO_NID.put( OBJ_id_smime_mod_ets_eSignature_88, Integer.valueOf( NID_id_smime_mod_ets_eSignature_88 ) );
        OID_TO_NID.put( OBJ_id_smime_mod_ets_eSignature_97, Integer.valueOf( NID_id_smime_mod_ets_eSignature_97 ) );
        OID_TO_NID.put( OBJ_id_smime_mod_ets_eSigPolicy_88, Integer.valueOf( NID_id_smime_mod_ets_eSigPolicy_88 ) );
        OID_TO_NID.put( OBJ_id_smime_mod_ets_eSigPolicy_97, Integer.valueOf( NID_id_smime_mod_ets_eSigPolicy_97 ) );
        OID_TO_NID.put( OBJ_id_smime_ct_receipt, Integer.valueOf( NID_id_smime_ct_receipt ) );
        OID_TO_NID.put( OBJ_id_smime_ct_authData, Integer.valueOf( NID_id_smime_ct_authData ) );
        OID_TO_NID.put( OBJ_id_smime_ct_publishCert, Integer.valueOf( NID_id_smime_ct_publishCert ) );
        OID_TO_NID.put( OBJ_id_smime_ct_TSTInfo, Integer.valueOf( NID_id_smime_ct_TSTInfo ) );
        OID_TO_NID.put( OBJ_id_smime_ct_TDTInfo, Integer.valueOf( NID_id_smime_ct_TDTInfo ) );
        OID_TO_NID.put( OBJ_id_smime_ct_contentInfo, Integer.valueOf( NID_id_smime_ct_contentInfo ) );
        OID_TO_NID.put( OBJ_id_smime_ct_DVCSRequestData, Integer.valueOf( NID_id_smime_ct_DVCSRequestData ) );
        OID_TO_NID.put( OBJ_id_smime_ct_DVCSResponseData, Integer.valueOf( NID_id_smime_ct_DVCSResponseData ) );
        OID_TO_NID.put( OBJ_id_smime_ct_compressedData, Integer.valueOf( NID_id_smime_ct_compressedData ) );
        OID_TO_NID.put( OBJ_id_ct_asciiTextWithCRLF, Integer.valueOf( NID_id_ct_asciiTextWithCRLF ) );
        OID_TO_NID.put( OBJ_id_smime_aa_receiptRequest, Integer.valueOf( NID_id_smime_aa_receiptRequest ) );
        OID_TO_NID.put( OBJ_id_smime_aa_securityLabel, Integer.valueOf( NID_id_smime_aa_securityLabel ) );
        OID_TO_NID.put( OBJ_id_smime_aa_mlExpandHistory, Integer.valueOf( NID_id_smime_aa_mlExpandHistory ) );
        OID_TO_NID.put( OBJ_id_smime_aa_contentHint, Integer.valueOf( NID_id_smime_aa_contentHint ) );
        OID_TO_NID.put( OBJ_id_smime_aa_msgSigDigest, Integer.valueOf( NID_id_smime_aa_msgSigDigest ) );
        OID_TO_NID.put( OBJ_id_smime_aa_encapContentType, Integer.valueOf( NID_id_smime_aa_encapContentType ) );
        OID_TO_NID.put( OBJ_id_smime_aa_contentIdentifier, Integer.valueOf( NID_id_smime_aa_contentIdentifier ) );
        OID_TO_NID.put( OBJ_id_smime_aa_macValue, Integer.valueOf( NID_id_smime_aa_macValue ) );
        OID_TO_NID.put( OBJ_id_smime_aa_equivalentLabels, Integer.valueOf( NID_id_smime_aa_equivalentLabels ) );
        OID_TO_NID.put( OBJ_id_smime_aa_contentReference, Integer.valueOf( NID_id_smime_aa_contentReference ) );
        OID_TO_NID.put( OBJ_id_smime_aa_encrypKeyPref, Integer.valueOf( NID_id_smime_aa_encrypKeyPref ) );
        OID_TO_NID.put( OBJ_id_smime_aa_signingCertificate, Integer.valueOf( NID_id_smime_aa_signingCertificate ) );
        OID_TO_NID.put( OBJ_id_smime_aa_smimeEncryptCerts, Integer.valueOf( NID_id_smime_aa_smimeEncryptCerts ) );
        OID_TO_NID.put( OBJ_id_smime_aa_timeStampToken, Integer.valueOf( NID_id_smime_aa_timeStampToken ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_sigPolicyId, Integer.valueOf( NID_id_smime_aa_ets_sigPolicyId ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_commitmentType, Integer.valueOf( NID_id_smime_aa_ets_commitmentType ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_signerLocation, Integer.valueOf( NID_id_smime_aa_ets_signerLocation ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_signerAttr, Integer.valueOf( NID_id_smime_aa_ets_signerAttr ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_otherSigCert, Integer.valueOf( NID_id_smime_aa_ets_otherSigCert ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_contentTimestamp, Integer.valueOf( NID_id_smime_aa_ets_contentTimestamp ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_CertificateRefs, Integer.valueOf( NID_id_smime_aa_ets_CertificateRefs ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_RevocationRefs, Integer.valueOf( NID_id_smime_aa_ets_RevocationRefs ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_certValues, Integer.valueOf( NID_id_smime_aa_ets_certValues ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_revocationValues, Integer.valueOf( NID_id_smime_aa_ets_revocationValues ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_escTimeStamp, Integer.valueOf( NID_id_smime_aa_ets_escTimeStamp ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_certCRLTimestamp, Integer.valueOf( NID_id_smime_aa_ets_certCRLTimestamp ) );
        OID_TO_NID.put( OBJ_id_smime_aa_ets_archiveTimeStamp, Integer.valueOf( NID_id_smime_aa_ets_archiveTimeStamp ) );
        OID_TO_NID.put( OBJ_id_smime_aa_signatureType, Integer.valueOf( NID_id_smime_aa_signatureType ) );
        OID_TO_NID.put( OBJ_id_smime_aa_dvcs_dvc, Integer.valueOf( NID_id_smime_aa_dvcs_dvc ) );
        OID_TO_NID.put( OBJ_id_smime_alg_ESDHwith3DES, Integer.valueOf( NID_id_smime_alg_ESDHwith3DES ) );
        OID_TO_NID.put( OBJ_id_smime_alg_ESDHwithRC2, Integer.valueOf( NID_id_smime_alg_ESDHwithRC2 ) );
        OID_TO_NID.put( OBJ_id_smime_alg_3DESwrap, Integer.valueOf( NID_id_smime_alg_3DESwrap ) );
        OID_TO_NID.put( OBJ_id_smime_alg_RC2wrap, Integer.valueOf( NID_id_smime_alg_RC2wrap ) );
        OID_TO_NID.put( OBJ_id_smime_alg_ESDH, Integer.valueOf( NID_id_smime_alg_ESDH ) );
        OID_TO_NID.put( OBJ_id_smime_alg_CMS3DESwrap, Integer.valueOf( NID_id_smime_alg_CMS3DESwrap ) );
        OID_TO_NID.put( OBJ_id_smime_alg_CMSRC2wrap, Integer.valueOf( NID_id_smime_alg_CMSRC2wrap ) );
        OID_TO_NID.put( OBJ_id_alg_PWRI_KEK, Integer.valueOf( NID_id_alg_PWRI_KEK ) );
        OID_TO_NID.put( OBJ_id_smime_cd_ldap, Integer.valueOf( NID_id_smime_cd_ldap ) );
        OID_TO_NID.put( OBJ_id_smime_spq_ets_sqt_uri, Integer.valueOf( NID_id_smime_spq_ets_sqt_uri ) );
        OID_TO_NID.put( OBJ_id_smime_spq_ets_sqt_unotice, Integer.valueOf( NID_id_smime_spq_ets_sqt_unotice ) );
        OID_TO_NID.put( OBJ_id_smime_cti_ets_proofOfOrigin, Integer.valueOf( NID_id_smime_cti_ets_proofOfOrigin ) );
        OID_TO_NID.put( OBJ_id_smime_cti_ets_proofOfReceipt, Integer.valueOf( NID_id_smime_cti_ets_proofOfReceipt ) );
        OID_TO_NID.put( OBJ_id_smime_cti_ets_proofOfDelivery, Integer.valueOf( NID_id_smime_cti_ets_proofOfDelivery ) );
        OID_TO_NID.put( OBJ_id_smime_cti_ets_proofOfSender, Integer.valueOf( NID_id_smime_cti_ets_proofOfSender ) );
        OID_TO_NID.put( OBJ_id_smime_cti_ets_proofOfApproval, Integer.valueOf( NID_id_smime_cti_ets_proofOfApproval ) );
        OID_TO_NID.put( OBJ_id_smime_cti_ets_proofOfCreation, Integer.valueOf( NID_id_smime_cti_ets_proofOfCreation ) );
        OID_TO_NID.put( OBJ_friendlyName, Integer.valueOf( NID_friendlyName ) );
        OID_TO_NID.put( OBJ_localKeyID, Integer.valueOf( NID_localKeyID ) );
        OID_TO_NID.put( OBJ_ms_csp_name, Integer.valueOf( NID_ms_csp_name ) );
        OID_TO_NID.put( OBJ_LocalKeySet, Integer.valueOf( NID_LocalKeySet ) );
        OID_TO_NID.put( OBJ_x509Certificate, Integer.valueOf( NID_x509Certificate ) );
        OID_TO_NID.put( OBJ_sdsiCertificate, Integer.valueOf( NID_sdsiCertificate ) );
        OID_TO_NID.put( OBJ_x509Crl, Integer.valueOf( NID_x509Crl ) );
        OID_TO_NID.put( OBJ_pbe_WithSHA1And128BitRC4, Integer.valueOf( NID_pbe_WithSHA1And128BitRC4 ) );
        OID_TO_NID.put( OBJ_pbe_WithSHA1And40BitRC4, Integer.valueOf( NID_pbe_WithSHA1And40BitRC4 ) );
        OID_TO_NID.put( OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC, Integer.valueOf( NID_pbe_WithSHA1And3_Key_TripleDES_CBC ) );
        OID_TO_NID.put( OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC, Integer.valueOf( NID_pbe_WithSHA1And2_Key_TripleDES_CBC ) );
        OID_TO_NID.put( OBJ_pbe_WithSHA1And128BitRC2_CBC, Integer.valueOf( NID_pbe_WithSHA1And128BitRC2_CBC ) );
        OID_TO_NID.put( OBJ_pbe_WithSHA1And40BitRC2_CBC, Integer.valueOf( NID_pbe_WithSHA1And40BitRC2_CBC ) );
        OID_TO_NID.put( OBJ_keyBag, Integer.valueOf( NID_keyBag ) );
        OID_TO_NID.put( OBJ_pkcs8ShroudedKeyBag, Integer.valueOf( NID_pkcs8ShroudedKeyBag ) );
        OID_TO_NID.put( OBJ_certBag, Integer.valueOf( NID_certBag ) );
        OID_TO_NID.put( OBJ_crlBag, Integer.valueOf( NID_crlBag ) );
        OID_TO_NID.put( OBJ_secretBag, Integer.valueOf( NID_secretBag ) );
        OID_TO_NID.put( OBJ_safeContentsBag, Integer.valueOf( NID_safeContentsBag ) );
        OID_TO_NID.put( OBJ_md2, Integer.valueOf( NID_md2 ) );
        OID_TO_NID.put( OBJ_md4, Integer.valueOf( NID_md4 ) );
        OID_TO_NID.put( OBJ_md5, Integer.valueOf( NID_md5 ) );
        OID_TO_NID.put( OBJ_hmacWithMD5, Integer.valueOf( NID_hmacWithMD5 ) );
        OID_TO_NID.put( OBJ_hmacWithSHA1, Integer.valueOf( NID_hmacWithSHA1 ) );
        OID_TO_NID.put( OBJ_hmacWithSHA224, Integer.valueOf( NID_hmacWithSHA224 ) );
        OID_TO_NID.put( OBJ_hmacWithSHA256, Integer.valueOf( NID_hmacWithSHA256 ) );
        OID_TO_NID.put( OBJ_hmacWithSHA384, Integer.valueOf( NID_hmacWithSHA384 ) );
        OID_TO_NID.put( OBJ_hmacWithSHA512, Integer.valueOf( NID_hmacWithSHA512 ) );
        OID_TO_NID.put( OBJ_rc2_cbc, Integer.valueOf( NID_rc2_cbc ) );
        OID_TO_NID.put( OBJ_rc4, Integer.valueOf( NID_rc4 ) );
        OID_TO_NID.put( OBJ_des_ede3_cbc, Integer.valueOf( NID_des_ede3_cbc ) );
        OID_TO_NID.put( OBJ_rc5_cbc, Integer.valueOf( NID_rc5_cbc ) );
        OID_TO_NID.put( OBJ_ms_ext_req, Integer.valueOf( NID_ms_ext_req ) );
        OID_TO_NID.put( OBJ_ms_code_ind, Integer.valueOf( NID_ms_code_ind ) );
        OID_TO_NID.put( OBJ_ms_code_com, Integer.valueOf( NID_ms_code_com ) );
        OID_TO_NID.put( OBJ_ms_ctl_sign, Integer.valueOf( NID_ms_ctl_sign ) );
        OID_TO_NID.put( OBJ_ms_sgc, Integer.valueOf( NID_ms_sgc ) );
        OID_TO_NID.put( OBJ_ms_efs, Integer.valueOf( NID_ms_efs ) );
        OID_TO_NID.put( OBJ_ms_smartcard_login, Integer.valueOf( NID_ms_smartcard_login ) );
        OID_TO_NID.put( OBJ_ms_upn, Integer.valueOf( NID_ms_upn ) );
        OID_TO_NID.put( OBJ_idea_cbc, Integer.valueOf( NID_idea_cbc ) );
        OID_TO_NID.put( OBJ_bf_cbc, Integer.valueOf( NID_bf_cbc ) );
        OID_TO_NID.put( OBJ_id_pkix, Integer.valueOf( NID_id_pkix ) );
        OID_TO_NID.put( OBJ_id_pkix_mod, Integer.valueOf( NID_id_pkix_mod ) );
        OID_TO_NID.put( OBJ_id_pe, Integer.valueOf( NID_id_pe ) );
        OID_TO_NID.put( OBJ_id_qt, Integer.valueOf( NID_id_qt ) );
        OID_TO_NID.put( OBJ_id_kp, Integer.valueOf( NID_id_kp ) );
        OID_TO_NID.put( OBJ_id_it, Integer.valueOf( NID_id_it ) );
        OID_TO_NID.put( OBJ_id_pkip, Integer.valueOf( NID_id_pkip ) );
        OID_TO_NID.put( OBJ_id_alg, Integer.valueOf( NID_id_alg ) );
        OID_TO_NID.put( OBJ_id_cmc, Integer.valueOf( NID_id_cmc ) );
        OID_TO_NID.put( OBJ_id_on, Integer.valueOf( NID_id_on ) );
        OID_TO_NID.put( OBJ_id_pda, Integer.valueOf( NID_id_pda ) );
        OID_TO_NID.put( OBJ_id_aca, Integer.valueOf( NID_id_aca ) );
        OID_TO_NID.put( OBJ_id_qcs, Integer.valueOf( NID_id_qcs ) );
        OID_TO_NID.put( OBJ_id_cct, Integer.valueOf( NID_id_cct ) );
        OID_TO_NID.put( OBJ_id_ppl, Integer.valueOf( NID_id_ppl ) );
        OID_TO_NID.put( OBJ_id_ad, Integer.valueOf( NID_id_ad ) );
        OID_TO_NID.put( OBJ_id_pkix1_explicit_88, Integer.valueOf( NID_id_pkix1_explicit_88 ) );
        OID_TO_NID.put( OBJ_id_pkix1_implicit_88, Integer.valueOf( NID_id_pkix1_implicit_88 ) );
        OID_TO_NID.put( OBJ_id_pkix1_explicit_93, Integer.valueOf( NID_id_pkix1_explicit_93 ) );
        OID_TO_NID.put( OBJ_id_pkix1_implicit_93, Integer.valueOf( NID_id_pkix1_implicit_93 ) );
        OID_TO_NID.put( OBJ_id_mod_crmf, Integer.valueOf( NID_id_mod_crmf ) );
        OID_TO_NID.put( OBJ_id_mod_cmc, Integer.valueOf( NID_id_mod_cmc ) );
        OID_TO_NID.put( OBJ_id_mod_kea_profile_88, Integer.valueOf( NID_id_mod_kea_profile_88 ) );
        OID_TO_NID.put( OBJ_id_mod_kea_profile_93, Integer.valueOf( NID_id_mod_kea_profile_93 ) );
        OID_TO_NID.put( OBJ_id_mod_cmp, Integer.valueOf( NID_id_mod_cmp ) );
        OID_TO_NID.put( OBJ_id_mod_qualified_cert_88, Integer.valueOf( NID_id_mod_qualified_cert_88 ) );
        OID_TO_NID.put( OBJ_id_mod_qualified_cert_93, Integer.valueOf( NID_id_mod_qualified_cert_93 ) );
        OID_TO_NID.put( OBJ_id_mod_attribute_cert, Integer.valueOf( NID_id_mod_attribute_cert ) );
        OID_TO_NID.put( OBJ_id_mod_timestamp_protocol, Integer.valueOf( NID_id_mod_timestamp_protocol ) );
        OID_TO_NID.put( OBJ_id_mod_ocsp, Integer.valueOf( NID_id_mod_ocsp ) );
        OID_TO_NID.put( OBJ_id_mod_dvcs, Integer.valueOf( NID_id_mod_dvcs ) );
        OID_TO_NID.put( OBJ_id_mod_cmp2000, Integer.valueOf( NID_id_mod_cmp2000 ) );
        OID_TO_NID.put( OBJ_info_access, Integer.valueOf( NID_info_access ) );
        OID_TO_NID.put( OBJ_biometricInfo, Integer.valueOf( NID_biometricInfo ) );
        OID_TO_NID.put( OBJ_qcStatements, Integer.valueOf( NID_qcStatements ) );
        OID_TO_NID.put( OBJ_ac_auditEntity, Integer.valueOf( NID_ac_auditEntity ) );
        OID_TO_NID.put( OBJ_ac_targeting, Integer.valueOf( NID_ac_targeting ) );
        OID_TO_NID.put( OBJ_aaControls, Integer.valueOf( NID_aaControls ) );
        OID_TO_NID.put( OBJ_sbgp_ipAddrBlock, Integer.valueOf( NID_sbgp_ipAddrBlock ) );
        OID_TO_NID.put( OBJ_sbgp_autonomousSysNum, Integer.valueOf( NID_sbgp_autonomousSysNum ) );
        OID_TO_NID.put( OBJ_sbgp_routerIdentifier, Integer.valueOf( NID_sbgp_routerIdentifier ) );
        OID_TO_NID.put( OBJ_ac_proxying, Integer.valueOf( NID_ac_proxying ) );
        OID_TO_NID.put( OBJ_sinfo_access, Integer.valueOf( NID_sinfo_access ) );
        OID_TO_NID.put( OBJ_proxyCertInfo, Integer.valueOf( NID_proxyCertInfo ) );
        OID_TO_NID.put( OBJ_id_qt_cps, Integer.valueOf( NID_id_qt_cps ) );
        OID_TO_NID.put( OBJ_id_qt_unotice, Integer.valueOf( NID_id_qt_unotice ) );
        OID_TO_NID.put( OBJ_textNotice, Integer.valueOf( NID_textNotice ) );
        OID_TO_NID.put( OBJ_server_auth, Integer.valueOf( NID_server_auth ) );
        OID_TO_NID.put( OBJ_client_auth, Integer.valueOf( NID_client_auth ) );
        OID_TO_NID.put( OBJ_code_sign, Integer.valueOf( NID_code_sign ) );
        OID_TO_NID.put( OBJ_email_protect, Integer.valueOf( NID_email_protect ) );
        OID_TO_NID.put( OBJ_ipsecEndSystem, Integer.valueOf( NID_ipsecEndSystem ) );
        OID_TO_NID.put( OBJ_ipsecTunnel, Integer.valueOf( NID_ipsecTunnel ) );
        OID_TO_NID.put( OBJ_ipsecUser, Integer.valueOf( NID_ipsecUser ) );
        OID_TO_NID.put( OBJ_time_stamp, Integer.valueOf( NID_time_stamp ) );
        OID_TO_NID.put( OBJ_OCSP_sign, Integer.valueOf( NID_OCSP_sign ) );
        OID_TO_NID.put( OBJ_dvcs, Integer.valueOf( NID_dvcs ) );
        OID_TO_NID.put( OBJ_id_it_caProtEncCert, Integer.valueOf( NID_id_it_caProtEncCert ) );
        OID_TO_NID.put( OBJ_id_it_signKeyPairTypes, Integer.valueOf( NID_id_it_signKeyPairTypes ) );
        OID_TO_NID.put( OBJ_id_it_encKeyPairTypes, Integer.valueOf( NID_id_it_encKeyPairTypes ) );
        OID_TO_NID.put( OBJ_id_it_preferredSymmAlg, Integer.valueOf( NID_id_it_preferredSymmAlg ) );
        OID_TO_NID.put( OBJ_id_it_caKeyUpdateInfo, Integer.valueOf( NID_id_it_caKeyUpdateInfo ) );
        OID_TO_NID.put( OBJ_id_it_currentCRL, Integer.valueOf( NID_id_it_currentCRL ) );
        OID_TO_NID.put( OBJ_id_it_unsupportedOIDs, Integer.valueOf( NID_id_it_unsupportedOIDs ) );
        OID_TO_NID.put( OBJ_id_it_subscriptionRequest, Integer.valueOf( NID_id_it_subscriptionRequest ) );
        OID_TO_NID.put( OBJ_id_it_subscriptionResponse, Integer.valueOf( NID_id_it_subscriptionResponse ) );
        OID_TO_NID.put( OBJ_id_it_keyPairParamReq, Integer.valueOf( NID_id_it_keyPairParamReq ) );
        OID_TO_NID.put( OBJ_id_it_keyPairParamRep, Integer.valueOf( NID_id_it_keyPairParamRep ) );
        OID_TO_NID.put( OBJ_id_it_revPassphrase, Integer.valueOf( NID_id_it_revPassphrase ) );
        OID_TO_NID.put( OBJ_id_it_implicitConfirm, Integer.valueOf( NID_id_it_implicitConfirm ) );
        OID_TO_NID.put( OBJ_id_it_confirmWaitTime, Integer.valueOf( NID_id_it_confirmWaitTime ) );
        OID_TO_NID.put( OBJ_id_it_origPKIMessage, Integer.valueOf( NID_id_it_origPKIMessage ) );
        OID_TO_NID.put( OBJ_id_it_suppLangTags, Integer.valueOf( NID_id_it_suppLangTags ) );
        OID_TO_NID.put( OBJ_id_regCtrl, Integer.valueOf( NID_id_regCtrl ) );
        OID_TO_NID.put( OBJ_id_regInfo, Integer.valueOf( NID_id_regInfo ) );
        OID_TO_NID.put( OBJ_id_regCtrl_regToken, Integer.valueOf( NID_id_regCtrl_regToken ) );
        OID_TO_NID.put( OBJ_id_regCtrl_authenticator, Integer.valueOf( NID_id_regCtrl_authenticator ) );
        OID_TO_NID.put( OBJ_id_regCtrl_pkiPublicationInfo, Integer.valueOf( NID_id_regCtrl_pkiPublicationInfo ) );
        OID_TO_NID.put( OBJ_id_regCtrl_pkiArchiveOptions, Integer.valueOf( NID_id_regCtrl_pkiArchiveOptions ) );
        OID_TO_NID.put( OBJ_id_regCtrl_oldCertID, Integer.valueOf( NID_id_regCtrl_oldCertID ) );
        OID_TO_NID.put( OBJ_id_regCtrl_protocolEncrKey, Integer.valueOf( NID_id_regCtrl_protocolEncrKey ) );
        OID_TO_NID.put( OBJ_id_regInfo_utf8Pairs, Integer.valueOf( NID_id_regInfo_utf8Pairs ) );
        OID_TO_NID.put( OBJ_id_regInfo_certReq, Integer.valueOf( NID_id_regInfo_certReq ) );
        OID_TO_NID.put( OBJ_id_alg_des40, Integer.valueOf( NID_id_alg_des40 ) );
        OID_TO_NID.put( OBJ_id_alg_noSignature, Integer.valueOf( NID_id_alg_noSignature ) );
        OID_TO_NID.put( OBJ_id_alg_dh_sig_hmac_sha1, Integer.valueOf( NID_id_alg_dh_sig_hmac_sha1 ) );
        OID_TO_NID.put( OBJ_id_alg_dh_pop, Integer.valueOf( NID_id_alg_dh_pop ) );
        OID_TO_NID.put( OBJ_id_cmc_statusInfo, Integer.valueOf( NID_id_cmc_statusInfo ) );
        OID_TO_NID.put( OBJ_id_cmc_identification, Integer.valueOf( NID_id_cmc_identification ) );
        OID_TO_NID.put( OBJ_id_cmc_identityProof, Integer.valueOf( NID_id_cmc_identityProof ) );
        OID_TO_NID.put( OBJ_id_cmc_dataReturn, Integer.valueOf( NID_id_cmc_dataReturn ) );
        OID_TO_NID.put( OBJ_id_cmc_transactionId, Integer.valueOf( NID_id_cmc_transactionId ) );
        OID_TO_NID.put( OBJ_id_cmc_senderNonce, Integer.valueOf( NID_id_cmc_senderNonce ) );
        OID_TO_NID.put( OBJ_id_cmc_recipientNonce, Integer.valueOf( NID_id_cmc_recipientNonce ) );
        OID_TO_NID.put( OBJ_id_cmc_addExtensions, Integer.valueOf( NID_id_cmc_addExtensions ) );
        OID_TO_NID.put( OBJ_id_cmc_encryptedPOP, Integer.valueOf( NID_id_cmc_encryptedPOP ) );
        OID_TO_NID.put( OBJ_id_cmc_decryptedPOP, Integer.valueOf( NID_id_cmc_decryptedPOP ) );
        OID_TO_NID.put( OBJ_id_cmc_lraPOPWitness, Integer.valueOf( NID_id_cmc_lraPOPWitness ) );
        OID_TO_NID.put( OBJ_id_cmc_getCert, Integer.valueOf( NID_id_cmc_getCert ) );
        OID_TO_NID.put( OBJ_id_cmc_getCRL, Integer.valueOf( NID_id_cmc_getCRL ) );
        OID_TO_NID.put( OBJ_id_cmc_revokeRequest, Integer.valueOf( NID_id_cmc_revokeRequest ) );
        OID_TO_NID.put( OBJ_id_cmc_regInfo, Integer.valueOf( NID_id_cmc_regInfo ) );
        OID_TO_NID.put( OBJ_id_cmc_responseInfo, Integer.valueOf( NID_id_cmc_responseInfo ) );
        OID_TO_NID.put( OBJ_id_cmc_queryPending, Integer.valueOf( NID_id_cmc_queryPending ) );
        OID_TO_NID.put( OBJ_id_cmc_popLinkRandom, Integer.valueOf( NID_id_cmc_popLinkRandom ) );
        OID_TO_NID.put( OBJ_id_cmc_popLinkWitness, Integer.valueOf( NID_id_cmc_popLinkWitness ) );
        OID_TO_NID.put( OBJ_id_cmc_confirmCertAcceptance, Integer.valueOf( NID_id_cmc_confirmCertAcceptance ) );
        OID_TO_NID.put( OBJ_id_on_personalData, Integer.valueOf( NID_id_on_personalData ) );
        OID_TO_NID.put( OBJ_id_on_permanentIdentifier, Integer.valueOf( NID_id_on_permanentIdentifier ) );
        OID_TO_NID.put( OBJ_id_pda_dateOfBirth, Integer.valueOf( NID_id_pda_dateOfBirth ) );
        OID_TO_NID.put( OBJ_id_pda_placeOfBirth, Integer.valueOf( NID_id_pda_placeOfBirth ) );
        OID_TO_NID.put( OBJ_id_pda_gender, Integer.valueOf( NID_id_pda_gender ) );
        OID_TO_NID.put( OBJ_id_pda_countryOfCitizenship, Integer.valueOf( NID_id_pda_countryOfCitizenship ) );
        OID_TO_NID.put( OBJ_id_pda_countryOfResidence, Integer.valueOf( NID_id_pda_countryOfResidence ) );
        OID_TO_NID.put( OBJ_id_aca_authenticationInfo, Integer.valueOf( NID_id_aca_authenticationInfo ) );
        OID_TO_NID.put( OBJ_id_aca_accessIdentity, Integer.valueOf( NID_id_aca_accessIdentity ) );
        OID_TO_NID.put( OBJ_id_aca_chargingIdentity, Integer.valueOf( NID_id_aca_chargingIdentity ) );
        OID_TO_NID.put( OBJ_id_aca_group, Integer.valueOf( NID_id_aca_group ) );
        OID_TO_NID.put( OBJ_id_aca_role, Integer.valueOf( NID_id_aca_role ) );
        OID_TO_NID.put( OBJ_id_aca_encAttrs, Integer.valueOf( NID_id_aca_encAttrs ) );
        OID_TO_NID.put( OBJ_id_qcs_pkixQCSyntax_v1, Integer.valueOf( NID_id_qcs_pkixQCSyntax_v1 ) );
        OID_TO_NID.put( OBJ_id_cct_crs, Integer.valueOf( NID_id_cct_crs ) );
        OID_TO_NID.put( OBJ_id_cct_PKIData, Integer.valueOf( NID_id_cct_PKIData ) );
        OID_TO_NID.put( OBJ_id_cct_PKIResponse, Integer.valueOf( NID_id_cct_PKIResponse ) );
        OID_TO_NID.put( OBJ_id_ppl_anyLanguage, Integer.valueOf( NID_id_ppl_anyLanguage ) );
        OID_TO_NID.put( OBJ_id_ppl_inheritAll, Integer.valueOf( NID_id_ppl_inheritAll ) );
        OID_TO_NID.put( OBJ_Independent, Integer.valueOf( NID_Independent ) );
        OID_TO_NID.put( OBJ_ad_OCSP, Integer.valueOf( NID_ad_OCSP ) );
        OID_TO_NID.put( OBJ_ad_ca_issuers, Integer.valueOf( NID_ad_ca_issuers ) );
        OID_TO_NID.put( OBJ_ad_timeStamping, Integer.valueOf( NID_ad_timeStamping ) );
        OID_TO_NID.put( OBJ_ad_dvcs, Integer.valueOf( NID_ad_dvcs ) );
        OID_TO_NID.put( OBJ_caRepository, Integer.valueOf( NID_caRepository ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_basic, Integer.valueOf( NID_id_pkix_OCSP_basic ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_Nonce, Integer.valueOf( NID_id_pkix_OCSP_Nonce ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_CrlID, Integer.valueOf( NID_id_pkix_OCSP_CrlID ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_acceptableResponses, Integer.valueOf( NID_id_pkix_OCSP_acceptableResponses ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_noCheck, Integer.valueOf( NID_id_pkix_OCSP_noCheck ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_archiveCutoff, Integer.valueOf( NID_id_pkix_OCSP_archiveCutoff ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_serviceLocator, Integer.valueOf( NID_id_pkix_OCSP_serviceLocator ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_extendedStatus, Integer.valueOf( NID_id_pkix_OCSP_extendedStatus ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_valid, Integer.valueOf( NID_id_pkix_OCSP_valid ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_path, Integer.valueOf( NID_id_pkix_OCSP_path ) );
        OID_TO_NID.put( OBJ_id_pkix_OCSP_trustRoot, Integer.valueOf( NID_id_pkix_OCSP_trustRoot ) );
        OID_TO_NID.put( OBJ_algorithm, Integer.valueOf( NID_algorithm ) );
        OID_TO_NID.put( OBJ_md5WithRSA, Integer.valueOf( NID_md5WithRSA ) );
        OID_TO_NID.put( OBJ_des_ecb, Integer.valueOf( NID_des_ecb ) );
        OID_TO_NID.put( OBJ_des_cbc, Integer.valueOf( NID_des_cbc ) );
        OID_TO_NID.put( OBJ_des_ofb64, Integer.valueOf( NID_des_ofb64 ) );
        OID_TO_NID.put( OBJ_des_cfb64, Integer.valueOf( NID_des_cfb64 ) );
        OID_TO_NID.put( OBJ_rsaSignature, Integer.valueOf( NID_rsaSignature ) );
        OID_TO_NID.put( OBJ_dsa_2, Integer.valueOf( NID_dsa_2 ) );
        OID_TO_NID.put( OBJ_dsaWithSHA, Integer.valueOf( NID_dsaWithSHA ) );
        OID_TO_NID.put( OBJ_shaWithRSAEncryption, Integer.valueOf( NID_shaWithRSAEncryption ) );
        OID_TO_NID.put( OBJ_des_ede_ecb, Integer.valueOf( NID_des_ede_ecb ) );
        OID_TO_NID.put( OBJ_sha, Integer.valueOf( NID_sha ) );
        OID_TO_NID.put( OBJ_sha1, Integer.valueOf( NID_sha1 ) );
        OID_TO_NID.put( OBJ_dsaWithSHA1_2, Integer.valueOf( NID_dsaWithSHA1_2 ) );
        OID_TO_NID.put( OBJ_sha1WithRSA, Integer.valueOf( NID_sha1WithRSA ) );
        OID_TO_NID.put( OBJ_ripemd160, Integer.valueOf( NID_ripemd160 ) );
        OID_TO_NID.put( OBJ_ripemd160WithRSA, Integer.valueOf( NID_ripemd160WithRSA ) );
        OID_TO_NID.put( OBJ_sxnet, Integer.valueOf( NID_sxnet ) );
        OID_TO_NID.put( OBJ_X500, Integer.valueOf( NID_X500 ) );
        OID_TO_NID.put( OBJ_X509, Integer.valueOf( NID_X509 ) );
        OID_TO_NID.put( OBJ_commonName, Integer.valueOf( NID_commonName ) );
        OID_TO_NID.put( OBJ_surname, Integer.valueOf( NID_surname ) );
        OID_TO_NID.put( OBJ_serialNumber, Integer.valueOf( NID_serialNumber ) );
        OID_TO_NID.put( OBJ_countryName, Integer.valueOf( NID_countryName ) );
        OID_TO_NID.put( OBJ_localityName, Integer.valueOf( NID_localityName ) );
        OID_TO_NID.put( OBJ_stateOrProvinceName, Integer.valueOf( NID_stateOrProvinceName ) );
        OID_TO_NID.put( OBJ_streetAddress, Integer.valueOf( NID_streetAddress ) );
        OID_TO_NID.put( OBJ_organizationName, Integer.valueOf( NID_organizationName ) );
        OID_TO_NID.put( OBJ_organizationalUnitName, Integer.valueOf( NID_organizationalUnitName ) );
        OID_TO_NID.put( OBJ_title, Integer.valueOf( NID_title ) );
        OID_TO_NID.put( OBJ_description, Integer.valueOf( NID_description ) );
        OID_TO_NID.put( OBJ_searchGuide, Integer.valueOf( NID_searchGuide ) );
        OID_TO_NID.put( OBJ_businessCategory, Integer.valueOf( NID_businessCategory ) );
        OID_TO_NID.put( OBJ_postalAddress, Integer.valueOf( NID_postalAddress ) );
        OID_TO_NID.put( OBJ_postalCode, Integer.valueOf( NID_postalCode ) );
        OID_TO_NID.put( OBJ_postOfficeBox, Integer.valueOf( NID_postOfficeBox ) );
        OID_TO_NID.put( OBJ_physicalDeliveryOfficeName, Integer.valueOf( NID_physicalDeliveryOfficeName ) );
        OID_TO_NID.put( OBJ_telephoneNumber, Integer.valueOf( NID_telephoneNumber ) );
        OID_TO_NID.put( OBJ_telexNumber, Integer.valueOf( NID_telexNumber ) );
        OID_TO_NID.put( OBJ_teletexTerminalIdentifier, Integer.valueOf( NID_teletexTerminalIdentifier ) );
        OID_TO_NID.put( OBJ_facsimileTelephoneNumber, Integer.valueOf( NID_facsimileTelephoneNumber ) );
        OID_TO_NID.put( OBJ_x121Address, Integer.valueOf( NID_x121Address ) );
        OID_TO_NID.put( OBJ_internationaliSDNNumber, Integer.valueOf( NID_internationaliSDNNumber ) );
        OID_TO_NID.put( OBJ_registeredAddress, Integer.valueOf( NID_registeredAddress ) );
        OID_TO_NID.put( OBJ_destinationIndicator, Integer.valueOf( NID_destinationIndicator ) );
        OID_TO_NID.put( OBJ_preferredDeliveryMethod, Integer.valueOf( NID_preferredDeliveryMethod ) );
        OID_TO_NID.put( OBJ_presentationAddress, Integer.valueOf( NID_presentationAddress ) );
        OID_TO_NID.put( OBJ_supportedApplicationContext, Integer.valueOf( NID_supportedApplicationContext ) );
        OID_TO_NID.put( OBJ_member, Integer.valueOf( NID_member ) );
        OID_TO_NID.put( OBJ_owner, Integer.valueOf( NID_owner ) );
        OID_TO_NID.put( OBJ_roleOccupant, Integer.valueOf( NID_roleOccupant ) );
        OID_TO_NID.put( OBJ_seeAlso, Integer.valueOf( NID_seeAlso ) );
        OID_TO_NID.put( OBJ_userPassword, Integer.valueOf( NID_userPassword ) );
        OID_TO_NID.put( OBJ_userCertificate, Integer.valueOf( NID_userCertificate ) );
        OID_TO_NID.put( OBJ_cACertificate, Integer.valueOf( NID_cACertificate ) );
        OID_TO_NID.put( OBJ_authorityRevocationList, Integer.valueOf( NID_authorityRevocationList ) );
        OID_TO_NID.put( OBJ_certificateRevocationList, Integer.valueOf( NID_certificateRevocationList ) );
        OID_TO_NID.put( OBJ_crossCertificatePair, Integer.valueOf( NID_crossCertificatePair ) );
        OID_TO_NID.put( OBJ_name, Integer.valueOf( NID_name ) );
        OID_TO_NID.put( OBJ_givenName, Integer.valueOf( NID_givenName ) );
        OID_TO_NID.put( OBJ_initials, Integer.valueOf( NID_initials ) );
        OID_TO_NID.put( OBJ_generationQualifier, Integer.valueOf( NID_generationQualifier ) );
        OID_TO_NID.put( OBJ_x500UniqueIdentifier, Integer.valueOf( NID_x500UniqueIdentifier ) );
        OID_TO_NID.put( OBJ_dnQualifier, Integer.valueOf( NID_dnQualifier ) );
        OID_TO_NID.put( OBJ_enhancedSearchGuide, Integer.valueOf( NID_enhancedSearchGuide ) );
        OID_TO_NID.put( OBJ_protocolInformation, Integer.valueOf( NID_protocolInformation ) );
        OID_TO_NID.put( OBJ_distinguishedName, Integer.valueOf( NID_distinguishedName ) );
        OID_TO_NID.put( OBJ_uniqueMember, Integer.valueOf( NID_uniqueMember ) );
        OID_TO_NID.put( OBJ_houseIdentifier, Integer.valueOf( NID_houseIdentifier ) );
        OID_TO_NID.put( OBJ_supportedAlgorithms, Integer.valueOf( NID_supportedAlgorithms ) );
        OID_TO_NID.put( OBJ_deltaRevocationList, Integer.valueOf( NID_deltaRevocationList ) );
        OID_TO_NID.put( OBJ_dmdName, Integer.valueOf( NID_dmdName ) );
        OID_TO_NID.put( OBJ_pseudonym, Integer.valueOf( NID_pseudonym ) );
        OID_TO_NID.put( OBJ_role, Integer.valueOf( NID_role ) );
        OID_TO_NID.put( OBJ_X500algorithms, Integer.valueOf( NID_X500algorithms ) );
        OID_TO_NID.put( OBJ_rsa, Integer.valueOf( NID_rsa ) );
        OID_TO_NID.put( OBJ_mdc2WithRSA, Integer.valueOf( NID_mdc2WithRSA ) );
        OID_TO_NID.put( OBJ_mdc2, Integer.valueOf( NID_mdc2 ) );
        OID_TO_NID.put( OBJ_id_ce, Integer.valueOf( NID_id_ce ) );
        OID_TO_NID.put( OBJ_subject_directory_attributes, Integer.valueOf( NID_subject_directory_attributes ) );
        OID_TO_NID.put( OBJ_subject_key_identifier, Integer.valueOf( NID_subject_key_identifier ) );
        OID_TO_NID.put( OBJ_key_usage, Integer.valueOf( NID_key_usage ) );
        OID_TO_NID.put( OBJ_private_key_usage_period, Integer.valueOf( NID_private_key_usage_period ) );
        OID_TO_NID.put( OBJ_subject_alt_name, Integer.valueOf( NID_subject_alt_name ) );
        OID_TO_NID.put( OBJ_issuer_alt_name, Integer.valueOf( NID_issuer_alt_name ) );
        OID_TO_NID.put( OBJ_basic_constraints, Integer.valueOf( NID_basic_constraints ) );
        OID_TO_NID.put( OBJ_crl_number, Integer.valueOf( NID_crl_number ) );
        OID_TO_NID.put( OBJ_crl_reason, Integer.valueOf( NID_crl_reason ) );
        OID_TO_NID.put( OBJ_invalidity_date, Integer.valueOf( NID_invalidity_date ) );
        OID_TO_NID.put( OBJ_delta_crl, Integer.valueOf( NID_delta_crl ) );
        OID_TO_NID.put( OBJ_issuing_distribution_point, Integer.valueOf( NID_issuing_distribution_point ) );
        OID_TO_NID.put( OBJ_certificate_issuer, Integer.valueOf( NID_certificate_issuer ) );
        OID_TO_NID.put( OBJ_name_constraints, Integer.valueOf( NID_name_constraints ) );
        OID_TO_NID.put( OBJ_crl_distribution_points, Integer.valueOf( NID_crl_distribution_points ) );
        OID_TO_NID.put( OBJ_certificate_policies, Integer.valueOf( NID_certificate_policies ) );
        OID_TO_NID.put( OBJ_any_policy, Integer.valueOf( NID_any_policy ) );
        OID_TO_NID.put( OBJ_policy_mappings, Integer.valueOf( NID_policy_mappings ) );
        OID_TO_NID.put( OBJ_authority_key_identifier, Integer.valueOf( NID_authority_key_identifier ) );
        OID_TO_NID.put( OBJ_policy_constraints, Integer.valueOf( NID_policy_constraints ) );
        OID_TO_NID.put( OBJ_ext_key_usage, Integer.valueOf( NID_ext_key_usage ) );
        OID_TO_NID.put( OBJ_freshest_crl, Integer.valueOf( NID_freshest_crl ) );
        OID_TO_NID.put( OBJ_inhibit_any_policy, Integer.valueOf( NID_inhibit_any_policy ) );
        OID_TO_NID.put( OBJ_target_information, Integer.valueOf( NID_target_information ) );
        OID_TO_NID.put( OBJ_no_rev_avail, Integer.valueOf( NID_no_rev_avail ) );
        OID_TO_NID.put( OBJ_anyExtendedKeyUsage, Integer.valueOf( NID_anyExtendedKeyUsage ) );
        OID_TO_NID.put( OBJ_netscape, Integer.valueOf( NID_netscape ) );
        OID_TO_NID.put( OBJ_netscape_cert_extension, Integer.valueOf( NID_netscape_cert_extension ) );
        OID_TO_NID.put( OBJ_netscape_data_type, Integer.valueOf( NID_netscape_data_type ) );
        OID_TO_NID.put( OBJ_netscape_cert_type, Integer.valueOf( NID_netscape_cert_type ) );
        OID_TO_NID.put( OBJ_netscape_base_url, Integer.valueOf( NID_netscape_base_url ) );
        OID_TO_NID.put( OBJ_netscape_revocation_url, Integer.valueOf( NID_netscape_revocation_url ) );
        OID_TO_NID.put( OBJ_netscape_ca_revocation_url, Integer.valueOf( NID_netscape_ca_revocation_url ) );
        OID_TO_NID.put( OBJ_netscape_renewal_url, Integer.valueOf( NID_netscape_renewal_url ) );
        OID_TO_NID.put( OBJ_netscape_ca_policy_url, Integer.valueOf( NID_netscape_ca_policy_url ) );
        OID_TO_NID.put( OBJ_netscape_ssl_server_name, Integer.valueOf( NID_netscape_ssl_server_name ) );
        OID_TO_NID.put( OBJ_netscape_comment, Integer.valueOf( NID_netscape_comment ) );
        OID_TO_NID.put( OBJ_netscape_cert_sequence, Integer.valueOf( NID_netscape_cert_sequence ) );
        OID_TO_NID.put( OBJ_ns_sgc, Integer.valueOf( NID_ns_sgc ) );
        OID_TO_NID.put( OBJ_org, Integer.valueOf( NID_org ) );
        OID_TO_NID.put( OBJ_dod, Integer.valueOf( NID_dod ) );
        OID_TO_NID.put( OBJ_iana, Integer.valueOf( NID_iana ) );
        OID_TO_NID.put( OBJ_Directory, Integer.valueOf( NID_Directory ) );
        OID_TO_NID.put( OBJ_Management, Integer.valueOf( NID_Management ) );
        OID_TO_NID.put( OBJ_Experimental, Integer.valueOf( NID_Experimental ) );
        OID_TO_NID.put( OBJ_Private, Integer.valueOf( NID_Private ) );
        OID_TO_NID.put( OBJ_Security, Integer.valueOf( NID_Security ) );
        OID_TO_NID.put( OBJ_SNMPv2, Integer.valueOf( NID_SNMPv2 ) );
        OID_TO_NID.put( OBJ_Mail, Integer.valueOf( NID_Mail ) );
        OID_TO_NID.put( OBJ_Enterprises, Integer.valueOf( NID_Enterprises ) );
        OID_TO_NID.put( OBJ_dcObject, Integer.valueOf( NID_dcObject ) );
        OID_TO_NID.put( OBJ_mime_mhs, Integer.valueOf( NID_mime_mhs ) );
        OID_TO_NID.put( OBJ_mime_mhs_headings, Integer.valueOf( NID_mime_mhs_headings ) );
        OID_TO_NID.put( OBJ_mime_mhs_bodies, Integer.valueOf( NID_mime_mhs_bodies ) );
        OID_TO_NID.put( OBJ_id_hex_partial_message, Integer.valueOf( NID_id_hex_partial_message ) );
        OID_TO_NID.put( OBJ_id_hex_multipart_message, Integer.valueOf( NID_id_hex_multipart_message ) );
        OID_TO_NID.put( OBJ_rle_compression, Integer.valueOf( NID_rle_compression ) );
        OID_TO_NID.put( OBJ_zlib_compression, Integer.valueOf( NID_zlib_compression ) );
        OID_TO_NID.put( OBJ_aes_128_ecb, Integer.valueOf( NID_aes_128_ecb ) );
        OID_TO_NID.put( OBJ_aes_128_cbc, Integer.valueOf( NID_aes_128_cbc ) );
        OID_TO_NID.put( OBJ_aes_128_ofb128, Integer.valueOf( NID_aes_128_ofb128 ) );
        OID_TO_NID.put( OBJ_aes_128_cfb128, Integer.valueOf( NID_aes_128_cfb128 ) );
        OID_TO_NID.put( OBJ_id_aes128_wrap, Integer.valueOf( NID_id_aes128_wrap ) );
        OID_TO_NID.put( OBJ_aes_128_gcm, Integer.valueOf( NID_aes_128_gcm ) );
        OID_TO_NID.put( OBJ_aes_128_ccm, Integer.valueOf( NID_aes_128_ccm ) );
        OID_TO_NID.put( OBJ_id_aes128_wrap_pad, Integer.valueOf( NID_id_aes128_wrap_pad ) );
        OID_TO_NID.put( OBJ_aes_192_ecb, Integer.valueOf( NID_aes_192_ecb ) );
        OID_TO_NID.put( OBJ_aes_192_cbc, Integer.valueOf( NID_aes_192_cbc ) );
        OID_TO_NID.put( OBJ_aes_192_ofb128, Integer.valueOf( NID_aes_192_ofb128 ) );
        OID_TO_NID.put( OBJ_aes_192_cfb128, Integer.valueOf( NID_aes_192_cfb128 ) );
        OID_TO_NID.put( OBJ_id_aes192_wrap, Integer.valueOf( NID_id_aes192_wrap ) );
        OID_TO_NID.put( OBJ_aes_192_gcm, Integer.valueOf( NID_aes_192_gcm ) );
        OID_TO_NID.put( OBJ_aes_192_ccm, Integer.valueOf( NID_aes_192_ccm ) );
        OID_TO_NID.put( OBJ_id_aes192_wrap_pad, Integer.valueOf( NID_id_aes192_wrap_pad ) );
        OID_TO_NID.put( OBJ_aes_256_ecb, Integer.valueOf( NID_aes_256_ecb ) );
        OID_TO_NID.put( OBJ_aes_256_cbc, Integer.valueOf( NID_aes_256_cbc ) );
        OID_TO_NID.put( OBJ_aes_256_ofb128, Integer.valueOf( NID_aes_256_ofb128 ) );
        OID_TO_NID.put( OBJ_aes_256_cfb128, Integer.valueOf( NID_aes_256_cfb128 ) );
        OID_TO_NID.put( OBJ_id_aes256_wrap, Integer.valueOf( NID_id_aes256_wrap ) );
        OID_TO_NID.put( OBJ_aes_256_gcm, Integer.valueOf( NID_aes_256_gcm ) );
        OID_TO_NID.put( OBJ_aes_256_ccm, Integer.valueOf( NID_aes_256_ccm ) );
        OID_TO_NID.put( OBJ_id_aes256_wrap_pad, Integer.valueOf( NID_id_aes256_wrap_pad ) );
        OID_TO_NID.put( OBJ_sha256, Integer.valueOf( NID_sha256 ) );
        OID_TO_NID.put( OBJ_sha384, Integer.valueOf( NID_sha384 ) );
        OID_TO_NID.put( OBJ_sha512, Integer.valueOf( NID_sha512 ) );
        OID_TO_NID.put( OBJ_sha224, Integer.valueOf( NID_sha224 ) );
        OID_TO_NID.put( OBJ_dsa_with_SHA224, Integer.valueOf( NID_dsa_with_SHA224 ) );
        OID_TO_NID.put( OBJ_dsa_with_SHA256, Integer.valueOf( NID_dsa_with_SHA256 ) );
        OID_TO_NID.put( OBJ_hold_instruction_code, Integer.valueOf( NID_hold_instruction_code ) );
        OID_TO_NID.put( OBJ_hold_instruction_none, Integer.valueOf( NID_hold_instruction_none ) );
        OID_TO_NID.put( OBJ_hold_instruction_call_issuer, Integer.valueOf( NID_hold_instruction_call_issuer ) );
        OID_TO_NID.put( OBJ_hold_instruction_reject, Integer.valueOf( NID_hold_instruction_reject ) );
        OID_TO_NID.put( OBJ_data, Integer.valueOf( NID_data ) );
        OID_TO_NID.put( OBJ_pss, Integer.valueOf( NID_pss ) );
        OID_TO_NID.put( OBJ_ucl, Integer.valueOf( NID_ucl ) );
        OID_TO_NID.put( OBJ_pilot, Integer.valueOf( NID_pilot ) );
        OID_TO_NID.put( OBJ_pilotAttributeType, Integer.valueOf( NID_pilotAttributeType ) );
        OID_TO_NID.put( OBJ_pilotAttributeSyntax, Integer.valueOf( NID_pilotAttributeSyntax ) );
        OID_TO_NID.put( OBJ_pilotObjectClass, Integer.valueOf( NID_pilotObjectClass ) );
        OID_TO_NID.put( OBJ_pilotGroups, Integer.valueOf( NID_pilotGroups ) );
        OID_TO_NID.put( OBJ_iA5StringSyntax, Integer.valueOf( NID_iA5StringSyntax ) );
        OID_TO_NID.put( OBJ_caseIgnoreIA5StringSyntax, Integer.valueOf( NID_caseIgnoreIA5StringSyntax ) );
        OID_TO_NID.put( OBJ_pilotObject, Integer.valueOf( NID_pilotObject ) );
        OID_TO_NID.put( OBJ_pilotPerson, Integer.valueOf( NID_pilotPerson ) );
        OID_TO_NID.put( OBJ_account, Integer.valueOf( NID_account ) );
        OID_TO_NID.put( OBJ_document, Integer.valueOf( NID_document ) );
        OID_TO_NID.put( OBJ_room, Integer.valueOf( NID_room ) );
        OID_TO_NID.put( OBJ_documentSeries, Integer.valueOf( NID_documentSeries ) );
        OID_TO_NID.put( OBJ_Domain, Integer.valueOf( NID_Domain ) );
        OID_TO_NID.put( OBJ_rFC822localPart, Integer.valueOf( NID_rFC822localPart ) );
        OID_TO_NID.put( OBJ_dNSDomain, Integer.valueOf( NID_dNSDomain ) );
        OID_TO_NID.put( OBJ_domainRelatedObject, Integer.valueOf( NID_domainRelatedObject ) );
        OID_TO_NID.put( OBJ_friendlyCountry, Integer.valueOf( NID_friendlyCountry ) );
        OID_TO_NID.put( OBJ_simpleSecurityObject, Integer.valueOf( NID_simpleSecurityObject ) );
        OID_TO_NID.put( OBJ_pilotOrganization, Integer.valueOf( NID_pilotOrganization ) );
        OID_TO_NID.put( OBJ_pilotDSA, Integer.valueOf( NID_pilotDSA ) );
        OID_TO_NID.put( OBJ_qualityLabelledData, Integer.valueOf( NID_qualityLabelledData ) );
        OID_TO_NID.put( OBJ_userId, Integer.valueOf( NID_userId ) );
        OID_TO_NID.put( OBJ_textEncodedORAddress, Integer.valueOf( NID_textEncodedORAddress ) );
        OID_TO_NID.put( OBJ_rfc822Mailbox, Integer.valueOf( NID_rfc822Mailbox ) );
        OID_TO_NID.put( OBJ_info, Integer.valueOf( NID_info ) );
        OID_TO_NID.put( OBJ_favouriteDrink, Integer.valueOf( NID_favouriteDrink ) );
        OID_TO_NID.put( OBJ_roomNumber, Integer.valueOf( NID_roomNumber ) );
        OID_TO_NID.put( OBJ_photo, Integer.valueOf( NID_photo ) );
        OID_TO_NID.put( OBJ_userClass, Integer.valueOf( NID_userClass ) );
        OID_TO_NID.put( OBJ_host, Integer.valueOf( NID_host ) );
        OID_TO_NID.put( OBJ_manager, Integer.valueOf( NID_manager ) );
        OID_TO_NID.put( OBJ_documentIdentifier, Integer.valueOf( NID_documentIdentifier ) );
        OID_TO_NID.put( OBJ_documentTitle, Integer.valueOf( NID_documentTitle ) );
        OID_TO_NID.put( OBJ_documentVersion, Integer.valueOf( NID_documentVersion ) );
        OID_TO_NID.put( OBJ_documentAuthor, Integer.valueOf( NID_documentAuthor ) );
        OID_TO_NID.put( OBJ_documentLocation, Integer.valueOf( NID_documentLocation ) );
        OID_TO_NID.put( OBJ_homeTelephoneNumber, Integer.valueOf( NID_homeTelephoneNumber ) );
        OID_TO_NID.put( OBJ_secretary, Integer.valueOf( NID_secretary ) );
        OID_TO_NID.put( OBJ_otherMailbox, Integer.valueOf( NID_otherMailbox ) );
        OID_TO_NID.put( OBJ_lastModifiedTime, Integer.valueOf( NID_lastModifiedTime ) );
        OID_TO_NID.put( OBJ_lastModifiedBy, Integer.valueOf( NID_lastModifiedBy ) );
        OID_TO_NID.put( OBJ_domainComponent, Integer.valueOf( NID_domainComponent ) );
        OID_TO_NID.put( OBJ_aRecord, Integer.valueOf( NID_aRecord ) );
        OID_TO_NID.put( OBJ_pilotAttributeType27, Integer.valueOf( NID_pilotAttributeType27 ) );
        OID_TO_NID.put( OBJ_mXRecord, Integer.valueOf( NID_mXRecord ) );
        OID_TO_NID.put( OBJ_nSRecord, Integer.valueOf( NID_nSRecord ) );
        OID_TO_NID.put( OBJ_sOARecord, Integer.valueOf( NID_sOARecord ) );
        OID_TO_NID.put( OBJ_cNAMERecord, Integer.valueOf( NID_cNAMERecord ) );
        OID_TO_NID.put( OBJ_associatedDomain, Integer.valueOf( NID_associatedDomain ) );
        OID_TO_NID.put( OBJ_associatedName, Integer.valueOf( NID_associatedName ) );
        OID_TO_NID.put( OBJ_homePostalAddress, Integer.valueOf( NID_homePostalAddress ) );
        OID_TO_NID.put( OBJ_personalTitle, Integer.valueOf( NID_personalTitle ) );
        OID_TO_NID.put( OBJ_mobileTelephoneNumber, Integer.valueOf( NID_mobileTelephoneNumber ) );
        OID_TO_NID.put( OBJ_pagerTelephoneNumber, Integer.valueOf( NID_pagerTelephoneNumber ) );
        OID_TO_NID.put( OBJ_friendlyCountryName, Integer.valueOf( NID_friendlyCountryName ) );
        OID_TO_NID.put( OBJ_organizationalStatus, Integer.valueOf( NID_organizationalStatus ) );
        OID_TO_NID.put( OBJ_janetMailbox, Integer.valueOf( NID_janetMailbox ) );
        OID_TO_NID.put( OBJ_mailPreferenceOption, Integer.valueOf( NID_mailPreferenceOption ) );
        OID_TO_NID.put( OBJ_buildingName, Integer.valueOf( NID_buildingName ) );
        OID_TO_NID.put( OBJ_dSAQuality, Integer.valueOf( NID_dSAQuality ) );
        OID_TO_NID.put( OBJ_singleLevelQuality, Integer.valueOf( NID_singleLevelQuality ) );
        OID_TO_NID.put( OBJ_subtreeMinimumQuality, Integer.valueOf( NID_subtreeMinimumQuality ) );
        OID_TO_NID.put( OBJ_subtreeMaximumQuality, Integer.valueOf( NID_subtreeMaximumQuality ) );
        OID_TO_NID.put( OBJ_personalSignature, Integer.valueOf( NID_personalSignature ) );
        OID_TO_NID.put( OBJ_dITRedirect, Integer.valueOf( NID_dITRedirect ) );
        OID_TO_NID.put( OBJ_audio, Integer.valueOf( NID_audio ) );
        OID_TO_NID.put( OBJ_documentPublisher, Integer.valueOf( NID_documentPublisher ) );
        OID_TO_NID.put( OBJ_id_set, Integer.valueOf( NID_id_set ) );
        OID_TO_NID.put( OBJ_set_ctype, Integer.valueOf( NID_set_ctype ) );
        OID_TO_NID.put( OBJ_set_msgExt, Integer.valueOf( NID_set_msgExt ) );
        OID_TO_NID.put( OBJ_set_attr, Integer.valueOf( NID_set_attr ) );
        OID_TO_NID.put( OBJ_set_policy, Integer.valueOf( NID_set_policy ) );
        OID_TO_NID.put( OBJ_set_certExt, Integer.valueOf( NID_set_certExt ) );
        OID_TO_NID.put( OBJ_set_brand, Integer.valueOf( NID_set_brand ) );
        OID_TO_NID.put( OBJ_setct_PANData, Integer.valueOf( NID_setct_PANData ) );
        OID_TO_NID.put( OBJ_setct_PANToken, Integer.valueOf( NID_setct_PANToken ) );
        OID_TO_NID.put( OBJ_setct_PANOnly, Integer.valueOf( NID_setct_PANOnly ) );
        OID_TO_NID.put( OBJ_setct_OIData, Integer.valueOf( NID_setct_OIData ) );
        OID_TO_NID.put( OBJ_setct_PI, Integer.valueOf( NID_setct_PI ) );
        OID_TO_NID.put( OBJ_setct_PIData, Integer.valueOf( NID_setct_PIData ) );
        OID_TO_NID.put( OBJ_setct_PIDataUnsigned, Integer.valueOf( NID_setct_PIDataUnsigned ) );
        OID_TO_NID.put( OBJ_setct_HODInput, Integer.valueOf( NID_setct_HODInput ) );
        OID_TO_NID.put( OBJ_setct_AuthResBaggage, Integer.valueOf( NID_setct_AuthResBaggage ) );
        OID_TO_NID.put( OBJ_setct_AuthRevReqBaggage, Integer.valueOf( NID_setct_AuthRevReqBaggage ) );
        OID_TO_NID.put( OBJ_setct_AuthRevResBaggage, Integer.valueOf( NID_setct_AuthRevResBaggage ) );
        OID_TO_NID.put( OBJ_setct_CapTokenSeq, Integer.valueOf( NID_setct_CapTokenSeq ) );
        OID_TO_NID.put( OBJ_setct_PInitResData, Integer.valueOf( NID_setct_PInitResData ) );
        OID_TO_NID.put( OBJ_setct_PI_TBS, Integer.valueOf( NID_setct_PI_TBS ) );
        OID_TO_NID.put( OBJ_setct_PResData, Integer.valueOf( NID_setct_PResData ) );
        OID_TO_NID.put( OBJ_setct_AuthReqTBS, Integer.valueOf( NID_setct_AuthReqTBS ) );
        OID_TO_NID.put( OBJ_setct_AuthResTBS, Integer.valueOf( NID_setct_AuthResTBS ) );
        OID_TO_NID.put( OBJ_setct_AuthResTBSX, Integer.valueOf( NID_setct_AuthResTBSX ) );
        OID_TO_NID.put( OBJ_setct_AuthTokenTBS, Integer.valueOf( NID_setct_AuthTokenTBS ) );
        OID_TO_NID.put( OBJ_setct_CapTokenData, Integer.valueOf( NID_setct_CapTokenData ) );
        OID_TO_NID.put( OBJ_setct_CapTokenTBS, Integer.valueOf( NID_setct_CapTokenTBS ) );
        OID_TO_NID.put( OBJ_setct_AcqCardCodeMsg, Integer.valueOf( NID_setct_AcqCardCodeMsg ) );
        OID_TO_NID.put( OBJ_setct_AuthRevReqTBS, Integer.valueOf( NID_setct_AuthRevReqTBS ) );
        OID_TO_NID.put( OBJ_setct_AuthRevResData, Integer.valueOf( NID_setct_AuthRevResData ) );
        OID_TO_NID.put( OBJ_setct_AuthRevResTBS, Integer.valueOf( NID_setct_AuthRevResTBS ) );
        OID_TO_NID.put( OBJ_setct_CapReqTBS, Integer.valueOf( NID_setct_CapReqTBS ) );
        OID_TO_NID.put( OBJ_setct_CapReqTBSX, Integer.valueOf( NID_setct_CapReqTBSX ) );
        OID_TO_NID.put( OBJ_setct_CapResData, Integer.valueOf( NID_setct_CapResData ) );
        OID_TO_NID.put( OBJ_setct_CapRevReqTBS, Integer.valueOf( NID_setct_CapRevReqTBS ) );
        OID_TO_NID.put( OBJ_setct_CapRevReqTBSX, Integer.valueOf( NID_setct_CapRevReqTBSX ) );
        OID_TO_NID.put( OBJ_setct_CapRevResData, Integer.valueOf( NID_setct_CapRevResData ) );
        OID_TO_NID.put( OBJ_setct_CredReqTBS, Integer.valueOf( NID_setct_CredReqTBS ) );
        OID_TO_NID.put( OBJ_setct_CredReqTBSX, Integer.valueOf( NID_setct_CredReqTBSX ) );
        OID_TO_NID.put( OBJ_setct_CredResData, Integer.valueOf( NID_setct_CredResData ) );
        OID_TO_NID.put( OBJ_setct_CredRevReqTBS, Integer.valueOf( NID_setct_CredRevReqTBS ) );
        OID_TO_NID.put( OBJ_setct_CredRevReqTBSX, Integer.valueOf( NID_setct_CredRevReqTBSX ) );
        OID_TO_NID.put( OBJ_setct_CredRevResData, Integer.valueOf( NID_setct_CredRevResData ) );
        OID_TO_NID.put( OBJ_setct_PCertReqData, Integer.valueOf( NID_setct_PCertReqData ) );
        OID_TO_NID.put( OBJ_setct_PCertResTBS, Integer.valueOf( NID_setct_PCertResTBS ) );
        OID_TO_NID.put( OBJ_setct_BatchAdminReqData, Integer.valueOf( NID_setct_BatchAdminReqData ) );
        OID_TO_NID.put( OBJ_setct_BatchAdminResData, Integer.valueOf( NID_setct_BatchAdminResData ) );
        OID_TO_NID.put( OBJ_setct_CardCInitResTBS, Integer.valueOf( NID_setct_CardCInitResTBS ) );
        OID_TO_NID.put( OBJ_setct_MeAqCInitResTBS, Integer.valueOf( NID_setct_MeAqCInitResTBS ) );
        OID_TO_NID.put( OBJ_setct_RegFormResTBS, Integer.valueOf( NID_setct_RegFormResTBS ) );
        OID_TO_NID.put( OBJ_setct_CertReqData, Integer.valueOf( NID_setct_CertReqData ) );
        OID_TO_NID.put( OBJ_setct_CertReqTBS, Integer.valueOf( NID_setct_CertReqTBS ) );
        OID_TO_NID.put( OBJ_setct_CertResData, Integer.valueOf( NID_setct_CertResData ) );
        OID_TO_NID.put( OBJ_setct_CertInqReqTBS, Integer.valueOf( NID_setct_CertInqReqTBS ) );
        OID_TO_NID.put( OBJ_setct_ErrorTBS, Integer.valueOf( NID_setct_ErrorTBS ) );
        OID_TO_NID.put( OBJ_setct_PIDualSignedTBE, Integer.valueOf( NID_setct_PIDualSignedTBE ) );
        OID_TO_NID.put( OBJ_setct_PIUnsignedTBE, Integer.valueOf( NID_setct_PIUnsignedTBE ) );
        OID_TO_NID.put( OBJ_setct_AuthReqTBE, Integer.valueOf( NID_setct_AuthReqTBE ) );
        OID_TO_NID.put( OBJ_setct_AuthResTBE, Integer.valueOf( NID_setct_AuthResTBE ) );
        OID_TO_NID.put( OBJ_setct_AuthResTBEX, Integer.valueOf( NID_setct_AuthResTBEX ) );
        OID_TO_NID.put( OBJ_setct_AuthTokenTBE, Integer.valueOf( NID_setct_AuthTokenTBE ) );
        OID_TO_NID.put( OBJ_setct_CapTokenTBE, Integer.valueOf( NID_setct_CapTokenTBE ) );
        OID_TO_NID.put( OBJ_setct_CapTokenTBEX, Integer.valueOf( NID_setct_CapTokenTBEX ) );
        OID_TO_NID.put( OBJ_setct_AcqCardCodeMsgTBE, Integer.valueOf( NID_setct_AcqCardCodeMsgTBE ) );
        OID_TO_NID.put( OBJ_setct_AuthRevReqTBE, Integer.valueOf( NID_setct_AuthRevReqTBE ) );
        OID_TO_NID.put( OBJ_setct_AuthRevResTBE, Integer.valueOf( NID_setct_AuthRevResTBE ) );
        OID_TO_NID.put( OBJ_setct_AuthRevResTBEB, Integer.valueOf( NID_setct_AuthRevResTBEB ) );
        OID_TO_NID.put( OBJ_setct_CapReqTBE, Integer.valueOf( NID_setct_CapReqTBE ) );
        OID_TO_NID.put( OBJ_setct_CapReqTBEX, Integer.valueOf( NID_setct_CapReqTBEX ) );
        OID_TO_NID.put( OBJ_setct_CapResTBE, Integer.valueOf( NID_setct_CapResTBE ) );
        OID_TO_NID.put( OBJ_setct_CapRevReqTBE, Integer.valueOf( NID_setct_CapRevReqTBE ) );
        OID_TO_NID.put( OBJ_setct_CapRevReqTBEX, Integer.valueOf( NID_setct_CapRevReqTBEX ) );
        OID_TO_NID.put( OBJ_setct_CapRevResTBE, Integer.valueOf( NID_setct_CapRevResTBE ) );
        OID_TO_NID.put( OBJ_setct_CredReqTBE, Integer.valueOf( NID_setct_CredReqTBE ) );
        OID_TO_NID.put( OBJ_setct_CredReqTBEX, Integer.valueOf( NID_setct_CredReqTBEX ) );
        OID_TO_NID.put( OBJ_setct_CredResTBE, Integer.valueOf( NID_setct_CredResTBE ) );
        OID_TO_NID.put( OBJ_setct_CredRevReqTBE, Integer.valueOf( NID_setct_CredRevReqTBE ) );
        OID_TO_NID.put( OBJ_setct_CredRevReqTBEX, Integer.valueOf( NID_setct_CredRevReqTBEX ) );
        OID_TO_NID.put( OBJ_setct_CredRevResTBE, Integer.valueOf( NID_setct_CredRevResTBE ) );
        OID_TO_NID.put( OBJ_setct_BatchAdminReqTBE, Integer.valueOf( NID_setct_BatchAdminReqTBE ) );
        OID_TO_NID.put( OBJ_setct_BatchAdminResTBE, Integer.valueOf( NID_setct_BatchAdminResTBE ) );
        OID_TO_NID.put( OBJ_setct_RegFormReqTBE, Integer.valueOf( NID_setct_RegFormReqTBE ) );
        OID_TO_NID.put( OBJ_setct_CertReqTBE, Integer.valueOf( NID_setct_CertReqTBE ) );
        OID_TO_NID.put( OBJ_setct_CertReqTBEX, Integer.valueOf( NID_setct_CertReqTBEX ) );
        OID_TO_NID.put( OBJ_setct_CertResTBE, Integer.valueOf( NID_setct_CertResTBE ) );
        OID_TO_NID.put( OBJ_setct_CRLNotificationTBS, Integer.valueOf( NID_setct_CRLNotificationTBS ) );
        OID_TO_NID.put( OBJ_setct_CRLNotificationResTBS, Integer.valueOf( NID_setct_CRLNotificationResTBS ) );
        OID_TO_NID.put( OBJ_setct_BCIDistributionTBS, Integer.valueOf( NID_setct_BCIDistributionTBS ) );
        OID_TO_NID.put( OBJ_setext_genCrypt, Integer.valueOf( NID_setext_genCrypt ) );
        OID_TO_NID.put( OBJ_setext_miAuth, Integer.valueOf( NID_setext_miAuth ) );
        OID_TO_NID.put( OBJ_setext_pinSecure, Integer.valueOf( NID_setext_pinSecure ) );
        OID_TO_NID.put( OBJ_setext_pinAny, Integer.valueOf( NID_setext_pinAny ) );
        OID_TO_NID.put( OBJ_setext_track2, Integer.valueOf( NID_setext_track2 ) );
        OID_TO_NID.put( OBJ_setext_cv, Integer.valueOf( NID_setext_cv ) );
        OID_TO_NID.put( OBJ_set_policy_root, Integer.valueOf( NID_set_policy_root ) );
        OID_TO_NID.put( OBJ_setCext_hashedRoot, Integer.valueOf( NID_setCext_hashedRoot ) );
        OID_TO_NID.put( OBJ_setCext_certType, Integer.valueOf( NID_setCext_certType ) );
        OID_TO_NID.put( OBJ_setCext_merchData, Integer.valueOf( NID_setCext_merchData ) );
        OID_TO_NID.put( OBJ_setCext_cCertRequired, Integer.valueOf( NID_setCext_cCertRequired ) );
        OID_TO_NID.put( OBJ_setCext_tunneling, Integer.valueOf( NID_setCext_tunneling ) );
        OID_TO_NID.put( OBJ_setCext_setExt, Integer.valueOf( NID_setCext_setExt ) );
        OID_TO_NID.put( OBJ_setCext_setQualf, Integer.valueOf( NID_setCext_setQualf ) );
        OID_TO_NID.put( OBJ_setCext_PGWYcapabilities, Integer.valueOf( NID_setCext_PGWYcapabilities ) );
        OID_TO_NID.put( OBJ_setCext_TokenIdentifier, Integer.valueOf( NID_setCext_TokenIdentifier ) );
        OID_TO_NID.put( OBJ_setCext_Track2Data, Integer.valueOf( NID_setCext_Track2Data ) );
        OID_TO_NID.put( OBJ_setCext_TokenType, Integer.valueOf( NID_setCext_TokenType ) );
        OID_TO_NID.put( OBJ_setCext_IssuerCapabilities, Integer.valueOf( NID_setCext_IssuerCapabilities ) );
        OID_TO_NID.put( OBJ_setAttr_Cert, Integer.valueOf( NID_setAttr_Cert ) );
        OID_TO_NID.put( OBJ_setAttr_PGWYcap, Integer.valueOf( NID_setAttr_PGWYcap ) );
        OID_TO_NID.put( OBJ_setAttr_TokenType, Integer.valueOf( NID_setAttr_TokenType ) );
        OID_TO_NID.put( OBJ_setAttr_IssCap, Integer.valueOf( NID_setAttr_IssCap ) );
        OID_TO_NID.put( OBJ_set_rootKeyThumb, Integer.valueOf( NID_set_rootKeyThumb ) );
        OID_TO_NID.put( OBJ_set_addPolicy, Integer.valueOf( NID_set_addPolicy ) );
        OID_TO_NID.put( OBJ_setAttr_Token_EMV, Integer.valueOf( NID_setAttr_Token_EMV ) );
        OID_TO_NID.put( OBJ_setAttr_Token_B0Prime, Integer.valueOf( NID_setAttr_Token_B0Prime ) );
        OID_TO_NID.put( OBJ_setAttr_IssCap_CVM, Integer.valueOf( NID_setAttr_IssCap_CVM ) );
        OID_TO_NID.put( OBJ_setAttr_IssCap_T2, Integer.valueOf( NID_setAttr_IssCap_T2 ) );
        OID_TO_NID.put( OBJ_setAttr_IssCap_Sig, Integer.valueOf( NID_setAttr_IssCap_Sig ) );
        OID_TO_NID.put( OBJ_setAttr_GenCryptgrm, Integer.valueOf( NID_setAttr_GenCryptgrm ) );
        OID_TO_NID.put( OBJ_setAttr_T2Enc, Integer.valueOf( NID_setAttr_T2Enc ) );
        OID_TO_NID.put( OBJ_setAttr_T2cleartxt, Integer.valueOf( NID_setAttr_T2cleartxt ) );
        OID_TO_NID.put( OBJ_setAttr_TokICCsig, Integer.valueOf( NID_setAttr_TokICCsig ) );
        OID_TO_NID.put( OBJ_setAttr_SecDevSig, Integer.valueOf( NID_setAttr_SecDevSig ) );
        OID_TO_NID.put( OBJ_set_brand_IATA_ATA, Integer.valueOf( NID_set_brand_IATA_ATA ) );
        OID_TO_NID.put( OBJ_set_brand_Diners, Integer.valueOf( NID_set_brand_Diners ) );
        OID_TO_NID.put( OBJ_set_brand_AmericanExpress, Integer.valueOf( NID_set_brand_AmericanExpress ) );
        OID_TO_NID.put( OBJ_set_brand_JCB, Integer.valueOf( NID_set_brand_JCB ) );
        OID_TO_NID.put( OBJ_set_brand_Visa, Integer.valueOf( NID_set_brand_Visa ) );
        OID_TO_NID.put( OBJ_set_brand_MasterCard, Integer.valueOf( NID_set_brand_MasterCard ) );
        OID_TO_NID.put( OBJ_set_brand_Novus, Integer.valueOf( NID_set_brand_Novus ) );
        OID_TO_NID.put( OBJ_des_cdmf, Integer.valueOf( NID_des_cdmf ) );
        OID_TO_NID.put( OBJ_rsaOAEPEncryptionSET, Integer.valueOf( NID_rsaOAEPEncryptionSET ) );
        OID_TO_NID.put( OBJ_whirlpool, Integer.valueOf( NID_whirlpool ) );
        OID_TO_NID.put( OBJ_cryptopro, Integer.valueOf( NID_cryptopro ) );
        OID_TO_NID.put( OBJ_cryptocom, Integer.valueOf( NID_cryptocom ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_with_GostR3410_2001, Integer.valueOf( NID_id_GostR3411_94_with_GostR3410_2001 ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_with_GostR3410_94, Integer.valueOf( NID_id_GostR3411_94_with_GostR3410_94 ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94, Integer.valueOf( NID_id_GostR3411_94 ) );
        OID_TO_NID.put( OBJ_id_HMACGostR3411_94, Integer.valueOf( NID_id_HMACGostR3411_94 ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001, Integer.valueOf( NID_id_GostR3410_2001 ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94, Integer.valueOf( NID_id_GostR3410_94 ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89, Integer.valueOf( NID_id_Gost28147_89 ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_MAC, Integer.valueOf( NID_id_Gost28147_89_MAC ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_prf, Integer.valueOf( NID_id_GostR3411_94_prf ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001DH, Integer.valueOf( NID_id_GostR3410_2001DH ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94DH, Integer.valueOf( NID_id_GostR3410_94DH ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_KeyMeshing, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_KeyMeshing ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_None_KeyMeshing, Integer.valueOf( NID_id_Gost28147_89_None_KeyMeshing ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_TestParamSet, Integer.valueOf( NID_id_GostR3411_94_TestParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_CryptoProParamSet, Integer.valueOf( NID_id_GostR3411_94_CryptoProParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_TestParamSet, Integer.valueOf( NID_id_Gost28147_89_TestParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_A_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_A_ParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_B_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_B_ParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_C_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_C_ParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_D_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_D_ParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet, Integer.valueOf( NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_TestParamSet, Integer.valueOf( NID_id_GostR3410_94_TestParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_A_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_A_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_B_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_B_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_C_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_C_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_D_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_D_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_XchA_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_XchB_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet, Integer.valueOf( NID_id_GostR3410_94_CryptoPro_XchC_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_TestParamSet, Integer.valueOf( NID_id_GostR3410_2001_TestParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet, Integer.valueOf( NID_id_GostR3410_2001_CryptoPro_A_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet, Integer.valueOf( NID_id_GostR3410_2001_CryptoPro_B_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet, Integer.valueOf( NID_id_GostR3410_2001_CryptoPro_C_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet, Integer.valueOf( NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet, Integer.valueOf( NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_a, Integer.valueOf( NID_id_GostR3410_94_a ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_aBis, Integer.valueOf( NID_id_GostR3410_94_aBis ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_b, Integer.valueOf( NID_id_GostR3410_94_b ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_bBis, Integer.valueOf( NID_id_GostR3410_94_bBis ) );
        OID_TO_NID.put( OBJ_id_Gost28147_89_cc, Integer.valueOf( NID_id_Gost28147_89_cc ) );
        OID_TO_NID.put( OBJ_id_GostR3410_94_cc, Integer.valueOf( NID_id_GostR3410_94_cc ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_cc, Integer.valueOf( NID_id_GostR3410_2001_cc ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_with_GostR3410_94_cc, Integer.valueOf( NID_id_GostR3411_94_with_GostR3410_94_cc ) );
        OID_TO_NID.put( OBJ_id_GostR3411_94_with_GostR3410_2001_cc, Integer.valueOf( NID_id_GostR3411_94_with_GostR3410_2001_cc ) );
        OID_TO_NID.put( OBJ_id_GostR3410_2001_ParamSet_cc, Integer.valueOf( NID_id_GostR3410_2001_ParamSet_cc ) );
        OID_TO_NID.put( OBJ_camellia_128_cbc, Integer.valueOf( NID_camellia_128_cbc ) );
        OID_TO_NID.put( OBJ_camellia_192_cbc, Integer.valueOf( NID_camellia_192_cbc ) );
        OID_TO_NID.put( OBJ_camellia_256_cbc, Integer.valueOf( NID_camellia_256_cbc ) );
        OID_TO_NID.put( OBJ_id_camellia128_wrap, Integer.valueOf( NID_id_camellia128_wrap ) );
        OID_TO_NID.put( OBJ_id_camellia192_wrap, Integer.valueOf( NID_id_camellia192_wrap ) );
        OID_TO_NID.put( OBJ_id_camellia256_wrap, Integer.valueOf( NID_id_camellia256_wrap ) );
        OID_TO_NID.put( OBJ_camellia_128_ecb, Integer.valueOf( NID_camellia_128_ecb ) );
        OID_TO_NID.put( OBJ_camellia_128_ofb128, Integer.valueOf( NID_camellia_128_ofb128 ) );
        OID_TO_NID.put( OBJ_camellia_128_cfb128, Integer.valueOf( NID_camellia_128_cfb128 ) );
        OID_TO_NID.put( OBJ_camellia_192_ecb, Integer.valueOf( NID_camellia_192_ecb ) );
        OID_TO_NID.put( OBJ_camellia_192_ofb128, Integer.valueOf( NID_camellia_192_ofb128 ) );
        OID_TO_NID.put( OBJ_camellia_192_cfb128, Integer.valueOf( NID_camellia_192_cfb128 ) );
        OID_TO_NID.put( OBJ_camellia_256_ecb, Integer.valueOf( NID_camellia_256_ecb ) );
        OID_TO_NID.put( OBJ_camellia_256_ofb128, Integer.valueOf( NID_camellia_256_ofb128 ) );
        OID_TO_NID.put( OBJ_camellia_256_cfb128, Integer.valueOf( NID_camellia_256_cfb128 ) );
        OID_TO_NID.put( OBJ_kisa, Integer.valueOf( NID_kisa ) );
        OID_TO_NID.put( OBJ_seed_ecb, Integer.valueOf( NID_seed_ecb ) );
        OID_TO_NID.put( OBJ_seed_cbc, Integer.valueOf( NID_seed_cbc ) );
        OID_TO_NID.put( OBJ_seed_cfb128, Integer.valueOf( NID_seed_cfb128 ) );
        OID_TO_NID.put( OBJ_seed_ofb128, Integer.valueOf( NID_seed_ofb128 ) );
        OID_TO_NID.put( OBJ_dhpublicnumber, Integer.valueOf( NID_dhpublicnumber ) );
        OID_TO_NID.put( OBJ_brainpoolP160r1, Integer.valueOf( NID_brainpoolP160r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP160t1, Integer.valueOf( NID_brainpoolP160t1 ) );
        OID_TO_NID.put( OBJ_brainpoolP192r1, Integer.valueOf( NID_brainpoolP192r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP192t1, Integer.valueOf( NID_brainpoolP192t1 ) );
        OID_TO_NID.put( OBJ_brainpoolP224r1, Integer.valueOf( NID_brainpoolP224r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP224t1, Integer.valueOf( NID_brainpoolP224t1 ) );
        OID_TO_NID.put( OBJ_brainpoolP256r1, Integer.valueOf( NID_brainpoolP256r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP256t1, Integer.valueOf( NID_brainpoolP256t1 ) );
        OID_TO_NID.put( OBJ_brainpoolP320r1, Integer.valueOf( NID_brainpoolP320r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP320t1, Integer.valueOf( NID_brainpoolP320t1 ) );
        OID_TO_NID.put( OBJ_brainpoolP384r1, Integer.valueOf( NID_brainpoolP384r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP384t1, Integer.valueOf( NID_brainpoolP384t1 ) );
        OID_TO_NID.put( OBJ_brainpoolP512r1, Integer.valueOf( NID_brainpoolP512r1 ) );
        OID_TO_NID.put( OBJ_brainpoolP512t1, Integer.valueOf( NID_brainpoolP512t1 ) );
        OID_TO_NID.put( OBJ_dhSinglePass_stdDH_sha1kdf_scheme, Integer.valueOf( NID_dhSinglePass_stdDH_sha1kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_stdDH_sha224kdf_scheme, Integer.valueOf( NID_dhSinglePass_stdDH_sha224kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_stdDH_sha256kdf_scheme, Integer.valueOf( NID_dhSinglePass_stdDH_sha256kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_stdDH_sha384kdf_scheme, Integer.valueOf( NID_dhSinglePass_stdDH_sha384kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_stdDH_sha512kdf_scheme, Integer.valueOf( NID_dhSinglePass_stdDH_sha512kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme, Integer.valueOf( NID_dhSinglePass_cofactorDH_sha1kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme, Integer.valueOf( NID_dhSinglePass_cofactorDH_sha224kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme, Integer.valueOf( NID_dhSinglePass_cofactorDH_sha256kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme, Integer.valueOf( NID_dhSinglePass_cofactorDH_sha384kdf_scheme ) );
        OID_TO_NID.put( OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme, Integer.valueOf( NID_dhSinglePass_cofactorDH_sha512kdf_scheme ) );
        OID_TO_NID.put( OBJ_ct_precert_scts, Integer.valueOf( NID_ct_precert_scts ) );
        OID_TO_NID.put( OBJ_ct_precert_poison, Integer.valueOf( NID_ct_precert_poison ) );
        OID_TO_NID.put( OBJ_ct_precert_signer, Integer.valueOf( NID_ct_precert_signer ) );
        OID_TO_NID.put( OBJ_ct_cert_scts, Integer.valueOf( NID_ct_cert_scts ) );
        OID_TO_NID.put( OBJ_jurisdictionLocalityName, Integer.valueOf( NID_jurisdictionLocalityName ) );
        OID_TO_NID.put( OBJ_jurisdictionStateOrProvinceName, Integer.valueOf( NID_jurisdictionStateOrProvinceName ) );
        OID_TO_NID.put( OBJ_jurisdictionCountryName, Integer.valueOf( NID_jurisdictionCountryName ) );
    }
    

    private static final String[] NID_TO_SN = new String[ 958 ];
    static {
        NID_TO_SN[ NID_undef ] = SN_undef;
        NID_TO_SN[ NID_itu_t ] = SN_itu_t;
        NID_TO_SN[ NID_iso ] = SN_iso;
        NID_TO_SN[ NID_joint_iso_itu_t ] = SN_joint_iso_itu_t;
        NID_TO_SN[ NID_member_body ] = SN_member_body;
        NID_TO_SN[ NID_identified_organization ] = SN_identified_organization;
        NID_TO_SN[ NID_hmac_md5 ] = SN_hmac_md5;
        NID_TO_SN[ NID_hmac_sha1 ] = SN_hmac_sha1;
        NID_TO_SN[ NID_certicom_arc ] = SN_certicom_arc;
        NID_TO_SN[ NID_international_organizations ] = SN_international_organizations;
        NID_TO_SN[ NID_wap ] = SN_wap;
        NID_TO_SN[ NID_wap_wsg ] = SN_wap_wsg;
        NID_TO_SN[ NID_selected_attribute_types ] = SN_selected_attribute_types;
        NID_TO_SN[ NID_clearance ] = SN_clearance;
        NID_TO_SN[ NID_ISO_US ] = SN_ISO_US;
        NID_TO_SN[ NID_X9_57 ] = SN_X9_57;
        NID_TO_SN[ NID_X9cm ] = SN_X9cm;
        NID_TO_SN[ NID_dsa ] = SN_dsa;
        NID_TO_SN[ NID_dsaWithSHA1 ] = SN_dsaWithSHA1;
        NID_TO_SN[ NID_ansi_X9_62 ] = SN_ansi_X9_62;
        NID_TO_SN[ NID_X9_62_prime_field ] = SN_X9_62_prime_field;
        NID_TO_SN[ NID_X9_62_characteristic_two_field ] = SN_X9_62_characteristic_two_field;
        NID_TO_SN[ NID_X9_62_id_characteristic_two_basis ] = SN_X9_62_id_characteristic_two_basis;
        NID_TO_SN[ NID_X9_62_onBasis ] = SN_X9_62_onBasis;
        NID_TO_SN[ NID_X9_62_tpBasis ] = SN_X9_62_tpBasis;
        NID_TO_SN[ NID_X9_62_ppBasis ] = SN_X9_62_ppBasis;
        NID_TO_SN[ NID_X9_62_id_ecPublicKey ] = SN_X9_62_id_ecPublicKey;
        NID_TO_SN[ NID_X9_62_c2pnb163v1 ] = SN_X9_62_c2pnb163v1;
        NID_TO_SN[ NID_X9_62_c2pnb163v2 ] = SN_X9_62_c2pnb163v2;
        NID_TO_SN[ NID_X9_62_c2pnb163v3 ] = SN_X9_62_c2pnb163v3;
        NID_TO_SN[ NID_X9_62_c2pnb176v1 ] = SN_X9_62_c2pnb176v1;
        NID_TO_SN[ NID_X9_62_c2tnb191v1 ] = SN_X9_62_c2tnb191v1;
        NID_TO_SN[ NID_X9_62_c2tnb191v2 ] = SN_X9_62_c2tnb191v2;
        NID_TO_SN[ NID_X9_62_c2tnb191v3 ] = SN_X9_62_c2tnb191v3;
        NID_TO_SN[ NID_X9_62_c2onb191v4 ] = SN_X9_62_c2onb191v4;
        NID_TO_SN[ NID_X9_62_c2onb191v5 ] = SN_X9_62_c2onb191v5;
        NID_TO_SN[ NID_X9_62_c2pnb208w1 ] = SN_X9_62_c2pnb208w1;
        NID_TO_SN[ NID_X9_62_c2tnb239v1 ] = SN_X9_62_c2tnb239v1;
        NID_TO_SN[ NID_X9_62_c2tnb239v2 ] = SN_X9_62_c2tnb239v2;
        NID_TO_SN[ NID_X9_62_c2tnb239v3 ] = SN_X9_62_c2tnb239v3;
        NID_TO_SN[ NID_X9_62_c2onb239v4 ] = SN_X9_62_c2onb239v4;
        NID_TO_SN[ NID_X9_62_c2onb239v5 ] = SN_X9_62_c2onb239v5;
        NID_TO_SN[ NID_X9_62_c2pnb272w1 ] = SN_X9_62_c2pnb272w1;
        NID_TO_SN[ NID_X9_62_c2pnb304w1 ] = SN_X9_62_c2pnb304w1;
        NID_TO_SN[ NID_X9_62_c2tnb359v1 ] = SN_X9_62_c2tnb359v1;
        NID_TO_SN[ NID_X9_62_c2pnb368w1 ] = SN_X9_62_c2pnb368w1;
        NID_TO_SN[ NID_X9_62_c2tnb431r1 ] = SN_X9_62_c2tnb431r1;
        NID_TO_SN[ NID_X9_62_prime192v1 ] = SN_X9_62_prime192v1;
        NID_TO_SN[ NID_X9_62_prime192v2 ] = SN_X9_62_prime192v2;
        NID_TO_SN[ NID_X9_62_prime192v3 ] = SN_X9_62_prime192v3;
        NID_TO_SN[ NID_X9_62_prime239v1 ] = SN_X9_62_prime239v1;
        NID_TO_SN[ NID_X9_62_prime239v2 ] = SN_X9_62_prime239v2;
        NID_TO_SN[ NID_X9_62_prime239v3 ] = SN_X9_62_prime239v3;
        NID_TO_SN[ NID_X9_62_prime256v1 ] = SN_X9_62_prime256v1;
        NID_TO_SN[ NID_ecdsa_with_SHA1 ] = SN_ecdsa_with_SHA1;
        NID_TO_SN[ NID_ecdsa_with_Recommended ] = SN_ecdsa_with_Recommended;
        NID_TO_SN[ NID_ecdsa_with_Specified ] = SN_ecdsa_with_Specified;
        NID_TO_SN[ NID_ecdsa_with_SHA224 ] = SN_ecdsa_with_SHA224;
        NID_TO_SN[ NID_ecdsa_with_SHA256 ] = SN_ecdsa_with_SHA256;
        NID_TO_SN[ NID_ecdsa_with_SHA384 ] = SN_ecdsa_with_SHA384;
        NID_TO_SN[ NID_ecdsa_with_SHA512 ] = SN_ecdsa_with_SHA512;
        NID_TO_SN[ NID_secp112r1 ] = SN_secp112r1;
        NID_TO_SN[ NID_secp112r2 ] = SN_secp112r2;
        NID_TO_SN[ NID_secp128r1 ] = SN_secp128r1;
        NID_TO_SN[ NID_secp128r2 ] = SN_secp128r2;
        NID_TO_SN[ NID_secp160k1 ] = SN_secp160k1;
        NID_TO_SN[ NID_secp160r1 ] = SN_secp160r1;
        NID_TO_SN[ NID_secp160r2 ] = SN_secp160r2;
        NID_TO_SN[ NID_secp192k1 ] = SN_secp192k1;
        NID_TO_SN[ NID_secp224k1 ] = SN_secp224k1;
        NID_TO_SN[ NID_secp224r1 ] = SN_secp224r1;
        NID_TO_SN[ NID_secp256k1 ] = SN_secp256k1;
        NID_TO_SN[ NID_secp384r1 ] = SN_secp384r1;
        NID_TO_SN[ NID_secp521r1 ] = SN_secp521r1;
        NID_TO_SN[ NID_sect113r1 ] = SN_sect113r1;
        NID_TO_SN[ NID_sect113r2 ] = SN_sect113r2;
        NID_TO_SN[ NID_sect131r1 ] = SN_sect131r1;
        NID_TO_SN[ NID_sect131r2 ] = SN_sect131r2;
        NID_TO_SN[ NID_sect163k1 ] = SN_sect163k1;
        NID_TO_SN[ NID_sect163r1 ] = SN_sect163r1;
        NID_TO_SN[ NID_sect163r2 ] = SN_sect163r2;
        NID_TO_SN[ NID_sect193r1 ] = SN_sect193r1;
        NID_TO_SN[ NID_sect193r2 ] = SN_sect193r2;
        NID_TO_SN[ NID_sect233k1 ] = SN_sect233k1;
        NID_TO_SN[ NID_sect233r1 ] = SN_sect233r1;
        NID_TO_SN[ NID_sect239k1 ] = SN_sect239k1;
        NID_TO_SN[ NID_sect283k1 ] = SN_sect283k1;
        NID_TO_SN[ NID_sect283r1 ] = SN_sect283r1;
        NID_TO_SN[ NID_sect409k1 ] = SN_sect409k1;
        NID_TO_SN[ NID_sect409r1 ] = SN_sect409r1;
        NID_TO_SN[ NID_sect571k1 ] = SN_sect571k1;
        NID_TO_SN[ NID_sect571r1 ] = SN_sect571r1;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls1 ] = SN_wap_wsg_idm_ecid_wtls1;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls3 ] = SN_wap_wsg_idm_ecid_wtls3;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls4 ] = SN_wap_wsg_idm_ecid_wtls4;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls5 ] = SN_wap_wsg_idm_ecid_wtls5;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls6 ] = SN_wap_wsg_idm_ecid_wtls6;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls7 ] = SN_wap_wsg_idm_ecid_wtls7;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls8 ] = SN_wap_wsg_idm_ecid_wtls8;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls9 ] = SN_wap_wsg_idm_ecid_wtls9;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls10 ] = SN_wap_wsg_idm_ecid_wtls10;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls11 ] = SN_wap_wsg_idm_ecid_wtls11;
        NID_TO_SN[ NID_wap_wsg_idm_ecid_wtls12 ] = SN_wap_wsg_idm_ecid_wtls12;
        NID_TO_SN[ NID_cast5_cbc ] = SN_cast5_cbc;
        NID_TO_SN[ NID_cast5_ecb ] = SN_cast5_ecb;
        NID_TO_SN[ NID_cast5_cfb64 ] = SN_cast5_cfb64;
        NID_TO_SN[ NID_cast5_ofb64 ] = SN_cast5_ofb64;
        NID_TO_SN[ NID_id_PasswordBasedMAC ] = SN_id_PasswordBasedMAC;
        NID_TO_SN[ NID_id_DHBasedMac ] = SN_id_DHBasedMac;
        NID_TO_SN[ NID_rsadsi ] = SN_rsadsi;
        NID_TO_SN[ NID_pkcs ] = SN_pkcs;
        NID_TO_SN[ NID_pkcs1 ] = SN_pkcs1;
        NID_TO_SN[ NID_md2WithRSAEncryption ] = SN_md2WithRSAEncryption;
        NID_TO_SN[ NID_md4WithRSAEncryption ] = SN_md4WithRSAEncryption;
        NID_TO_SN[ NID_md5WithRSAEncryption ] = SN_md5WithRSAEncryption;
        NID_TO_SN[ NID_sha1WithRSAEncryption ] = SN_sha1WithRSAEncryption;
        NID_TO_SN[ NID_rsaesOaep ] = SN_rsaesOaep;
        NID_TO_SN[ NID_mgf1 ] = SN_mgf1;
        NID_TO_SN[ NID_pSpecified ] = SN_pSpecified;
        NID_TO_SN[ NID_rsassaPss ] = SN_rsassaPss;
        NID_TO_SN[ NID_sha256WithRSAEncryption ] = SN_sha256WithRSAEncryption;
        NID_TO_SN[ NID_sha384WithRSAEncryption ] = SN_sha384WithRSAEncryption;
        NID_TO_SN[ NID_sha512WithRSAEncryption ] = SN_sha512WithRSAEncryption;
        NID_TO_SN[ NID_sha224WithRSAEncryption ] = SN_sha224WithRSAEncryption;
        NID_TO_SN[ NID_pkcs3 ] = SN_pkcs3;
        NID_TO_SN[ NID_pkcs5 ] = SN_pkcs5;
        NID_TO_SN[ NID_pbeWithMD2AndDES_CBC ] = SN_pbeWithMD2AndDES_CBC;
        NID_TO_SN[ NID_pbeWithMD5AndDES_CBC ] = SN_pbeWithMD5AndDES_CBC;
        NID_TO_SN[ NID_pbeWithMD2AndRC2_CBC ] = SN_pbeWithMD2AndRC2_CBC;
        NID_TO_SN[ NID_pbeWithMD5AndRC2_CBC ] = SN_pbeWithMD5AndRC2_CBC;
        NID_TO_SN[ NID_pbeWithSHA1AndDES_CBC ] = SN_pbeWithSHA1AndDES_CBC;
        NID_TO_SN[ NID_pbeWithSHA1AndRC2_CBC ] = SN_pbeWithSHA1AndRC2_CBC;
        NID_TO_SN[ NID_pkcs7 ] = SN_pkcs7;
        NID_TO_SN[ NID_pkcs9 ] = SN_pkcs9;
        NID_TO_SN[ NID_ext_req ] = SN_ext_req;
        NID_TO_SN[ NID_SMIMECapabilities ] = SN_SMIMECapabilities;
        NID_TO_SN[ NID_SMIME ] = SN_SMIME;
        NID_TO_SN[ NID_id_smime_mod ] = SN_id_smime_mod;
        NID_TO_SN[ NID_id_smime_ct ] = SN_id_smime_ct;
        NID_TO_SN[ NID_id_smime_aa ] = SN_id_smime_aa;
        NID_TO_SN[ NID_id_smime_alg ] = SN_id_smime_alg;
        NID_TO_SN[ NID_id_smime_cd ] = SN_id_smime_cd;
        NID_TO_SN[ NID_id_smime_spq ] = SN_id_smime_spq;
        NID_TO_SN[ NID_id_smime_cti ] = SN_id_smime_cti;
        NID_TO_SN[ NID_id_smime_mod_cms ] = SN_id_smime_mod_cms;
        NID_TO_SN[ NID_id_smime_mod_ess ] = SN_id_smime_mod_ess;
        NID_TO_SN[ NID_id_smime_mod_oid ] = SN_id_smime_mod_oid;
        NID_TO_SN[ NID_id_smime_mod_msg_v3 ] = SN_id_smime_mod_msg_v3;
        NID_TO_SN[ NID_id_smime_mod_ets_eSignature_88 ] = SN_id_smime_mod_ets_eSignature_88;
        NID_TO_SN[ NID_id_smime_mod_ets_eSignature_97 ] = SN_id_smime_mod_ets_eSignature_97;
        NID_TO_SN[ NID_id_smime_mod_ets_eSigPolicy_88 ] = SN_id_smime_mod_ets_eSigPolicy_88;
        NID_TO_SN[ NID_id_smime_mod_ets_eSigPolicy_97 ] = SN_id_smime_mod_ets_eSigPolicy_97;
        NID_TO_SN[ NID_id_smime_ct_receipt ] = SN_id_smime_ct_receipt;
        NID_TO_SN[ NID_id_smime_ct_authData ] = SN_id_smime_ct_authData;
        NID_TO_SN[ NID_id_smime_ct_publishCert ] = SN_id_smime_ct_publishCert;
        NID_TO_SN[ NID_id_smime_ct_TSTInfo ] = SN_id_smime_ct_TSTInfo;
        NID_TO_SN[ NID_id_smime_ct_TDTInfo ] = SN_id_smime_ct_TDTInfo;
        NID_TO_SN[ NID_id_smime_ct_contentInfo ] = SN_id_smime_ct_contentInfo;
        NID_TO_SN[ NID_id_smime_ct_DVCSRequestData ] = SN_id_smime_ct_DVCSRequestData;
        NID_TO_SN[ NID_id_smime_ct_DVCSResponseData ] = SN_id_smime_ct_DVCSResponseData;
        NID_TO_SN[ NID_id_smime_ct_compressedData ] = SN_id_smime_ct_compressedData;
        NID_TO_SN[ NID_id_ct_asciiTextWithCRLF ] = SN_id_ct_asciiTextWithCRLF;
        NID_TO_SN[ NID_id_smime_aa_receiptRequest ] = SN_id_smime_aa_receiptRequest;
        NID_TO_SN[ NID_id_smime_aa_securityLabel ] = SN_id_smime_aa_securityLabel;
        NID_TO_SN[ NID_id_smime_aa_mlExpandHistory ] = SN_id_smime_aa_mlExpandHistory;
        NID_TO_SN[ NID_id_smime_aa_contentHint ] = SN_id_smime_aa_contentHint;
        NID_TO_SN[ NID_id_smime_aa_msgSigDigest ] = SN_id_smime_aa_msgSigDigest;
        NID_TO_SN[ NID_id_smime_aa_encapContentType ] = SN_id_smime_aa_encapContentType;
        NID_TO_SN[ NID_id_smime_aa_contentIdentifier ] = SN_id_smime_aa_contentIdentifier;
        NID_TO_SN[ NID_id_smime_aa_macValue ] = SN_id_smime_aa_macValue;
        NID_TO_SN[ NID_id_smime_aa_equivalentLabels ] = SN_id_smime_aa_equivalentLabels;
        NID_TO_SN[ NID_id_smime_aa_contentReference ] = SN_id_smime_aa_contentReference;
        NID_TO_SN[ NID_id_smime_aa_encrypKeyPref ] = SN_id_smime_aa_encrypKeyPref;
        NID_TO_SN[ NID_id_smime_aa_signingCertificate ] = SN_id_smime_aa_signingCertificate;
        NID_TO_SN[ NID_id_smime_aa_smimeEncryptCerts ] = SN_id_smime_aa_smimeEncryptCerts;
        NID_TO_SN[ NID_id_smime_aa_timeStampToken ] = SN_id_smime_aa_timeStampToken;
        NID_TO_SN[ NID_id_smime_aa_ets_sigPolicyId ] = SN_id_smime_aa_ets_sigPolicyId;
        NID_TO_SN[ NID_id_smime_aa_ets_commitmentType ] = SN_id_smime_aa_ets_commitmentType;
        NID_TO_SN[ NID_id_smime_aa_ets_signerLocation ] = SN_id_smime_aa_ets_signerLocation;
        NID_TO_SN[ NID_id_smime_aa_ets_signerAttr ] = SN_id_smime_aa_ets_signerAttr;
        NID_TO_SN[ NID_id_smime_aa_ets_otherSigCert ] = SN_id_smime_aa_ets_otherSigCert;
        NID_TO_SN[ NID_id_smime_aa_ets_contentTimestamp ] = SN_id_smime_aa_ets_contentTimestamp;
        NID_TO_SN[ NID_id_smime_aa_ets_CertificateRefs ] = SN_id_smime_aa_ets_CertificateRefs;
        NID_TO_SN[ NID_id_smime_aa_ets_RevocationRefs ] = SN_id_smime_aa_ets_RevocationRefs;
        NID_TO_SN[ NID_id_smime_aa_ets_certValues ] = SN_id_smime_aa_ets_certValues;
        NID_TO_SN[ NID_id_smime_aa_ets_revocationValues ] = SN_id_smime_aa_ets_revocationValues;
        NID_TO_SN[ NID_id_smime_aa_ets_escTimeStamp ] = SN_id_smime_aa_ets_escTimeStamp;
        NID_TO_SN[ NID_id_smime_aa_ets_certCRLTimestamp ] = SN_id_smime_aa_ets_certCRLTimestamp;
        NID_TO_SN[ NID_id_smime_aa_ets_archiveTimeStamp ] = SN_id_smime_aa_ets_archiveTimeStamp;
        NID_TO_SN[ NID_id_smime_aa_signatureType ] = SN_id_smime_aa_signatureType;
        NID_TO_SN[ NID_id_smime_aa_dvcs_dvc ] = SN_id_smime_aa_dvcs_dvc;
        NID_TO_SN[ NID_id_smime_alg_ESDHwith3DES ] = SN_id_smime_alg_ESDHwith3DES;
        NID_TO_SN[ NID_id_smime_alg_ESDHwithRC2 ] = SN_id_smime_alg_ESDHwithRC2;
        NID_TO_SN[ NID_id_smime_alg_3DESwrap ] = SN_id_smime_alg_3DESwrap;
        NID_TO_SN[ NID_id_smime_alg_RC2wrap ] = SN_id_smime_alg_RC2wrap;
        NID_TO_SN[ NID_id_smime_alg_ESDH ] = SN_id_smime_alg_ESDH;
        NID_TO_SN[ NID_id_smime_alg_CMS3DESwrap ] = SN_id_smime_alg_CMS3DESwrap;
        NID_TO_SN[ NID_id_smime_alg_CMSRC2wrap ] = SN_id_smime_alg_CMSRC2wrap;
        NID_TO_SN[ NID_id_alg_PWRI_KEK ] = SN_id_alg_PWRI_KEK;
        NID_TO_SN[ NID_id_smime_cd_ldap ] = SN_id_smime_cd_ldap;
        NID_TO_SN[ NID_id_smime_spq_ets_sqt_uri ] = SN_id_smime_spq_ets_sqt_uri;
        NID_TO_SN[ NID_id_smime_spq_ets_sqt_unotice ] = SN_id_smime_spq_ets_sqt_unotice;
        NID_TO_SN[ NID_id_smime_cti_ets_proofOfOrigin ] = SN_id_smime_cti_ets_proofOfOrigin;
        NID_TO_SN[ NID_id_smime_cti_ets_proofOfReceipt ] = SN_id_smime_cti_ets_proofOfReceipt;
        NID_TO_SN[ NID_id_smime_cti_ets_proofOfDelivery ] = SN_id_smime_cti_ets_proofOfDelivery;
        NID_TO_SN[ NID_id_smime_cti_ets_proofOfSender ] = SN_id_smime_cti_ets_proofOfSender;
        NID_TO_SN[ NID_id_smime_cti_ets_proofOfApproval ] = SN_id_smime_cti_ets_proofOfApproval;
        NID_TO_SN[ NID_id_smime_cti_ets_proofOfCreation ] = SN_id_smime_cti_ets_proofOfCreation;
        NID_TO_SN[ NID_ms_csp_name ] = SN_ms_csp_name;
        NID_TO_SN[ NID_LocalKeySet ] = SN_LocalKeySet;
        NID_TO_SN[ NID_pbe_WithSHA1And128BitRC4 ] = SN_pbe_WithSHA1And128BitRC4;
        NID_TO_SN[ NID_pbe_WithSHA1And40BitRC4 ] = SN_pbe_WithSHA1And40BitRC4;
        NID_TO_SN[ NID_pbe_WithSHA1And3_Key_TripleDES_CBC ] = SN_pbe_WithSHA1And3_Key_TripleDES_CBC;
        NID_TO_SN[ NID_pbe_WithSHA1And2_Key_TripleDES_CBC ] = SN_pbe_WithSHA1And2_Key_TripleDES_CBC;
        NID_TO_SN[ NID_pbe_WithSHA1And128BitRC2_CBC ] = SN_pbe_WithSHA1And128BitRC2_CBC;
        NID_TO_SN[ NID_pbe_WithSHA1And40BitRC2_CBC ] = SN_pbe_WithSHA1And40BitRC2_CBC;
        NID_TO_SN[ NID_md2 ] = SN_md2;
        NID_TO_SN[ NID_md4 ] = SN_md4;
        NID_TO_SN[ NID_md5 ] = SN_md5;
        NID_TO_SN[ NID_md5_sha1 ] = SN_md5_sha1;
        NID_TO_SN[ NID_rc2_cbc ] = SN_rc2_cbc;
        NID_TO_SN[ NID_rc2_ecb ] = SN_rc2_ecb;
        NID_TO_SN[ NID_rc2_cfb64 ] = SN_rc2_cfb64;
        NID_TO_SN[ NID_rc2_ofb64 ] = SN_rc2_ofb64;
        NID_TO_SN[ NID_rc2_40_cbc ] = SN_rc2_40_cbc;
        NID_TO_SN[ NID_rc2_64_cbc ] = SN_rc2_64_cbc;
        NID_TO_SN[ NID_rc4 ] = SN_rc4;
        NID_TO_SN[ NID_rc4_40 ] = SN_rc4_40;
        NID_TO_SN[ NID_des_ede3_cbc ] = SN_des_ede3_cbc;
        NID_TO_SN[ NID_rc5_cbc ] = SN_rc5_cbc;
        NID_TO_SN[ NID_rc5_ecb ] = SN_rc5_ecb;
        NID_TO_SN[ NID_rc5_cfb64 ] = SN_rc5_cfb64;
        NID_TO_SN[ NID_rc5_ofb64 ] = SN_rc5_ofb64;
        NID_TO_SN[ NID_ms_ext_req ] = SN_ms_ext_req;
        NID_TO_SN[ NID_ms_code_ind ] = SN_ms_code_ind;
        NID_TO_SN[ NID_ms_code_com ] = SN_ms_code_com;
        NID_TO_SN[ NID_ms_ctl_sign ] = SN_ms_ctl_sign;
        NID_TO_SN[ NID_ms_sgc ] = SN_ms_sgc;
        NID_TO_SN[ NID_ms_efs ] = SN_ms_efs;
        NID_TO_SN[ NID_ms_smartcard_login ] = SN_ms_smartcard_login;
        NID_TO_SN[ NID_ms_upn ] = SN_ms_upn;
        NID_TO_SN[ NID_idea_cbc ] = SN_idea_cbc;
        NID_TO_SN[ NID_idea_ecb ] = SN_idea_ecb;
        NID_TO_SN[ NID_idea_cfb64 ] = SN_idea_cfb64;
        NID_TO_SN[ NID_idea_ofb64 ] = SN_idea_ofb64;
        NID_TO_SN[ NID_bf_cbc ] = SN_bf_cbc;
        NID_TO_SN[ NID_bf_ecb ] = SN_bf_ecb;
        NID_TO_SN[ NID_bf_cfb64 ] = SN_bf_cfb64;
        NID_TO_SN[ NID_bf_ofb64 ] = SN_bf_ofb64;
        NID_TO_SN[ NID_id_pkix ] = SN_id_pkix;
        NID_TO_SN[ NID_id_pkix_mod ] = SN_id_pkix_mod;
        NID_TO_SN[ NID_id_pe ] = SN_id_pe;
        NID_TO_SN[ NID_id_qt ] = SN_id_qt;
        NID_TO_SN[ NID_id_kp ] = SN_id_kp;
        NID_TO_SN[ NID_id_it ] = SN_id_it;
        NID_TO_SN[ NID_id_pkip ] = SN_id_pkip;
        NID_TO_SN[ NID_id_alg ] = SN_id_alg;
        NID_TO_SN[ NID_id_cmc ] = SN_id_cmc;
        NID_TO_SN[ NID_id_on ] = SN_id_on;
        NID_TO_SN[ NID_id_pda ] = SN_id_pda;
        NID_TO_SN[ NID_id_aca ] = SN_id_aca;
        NID_TO_SN[ NID_id_qcs ] = SN_id_qcs;
        NID_TO_SN[ NID_id_cct ] = SN_id_cct;
        NID_TO_SN[ NID_id_ppl ] = SN_id_ppl;
        NID_TO_SN[ NID_id_ad ] = SN_id_ad;
        NID_TO_SN[ NID_id_pkix1_explicit_88 ] = SN_id_pkix1_explicit_88;
        NID_TO_SN[ NID_id_pkix1_implicit_88 ] = SN_id_pkix1_implicit_88;
        NID_TO_SN[ NID_id_pkix1_explicit_93 ] = SN_id_pkix1_explicit_93;
        NID_TO_SN[ NID_id_pkix1_implicit_93 ] = SN_id_pkix1_implicit_93;
        NID_TO_SN[ NID_id_mod_crmf ] = SN_id_mod_crmf;
        NID_TO_SN[ NID_id_mod_cmc ] = SN_id_mod_cmc;
        NID_TO_SN[ NID_id_mod_kea_profile_88 ] = SN_id_mod_kea_profile_88;
        NID_TO_SN[ NID_id_mod_kea_profile_93 ] = SN_id_mod_kea_profile_93;
        NID_TO_SN[ NID_id_mod_cmp ] = SN_id_mod_cmp;
        NID_TO_SN[ NID_id_mod_qualified_cert_88 ] = SN_id_mod_qualified_cert_88;
        NID_TO_SN[ NID_id_mod_qualified_cert_93 ] = SN_id_mod_qualified_cert_93;
        NID_TO_SN[ NID_id_mod_attribute_cert ] = SN_id_mod_attribute_cert;
        NID_TO_SN[ NID_id_mod_timestamp_protocol ] = SN_id_mod_timestamp_protocol;
        NID_TO_SN[ NID_id_mod_ocsp ] = SN_id_mod_ocsp;
        NID_TO_SN[ NID_id_mod_dvcs ] = SN_id_mod_dvcs;
        NID_TO_SN[ NID_id_mod_cmp2000 ] = SN_id_mod_cmp2000;
        NID_TO_SN[ NID_info_access ] = SN_info_access;
        NID_TO_SN[ NID_biometricInfo ] = SN_biometricInfo;
        NID_TO_SN[ NID_qcStatements ] = SN_qcStatements;
        NID_TO_SN[ NID_ac_auditEntity ] = SN_ac_auditEntity;
        NID_TO_SN[ NID_ac_targeting ] = SN_ac_targeting;
        NID_TO_SN[ NID_aaControls ] = SN_aaControls;
        NID_TO_SN[ NID_sbgp_ipAddrBlock ] = SN_sbgp_ipAddrBlock;
        NID_TO_SN[ NID_sbgp_autonomousSysNum ] = SN_sbgp_autonomousSysNum;
        NID_TO_SN[ NID_sbgp_routerIdentifier ] = SN_sbgp_routerIdentifier;
        NID_TO_SN[ NID_ac_proxying ] = SN_ac_proxying;
        NID_TO_SN[ NID_sinfo_access ] = SN_sinfo_access;
        NID_TO_SN[ NID_proxyCertInfo ] = SN_proxyCertInfo;
        NID_TO_SN[ NID_id_qt_cps ] = SN_id_qt_cps;
        NID_TO_SN[ NID_id_qt_unotice ] = SN_id_qt_unotice;
        NID_TO_SN[ NID_textNotice ] = SN_textNotice;
        NID_TO_SN[ NID_server_auth ] = SN_server_auth;
        NID_TO_SN[ NID_client_auth ] = SN_client_auth;
        NID_TO_SN[ NID_code_sign ] = SN_code_sign;
        NID_TO_SN[ NID_email_protect ] = SN_email_protect;
        NID_TO_SN[ NID_ipsecEndSystem ] = SN_ipsecEndSystem;
        NID_TO_SN[ NID_ipsecTunnel ] = SN_ipsecTunnel;
        NID_TO_SN[ NID_ipsecUser ] = SN_ipsecUser;
        NID_TO_SN[ NID_time_stamp ] = SN_time_stamp;
        NID_TO_SN[ NID_OCSP_sign ] = SN_OCSP_sign;
        NID_TO_SN[ NID_dvcs ] = SN_dvcs;
        NID_TO_SN[ NID_id_it_caProtEncCert ] = SN_id_it_caProtEncCert;
        NID_TO_SN[ NID_id_it_signKeyPairTypes ] = SN_id_it_signKeyPairTypes;
        NID_TO_SN[ NID_id_it_encKeyPairTypes ] = SN_id_it_encKeyPairTypes;
        NID_TO_SN[ NID_id_it_preferredSymmAlg ] = SN_id_it_preferredSymmAlg;
        NID_TO_SN[ NID_id_it_caKeyUpdateInfo ] = SN_id_it_caKeyUpdateInfo;
        NID_TO_SN[ NID_id_it_currentCRL ] = SN_id_it_currentCRL;
        NID_TO_SN[ NID_id_it_unsupportedOIDs ] = SN_id_it_unsupportedOIDs;
        NID_TO_SN[ NID_id_it_subscriptionRequest ] = SN_id_it_subscriptionRequest;
        NID_TO_SN[ NID_id_it_subscriptionResponse ] = SN_id_it_subscriptionResponse;
        NID_TO_SN[ NID_id_it_keyPairParamReq ] = SN_id_it_keyPairParamReq;
        NID_TO_SN[ NID_id_it_keyPairParamRep ] = SN_id_it_keyPairParamRep;
        NID_TO_SN[ NID_id_it_revPassphrase ] = SN_id_it_revPassphrase;
        NID_TO_SN[ NID_id_it_implicitConfirm ] = SN_id_it_implicitConfirm;
        NID_TO_SN[ NID_id_it_confirmWaitTime ] = SN_id_it_confirmWaitTime;
        NID_TO_SN[ NID_id_it_origPKIMessage ] = SN_id_it_origPKIMessage;
        NID_TO_SN[ NID_id_it_suppLangTags ] = SN_id_it_suppLangTags;
        NID_TO_SN[ NID_id_regCtrl ] = SN_id_regCtrl;
        NID_TO_SN[ NID_id_regInfo ] = SN_id_regInfo;
        NID_TO_SN[ NID_id_regCtrl_regToken ] = SN_id_regCtrl_regToken;
        NID_TO_SN[ NID_id_regCtrl_authenticator ] = SN_id_regCtrl_authenticator;
        NID_TO_SN[ NID_id_regCtrl_pkiPublicationInfo ] = SN_id_regCtrl_pkiPublicationInfo;
        NID_TO_SN[ NID_id_regCtrl_pkiArchiveOptions ] = SN_id_regCtrl_pkiArchiveOptions;
        NID_TO_SN[ NID_id_regCtrl_oldCertID ] = SN_id_regCtrl_oldCertID;
        NID_TO_SN[ NID_id_regCtrl_protocolEncrKey ] = SN_id_regCtrl_protocolEncrKey;
        NID_TO_SN[ NID_id_regInfo_utf8Pairs ] = SN_id_regInfo_utf8Pairs;
        NID_TO_SN[ NID_id_regInfo_certReq ] = SN_id_regInfo_certReq;
        NID_TO_SN[ NID_id_alg_des40 ] = SN_id_alg_des40;
        NID_TO_SN[ NID_id_alg_noSignature ] = SN_id_alg_noSignature;
        NID_TO_SN[ NID_id_alg_dh_sig_hmac_sha1 ] = SN_id_alg_dh_sig_hmac_sha1;
        NID_TO_SN[ NID_id_alg_dh_pop ] = SN_id_alg_dh_pop;
        NID_TO_SN[ NID_id_cmc_statusInfo ] = SN_id_cmc_statusInfo;
        NID_TO_SN[ NID_id_cmc_identification ] = SN_id_cmc_identification;
        NID_TO_SN[ NID_id_cmc_identityProof ] = SN_id_cmc_identityProof;
        NID_TO_SN[ NID_id_cmc_dataReturn ] = SN_id_cmc_dataReturn;
        NID_TO_SN[ NID_id_cmc_transactionId ] = SN_id_cmc_transactionId;
        NID_TO_SN[ NID_id_cmc_senderNonce ] = SN_id_cmc_senderNonce;
        NID_TO_SN[ NID_id_cmc_recipientNonce ] = SN_id_cmc_recipientNonce;
        NID_TO_SN[ NID_id_cmc_addExtensions ] = SN_id_cmc_addExtensions;
        NID_TO_SN[ NID_id_cmc_encryptedPOP ] = SN_id_cmc_encryptedPOP;
        NID_TO_SN[ NID_id_cmc_decryptedPOP ] = SN_id_cmc_decryptedPOP;
        NID_TO_SN[ NID_id_cmc_lraPOPWitness ] = SN_id_cmc_lraPOPWitness;
        NID_TO_SN[ NID_id_cmc_getCert ] = SN_id_cmc_getCert;
        NID_TO_SN[ NID_id_cmc_getCRL ] = SN_id_cmc_getCRL;
        NID_TO_SN[ NID_id_cmc_revokeRequest ] = SN_id_cmc_revokeRequest;
        NID_TO_SN[ NID_id_cmc_regInfo ] = SN_id_cmc_regInfo;
        NID_TO_SN[ NID_id_cmc_responseInfo ] = SN_id_cmc_responseInfo;
        NID_TO_SN[ NID_id_cmc_queryPending ] = SN_id_cmc_queryPending;
        NID_TO_SN[ NID_id_cmc_popLinkRandom ] = SN_id_cmc_popLinkRandom;
        NID_TO_SN[ NID_id_cmc_popLinkWitness ] = SN_id_cmc_popLinkWitness;
        NID_TO_SN[ NID_id_cmc_confirmCertAcceptance ] = SN_id_cmc_confirmCertAcceptance;
        NID_TO_SN[ NID_id_on_personalData ] = SN_id_on_personalData;
        NID_TO_SN[ NID_id_on_permanentIdentifier ] = SN_id_on_permanentIdentifier;
        NID_TO_SN[ NID_id_pda_dateOfBirth ] = SN_id_pda_dateOfBirth;
        NID_TO_SN[ NID_id_pda_placeOfBirth ] = SN_id_pda_placeOfBirth;
        NID_TO_SN[ NID_id_pda_gender ] = SN_id_pda_gender;
        NID_TO_SN[ NID_id_pda_countryOfCitizenship ] = SN_id_pda_countryOfCitizenship;
        NID_TO_SN[ NID_id_pda_countryOfResidence ] = SN_id_pda_countryOfResidence;
        NID_TO_SN[ NID_id_aca_authenticationInfo ] = SN_id_aca_authenticationInfo;
        NID_TO_SN[ NID_id_aca_accessIdentity ] = SN_id_aca_accessIdentity;
        NID_TO_SN[ NID_id_aca_chargingIdentity ] = SN_id_aca_chargingIdentity;
        NID_TO_SN[ NID_id_aca_group ] = SN_id_aca_group;
        NID_TO_SN[ NID_id_aca_role ] = SN_id_aca_role;
        NID_TO_SN[ NID_id_aca_encAttrs ] = SN_id_aca_encAttrs;
        NID_TO_SN[ NID_id_qcs_pkixQCSyntax_v1 ] = SN_id_qcs_pkixQCSyntax_v1;
        NID_TO_SN[ NID_id_cct_crs ] = SN_id_cct_crs;
        NID_TO_SN[ NID_id_cct_PKIData ] = SN_id_cct_PKIData;
        NID_TO_SN[ NID_id_cct_PKIResponse ] = SN_id_cct_PKIResponse;
        NID_TO_SN[ NID_id_ppl_anyLanguage ] = SN_id_ppl_anyLanguage;
        NID_TO_SN[ NID_id_ppl_inheritAll ] = SN_id_ppl_inheritAll;
        NID_TO_SN[ NID_Independent ] = SN_Independent;
        NID_TO_SN[ NID_ad_OCSP ] = SN_ad_OCSP;
        NID_TO_SN[ NID_ad_ca_issuers ] = SN_ad_ca_issuers;
        NID_TO_SN[ NID_ad_timeStamping ] = SN_ad_timeStamping;
        NID_TO_SN[ NID_ad_dvcs ] = SN_ad_dvcs;
        NID_TO_SN[ NID_caRepository ] = SN_caRepository;
        NID_TO_SN[ NID_id_pkix_OCSP_basic ] = SN_id_pkix_OCSP_basic;
        NID_TO_SN[ NID_id_pkix_OCSP_Nonce ] = SN_id_pkix_OCSP_Nonce;
        NID_TO_SN[ NID_id_pkix_OCSP_CrlID ] = SN_id_pkix_OCSP_CrlID;
        NID_TO_SN[ NID_id_pkix_OCSP_acceptableResponses ] = SN_id_pkix_OCSP_acceptableResponses;
        NID_TO_SN[ NID_id_pkix_OCSP_noCheck ] = SN_id_pkix_OCSP_noCheck;
        NID_TO_SN[ NID_id_pkix_OCSP_archiveCutoff ] = SN_id_pkix_OCSP_archiveCutoff;
        NID_TO_SN[ NID_id_pkix_OCSP_serviceLocator ] = SN_id_pkix_OCSP_serviceLocator;
        NID_TO_SN[ NID_id_pkix_OCSP_extendedStatus ] = SN_id_pkix_OCSP_extendedStatus;
        NID_TO_SN[ NID_id_pkix_OCSP_valid ] = SN_id_pkix_OCSP_valid;
        NID_TO_SN[ NID_id_pkix_OCSP_path ] = SN_id_pkix_OCSP_path;
        NID_TO_SN[ NID_id_pkix_OCSP_trustRoot ] = SN_id_pkix_OCSP_trustRoot;
        NID_TO_SN[ NID_algorithm ] = SN_algorithm;
        NID_TO_SN[ NID_md5WithRSA ] = SN_md5WithRSA;
        NID_TO_SN[ NID_des_ecb ] = SN_des_ecb;
        NID_TO_SN[ NID_des_cbc ] = SN_des_cbc;
        NID_TO_SN[ NID_des_ofb64 ] = SN_des_ofb64;
        NID_TO_SN[ NID_des_cfb64 ] = SN_des_cfb64;
        NID_TO_SN[ NID_rsaSignature ] = SN_rsaSignature;
        NID_TO_SN[ NID_dsa_2 ] = SN_dsa_2;
        NID_TO_SN[ NID_dsaWithSHA ] = SN_dsaWithSHA;
        NID_TO_SN[ NID_shaWithRSAEncryption ] = SN_shaWithRSAEncryption;
        NID_TO_SN[ NID_des_ede_ecb ] = SN_des_ede_ecb;
        NID_TO_SN[ NID_des_ede3_ecb ] = SN_des_ede3_ecb;
        NID_TO_SN[ NID_des_ede_cbc ] = SN_des_ede_cbc;
        NID_TO_SN[ NID_des_ede_cfb64 ] = SN_des_ede_cfb64;
        NID_TO_SN[ NID_des_ede3_cfb64 ] = SN_des_ede3_cfb64;
        NID_TO_SN[ NID_des_ede_ofb64 ] = SN_des_ede_ofb64;
        NID_TO_SN[ NID_des_ede3_ofb64 ] = SN_des_ede3_ofb64;
        NID_TO_SN[ NID_desx_cbc ] = SN_desx_cbc;
        NID_TO_SN[ NID_sha ] = SN_sha;
        NID_TO_SN[ NID_sha1 ] = SN_sha1;
        NID_TO_SN[ NID_dsaWithSHA1_2 ] = SN_dsaWithSHA1_2;
        NID_TO_SN[ NID_sha1WithRSA ] = SN_sha1WithRSA;
        NID_TO_SN[ NID_ripemd160 ] = SN_ripemd160;
        NID_TO_SN[ NID_ripemd160WithRSA ] = SN_ripemd160WithRSA;
        NID_TO_SN[ NID_sxnet ] = SN_sxnet;
        NID_TO_SN[ NID_X500 ] = SN_X500;
        NID_TO_SN[ NID_X509 ] = SN_X509;
        NID_TO_SN[ NID_commonName ] = SN_commonName;
        NID_TO_SN[ NID_surname ] = SN_surname;
        NID_TO_SN[ NID_countryName ] = SN_countryName;
        NID_TO_SN[ NID_localityName ] = SN_localityName;
        NID_TO_SN[ NID_stateOrProvinceName ] = SN_stateOrProvinceName;
        NID_TO_SN[ NID_streetAddress ] = SN_streetAddress;
        NID_TO_SN[ NID_organizationName ] = SN_organizationName;
        NID_TO_SN[ NID_organizationalUnitName ] = SN_organizationalUnitName;
        NID_TO_SN[ NID_title ] = SN_title;
        NID_TO_SN[ NID_member ] = SN_member;
        NID_TO_SN[ NID_owner ] = SN_owner;
        NID_TO_SN[ NID_seeAlso ] = SN_seeAlso;
        NID_TO_SN[ NID_name ] = SN_name;
        NID_TO_SN[ NID_givenName ] = SN_givenName;
        NID_TO_SN[ NID_initials ] = SN_initials;
        NID_TO_SN[ NID_dnQualifier ] = SN_dnQualifier;
        NID_TO_SN[ NID_dmdName ] = SN_dmdName;
        NID_TO_SN[ NID_role ] = SN_role;
        NID_TO_SN[ NID_X500algorithms ] = SN_X500algorithms;
        NID_TO_SN[ NID_rsa ] = SN_rsa;
        NID_TO_SN[ NID_mdc2WithRSA ] = SN_mdc2WithRSA;
        NID_TO_SN[ NID_mdc2 ] = SN_mdc2;
        NID_TO_SN[ NID_id_ce ] = SN_id_ce;
        NID_TO_SN[ NID_subject_directory_attributes ] = SN_subject_directory_attributes;
        NID_TO_SN[ NID_subject_key_identifier ] = SN_subject_key_identifier;
        NID_TO_SN[ NID_key_usage ] = SN_key_usage;
        NID_TO_SN[ NID_private_key_usage_period ] = SN_private_key_usage_period;
        NID_TO_SN[ NID_subject_alt_name ] = SN_subject_alt_name;
        NID_TO_SN[ NID_issuer_alt_name ] = SN_issuer_alt_name;
        NID_TO_SN[ NID_basic_constraints ] = SN_basic_constraints;
        NID_TO_SN[ NID_crl_number ] = SN_crl_number;
        NID_TO_SN[ NID_crl_reason ] = SN_crl_reason;
        NID_TO_SN[ NID_invalidity_date ] = SN_invalidity_date;
        NID_TO_SN[ NID_delta_crl ] = SN_delta_crl;
        NID_TO_SN[ NID_issuing_distribution_point ] = SN_issuing_distribution_point;
        NID_TO_SN[ NID_certificate_issuer ] = SN_certificate_issuer;
        NID_TO_SN[ NID_name_constraints ] = SN_name_constraints;
        NID_TO_SN[ NID_crl_distribution_points ] = SN_crl_distribution_points;
        NID_TO_SN[ NID_certificate_policies ] = SN_certificate_policies;
        NID_TO_SN[ NID_any_policy ] = SN_any_policy;
        NID_TO_SN[ NID_policy_mappings ] = SN_policy_mappings;
        NID_TO_SN[ NID_authority_key_identifier ] = SN_authority_key_identifier;
        NID_TO_SN[ NID_policy_constraints ] = SN_policy_constraints;
        NID_TO_SN[ NID_ext_key_usage ] = SN_ext_key_usage;
        NID_TO_SN[ NID_freshest_crl ] = SN_freshest_crl;
        NID_TO_SN[ NID_inhibit_any_policy ] = SN_inhibit_any_policy;
        NID_TO_SN[ NID_target_information ] = SN_target_information;
        NID_TO_SN[ NID_no_rev_avail ] = SN_no_rev_avail;
        NID_TO_SN[ NID_anyExtendedKeyUsage ] = SN_anyExtendedKeyUsage;
        NID_TO_SN[ NID_netscape ] = SN_netscape;
        NID_TO_SN[ NID_netscape_cert_extension ] = SN_netscape_cert_extension;
        NID_TO_SN[ NID_netscape_data_type ] = SN_netscape_data_type;
        NID_TO_SN[ NID_netscape_cert_type ] = SN_netscape_cert_type;
        NID_TO_SN[ NID_netscape_base_url ] = SN_netscape_base_url;
        NID_TO_SN[ NID_netscape_revocation_url ] = SN_netscape_revocation_url;
        NID_TO_SN[ NID_netscape_ca_revocation_url ] = SN_netscape_ca_revocation_url;
        NID_TO_SN[ NID_netscape_renewal_url ] = SN_netscape_renewal_url;
        NID_TO_SN[ NID_netscape_ca_policy_url ] = SN_netscape_ca_policy_url;
        NID_TO_SN[ NID_netscape_ssl_server_name ] = SN_netscape_ssl_server_name;
        NID_TO_SN[ NID_netscape_comment ] = SN_netscape_comment;
        NID_TO_SN[ NID_netscape_cert_sequence ] = SN_netscape_cert_sequence;
        NID_TO_SN[ NID_ns_sgc ] = SN_ns_sgc;
        NID_TO_SN[ NID_org ] = SN_org;
        NID_TO_SN[ NID_dod ] = SN_dod;
        NID_TO_SN[ NID_iana ] = SN_iana;
        NID_TO_SN[ NID_Directory ] = SN_Directory;
        NID_TO_SN[ NID_Management ] = SN_Management;
        NID_TO_SN[ NID_Experimental ] = SN_Experimental;
        NID_TO_SN[ NID_Private ] = SN_Private;
        NID_TO_SN[ NID_Security ] = SN_Security;
        NID_TO_SN[ NID_SNMPv2 ] = SN_SNMPv2;
        NID_TO_SN[ NID_Enterprises ] = SN_Enterprises;
        NID_TO_SN[ NID_dcObject ] = SN_dcObject;
        NID_TO_SN[ NID_mime_mhs ] = SN_mime_mhs;
        NID_TO_SN[ NID_mime_mhs_headings ] = SN_mime_mhs_headings;
        NID_TO_SN[ NID_mime_mhs_bodies ] = SN_mime_mhs_bodies;
        NID_TO_SN[ NID_id_hex_partial_message ] = SN_id_hex_partial_message;
        NID_TO_SN[ NID_id_hex_multipart_message ] = SN_id_hex_multipart_message;
        NID_TO_SN[ NID_rle_compression ] = SN_rle_compression;
        NID_TO_SN[ NID_zlib_compression ] = SN_zlib_compression;
        NID_TO_SN[ NID_aes_128_ecb ] = SN_aes_128_ecb;
        NID_TO_SN[ NID_aes_128_cbc ] = SN_aes_128_cbc;
        NID_TO_SN[ NID_aes_128_ofb128 ] = SN_aes_128_ofb128;
        NID_TO_SN[ NID_aes_128_cfb128 ] = SN_aes_128_cfb128;
        NID_TO_SN[ NID_id_aes128_wrap ] = SN_id_aes128_wrap;
        NID_TO_SN[ NID_aes_128_gcm ] = SN_aes_128_gcm;
        NID_TO_SN[ NID_aes_128_ccm ] = SN_aes_128_ccm;
        NID_TO_SN[ NID_id_aes128_wrap_pad ] = SN_id_aes128_wrap_pad;
        NID_TO_SN[ NID_aes_192_ecb ] = SN_aes_192_ecb;
        NID_TO_SN[ NID_aes_192_cbc ] = SN_aes_192_cbc;
        NID_TO_SN[ NID_aes_192_ofb128 ] = SN_aes_192_ofb128;
        NID_TO_SN[ NID_aes_192_cfb128 ] = SN_aes_192_cfb128;
        NID_TO_SN[ NID_id_aes192_wrap ] = SN_id_aes192_wrap;
        NID_TO_SN[ NID_aes_192_gcm ] = SN_aes_192_gcm;
        NID_TO_SN[ NID_aes_192_ccm ] = SN_aes_192_ccm;
        NID_TO_SN[ NID_id_aes192_wrap_pad ] = SN_id_aes192_wrap_pad;
        NID_TO_SN[ NID_aes_256_ecb ] = SN_aes_256_ecb;
        NID_TO_SN[ NID_aes_256_cbc ] = SN_aes_256_cbc;
        NID_TO_SN[ NID_aes_256_ofb128 ] = SN_aes_256_ofb128;
        NID_TO_SN[ NID_aes_256_cfb128 ] = SN_aes_256_cfb128;
        NID_TO_SN[ NID_id_aes256_wrap ] = SN_id_aes256_wrap;
        NID_TO_SN[ NID_aes_256_gcm ] = SN_aes_256_gcm;
        NID_TO_SN[ NID_aes_256_ccm ] = SN_aes_256_ccm;
        NID_TO_SN[ NID_id_aes256_wrap_pad ] = SN_id_aes256_wrap_pad;
        NID_TO_SN[ NID_aes_128_cfb1 ] = SN_aes_128_cfb1;
        NID_TO_SN[ NID_aes_192_cfb1 ] = SN_aes_192_cfb1;
        NID_TO_SN[ NID_aes_256_cfb1 ] = SN_aes_256_cfb1;
        NID_TO_SN[ NID_aes_128_cfb8 ] = SN_aes_128_cfb8;
        NID_TO_SN[ NID_aes_192_cfb8 ] = SN_aes_192_cfb8;
        NID_TO_SN[ NID_aes_256_cfb8 ] = SN_aes_256_cfb8;
        NID_TO_SN[ NID_aes_128_ctr ] = SN_aes_128_ctr;
        NID_TO_SN[ NID_aes_192_ctr ] = SN_aes_192_ctr;
        NID_TO_SN[ NID_aes_256_ctr ] = SN_aes_256_ctr;
        NID_TO_SN[ NID_aes_128_xts ] = SN_aes_128_xts;
        NID_TO_SN[ NID_aes_256_xts ] = SN_aes_256_xts;
        NID_TO_SN[ NID_des_cfb1 ] = SN_des_cfb1;
        NID_TO_SN[ NID_des_cfb8 ] = SN_des_cfb8;
        NID_TO_SN[ NID_des_ede3_cfb1 ] = SN_des_ede3_cfb1;
        NID_TO_SN[ NID_des_ede3_cfb8 ] = SN_des_ede3_cfb8;
        NID_TO_SN[ NID_sha256 ] = SN_sha256;
        NID_TO_SN[ NID_sha384 ] = SN_sha384;
        NID_TO_SN[ NID_sha512 ] = SN_sha512;
        NID_TO_SN[ NID_sha224 ] = SN_sha224;
        NID_TO_SN[ NID_dsa_with_SHA224 ] = SN_dsa_with_SHA224;
        NID_TO_SN[ NID_dsa_with_SHA256 ] = SN_dsa_with_SHA256;
        NID_TO_SN[ NID_hold_instruction_code ] = SN_hold_instruction_code;
        NID_TO_SN[ NID_hold_instruction_none ] = SN_hold_instruction_none;
        NID_TO_SN[ NID_hold_instruction_call_issuer ] = SN_hold_instruction_call_issuer;
        NID_TO_SN[ NID_hold_instruction_reject ] = SN_hold_instruction_reject;
        NID_TO_SN[ NID_data ] = SN_data;
        NID_TO_SN[ NID_pss ] = SN_pss;
        NID_TO_SN[ NID_ucl ] = SN_ucl;
        NID_TO_SN[ NID_pilot ] = SN_pilot;
        NID_TO_SN[ NID_account ] = SN_account;
        NID_TO_SN[ NID_document ] = SN_document;
        NID_TO_SN[ NID_room ] = SN_room;
        NID_TO_SN[ NID_Domain ] = SN_Domain;
        NID_TO_SN[ NID_userId ] = SN_userId;
        NID_TO_SN[ NID_rfc822Mailbox ] = SN_rfc822Mailbox;
        NID_TO_SN[ NID_info ] = SN_info;
        NID_TO_SN[ NID_photo ] = SN_photo;
        NID_TO_SN[ NID_host ] = SN_host;
        NID_TO_SN[ NID_manager ] = SN_manager;
        NID_TO_SN[ NID_secretary ] = SN_secretary;
        NID_TO_SN[ NID_domainComponent ] = SN_domainComponent;
        NID_TO_SN[ NID_audio ] = SN_audio;
        NID_TO_SN[ NID_id_set ] = SN_id_set;
        NID_TO_SN[ NID_set_ctype ] = SN_set_ctype;
        NID_TO_SN[ NID_set_msgExt ] = SN_set_msgExt;
        NID_TO_SN[ NID_set_attr ] = SN_set_attr;
        NID_TO_SN[ NID_set_policy ] = SN_set_policy;
        NID_TO_SN[ NID_set_certExt ] = SN_set_certExt;
        NID_TO_SN[ NID_set_brand ] = SN_set_brand;
        NID_TO_SN[ NID_setct_PANData ] = SN_setct_PANData;
        NID_TO_SN[ NID_setct_PANToken ] = SN_setct_PANToken;
        NID_TO_SN[ NID_setct_PANOnly ] = SN_setct_PANOnly;
        NID_TO_SN[ NID_setct_OIData ] = SN_setct_OIData;
        NID_TO_SN[ NID_setct_PI ] = SN_setct_PI;
        NID_TO_SN[ NID_setct_PIData ] = SN_setct_PIData;
        NID_TO_SN[ NID_setct_PIDataUnsigned ] = SN_setct_PIDataUnsigned;
        NID_TO_SN[ NID_setct_HODInput ] = SN_setct_HODInput;
        NID_TO_SN[ NID_setct_AuthResBaggage ] = SN_setct_AuthResBaggage;
        NID_TO_SN[ NID_setct_AuthRevReqBaggage ] = SN_setct_AuthRevReqBaggage;
        NID_TO_SN[ NID_setct_AuthRevResBaggage ] = SN_setct_AuthRevResBaggage;
        NID_TO_SN[ NID_setct_CapTokenSeq ] = SN_setct_CapTokenSeq;
        NID_TO_SN[ NID_setct_PInitResData ] = SN_setct_PInitResData;
        NID_TO_SN[ NID_setct_PI_TBS ] = SN_setct_PI_TBS;
        NID_TO_SN[ NID_setct_PResData ] = SN_setct_PResData;
        NID_TO_SN[ NID_setct_AuthReqTBS ] = SN_setct_AuthReqTBS;
        NID_TO_SN[ NID_setct_AuthResTBS ] = SN_setct_AuthResTBS;
        NID_TO_SN[ NID_setct_AuthResTBSX ] = SN_setct_AuthResTBSX;
        NID_TO_SN[ NID_setct_AuthTokenTBS ] = SN_setct_AuthTokenTBS;
        NID_TO_SN[ NID_setct_CapTokenData ] = SN_setct_CapTokenData;
        NID_TO_SN[ NID_setct_CapTokenTBS ] = SN_setct_CapTokenTBS;
        NID_TO_SN[ NID_setct_AcqCardCodeMsg ] = SN_setct_AcqCardCodeMsg;
        NID_TO_SN[ NID_setct_AuthRevReqTBS ] = SN_setct_AuthRevReqTBS;
        NID_TO_SN[ NID_setct_AuthRevResData ] = SN_setct_AuthRevResData;
        NID_TO_SN[ NID_setct_AuthRevResTBS ] = SN_setct_AuthRevResTBS;
        NID_TO_SN[ NID_setct_CapReqTBS ] = SN_setct_CapReqTBS;
        NID_TO_SN[ NID_setct_CapReqTBSX ] = SN_setct_CapReqTBSX;
        NID_TO_SN[ NID_setct_CapResData ] = SN_setct_CapResData;
        NID_TO_SN[ NID_setct_CapRevReqTBS ] = SN_setct_CapRevReqTBS;
        NID_TO_SN[ NID_setct_CapRevReqTBSX ] = SN_setct_CapRevReqTBSX;
        NID_TO_SN[ NID_setct_CapRevResData ] = SN_setct_CapRevResData;
        NID_TO_SN[ NID_setct_CredReqTBS ] = SN_setct_CredReqTBS;
        NID_TO_SN[ NID_setct_CredReqTBSX ] = SN_setct_CredReqTBSX;
        NID_TO_SN[ NID_setct_CredResData ] = SN_setct_CredResData;
        NID_TO_SN[ NID_setct_CredRevReqTBS ] = SN_setct_CredRevReqTBS;
        NID_TO_SN[ NID_setct_CredRevReqTBSX ] = SN_setct_CredRevReqTBSX;
        NID_TO_SN[ NID_setct_CredRevResData ] = SN_setct_CredRevResData;
        NID_TO_SN[ NID_setct_PCertReqData ] = SN_setct_PCertReqData;
        NID_TO_SN[ NID_setct_PCertResTBS ] = SN_setct_PCertResTBS;
        NID_TO_SN[ NID_setct_BatchAdminReqData ] = SN_setct_BatchAdminReqData;
        NID_TO_SN[ NID_setct_BatchAdminResData ] = SN_setct_BatchAdminResData;
        NID_TO_SN[ NID_setct_CardCInitResTBS ] = SN_setct_CardCInitResTBS;
        NID_TO_SN[ NID_setct_MeAqCInitResTBS ] = SN_setct_MeAqCInitResTBS;
        NID_TO_SN[ NID_setct_RegFormResTBS ] = SN_setct_RegFormResTBS;
        NID_TO_SN[ NID_setct_CertReqData ] = SN_setct_CertReqData;
        NID_TO_SN[ NID_setct_CertReqTBS ] = SN_setct_CertReqTBS;
        NID_TO_SN[ NID_setct_CertResData ] = SN_setct_CertResData;
        NID_TO_SN[ NID_setct_CertInqReqTBS ] = SN_setct_CertInqReqTBS;
        NID_TO_SN[ NID_setct_ErrorTBS ] = SN_setct_ErrorTBS;
        NID_TO_SN[ NID_setct_PIDualSignedTBE ] = SN_setct_PIDualSignedTBE;
        NID_TO_SN[ NID_setct_PIUnsignedTBE ] = SN_setct_PIUnsignedTBE;
        NID_TO_SN[ NID_setct_AuthReqTBE ] = SN_setct_AuthReqTBE;
        NID_TO_SN[ NID_setct_AuthResTBE ] = SN_setct_AuthResTBE;
        NID_TO_SN[ NID_setct_AuthResTBEX ] = SN_setct_AuthResTBEX;
        NID_TO_SN[ NID_setct_AuthTokenTBE ] = SN_setct_AuthTokenTBE;
        NID_TO_SN[ NID_setct_CapTokenTBE ] = SN_setct_CapTokenTBE;
        NID_TO_SN[ NID_setct_CapTokenTBEX ] = SN_setct_CapTokenTBEX;
        NID_TO_SN[ NID_setct_AcqCardCodeMsgTBE ] = SN_setct_AcqCardCodeMsgTBE;
        NID_TO_SN[ NID_setct_AuthRevReqTBE ] = SN_setct_AuthRevReqTBE;
        NID_TO_SN[ NID_setct_AuthRevResTBE ] = SN_setct_AuthRevResTBE;
        NID_TO_SN[ NID_setct_AuthRevResTBEB ] = SN_setct_AuthRevResTBEB;
        NID_TO_SN[ NID_setct_CapReqTBE ] = SN_setct_CapReqTBE;
        NID_TO_SN[ NID_setct_CapReqTBEX ] = SN_setct_CapReqTBEX;
        NID_TO_SN[ NID_setct_CapResTBE ] = SN_setct_CapResTBE;
        NID_TO_SN[ NID_setct_CapRevReqTBE ] = SN_setct_CapRevReqTBE;
        NID_TO_SN[ NID_setct_CapRevReqTBEX ] = SN_setct_CapRevReqTBEX;
        NID_TO_SN[ NID_setct_CapRevResTBE ] = SN_setct_CapRevResTBE;
        NID_TO_SN[ NID_setct_CredReqTBE ] = SN_setct_CredReqTBE;
        NID_TO_SN[ NID_setct_CredReqTBEX ] = SN_setct_CredReqTBEX;
        NID_TO_SN[ NID_setct_CredResTBE ] = SN_setct_CredResTBE;
        NID_TO_SN[ NID_setct_CredRevReqTBE ] = SN_setct_CredRevReqTBE;
        NID_TO_SN[ NID_setct_CredRevReqTBEX ] = SN_setct_CredRevReqTBEX;
        NID_TO_SN[ NID_setct_CredRevResTBE ] = SN_setct_CredRevResTBE;
        NID_TO_SN[ NID_setct_BatchAdminReqTBE ] = SN_setct_BatchAdminReqTBE;
        NID_TO_SN[ NID_setct_BatchAdminResTBE ] = SN_setct_BatchAdminResTBE;
        NID_TO_SN[ NID_setct_RegFormReqTBE ] = SN_setct_RegFormReqTBE;
        NID_TO_SN[ NID_setct_CertReqTBE ] = SN_setct_CertReqTBE;
        NID_TO_SN[ NID_setct_CertReqTBEX ] = SN_setct_CertReqTBEX;
        NID_TO_SN[ NID_setct_CertResTBE ] = SN_setct_CertResTBE;
        NID_TO_SN[ NID_setct_CRLNotificationTBS ] = SN_setct_CRLNotificationTBS;
        NID_TO_SN[ NID_setct_CRLNotificationResTBS ] = SN_setct_CRLNotificationResTBS;
        NID_TO_SN[ NID_setct_BCIDistributionTBS ] = SN_setct_BCIDistributionTBS;
        NID_TO_SN[ NID_setext_genCrypt ] = SN_setext_genCrypt;
        NID_TO_SN[ NID_setext_miAuth ] = SN_setext_miAuth;
        NID_TO_SN[ NID_setext_pinSecure ] = SN_setext_pinSecure;
        NID_TO_SN[ NID_setext_pinAny ] = SN_setext_pinAny;
        NID_TO_SN[ NID_setext_track2 ] = SN_setext_track2;
        NID_TO_SN[ NID_setext_cv ] = SN_setext_cv;
        NID_TO_SN[ NID_set_policy_root ] = SN_set_policy_root;
        NID_TO_SN[ NID_setCext_hashedRoot ] = SN_setCext_hashedRoot;
        NID_TO_SN[ NID_setCext_certType ] = SN_setCext_certType;
        NID_TO_SN[ NID_setCext_merchData ] = SN_setCext_merchData;
        NID_TO_SN[ NID_setCext_cCertRequired ] = SN_setCext_cCertRequired;
        NID_TO_SN[ NID_setCext_tunneling ] = SN_setCext_tunneling;
        NID_TO_SN[ NID_setCext_setExt ] = SN_setCext_setExt;
        NID_TO_SN[ NID_setCext_setQualf ] = SN_setCext_setQualf;
        NID_TO_SN[ NID_setCext_PGWYcapabilities ] = SN_setCext_PGWYcapabilities;
        NID_TO_SN[ NID_setCext_TokenIdentifier ] = SN_setCext_TokenIdentifier;
        NID_TO_SN[ NID_setCext_Track2Data ] = SN_setCext_Track2Data;
        NID_TO_SN[ NID_setCext_TokenType ] = SN_setCext_TokenType;
        NID_TO_SN[ NID_setCext_IssuerCapabilities ] = SN_setCext_IssuerCapabilities;
        NID_TO_SN[ NID_setAttr_Cert ] = SN_setAttr_Cert;
        NID_TO_SN[ NID_setAttr_PGWYcap ] = SN_setAttr_PGWYcap;
        NID_TO_SN[ NID_setAttr_TokenType ] = SN_setAttr_TokenType;
        NID_TO_SN[ NID_setAttr_IssCap ] = SN_setAttr_IssCap;
        NID_TO_SN[ NID_set_rootKeyThumb ] = SN_set_rootKeyThumb;
        NID_TO_SN[ NID_set_addPolicy ] = SN_set_addPolicy;
        NID_TO_SN[ NID_setAttr_Token_EMV ] = SN_setAttr_Token_EMV;
        NID_TO_SN[ NID_setAttr_Token_B0Prime ] = SN_setAttr_Token_B0Prime;
        NID_TO_SN[ NID_setAttr_IssCap_CVM ] = SN_setAttr_IssCap_CVM;
        NID_TO_SN[ NID_setAttr_IssCap_T2 ] = SN_setAttr_IssCap_T2;
        NID_TO_SN[ NID_setAttr_IssCap_Sig ] = SN_setAttr_IssCap_Sig;
        NID_TO_SN[ NID_setAttr_GenCryptgrm ] = SN_setAttr_GenCryptgrm;
        NID_TO_SN[ NID_setAttr_T2Enc ] = SN_setAttr_T2Enc;
        NID_TO_SN[ NID_setAttr_T2cleartxt ] = SN_setAttr_T2cleartxt;
        NID_TO_SN[ NID_setAttr_TokICCsig ] = SN_setAttr_TokICCsig;
        NID_TO_SN[ NID_setAttr_SecDevSig ] = SN_setAttr_SecDevSig;
        NID_TO_SN[ NID_set_brand_IATA_ATA ] = SN_set_brand_IATA_ATA;
        NID_TO_SN[ NID_set_brand_Diners ] = SN_set_brand_Diners;
        NID_TO_SN[ NID_set_brand_AmericanExpress ] = SN_set_brand_AmericanExpress;
        NID_TO_SN[ NID_set_brand_JCB ] = SN_set_brand_JCB;
        NID_TO_SN[ NID_set_brand_Visa ] = SN_set_brand_Visa;
        NID_TO_SN[ NID_set_brand_MasterCard ] = SN_set_brand_MasterCard;
        NID_TO_SN[ NID_set_brand_Novus ] = SN_set_brand_Novus;
        NID_TO_SN[ NID_des_cdmf ] = SN_des_cdmf;
        NID_TO_SN[ NID_rsaOAEPEncryptionSET ] = SN_rsaOAEPEncryptionSET;
        NID_TO_SN[ NID_ipsec3 ] = SN_ipsec3;
        NID_TO_SN[ NID_ipsec4 ] = SN_ipsec4;
        NID_TO_SN[ NID_whirlpool ] = SN_whirlpool;
        NID_TO_SN[ NID_cryptopro ] = SN_cryptopro;
        NID_TO_SN[ NID_cryptocom ] = SN_cryptocom;
        NID_TO_SN[ NID_id_GostR3411_94_with_GostR3410_2001 ] = SN_id_GostR3411_94_with_GostR3410_2001;
        NID_TO_SN[ NID_id_GostR3411_94_with_GostR3410_94 ] = SN_id_GostR3411_94_with_GostR3410_94;
        NID_TO_SN[ NID_id_GostR3411_94 ] = SN_id_GostR3411_94;
        NID_TO_SN[ NID_id_HMACGostR3411_94 ] = SN_id_HMACGostR3411_94;
        NID_TO_SN[ NID_id_GostR3410_2001 ] = SN_id_GostR3410_2001;
        NID_TO_SN[ NID_id_GostR3410_94 ] = SN_id_GostR3410_94;
        NID_TO_SN[ NID_id_Gost28147_89 ] = SN_id_Gost28147_89;
        NID_TO_SN[ NID_gost89_cnt ] = SN_gost89_cnt;
        NID_TO_SN[ NID_id_Gost28147_89_MAC ] = SN_id_Gost28147_89_MAC;
        NID_TO_SN[ NID_id_GostR3411_94_prf ] = SN_id_GostR3411_94_prf;
        NID_TO_SN[ NID_id_GostR3410_2001DH ] = SN_id_GostR3410_2001DH;
        NID_TO_SN[ NID_id_GostR3410_94DH ] = SN_id_GostR3410_94DH;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_KeyMeshing ] = SN_id_Gost28147_89_CryptoPro_KeyMeshing;
        NID_TO_SN[ NID_id_Gost28147_89_None_KeyMeshing ] = SN_id_Gost28147_89_None_KeyMeshing;
        NID_TO_SN[ NID_id_GostR3411_94_TestParamSet ] = SN_id_GostR3411_94_TestParamSet;
        NID_TO_SN[ NID_id_GostR3411_94_CryptoProParamSet ] = SN_id_GostR3411_94_CryptoProParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_TestParamSet ] = SN_id_Gost28147_89_TestParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_A_ParamSet ] = SN_id_Gost28147_89_CryptoPro_A_ParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_B_ParamSet ] = SN_id_Gost28147_89_CryptoPro_B_ParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_C_ParamSet ] = SN_id_Gost28147_89_CryptoPro_C_ParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_D_ParamSet ] = SN_id_Gost28147_89_CryptoPro_D_ParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet ] = SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet ] = SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet;
        NID_TO_SN[ NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet ] = SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_TestParamSet ] = SN_id_GostR3410_94_TestParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_A_ParamSet ] = SN_id_GostR3410_94_CryptoPro_A_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_B_ParamSet ] = SN_id_GostR3410_94_CryptoPro_B_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_C_ParamSet ] = SN_id_GostR3410_94_CryptoPro_C_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_D_ParamSet ] = SN_id_GostR3410_94_CryptoPro_D_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_XchA_ParamSet ] = SN_id_GostR3410_94_CryptoPro_XchA_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_XchB_ParamSet ] = SN_id_GostR3410_94_CryptoPro_XchB_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_CryptoPro_XchC_ParamSet ] = SN_id_GostR3410_94_CryptoPro_XchC_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_2001_TestParamSet ] = SN_id_GostR3410_2001_TestParamSet;
        NID_TO_SN[ NID_id_GostR3410_2001_CryptoPro_A_ParamSet ] = SN_id_GostR3410_2001_CryptoPro_A_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_2001_CryptoPro_B_ParamSet ] = SN_id_GostR3410_2001_CryptoPro_B_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_2001_CryptoPro_C_ParamSet ] = SN_id_GostR3410_2001_CryptoPro_C_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet ] = SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet ] = SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet;
        NID_TO_SN[ NID_id_GostR3410_94_a ] = SN_id_GostR3410_94_a;
        NID_TO_SN[ NID_id_GostR3410_94_aBis ] = SN_id_GostR3410_94_aBis;
        NID_TO_SN[ NID_id_GostR3410_94_b ] = SN_id_GostR3410_94_b;
        NID_TO_SN[ NID_id_GostR3410_94_bBis ] = SN_id_GostR3410_94_bBis;
        NID_TO_SN[ NID_id_Gost28147_89_cc ] = SN_id_Gost28147_89_cc;
        NID_TO_SN[ NID_id_GostR3410_94_cc ] = SN_id_GostR3410_94_cc;
        NID_TO_SN[ NID_id_GostR3410_2001_cc ] = SN_id_GostR3410_2001_cc;
        NID_TO_SN[ NID_id_GostR3411_94_with_GostR3410_94_cc ] = SN_id_GostR3411_94_with_GostR3410_94_cc;
        NID_TO_SN[ NID_id_GostR3411_94_with_GostR3410_2001_cc ] = SN_id_GostR3411_94_with_GostR3410_2001_cc;
        NID_TO_SN[ NID_id_GostR3410_2001_ParamSet_cc ] = SN_id_GostR3410_2001_ParamSet_cc;
        NID_TO_SN[ NID_camellia_128_cbc ] = SN_camellia_128_cbc;
        NID_TO_SN[ NID_camellia_192_cbc ] = SN_camellia_192_cbc;
        NID_TO_SN[ NID_camellia_256_cbc ] = SN_camellia_256_cbc;
        NID_TO_SN[ NID_id_camellia128_wrap ] = SN_id_camellia128_wrap;
        NID_TO_SN[ NID_id_camellia192_wrap ] = SN_id_camellia192_wrap;
        NID_TO_SN[ NID_id_camellia256_wrap ] = SN_id_camellia256_wrap;
        NID_TO_SN[ NID_camellia_128_ecb ] = SN_camellia_128_ecb;
        NID_TO_SN[ NID_camellia_128_ofb128 ] = SN_camellia_128_ofb128;
        NID_TO_SN[ NID_camellia_128_cfb128 ] = SN_camellia_128_cfb128;
        NID_TO_SN[ NID_camellia_192_ecb ] = SN_camellia_192_ecb;
        NID_TO_SN[ NID_camellia_192_ofb128 ] = SN_camellia_192_ofb128;
        NID_TO_SN[ NID_camellia_192_cfb128 ] = SN_camellia_192_cfb128;
        NID_TO_SN[ NID_camellia_256_ecb ] = SN_camellia_256_ecb;
        NID_TO_SN[ NID_camellia_256_ofb128 ] = SN_camellia_256_ofb128;
        NID_TO_SN[ NID_camellia_256_cfb128 ] = SN_camellia_256_cfb128;
        NID_TO_SN[ NID_camellia_128_cfb1 ] = SN_camellia_128_cfb1;
        NID_TO_SN[ NID_camellia_192_cfb1 ] = SN_camellia_192_cfb1;
        NID_TO_SN[ NID_camellia_256_cfb1 ] = SN_camellia_256_cfb1;
        NID_TO_SN[ NID_camellia_128_cfb8 ] = SN_camellia_128_cfb8;
        NID_TO_SN[ NID_camellia_192_cfb8 ] = SN_camellia_192_cfb8;
        NID_TO_SN[ NID_camellia_256_cfb8 ] = SN_camellia_256_cfb8;
        NID_TO_SN[ NID_kisa ] = SN_kisa;
        NID_TO_SN[ NID_seed_ecb ] = SN_seed_ecb;
        NID_TO_SN[ NID_seed_cbc ] = SN_seed_cbc;
        NID_TO_SN[ NID_seed_cfb128 ] = SN_seed_cfb128;
        NID_TO_SN[ NID_seed_ofb128 ] = SN_seed_ofb128;
        NID_TO_SN[ NID_hmac ] = SN_hmac;
        NID_TO_SN[ NID_cmac ] = SN_cmac;
        NID_TO_SN[ NID_rc4_hmac_md5 ] = SN_rc4_hmac_md5;
        NID_TO_SN[ NID_aes_128_cbc_hmac_sha1 ] = SN_aes_128_cbc_hmac_sha1;
        NID_TO_SN[ NID_aes_192_cbc_hmac_sha1 ] = SN_aes_192_cbc_hmac_sha1;
        NID_TO_SN[ NID_aes_256_cbc_hmac_sha1 ] = SN_aes_256_cbc_hmac_sha1;
        NID_TO_SN[ NID_aes_128_cbc_hmac_sha256 ] = SN_aes_128_cbc_hmac_sha256;
        NID_TO_SN[ NID_aes_192_cbc_hmac_sha256 ] = SN_aes_192_cbc_hmac_sha256;
        NID_TO_SN[ NID_aes_256_cbc_hmac_sha256 ] = SN_aes_256_cbc_hmac_sha256;
        NID_TO_SN[ NID_dhpublicnumber ] = SN_dhpublicnumber;
        NID_TO_SN[ NID_brainpoolP160r1 ] = SN_brainpoolP160r1;
        NID_TO_SN[ NID_brainpoolP160t1 ] = SN_brainpoolP160t1;
        NID_TO_SN[ NID_brainpoolP192r1 ] = SN_brainpoolP192r1;
        NID_TO_SN[ NID_brainpoolP192t1 ] = SN_brainpoolP192t1;
        NID_TO_SN[ NID_brainpoolP224r1 ] = SN_brainpoolP224r1;
        NID_TO_SN[ NID_brainpoolP224t1 ] = SN_brainpoolP224t1;
        NID_TO_SN[ NID_brainpoolP256r1 ] = SN_brainpoolP256r1;
        NID_TO_SN[ NID_brainpoolP256t1 ] = SN_brainpoolP256t1;
        NID_TO_SN[ NID_brainpoolP320r1 ] = SN_brainpoolP320r1;
        NID_TO_SN[ NID_brainpoolP320t1 ] = SN_brainpoolP320t1;
        NID_TO_SN[ NID_brainpoolP384r1 ] = SN_brainpoolP384r1;
        NID_TO_SN[ NID_brainpoolP384t1 ] = SN_brainpoolP384t1;
        NID_TO_SN[ NID_brainpoolP512r1 ] = SN_brainpoolP512r1;
        NID_TO_SN[ NID_brainpoolP512t1 ] = SN_brainpoolP512t1;
        NID_TO_SN[ NID_dhSinglePass_stdDH_sha1kdf_scheme ] = SN_dhSinglePass_stdDH_sha1kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_stdDH_sha224kdf_scheme ] = SN_dhSinglePass_stdDH_sha224kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_stdDH_sha256kdf_scheme ] = SN_dhSinglePass_stdDH_sha256kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_stdDH_sha384kdf_scheme ] = SN_dhSinglePass_stdDH_sha384kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_stdDH_sha512kdf_scheme ] = SN_dhSinglePass_stdDH_sha512kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_cofactorDH_sha1kdf_scheme ] = SN_dhSinglePass_cofactorDH_sha1kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_cofactorDH_sha224kdf_scheme ] = SN_dhSinglePass_cofactorDH_sha224kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_cofactorDH_sha256kdf_scheme ] = SN_dhSinglePass_cofactorDH_sha256kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_cofactorDH_sha384kdf_scheme ] = SN_dhSinglePass_cofactorDH_sha384kdf_scheme;
        NID_TO_SN[ NID_dhSinglePass_cofactorDH_sha512kdf_scheme ] = SN_dhSinglePass_cofactorDH_sha512kdf_scheme;
        NID_TO_SN[ NID_dh_std_kdf ] = SN_dh_std_kdf;
        NID_TO_SN[ NID_dh_cofactor_kdf ] = SN_dh_cofactor_kdf;
        NID_TO_SN[ NID_ct_precert_scts ] = SN_ct_precert_scts;
        NID_TO_SN[ NID_ct_precert_poison ] = SN_ct_precert_poison;
        NID_TO_SN[ NID_ct_precert_signer ] = SN_ct_precert_signer;
        NID_TO_SN[ NID_ct_cert_scts ] = SN_ct_cert_scts;
        NID_TO_SN[ NID_jurisdictionLocalityName ] = SN_jurisdictionLocalityName;
        NID_TO_SN[ NID_jurisdictionStateOrProvinceName ] = SN_jurisdictionStateOrProvinceName;
        NID_TO_SN[ NID_jurisdictionCountryName ] = SN_jurisdictionCountryName;
    }
    

    private static final String[] NID_TO_LN = new String[ 958 ];
    static {
        NID_TO_LN[ NID_undef ] = LN_undef;
        NID_TO_LN[ NID_itu_t ] = LN_itu_t;
        NID_TO_LN[ NID_iso ] = LN_iso;
        NID_TO_LN[ NID_joint_iso_itu_t ] = LN_joint_iso_itu_t;
        NID_TO_LN[ NID_member_body ] = LN_member_body;
        NID_TO_LN[ NID_hmac_md5 ] = LN_hmac_md5;
        NID_TO_LN[ NID_hmac_sha1 ] = LN_hmac_sha1;
        NID_TO_LN[ NID_international_organizations ] = LN_international_organizations;
        NID_TO_LN[ NID_selected_attribute_types ] = LN_selected_attribute_types;
        NID_TO_LN[ NID_ISO_US ] = LN_ISO_US;
        NID_TO_LN[ NID_X9_57 ] = LN_X9_57;
        NID_TO_LN[ NID_X9cm ] = LN_X9cm;
        NID_TO_LN[ NID_dsa ] = LN_dsa;
        NID_TO_LN[ NID_dsaWithSHA1 ] = LN_dsaWithSHA1;
        NID_TO_LN[ NID_ansi_X9_62 ] = LN_ansi_X9_62;
        NID_TO_LN[ NID_cast5_cbc ] = LN_cast5_cbc;
        NID_TO_LN[ NID_cast5_ecb ] = LN_cast5_ecb;
        NID_TO_LN[ NID_cast5_cfb64 ] = LN_cast5_cfb64;
        NID_TO_LN[ NID_cast5_ofb64 ] = LN_cast5_ofb64;
        NID_TO_LN[ NID_pbeWithMD5AndCast5_CBC ] = LN_pbeWithMD5AndCast5_CBC;
        NID_TO_LN[ NID_id_PasswordBasedMAC ] = LN_id_PasswordBasedMAC;
        NID_TO_LN[ NID_id_DHBasedMac ] = LN_id_DHBasedMac;
        NID_TO_LN[ NID_rsadsi ] = LN_rsadsi;
        NID_TO_LN[ NID_pkcs ] = LN_pkcs;
        NID_TO_LN[ NID_rsaEncryption ] = LN_rsaEncryption;
        NID_TO_LN[ NID_md2WithRSAEncryption ] = LN_md2WithRSAEncryption;
        NID_TO_LN[ NID_md4WithRSAEncryption ] = LN_md4WithRSAEncryption;
        NID_TO_LN[ NID_md5WithRSAEncryption ] = LN_md5WithRSAEncryption;
        NID_TO_LN[ NID_sha1WithRSAEncryption ] = LN_sha1WithRSAEncryption;
        NID_TO_LN[ NID_rsaesOaep ] = LN_rsaesOaep;
        NID_TO_LN[ NID_mgf1 ] = LN_mgf1;
        NID_TO_LN[ NID_pSpecified ] = LN_pSpecified;
        NID_TO_LN[ NID_rsassaPss ] = LN_rsassaPss;
        NID_TO_LN[ NID_sha256WithRSAEncryption ] = LN_sha256WithRSAEncryption;
        NID_TO_LN[ NID_sha384WithRSAEncryption ] = LN_sha384WithRSAEncryption;
        NID_TO_LN[ NID_sha512WithRSAEncryption ] = LN_sha512WithRSAEncryption;
        NID_TO_LN[ NID_sha224WithRSAEncryption ] = LN_sha224WithRSAEncryption;
        NID_TO_LN[ NID_dhKeyAgreement ] = LN_dhKeyAgreement;
        NID_TO_LN[ NID_pbeWithMD2AndDES_CBC ] = LN_pbeWithMD2AndDES_CBC;
        NID_TO_LN[ NID_pbeWithMD5AndDES_CBC ] = LN_pbeWithMD5AndDES_CBC;
        NID_TO_LN[ NID_pbeWithMD2AndRC2_CBC ] = LN_pbeWithMD2AndRC2_CBC;
        NID_TO_LN[ NID_pbeWithMD5AndRC2_CBC ] = LN_pbeWithMD5AndRC2_CBC;
        NID_TO_LN[ NID_pbeWithSHA1AndDES_CBC ] = LN_pbeWithSHA1AndDES_CBC;
        NID_TO_LN[ NID_pbeWithSHA1AndRC2_CBC ] = LN_pbeWithSHA1AndRC2_CBC;
        NID_TO_LN[ NID_id_pbkdf2 ] = LN_id_pbkdf2;
        NID_TO_LN[ NID_pbes2 ] = LN_pbes2;
        NID_TO_LN[ NID_pbmac1 ] = LN_pbmac1;
        NID_TO_LN[ NID_pkcs7_data ] = LN_pkcs7_data;
        NID_TO_LN[ NID_pkcs7_signed ] = LN_pkcs7_signed;
        NID_TO_LN[ NID_pkcs7_enveloped ] = LN_pkcs7_enveloped;
        NID_TO_LN[ NID_pkcs7_signedAndEnveloped ] = LN_pkcs7_signedAndEnveloped;
        NID_TO_LN[ NID_pkcs7_digest ] = LN_pkcs7_digest;
        NID_TO_LN[ NID_pkcs7_encrypted ] = LN_pkcs7_encrypted;
        NID_TO_LN[ NID_pkcs9_emailAddress ] = LN_pkcs9_emailAddress;
        NID_TO_LN[ NID_pkcs9_unstructuredName ] = LN_pkcs9_unstructuredName;
        NID_TO_LN[ NID_pkcs9_contentType ] = LN_pkcs9_contentType;
        NID_TO_LN[ NID_pkcs9_messageDigest ] = LN_pkcs9_messageDigest;
        NID_TO_LN[ NID_pkcs9_signingTime ] = LN_pkcs9_signingTime;
        NID_TO_LN[ NID_pkcs9_countersignature ] = LN_pkcs9_countersignature;
        NID_TO_LN[ NID_pkcs9_challengePassword ] = LN_pkcs9_challengePassword;
        NID_TO_LN[ NID_pkcs9_unstructuredAddress ] = LN_pkcs9_unstructuredAddress;
        NID_TO_LN[ NID_pkcs9_extCertAttributes ] = LN_pkcs9_extCertAttributes;
        NID_TO_LN[ NID_ext_req ] = LN_ext_req;
        NID_TO_LN[ NID_SMIMECapabilities ] = LN_SMIMECapabilities;
        NID_TO_LN[ NID_SMIME ] = LN_SMIME;
        NID_TO_LN[ NID_friendlyName ] = LN_friendlyName;
        NID_TO_LN[ NID_localKeyID ] = LN_localKeyID;
        NID_TO_LN[ NID_ms_csp_name ] = LN_ms_csp_name;
        NID_TO_LN[ NID_LocalKeySet ] = LN_LocalKeySet;
        NID_TO_LN[ NID_x509Certificate ] = LN_x509Certificate;
        NID_TO_LN[ NID_sdsiCertificate ] = LN_sdsiCertificate;
        NID_TO_LN[ NID_x509Crl ] = LN_x509Crl;
        NID_TO_LN[ NID_pbe_WithSHA1And128BitRC4 ] = LN_pbe_WithSHA1And128BitRC4;
        NID_TO_LN[ NID_pbe_WithSHA1And40BitRC4 ] = LN_pbe_WithSHA1And40BitRC4;
        NID_TO_LN[ NID_pbe_WithSHA1And3_Key_TripleDES_CBC ] = LN_pbe_WithSHA1And3_Key_TripleDES_CBC;
        NID_TO_LN[ NID_pbe_WithSHA1And2_Key_TripleDES_CBC ] = LN_pbe_WithSHA1And2_Key_TripleDES_CBC;
        NID_TO_LN[ NID_pbe_WithSHA1And128BitRC2_CBC ] = LN_pbe_WithSHA1And128BitRC2_CBC;
        NID_TO_LN[ NID_pbe_WithSHA1And40BitRC2_CBC ] = LN_pbe_WithSHA1And40BitRC2_CBC;
        NID_TO_LN[ NID_keyBag ] = LN_keyBag;
        NID_TO_LN[ NID_pkcs8ShroudedKeyBag ] = LN_pkcs8ShroudedKeyBag;
        NID_TO_LN[ NID_certBag ] = LN_certBag;
        NID_TO_LN[ NID_crlBag ] = LN_crlBag;
        NID_TO_LN[ NID_secretBag ] = LN_secretBag;
        NID_TO_LN[ NID_safeContentsBag ] = LN_safeContentsBag;
        NID_TO_LN[ NID_md2 ] = LN_md2;
        NID_TO_LN[ NID_md4 ] = LN_md4;
        NID_TO_LN[ NID_md5 ] = LN_md5;
        NID_TO_LN[ NID_md5_sha1 ] = LN_md5_sha1;
        NID_TO_LN[ NID_hmacWithMD5 ] = LN_hmacWithMD5;
        NID_TO_LN[ NID_hmacWithSHA1 ] = LN_hmacWithSHA1;
        NID_TO_LN[ NID_hmacWithSHA224 ] = LN_hmacWithSHA224;
        NID_TO_LN[ NID_hmacWithSHA256 ] = LN_hmacWithSHA256;
        NID_TO_LN[ NID_hmacWithSHA384 ] = LN_hmacWithSHA384;
        NID_TO_LN[ NID_hmacWithSHA512 ] = LN_hmacWithSHA512;
        NID_TO_LN[ NID_rc2_cbc ] = LN_rc2_cbc;
        NID_TO_LN[ NID_rc2_ecb ] = LN_rc2_ecb;
        NID_TO_LN[ NID_rc2_cfb64 ] = LN_rc2_cfb64;
        NID_TO_LN[ NID_rc2_ofb64 ] = LN_rc2_ofb64;
        NID_TO_LN[ NID_rc2_40_cbc ] = LN_rc2_40_cbc;
        NID_TO_LN[ NID_rc2_64_cbc ] = LN_rc2_64_cbc;
        NID_TO_LN[ NID_rc4 ] = LN_rc4;
        NID_TO_LN[ NID_rc4_40 ] = LN_rc4_40;
        NID_TO_LN[ NID_des_ede3_cbc ] = LN_des_ede3_cbc;
        NID_TO_LN[ NID_rc5_cbc ] = LN_rc5_cbc;
        NID_TO_LN[ NID_rc5_ecb ] = LN_rc5_ecb;
        NID_TO_LN[ NID_rc5_cfb64 ] = LN_rc5_cfb64;
        NID_TO_LN[ NID_rc5_ofb64 ] = LN_rc5_ofb64;
        NID_TO_LN[ NID_ms_ext_req ] = LN_ms_ext_req;
        NID_TO_LN[ NID_ms_code_ind ] = LN_ms_code_ind;
        NID_TO_LN[ NID_ms_code_com ] = LN_ms_code_com;
        NID_TO_LN[ NID_ms_ctl_sign ] = LN_ms_ctl_sign;
        NID_TO_LN[ NID_ms_sgc ] = LN_ms_sgc;
        NID_TO_LN[ NID_ms_efs ] = LN_ms_efs;
        NID_TO_LN[ NID_ms_smartcard_login ] = LN_ms_smartcard_login;
        NID_TO_LN[ NID_ms_upn ] = LN_ms_upn;
        NID_TO_LN[ NID_idea_cbc ] = LN_idea_cbc;
        NID_TO_LN[ NID_idea_ecb ] = LN_idea_ecb;
        NID_TO_LN[ NID_idea_cfb64 ] = LN_idea_cfb64;
        NID_TO_LN[ NID_idea_ofb64 ] = LN_idea_ofb64;
        NID_TO_LN[ NID_bf_cbc ] = LN_bf_cbc;
        NID_TO_LN[ NID_bf_ecb ] = LN_bf_ecb;
        NID_TO_LN[ NID_bf_cfb64 ] = LN_bf_cfb64;
        NID_TO_LN[ NID_bf_ofb64 ] = LN_bf_ofb64;
        NID_TO_LN[ NID_info_access ] = LN_info_access;
        NID_TO_LN[ NID_biometricInfo ] = LN_biometricInfo;
        NID_TO_LN[ NID_sinfo_access ] = LN_sinfo_access;
        NID_TO_LN[ NID_proxyCertInfo ] = LN_proxyCertInfo;
        NID_TO_LN[ NID_id_qt_cps ] = LN_id_qt_cps;
        NID_TO_LN[ NID_id_qt_unotice ] = LN_id_qt_unotice;
        NID_TO_LN[ NID_server_auth ] = LN_server_auth;
        NID_TO_LN[ NID_client_auth ] = LN_client_auth;
        NID_TO_LN[ NID_code_sign ] = LN_code_sign;
        NID_TO_LN[ NID_email_protect ] = LN_email_protect;
        NID_TO_LN[ NID_ipsecEndSystem ] = LN_ipsecEndSystem;
        NID_TO_LN[ NID_ipsecTunnel ] = LN_ipsecTunnel;
        NID_TO_LN[ NID_ipsecUser ] = LN_ipsecUser;
        NID_TO_LN[ NID_time_stamp ] = LN_time_stamp;
        NID_TO_LN[ NID_OCSP_sign ] = LN_OCSP_sign;
        NID_TO_LN[ NID_dvcs ] = LN_dvcs;
        NID_TO_LN[ NID_id_on_permanentIdentifier ] = LN_id_on_permanentIdentifier;
        NID_TO_LN[ NID_id_ppl_anyLanguage ] = LN_id_ppl_anyLanguage;
        NID_TO_LN[ NID_id_ppl_inheritAll ] = LN_id_ppl_inheritAll;
        NID_TO_LN[ NID_Independent ] = LN_Independent;
        NID_TO_LN[ NID_ad_OCSP ] = LN_ad_OCSP;
        NID_TO_LN[ NID_ad_ca_issuers ] = LN_ad_ca_issuers;
        NID_TO_LN[ NID_ad_timeStamping ] = LN_ad_timeStamping;
        NID_TO_LN[ NID_ad_dvcs ] = LN_ad_dvcs;
        NID_TO_LN[ NID_caRepository ] = LN_caRepository;
        NID_TO_LN[ NID_id_pkix_OCSP_basic ] = LN_id_pkix_OCSP_basic;
        NID_TO_LN[ NID_id_pkix_OCSP_Nonce ] = LN_id_pkix_OCSP_Nonce;
        NID_TO_LN[ NID_id_pkix_OCSP_CrlID ] = LN_id_pkix_OCSP_CrlID;
        NID_TO_LN[ NID_id_pkix_OCSP_acceptableResponses ] = LN_id_pkix_OCSP_acceptableResponses;
        NID_TO_LN[ NID_id_pkix_OCSP_noCheck ] = LN_id_pkix_OCSP_noCheck;
        NID_TO_LN[ NID_id_pkix_OCSP_archiveCutoff ] = LN_id_pkix_OCSP_archiveCutoff;
        NID_TO_LN[ NID_id_pkix_OCSP_serviceLocator ] = LN_id_pkix_OCSP_serviceLocator;
        NID_TO_LN[ NID_id_pkix_OCSP_extendedStatus ] = LN_id_pkix_OCSP_extendedStatus;
        NID_TO_LN[ NID_id_pkix_OCSP_trustRoot ] = LN_id_pkix_OCSP_trustRoot;
        NID_TO_LN[ NID_algorithm ] = LN_algorithm;
        NID_TO_LN[ NID_md5WithRSA ] = LN_md5WithRSA;
        NID_TO_LN[ NID_des_ecb ] = LN_des_ecb;
        NID_TO_LN[ NID_des_cbc ] = LN_des_cbc;
        NID_TO_LN[ NID_des_ofb64 ] = LN_des_ofb64;
        NID_TO_LN[ NID_des_cfb64 ] = LN_des_cfb64;
        NID_TO_LN[ NID_dsa_2 ] = LN_dsa_2;
        NID_TO_LN[ NID_dsaWithSHA ] = LN_dsaWithSHA;
        NID_TO_LN[ NID_shaWithRSAEncryption ] = LN_shaWithRSAEncryption;
        NID_TO_LN[ NID_des_ede_ecb ] = LN_des_ede_ecb;
        NID_TO_LN[ NID_des_ede3_ecb ] = LN_des_ede3_ecb;
        NID_TO_LN[ NID_des_ede_cbc ] = LN_des_ede_cbc;
        NID_TO_LN[ NID_des_ede_cfb64 ] = LN_des_ede_cfb64;
        NID_TO_LN[ NID_des_ede3_cfb64 ] = LN_des_ede3_cfb64;
        NID_TO_LN[ NID_des_ede_ofb64 ] = LN_des_ede_ofb64;
        NID_TO_LN[ NID_des_ede3_ofb64 ] = LN_des_ede3_ofb64;
        NID_TO_LN[ NID_desx_cbc ] = LN_desx_cbc;
        NID_TO_LN[ NID_sha ] = LN_sha;
        NID_TO_LN[ NID_sha1 ] = LN_sha1;
        NID_TO_LN[ NID_dsaWithSHA1_2 ] = LN_dsaWithSHA1_2;
        NID_TO_LN[ NID_sha1WithRSA ] = LN_sha1WithRSA;
        NID_TO_LN[ NID_ripemd160 ] = LN_ripemd160;
        NID_TO_LN[ NID_ripemd160WithRSA ] = LN_ripemd160WithRSA;
        NID_TO_LN[ NID_sxnet ] = LN_sxnet;
        NID_TO_LN[ NID_X500 ] = LN_X500;
        NID_TO_LN[ NID_commonName ] = LN_commonName;
        NID_TO_LN[ NID_surname ] = LN_surname;
        NID_TO_LN[ NID_serialNumber ] = LN_serialNumber;
        NID_TO_LN[ NID_countryName ] = LN_countryName;
        NID_TO_LN[ NID_localityName ] = LN_localityName;
        NID_TO_LN[ NID_stateOrProvinceName ] = LN_stateOrProvinceName;
        NID_TO_LN[ NID_streetAddress ] = LN_streetAddress;
        NID_TO_LN[ NID_organizationName ] = LN_organizationName;
        NID_TO_LN[ NID_organizationalUnitName ] = LN_organizationalUnitName;
        NID_TO_LN[ NID_title ] = LN_title;
        NID_TO_LN[ NID_description ] = LN_description;
        NID_TO_LN[ NID_searchGuide ] = LN_searchGuide;
        NID_TO_LN[ NID_businessCategory ] = LN_businessCategory;
        NID_TO_LN[ NID_postalAddress ] = LN_postalAddress;
        NID_TO_LN[ NID_postalCode ] = LN_postalCode;
        NID_TO_LN[ NID_postOfficeBox ] = LN_postOfficeBox;
        NID_TO_LN[ NID_physicalDeliveryOfficeName ] = LN_physicalDeliveryOfficeName;
        NID_TO_LN[ NID_telephoneNumber ] = LN_telephoneNumber;
        NID_TO_LN[ NID_telexNumber ] = LN_telexNumber;
        NID_TO_LN[ NID_teletexTerminalIdentifier ] = LN_teletexTerminalIdentifier;
        NID_TO_LN[ NID_facsimileTelephoneNumber ] = LN_facsimileTelephoneNumber;
        NID_TO_LN[ NID_x121Address ] = LN_x121Address;
        NID_TO_LN[ NID_internationaliSDNNumber ] = LN_internationaliSDNNumber;
        NID_TO_LN[ NID_registeredAddress ] = LN_registeredAddress;
        NID_TO_LN[ NID_destinationIndicator ] = LN_destinationIndicator;
        NID_TO_LN[ NID_preferredDeliveryMethod ] = LN_preferredDeliveryMethod;
        NID_TO_LN[ NID_presentationAddress ] = LN_presentationAddress;
        NID_TO_LN[ NID_supportedApplicationContext ] = LN_supportedApplicationContext;
        NID_TO_LN[ NID_roleOccupant ] = LN_roleOccupant;
        NID_TO_LN[ NID_userPassword ] = LN_userPassword;
        NID_TO_LN[ NID_userCertificate ] = LN_userCertificate;
        NID_TO_LN[ NID_cACertificate ] = LN_cACertificate;
        NID_TO_LN[ NID_authorityRevocationList ] = LN_authorityRevocationList;
        NID_TO_LN[ NID_certificateRevocationList ] = LN_certificateRevocationList;
        NID_TO_LN[ NID_crossCertificatePair ] = LN_crossCertificatePair;
        NID_TO_LN[ NID_name ] = LN_name;
        NID_TO_LN[ NID_givenName ] = LN_givenName;
        NID_TO_LN[ NID_initials ] = LN_initials;
        NID_TO_LN[ NID_generationQualifier ] = LN_generationQualifier;
        NID_TO_LN[ NID_x500UniqueIdentifier ] = LN_x500UniqueIdentifier;
        NID_TO_LN[ NID_dnQualifier ] = LN_dnQualifier;
        NID_TO_LN[ NID_enhancedSearchGuide ] = LN_enhancedSearchGuide;
        NID_TO_LN[ NID_protocolInformation ] = LN_protocolInformation;
        NID_TO_LN[ NID_distinguishedName ] = LN_distinguishedName;
        NID_TO_LN[ NID_uniqueMember ] = LN_uniqueMember;
        NID_TO_LN[ NID_houseIdentifier ] = LN_houseIdentifier;
        NID_TO_LN[ NID_supportedAlgorithms ] = LN_supportedAlgorithms;
        NID_TO_LN[ NID_deltaRevocationList ] = LN_deltaRevocationList;
        NID_TO_LN[ NID_pseudonym ] = LN_pseudonym;
        NID_TO_LN[ NID_role ] = LN_role;
        NID_TO_LN[ NID_X500algorithms ] = LN_X500algorithms;
        NID_TO_LN[ NID_rsa ] = LN_rsa;
        NID_TO_LN[ NID_mdc2WithRSA ] = LN_mdc2WithRSA;
        NID_TO_LN[ NID_mdc2 ] = LN_mdc2;
        NID_TO_LN[ NID_subject_directory_attributes ] = LN_subject_directory_attributes;
        NID_TO_LN[ NID_subject_key_identifier ] = LN_subject_key_identifier;
        NID_TO_LN[ NID_key_usage ] = LN_key_usage;
        NID_TO_LN[ NID_private_key_usage_period ] = LN_private_key_usage_period;
        NID_TO_LN[ NID_subject_alt_name ] = LN_subject_alt_name;
        NID_TO_LN[ NID_issuer_alt_name ] = LN_issuer_alt_name;
        NID_TO_LN[ NID_basic_constraints ] = LN_basic_constraints;
        NID_TO_LN[ NID_crl_number ] = LN_crl_number;
        NID_TO_LN[ NID_crl_reason ] = LN_crl_reason;
        NID_TO_LN[ NID_invalidity_date ] = LN_invalidity_date;
        NID_TO_LN[ NID_delta_crl ] = LN_delta_crl;
        NID_TO_LN[ NID_issuing_distribution_point ] = LN_issuing_distribution_point;
        NID_TO_LN[ NID_certificate_issuer ] = LN_certificate_issuer;
        NID_TO_LN[ NID_name_constraints ] = LN_name_constraints;
        NID_TO_LN[ NID_crl_distribution_points ] = LN_crl_distribution_points;
        NID_TO_LN[ NID_certificate_policies ] = LN_certificate_policies;
        NID_TO_LN[ NID_any_policy ] = LN_any_policy;
        NID_TO_LN[ NID_policy_mappings ] = LN_policy_mappings;
        NID_TO_LN[ NID_authority_key_identifier ] = LN_authority_key_identifier;
        NID_TO_LN[ NID_policy_constraints ] = LN_policy_constraints;
        NID_TO_LN[ NID_ext_key_usage ] = LN_ext_key_usage;
        NID_TO_LN[ NID_freshest_crl ] = LN_freshest_crl;
        NID_TO_LN[ NID_inhibit_any_policy ] = LN_inhibit_any_policy;
        NID_TO_LN[ NID_target_information ] = LN_target_information;
        NID_TO_LN[ NID_no_rev_avail ] = LN_no_rev_avail;
        NID_TO_LN[ NID_anyExtendedKeyUsage ] = LN_anyExtendedKeyUsage;
        NID_TO_LN[ NID_netscape ] = LN_netscape;
        NID_TO_LN[ NID_netscape_cert_extension ] = LN_netscape_cert_extension;
        NID_TO_LN[ NID_netscape_data_type ] = LN_netscape_data_type;
        NID_TO_LN[ NID_netscape_cert_type ] = LN_netscape_cert_type;
        NID_TO_LN[ NID_netscape_base_url ] = LN_netscape_base_url;
        NID_TO_LN[ NID_netscape_revocation_url ] = LN_netscape_revocation_url;
        NID_TO_LN[ NID_netscape_ca_revocation_url ] = LN_netscape_ca_revocation_url;
        NID_TO_LN[ NID_netscape_renewal_url ] = LN_netscape_renewal_url;
        NID_TO_LN[ NID_netscape_ca_policy_url ] = LN_netscape_ca_policy_url;
        NID_TO_LN[ NID_netscape_ssl_server_name ] = LN_netscape_ssl_server_name;
        NID_TO_LN[ NID_netscape_comment ] = LN_netscape_comment;
        NID_TO_LN[ NID_netscape_cert_sequence ] = LN_netscape_cert_sequence;
        NID_TO_LN[ NID_ns_sgc ] = LN_ns_sgc;
        NID_TO_LN[ NID_org ] = LN_org;
        NID_TO_LN[ NID_dod ] = LN_dod;
        NID_TO_LN[ NID_iana ] = LN_iana;
        NID_TO_LN[ NID_Directory ] = LN_Directory;
        NID_TO_LN[ NID_Management ] = LN_Management;
        NID_TO_LN[ NID_Experimental ] = LN_Experimental;
        NID_TO_LN[ NID_Private ] = LN_Private;
        NID_TO_LN[ NID_Security ] = LN_Security;
        NID_TO_LN[ NID_SNMPv2 ] = LN_SNMPv2;
        NID_TO_LN[ NID_Mail ] = LN_Mail;
        NID_TO_LN[ NID_Enterprises ] = LN_Enterprises;
        NID_TO_LN[ NID_dcObject ] = LN_dcObject;
        NID_TO_LN[ NID_mime_mhs ] = LN_mime_mhs;
        NID_TO_LN[ NID_mime_mhs_headings ] = LN_mime_mhs_headings;
        NID_TO_LN[ NID_mime_mhs_bodies ] = LN_mime_mhs_bodies;
        NID_TO_LN[ NID_id_hex_partial_message ] = LN_id_hex_partial_message;
        NID_TO_LN[ NID_id_hex_multipart_message ] = LN_id_hex_multipart_message;
        NID_TO_LN[ NID_rle_compression ] = LN_rle_compression;
        NID_TO_LN[ NID_zlib_compression ] = LN_zlib_compression;
        NID_TO_LN[ NID_aes_128_ecb ] = LN_aes_128_ecb;
        NID_TO_LN[ NID_aes_128_cbc ] = LN_aes_128_cbc;
        NID_TO_LN[ NID_aes_128_ofb128 ] = LN_aes_128_ofb128;
        NID_TO_LN[ NID_aes_128_cfb128 ] = LN_aes_128_cfb128;
        NID_TO_LN[ NID_aes_128_gcm ] = LN_aes_128_gcm;
        NID_TO_LN[ NID_aes_128_ccm ] = LN_aes_128_ccm;
        NID_TO_LN[ NID_aes_192_ecb ] = LN_aes_192_ecb;
        NID_TO_LN[ NID_aes_192_cbc ] = LN_aes_192_cbc;
        NID_TO_LN[ NID_aes_192_ofb128 ] = LN_aes_192_ofb128;
        NID_TO_LN[ NID_aes_192_cfb128 ] = LN_aes_192_cfb128;
        NID_TO_LN[ NID_aes_192_gcm ] = LN_aes_192_gcm;
        NID_TO_LN[ NID_aes_192_ccm ] = LN_aes_192_ccm;
        NID_TO_LN[ NID_aes_256_ecb ] = LN_aes_256_ecb;
        NID_TO_LN[ NID_aes_256_cbc ] = LN_aes_256_cbc;
        NID_TO_LN[ NID_aes_256_ofb128 ] = LN_aes_256_ofb128;
        NID_TO_LN[ NID_aes_256_cfb128 ] = LN_aes_256_cfb128;
        NID_TO_LN[ NID_aes_256_gcm ] = LN_aes_256_gcm;
        NID_TO_LN[ NID_aes_256_ccm ] = LN_aes_256_ccm;
        NID_TO_LN[ NID_aes_128_cfb1 ] = LN_aes_128_cfb1;
        NID_TO_LN[ NID_aes_192_cfb1 ] = LN_aes_192_cfb1;
        NID_TO_LN[ NID_aes_256_cfb1 ] = LN_aes_256_cfb1;
        NID_TO_LN[ NID_aes_128_cfb8 ] = LN_aes_128_cfb8;
        NID_TO_LN[ NID_aes_192_cfb8 ] = LN_aes_192_cfb8;
        NID_TO_LN[ NID_aes_256_cfb8 ] = LN_aes_256_cfb8;
        NID_TO_LN[ NID_aes_128_ctr ] = LN_aes_128_ctr;
        NID_TO_LN[ NID_aes_192_ctr ] = LN_aes_192_ctr;
        NID_TO_LN[ NID_aes_256_ctr ] = LN_aes_256_ctr;
        NID_TO_LN[ NID_aes_128_xts ] = LN_aes_128_xts;
        NID_TO_LN[ NID_aes_256_xts ] = LN_aes_256_xts;
        NID_TO_LN[ NID_des_cfb1 ] = LN_des_cfb1;
        NID_TO_LN[ NID_des_cfb8 ] = LN_des_cfb8;
        NID_TO_LN[ NID_des_ede3_cfb1 ] = LN_des_ede3_cfb1;
        NID_TO_LN[ NID_des_ede3_cfb8 ] = LN_des_ede3_cfb8;
        NID_TO_LN[ NID_sha256 ] = LN_sha256;
        NID_TO_LN[ NID_sha384 ] = LN_sha384;
        NID_TO_LN[ NID_sha512 ] = LN_sha512;
        NID_TO_LN[ NID_sha224 ] = LN_sha224;
        NID_TO_LN[ NID_hold_instruction_code ] = LN_hold_instruction_code;
        NID_TO_LN[ NID_hold_instruction_none ] = LN_hold_instruction_none;
        NID_TO_LN[ NID_hold_instruction_call_issuer ] = LN_hold_instruction_call_issuer;
        NID_TO_LN[ NID_hold_instruction_reject ] = LN_hold_instruction_reject;
        NID_TO_LN[ NID_pilotAttributeType ] = LN_pilotAttributeType;
        NID_TO_LN[ NID_pilotAttributeSyntax ] = LN_pilotAttributeSyntax;
        NID_TO_LN[ NID_pilotObjectClass ] = LN_pilotObjectClass;
        NID_TO_LN[ NID_pilotGroups ] = LN_pilotGroups;
        NID_TO_LN[ NID_iA5StringSyntax ] = LN_iA5StringSyntax;
        NID_TO_LN[ NID_caseIgnoreIA5StringSyntax ] = LN_caseIgnoreIA5StringSyntax;
        NID_TO_LN[ NID_pilotObject ] = LN_pilotObject;
        NID_TO_LN[ NID_pilotPerson ] = LN_pilotPerson;
        NID_TO_LN[ NID_documentSeries ] = LN_documentSeries;
        NID_TO_LN[ NID_Domain ] = LN_Domain;
        NID_TO_LN[ NID_rFC822localPart ] = LN_rFC822localPart;
        NID_TO_LN[ NID_dNSDomain ] = LN_dNSDomain;
        NID_TO_LN[ NID_domainRelatedObject ] = LN_domainRelatedObject;
        NID_TO_LN[ NID_friendlyCountry ] = LN_friendlyCountry;
        NID_TO_LN[ NID_simpleSecurityObject ] = LN_simpleSecurityObject;
        NID_TO_LN[ NID_pilotOrganization ] = LN_pilotOrganization;
        NID_TO_LN[ NID_pilotDSA ] = LN_pilotDSA;
        NID_TO_LN[ NID_qualityLabelledData ] = LN_qualityLabelledData;
        NID_TO_LN[ NID_userId ] = LN_userId;
        NID_TO_LN[ NID_textEncodedORAddress ] = LN_textEncodedORAddress;
        NID_TO_LN[ NID_rfc822Mailbox ] = LN_rfc822Mailbox;
        NID_TO_LN[ NID_favouriteDrink ] = LN_favouriteDrink;
        NID_TO_LN[ NID_roomNumber ] = LN_roomNumber;
        NID_TO_LN[ NID_userClass ] = LN_userClass;
        NID_TO_LN[ NID_documentIdentifier ] = LN_documentIdentifier;
        NID_TO_LN[ NID_documentTitle ] = LN_documentTitle;
        NID_TO_LN[ NID_documentVersion ] = LN_documentVersion;
        NID_TO_LN[ NID_documentAuthor ] = LN_documentAuthor;
        NID_TO_LN[ NID_documentLocation ] = LN_documentLocation;
        NID_TO_LN[ NID_homeTelephoneNumber ] = LN_homeTelephoneNumber;
        NID_TO_LN[ NID_otherMailbox ] = LN_otherMailbox;
        NID_TO_LN[ NID_lastModifiedTime ] = LN_lastModifiedTime;
        NID_TO_LN[ NID_lastModifiedBy ] = LN_lastModifiedBy;
        NID_TO_LN[ NID_domainComponent ] = LN_domainComponent;
        NID_TO_LN[ NID_aRecord ] = LN_aRecord;
        NID_TO_LN[ NID_pilotAttributeType27 ] = LN_pilotAttributeType27;
        NID_TO_LN[ NID_mXRecord ] = LN_mXRecord;
        NID_TO_LN[ NID_nSRecord ] = LN_nSRecord;
        NID_TO_LN[ NID_sOARecord ] = LN_sOARecord;
        NID_TO_LN[ NID_cNAMERecord ] = LN_cNAMERecord;
        NID_TO_LN[ NID_associatedDomain ] = LN_associatedDomain;
        NID_TO_LN[ NID_associatedName ] = LN_associatedName;
        NID_TO_LN[ NID_homePostalAddress ] = LN_homePostalAddress;
        NID_TO_LN[ NID_personalTitle ] = LN_personalTitle;
        NID_TO_LN[ NID_mobileTelephoneNumber ] = LN_mobileTelephoneNumber;
        NID_TO_LN[ NID_pagerTelephoneNumber ] = LN_pagerTelephoneNumber;
        NID_TO_LN[ NID_friendlyCountryName ] = LN_friendlyCountryName;
        NID_TO_LN[ NID_organizationalStatus ] = LN_organizationalStatus;
        NID_TO_LN[ NID_janetMailbox ] = LN_janetMailbox;
        NID_TO_LN[ NID_mailPreferenceOption ] = LN_mailPreferenceOption;
        NID_TO_LN[ NID_buildingName ] = LN_buildingName;
        NID_TO_LN[ NID_dSAQuality ] = LN_dSAQuality;
        NID_TO_LN[ NID_singleLevelQuality ] = LN_singleLevelQuality;
        NID_TO_LN[ NID_subtreeMinimumQuality ] = LN_subtreeMinimumQuality;
        NID_TO_LN[ NID_subtreeMaximumQuality ] = LN_subtreeMaximumQuality;
        NID_TO_LN[ NID_personalSignature ] = LN_personalSignature;
        NID_TO_LN[ NID_dITRedirect ] = LN_dITRedirect;
        NID_TO_LN[ NID_documentPublisher ] = LN_documentPublisher;
        NID_TO_LN[ NID_id_set ] = LN_id_set;
        NID_TO_LN[ NID_set_ctype ] = LN_set_ctype;
        NID_TO_LN[ NID_set_msgExt ] = LN_set_msgExt;
        NID_TO_LN[ NID_set_certExt ] = LN_set_certExt;
        NID_TO_LN[ NID_setext_genCrypt ] = LN_setext_genCrypt;
        NID_TO_LN[ NID_setext_miAuth ] = LN_setext_miAuth;
        NID_TO_LN[ NID_setext_cv ] = LN_setext_cv;
        NID_TO_LN[ NID_setAttr_PGWYcap ] = LN_setAttr_PGWYcap;
        NID_TO_LN[ NID_setAttr_IssCap ] = LN_setAttr_IssCap;
        NID_TO_LN[ NID_setAttr_GenCryptgrm ] = LN_setAttr_GenCryptgrm;
        NID_TO_LN[ NID_setAttr_T2Enc ] = LN_setAttr_T2Enc;
        NID_TO_LN[ NID_setAttr_T2cleartxt ] = LN_setAttr_T2cleartxt;
        NID_TO_LN[ NID_setAttr_TokICCsig ] = LN_setAttr_TokICCsig;
        NID_TO_LN[ NID_setAttr_SecDevSig ] = LN_setAttr_SecDevSig;
        NID_TO_LN[ NID_des_cdmf ] = LN_des_cdmf;
        NID_TO_LN[ NID_ipsec3 ] = LN_ipsec3;
        NID_TO_LN[ NID_ipsec4 ] = LN_ipsec4;
        NID_TO_LN[ NID_id_GostR3411_94_with_GostR3410_2001 ] = LN_id_GostR3411_94_with_GostR3410_2001;
        NID_TO_LN[ NID_id_GostR3411_94_with_GostR3410_94 ] = LN_id_GostR3411_94_with_GostR3410_94;
        NID_TO_LN[ NID_id_GostR3411_94 ] = LN_id_GostR3411_94;
        NID_TO_LN[ NID_id_HMACGostR3411_94 ] = LN_id_HMACGostR3411_94;
        NID_TO_LN[ NID_id_GostR3410_2001 ] = LN_id_GostR3410_2001;
        NID_TO_LN[ NID_id_GostR3410_94 ] = LN_id_GostR3410_94;
        NID_TO_LN[ NID_id_Gost28147_89 ] = LN_id_Gost28147_89;
        NID_TO_LN[ NID_id_Gost28147_89_MAC ] = LN_id_Gost28147_89_MAC;
        NID_TO_LN[ NID_id_GostR3411_94_prf ] = LN_id_GostR3411_94_prf;
        NID_TO_LN[ NID_id_GostR3410_2001DH ] = LN_id_GostR3410_2001DH;
        NID_TO_LN[ NID_id_GostR3410_94DH ] = LN_id_GostR3410_94DH;
        NID_TO_LN[ NID_id_Gost28147_89_cc ] = LN_id_Gost28147_89_cc;
        NID_TO_LN[ NID_id_GostR3410_94_cc ] = LN_id_GostR3410_94_cc;
        NID_TO_LN[ NID_id_GostR3410_2001_cc ] = LN_id_GostR3410_2001_cc;
        NID_TO_LN[ NID_id_GostR3411_94_with_GostR3410_94_cc ] = LN_id_GostR3411_94_with_GostR3410_94_cc;
        NID_TO_LN[ NID_id_GostR3411_94_with_GostR3410_2001_cc ] = LN_id_GostR3411_94_with_GostR3410_2001_cc;
        NID_TO_LN[ NID_id_GostR3410_2001_ParamSet_cc ] = LN_id_GostR3410_2001_ParamSet_cc;
        NID_TO_LN[ NID_camellia_128_cbc ] = LN_camellia_128_cbc;
        NID_TO_LN[ NID_camellia_192_cbc ] = LN_camellia_192_cbc;
        NID_TO_LN[ NID_camellia_256_cbc ] = LN_camellia_256_cbc;
        NID_TO_LN[ NID_camellia_128_ecb ] = LN_camellia_128_ecb;
        NID_TO_LN[ NID_camellia_128_ofb128 ] = LN_camellia_128_ofb128;
        NID_TO_LN[ NID_camellia_128_cfb128 ] = LN_camellia_128_cfb128;
        NID_TO_LN[ NID_camellia_192_ecb ] = LN_camellia_192_ecb;
        NID_TO_LN[ NID_camellia_192_ofb128 ] = LN_camellia_192_ofb128;
        NID_TO_LN[ NID_camellia_192_cfb128 ] = LN_camellia_192_cfb128;
        NID_TO_LN[ NID_camellia_256_ecb ] = LN_camellia_256_ecb;
        NID_TO_LN[ NID_camellia_256_ofb128 ] = LN_camellia_256_ofb128;
        NID_TO_LN[ NID_camellia_256_cfb128 ] = LN_camellia_256_cfb128;
        NID_TO_LN[ NID_camellia_128_cfb1 ] = LN_camellia_128_cfb1;
        NID_TO_LN[ NID_camellia_192_cfb1 ] = LN_camellia_192_cfb1;
        NID_TO_LN[ NID_camellia_256_cfb1 ] = LN_camellia_256_cfb1;
        NID_TO_LN[ NID_camellia_128_cfb8 ] = LN_camellia_128_cfb8;
        NID_TO_LN[ NID_camellia_192_cfb8 ] = LN_camellia_192_cfb8;
        NID_TO_LN[ NID_camellia_256_cfb8 ] = LN_camellia_256_cfb8;
        NID_TO_LN[ NID_kisa ] = LN_kisa;
        NID_TO_LN[ NID_seed_ecb ] = LN_seed_ecb;
        NID_TO_LN[ NID_seed_cbc ] = LN_seed_cbc;
        NID_TO_LN[ NID_seed_cfb128 ] = LN_seed_cfb128;
        NID_TO_LN[ NID_seed_ofb128 ] = LN_seed_ofb128;
        NID_TO_LN[ NID_hmac ] = LN_hmac;
        NID_TO_LN[ NID_cmac ] = LN_cmac;
        NID_TO_LN[ NID_rc4_hmac_md5 ] = LN_rc4_hmac_md5;
        NID_TO_LN[ NID_aes_128_cbc_hmac_sha1 ] = LN_aes_128_cbc_hmac_sha1;
        NID_TO_LN[ NID_aes_192_cbc_hmac_sha1 ] = LN_aes_192_cbc_hmac_sha1;
        NID_TO_LN[ NID_aes_256_cbc_hmac_sha1 ] = LN_aes_256_cbc_hmac_sha1;
        NID_TO_LN[ NID_aes_128_cbc_hmac_sha256 ] = LN_aes_128_cbc_hmac_sha256;
        NID_TO_LN[ NID_aes_192_cbc_hmac_sha256 ] = LN_aes_192_cbc_hmac_sha256;
        NID_TO_LN[ NID_aes_256_cbc_hmac_sha256 ] = LN_aes_256_cbc_hmac_sha256;
        NID_TO_LN[ NID_dhpublicnumber ] = LN_dhpublicnumber;
        NID_TO_LN[ NID_ct_precert_scts ] = LN_ct_precert_scts;
        NID_TO_LN[ NID_ct_precert_poison ] = LN_ct_precert_poison;
        NID_TO_LN[ NID_ct_precert_signer ] = LN_ct_precert_signer;
        NID_TO_LN[ NID_ct_cert_scts ] = LN_ct_cert_scts;
        NID_TO_LN[ NID_jurisdictionLocalityName ] = LN_jurisdictionLocalityName;
        NID_TO_LN[ NID_jurisdictionStateOrProvinceName ] = LN_jurisdictionStateOrProvinceName;
        NID_TO_LN[ NID_jurisdictionCountryName ] = LN_jurisdictionCountryName;
    }
    

    private static final String[] NID_TO_OID = new String[ 958 ];
    static {
        NID_TO_OID[ NID_undef ] = OBJ_undef;
        NID_TO_OID[ NID_itu_t ] = OBJ_itu_t;
        NID_TO_OID[ NID_ccitt ] = OBJ_ccitt;
        NID_TO_OID[ NID_iso ] = OBJ_iso;
        NID_TO_OID[ NID_joint_iso_itu_t ] = OBJ_joint_iso_itu_t;
        NID_TO_OID[ NID_joint_iso_ccitt ] = OBJ_joint_iso_ccitt;
        NID_TO_OID[ NID_member_body ] = OBJ_member_body;
        NID_TO_OID[ NID_identified_organization ] = OBJ_identified_organization;
        NID_TO_OID[ NID_hmac_md5 ] = OBJ_hmac_md5;
        NID_TO_OID[ NID_hmac_sha1 ] = OBJ_hmac_sha1;
        NID_TO_OID[ NID_certicom_arc ] = OBJ_certicom_arc;
        NID_TO_OID[ NID_international_organizations ] = OBJ_international_organizations;
        NID_TO_OID[ NID_wap ] = OBJ_wap;
        NID_TO_OID[ NID_wap_wsg ] = OBJ_wap_wsg;
        NID_TO_OID[ NID_selected_attribute_types ] = OBJ_selected_attribute_types;
        NID_TO_OID[ NID_clearance ] = OBJ_clearance;
        NID_TO_OID[ NID_ISO_US ] = OBJ_ISO_US;
        NID_TO_OID[ NID_X9_57 ] = OBJ_X9_57;
        NID_TO_OID[ NID_X9cm ] = OBJ_X9cm;
        NID_TO_OID[ NID_dsa ] = OBJ_dsa;
        NID_TO_OID[ NID_dsaWithSHA1 ] = OBJ_dsaWithSHA1;
        NID_TO_OID[ NID_ansi_X9_62 ] = OBJ_ansi_X9_62;
        NID_TO_OID[ NID_X9_62_prime_field ] = OBJ_X9_62_prime_field;
        NID_TO_OID[ NID_X9_62_characteristic_two_field ] = OBJ_X9_62_characteristic_two_field;
        NID_TO_OID[ NID_X9_62_id_characteristic_two_basis ] = OBJ_X9_62_id_characteristic_two_basis;
        NID_TO_OID[ NID_X9_62_onBasis ] = OBJ_X9_62_onBasis;
        NID_TO_OID[ NID_X9_62_tpBasis ] = OBJ_X9_62_tpBasis;
        NID_TO_OID[ NID_X9_62_ppBasis ] = OBJ_X9_62_ppBasis;
        NID_TO_OID[ NID_X9_62_id_ecPublicKey ] = OBJ_X9_62_id_ecPublicKey;
        NID_TO_OID[ NID_X9_62_c2pnb163v1 ] = OBJ_X9_62_c2pnb163v1;
        NID_TO_OID[ NID_X9_62_c2pnb163v2 ] = OBJ_X9_62_c2pnb163v2;
        NID_TO_OID[ NID_X9_62_c2pnb163v3 ] = OBJ_X9_62_c2pnb163v3;
        NID_TO_OID[ NID_X9_62_c2pnb176v1 ] = OBJ_X9_62_c2pnb176v1;
        NID_TO_OID[ NID_X9_62_c2tnb191v1 ] = OBJ_X9_62_c2tnb191v1;
        NID_TO_OID[ NID_X9_62_c2tnb191v2 ] = OBJ_X9_62_c2tnb191v2;
        NID_TO_OID[ NID_X9_62_c2tnb191v3 ] = OBJ_X9_62_c2tnb191v3;
        NID_TO_OID[ NID_X9_62_c2onb191v4 ] = OBJ_X9_62_c2onb191v4;
        NID_TO_OID[ NID_X9_62_c2onb191v5 ] = OBJ_X9_62_c2onb191v5;
        NID_TO_OID[ NID_X9_62_c2pnb208w1 ] = OBJ_X9_62_c2pnb208w1;
        NID_TO_OID[ NID_X9_62_c2tnb239v1 ] = OBJ_X9_62_c2tnb239v1;
        NID_TO_OID[ NID_X9_62_c2tnb239v2 ] = OBJ_X9_62_c2tnb239v2;
        NID_TO_OID[ NID_X9_62_c2tnb239v3 ] = OBJ_X9_62_c2tnb239v3;
        NID_TO_OID[ NID_X9_62_c2onb239v4 ] = OBJ_X9_62_c2onb239v4;
        NID_TO_OID[ NID_X9_62_c2onb239v5 ] = OBJ_X9_62_c2onb239v5;
        NID_TO_OID[ NID_X9_62_c2pnb272w1 ] = OBJ_X9_62_c2pnb272w1;
        NID_TO_OID[ NID_X9_62_c2pnb304w1 ] = OBJ_X9_62_c2pnb304w1;
        NID_TO_OID[ NID_X9_62_c2tnb359v1 ] = OBJ_X9_62_c2tnb359v1;
        NID_TO_OID[ NID_X9_62_c2pnb368w1 ] = OBJ_X9_62_c2pnb368w1;
        NID_TO_OID[ NID_X9_62_c2tnb431r1 ] = OBJ_X9_62_c2tnb431r1;
        NID_TO_OID[ NID_X9_62_prime192v1 ] = OBJ_X9_62_prime192v1;
        NID_TO_OID[ NID_X9_62_prime192v2 ] = OBJ_X9_62_prime192v2;
        NID_TO_OID[ NID_X9_62_prime192v3 ] = OBJ_X9_62_prime192v3;
        NID_TO_OID[ NID_X9_62_prime239v1 ] = OBJ_X9_62_prime239v1;
        NID_TO_OID[ NID_X9_62_prime239v2 ] = OBJ_X9_62_prime239v2;
        NID_TO_OID[ NID_X9_62_prime239v3 ] = OBJ_X9_62_prime239v3;
        NID_TO_OID[ NID_X9_62_prime256v1 ] = OBJ_X9_62_prime256v1;
        NID_TO_OID[ NID_ecdsa_with_SHA1 ] = OBJ_ecdsa_with_SHA1;
        NID_TO_OID[ NID_ecdsa_with_Recommended ] = OBJ_ecdsa_with_Recommended;
        NID_TO_OID[ NID_ecdsa_with_Specified ] = OBJ_ecdsa_with_Specified;
        NID_TO_OID[ NID_ecdsa_with_SHA224 ] = OBJ_ecdsa_with_SHA224;
        NID_TO_OID[ NID_ecdsa_with_SHA256 ] = OBJ_ecdsa_with_SHA256;
        NID_TO_OID[ NID_ecdsa_with_SHA384 ] = OBJ_ecdsa_with_SHA384;
        NID_TO_OID[ NID_ecdsa_with_SHA512 ] = OBJ_ecdsa_with_SHA512;
        NID_TO_OID[ NID_secp112r1 ] = OBJ_secp112r1;
        NID_TO_OID[ NID_secp112r2 ] = OBJ_secp112r2;
        NID_TO_OID[ NID_secp128r1 ] = OBJ_secp128r1;
        NID_TO_OID[ NID_secp128r2 ] = OBJ_secp128r2;
        NID_TO_OID[ NID_secp160k1 ] = OBJ_secp160k1;
        NID_TO_OID[ NID_secp160r1 ] = OBJ_secp160r1;
        NID_TO_OID[ NID_secp160r2 ] = OBJ_secp160r2;
        NID_TO_OID[ NID_secp192k1 ] = OBJ_secp192k1;
        NID_TO_OID[ NID_secp224k1 ] = OBJ_secp224k1;
        NID_TO_OID[ NID_secp224r1 ] = OBJ_secp224r1;
        NID_TO_OID[ NID_secp256k1 ] = OBJ_secp256k1;
        NID_TO_OID[ NID_secp384r1 ] = OBJ_secp384r1;
        NID_TO_OID[ NID_secp521r1 ] = OBJ_secp521r1;
        NID_TO_OID[ NID_sect113r1 ] = OBJ_sect113r1;
        NID_TO_OID[ NID_sect113r2 ] = OBJ_sect113r2;
        NID_TO_OID[ NID_sect131r1 ] = OBJ_sect131r1;
        NID_TO_OID[ NID_sect131r2 ] = OBJ_sect131r2;
        NID_TO_OID[ NID_sect163k1 ] = OBJ_sect163k1;
        NID_TO_OID[ NID_sect163r1 ] = OBJ_sect163r1;
        NID_TO_OID[ NID_sect163r2 ] = OBJ_sect163r2;
        NID_TO_OID[ NID_sect193r1 ] = OBJ_sect193r1;
        NID_TO_OID[ NID_sect193r2 ] = OBJ_sect193r2;
        NID_TO_OID[ NID_sect233k1 ] = OBJ_sect233k1;
        NID_TO_OID[ NID_sect233r1 ] = OBJ_sect233r1;
        NID_TO_OID[ NID_sect239k1 ] = OBJ_sect239k1;
        NID_TO_OID[ NID_sect283k1 ] = OBJ_sect283k1;
        NID_TO_OID[ NID_sect283r1 ] = OBJ_sect283r1;
        NID_TO_OID[ NID_sect409k1 ] = OBJ_sect409k1;
        NID_TO_OID[ NID_sect409r1 ] = OBJ_sect409r1;
        NID_TO_OID[ NID_sect571k1 ] = OBJ_sect571k1;
        NID_TO_OID[ NID_sect571r1 ] = OBJ_sect571r1;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls1 ] = OBJ_wap_wsg_idm_ecid_wtls1;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls3 ] = OBJ_wap_wsg_idm_ecid_wtls3;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls4 ] = OBJ_wap_wsg_idm_ecid_wtls4;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls5 ] = OBJ_wap_wsg_idm_ecid_wtls5;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls6 ] = OBJ_wap_wsg_idm_ecid_wtls6;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls7 ] = OBJ_wap_wsg_idm_ecid_wtls7;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls8 ] = OBJ_wap_wsg_idm_ecid_wtls8;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls9 ] = OBJ_wap_wsg_idm_ecid_wtls9;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls10 ] = OBJ_wap_wsg_idm_ecid_wtls10;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls11 ] = OBJ_wap_wsg_idm_ecid_wtls11;
        NID_TO_OID[ NID_wap_wsg_idm_ecid_wtls12 ] = OBJ_wap_wsg_idm_ecid_wtls12;
        NID_TO_OID[ NID_cast5_cbc ] = OBJ_cast5_cbc;
        NID_TO_OID[ NID_pbeWithMD5AndCast5_CBC ] = OBJ_pbeWithMD5AndCast5_CBC;
        NID_TO_OID[ NID_id_PasswordBasedMAC ] = OBJ_id_PasswordBasedMAC;
        NID_TO_OID[ NID_id_DHBasedMac ] = OBJ_id_DHBasedMac;
        NID_TO_OID[ NID_rsadsi ] = OBJ_rsadsi;
        NID_TO_OID[ NID_pkcs ] = OBJ_pkcs;
        NID_TO_OID[ NID_pkcs1 ] = OBJ_pkcs1;
        NID_TO_OID[ NID_rsaEncryption ] = OBJ_rsaEncryption;
        NID_TO_OID[ NID_md2WithRSAEncryption ] = OBJ_md2WithRSAEncryption;
        NID_TO_OID[ NID_md4WithRSAEncryption ] = OBJ_md4WithRSAEncryption;
        NID_TO_OID[ NID_md5WithRSAEncryption ] = OBJ_md5WithRSAEncryption;
        NID_TO_OID[ NID_sha1WithRSAEncryption ] = OBJ_sha1WithRSAEncryption;
        NID_TO_OID[ NID_rsaesOaep ] = OBJ_rsaesOaep;
        NID_TO_OID[ NID_mgf1 ] = OBJ_mgf1;
        NID_TO_OID[ NID_pSpecified ] = OBJ_pSpecified;
        NID_TO_OID[ NID_rsassaPss ] = OBJ_rsassaPss;
        NID_TO_OID[ NID_sha256WithRSAEncryption ] = OBJ_sha256WithRSAEncryption;
        NID_TO_OID[ NID_sha384WithRSAEncryption ] = OBJ_sha384WithRSAEncryption;
        NID_TO_OID[ NID_sha512WithRSAEncryption ] = OBJ_sha512WithRSAEncryption;
        NID_TO_OID[ NID_sha224WithRSAEncryption ] = OBJ_sha224WithRSAEncryption;
        NID_TO_OID[ NID_pkcs3 ] = OBJ_pkcs3;
        NID_TO_OID[ NID_dhKeyAgreement ] = OBJ_dhKeyAgreement;
        NID_TO_OID[ NID_pkcs5 ] = OBJ_pkcs5;
        NID_TO_OID[ NID_pbeWithMD2AndDES_CBC ] = OBJ_pbeWithMD2AndDES_CBC;
        NID_TO_OID[ NID_pbeWithMD5AndDES_CBC ] = OBJ_pbeWithMD5AndDES_CBC;
        NID_TO_OID[ NID_pbeWithMD2AndRC2_CBC ] = OBJ_pbeWithMD2AndRC2_CBC;
        NID_TO_OID[ NID_pbeWithMD5AndRC2_CBC ] = OBJ_pbeWithMD5AndRC2_CBC;
        NID_TO_OID[ NID_pbeWithSHA1AndDES_CBC ] = OBJ_pbeWithSHA1AndDES_CBC;
        NID_TO_OID[ NID_pbeWithSHA1AndRC2_CBC ] = OBJ_pbeWithSHA1AndRC2_CBC;
        NID_TO_OID[ NID_id_pbkdf2 ] = OBJ_id_pbkdf2;
        NID_TO_OID[ NID_pbes2 ] = OBJ_pbes2;
        NID_TO_OID[ NID_pbmac1 ] = OBJ_pbmac1;
        NID_TO_OID[ NID_pkcs7 ] = OBJ_pkcs7;
        NID_TO_OID[ NID_pkcs7_data ] = OBJ_pkcs7_data;
        NID_TO_OID[ NID_pkcs7_signed ] = OBJ_pkcs7_signed;
        NID_TO_OID[ NID_pkcs7_enveloped ] = OBJ_pkcs7_enveloped;
        NID_TO_OID[ NID_pkcs7_signedAndEnveloped ] = OBJ_pkcs7_signedAndEnveloped;
        NID_TO_OID[ NID_pkcs7_digest ] = OBJ_pkcs7_digest;
        NID_TO_OID[ NID_pkcs7_encrypted ] = OBJ_pkcs7_encrypted;
        NID_TO_OID[ NID_pkcs9 ] = OBJ_pkcs9;
        NID_TO_OID[ NID_pkcs9_emailAddress ] = OBJ_pkcs9_emailAddress;
        NID_TO_OID[ NID_pkcs9_unstructuredName ] = OBJ_pkcs9_unstructuredName;
        NID_TO_OID[ NID_pkcs9_contentType ] = OBJ_pkcs9_contentType;
        NID_TO_OID[ NID_pkcs9_messageDigest ] = OBJ_pkcs9_messageDigest;
        NID_TO_OID[ NID_pkcs9_signingTime ] = OBJ_pkcs9_signingTime;
        NID_TO_OID[ NID_pkcs9_countersignature ] = OBJ_pkcs9_countersignature;
        NID_TO_OID[ NID_pkcs9_challengePassword ] = OBJ_pkcs9_challengePassword;
        NID_TO_OID[ NID_pkcs9_unstructuredAddress ] = OBJ_pkcs9_unstructuredAddress;
        NID_TO_OID[ NID_pkcs9_extCertAttributes ] = OBJ_pkcs9_extCertAttributes;
        NID_TO_OID[ NID_ext_req ] = OBJ_ext_req;
        NID_TO_OID[ NID_SMIMECapabilities ] = OBJ_SMIMECapabilities;
        NID_TO_OID[ NID_SMIME ] = OBJ_SMIME;
        NID_TO_OID[ NID_id_smime_mod ] = OBJ_id_smime_mod;
        NID_TO_OID[ NID_id_smime_ct ] = OBJ_id_smime_ct;
        NID_TO_OID[ NID_id_smime_aa ] = OBJ_id_smime_aa;
        NID_TO_OID[ NID_id_smime_alg ] = OBJ_id_smime_alg;
        NID_TO_OID[ NID_id_smime_cd ] = OBJ_id_smime_cd;
        NID_TO_OID[ NID_id_smime_spq ] = OBJ_id_smime_spq;
        NID_TO_OID[ NID_id_smime_cti ] = OBJ_id_smime_cti;
        NID_TO_OID[ NID_id_smime_mod_cms ] = OBJ_id_smime_mod_cms;
        NID_TO_OID[ NID_id_smime_mod_ess ] = OBJ_id_smime_mod_ess;
        NID_TO_OID[ NID_id_smime_mod_oid ] = OBJ_id_smime_mod_oid;
        NID_TO_OID[ NID_id_smime_mod_msg_v3 ] = OBJ_id_smime_mod_msg_v3;
        NID_TO_OID[ NID_id_smime_mod_ets_eSignature_88 ] = OBJ_id_smime_mod_ets_eSignature_88;
        NID_TO_OID[ NID_id_smime_mod_ets_eSignature_97 ] = OBJ_id_smime_mod_ets_eSignature_97;
        NID_TO_OID[ NID_id_smime_mod_ets_eSigPolicy_88 ] = OBJ_id_smime_mod_ets_eSigPolicy_88;
        NID_TO_OID[ NID_id_smime_mod_ets_eSigPolicy_97 ] = OBJ_id_smime_mod_ets_eSigPolicy_97;
        NID_TO_OID[ NID_id_smime_ct_receipt ] = OBJ_id_smime_ct_receipt;
        NID_TO_OID[ NID_id_smime_ct_authData ] = OBJ_id_smime_ct_authData;
        NID_TO_OID[ NID_id_smime_ct_publishCert ] = OBJ_id_smime_ct_publishCert;
        NID_TO_OID[ NID_id_smime_ct_TSTInfo ] = OBJ_id_smime_ct_TSTInfo;
        NID_TO_OID[ NID_id_smime_ct_TDTInfo ] = OBJ_id_smime_ct_TDTInfo;
        NID_TO_OID[ NID_id_smime_ct_contentInfo ] = OBJ_id_smime_ct_contentInfo;
        NID_TO_OID[ NID_id_smime_ct_DVCSRequestData ] = OBJ_id_smime_ct_DVCSRequestData;
        NID_TO_OID[ NID_id_smime_ct_DVCSResponseData ] = OBJ_id_smime_ct_DVCSResponseData;
        NID_TO_OID[ NID_id_smime_ct_compressedData ] = OBJ_id_smime_ct_compressedData;
        NID_TO_OID[ NID_id_ct_asciiTextWithCRLF ] = OBJ_id_ct_asciiTextWithCRLF;
        NID_TO_OID[ NID_id_smime_aa_receiptRequest ] = OBJ_id_smime_aa_receiptRequest;
        NID_TO_OID[ NID_id_smime_aa_securityLabel ] = OBJ_id_smime_aa_securityLabel;
        NID_TO_OID[ NID_id_smime_aa_mlExpandHistory ] = OBJ_id_smime_aa_mlExpandHistory;
        NID_TO_OID[ NID_id_smime_aa_contentHint ] = OBJ_id_smime_aa_contentHint;
        NID_TO_OID[ NID_id_smime_aa_msgSigDigest ] = OBJ_id_smime_aa_msgSigDigest;
        NID_TO_OID[ NID_id_smime_aa_encapContentType ] = OBJ_id_smime_aa_encapContentType;
        NID_TO_OID[ NID_id_smime_aa_contentIdentifier ] = OBJ_id_smime_aa_contentIdentifier;
        NID_TO_OID[ NID_id_smime_aa_macValue ] = OBJ_id_smime_aa_macValue;
        NID_TO_OID[ NID_id_smime_aa_equivalentLabels ] = OBJ_id_smime_aa_equivalentLabels;
        NID_TO_OID[ NID_id_smime_aa_contentReference ] = OBJ_id_smime_aa_contentReference;
        NID_TO_OID[ NID_id_smime_aa_encrypKeyPref ] = OBJ_id_smime_aa_encrypKeyPref;
        NID_TO_OID[ NID_id_smime_aa_signingCertificate ] = OBJ_id_smime_aa_signingCertificate;
        NID_TO_OID[ NID_id_smime_aa_smimeEncryptCerts ] = OBJ_id_smime_aa_smimeEncryptCerts;
        NID_TO_OID[ NID_id_smime_aa_timeStampToken ] = OBJ_id_smime_aa_timeStampToken;
        NID_TO_OID[ NID_id_smime_aa_ets_sigPolicyId ] = OBJ_id_smime_aa_ets_sigPolicyId;
        NID_TO_OID[ NID_id_smime_aa_ets_commitmentType ] = OBJ_id_smime_aa_ets_commitmentType;
        NID_TO_OID[ NID_id_smime_aa_ets_signerLocation ] = OBJ_id_smime_aa_ets_signerLocation;
        NID_TO_OID[ NID_id_smime_aa_ets_signerAttr ] = OBJ_id_smime_aa_ets_signerAttr;
        NID_TO_OID[ NID_id_smime_aa_ets_otherSigCert ] = OBJ_id_smime_aa_ets_otherSigCert;
        NID_TO_OID[ NID_id_smime_aa_ets_contentTimestamp ] = OBJ_id_smime_aa_ets_contentTimestamp;
        NID_TO_OID[ NID_id_smime_aa_ets_CertificateRefs ] = OBJ_id_smime_aa_ets_CertificateRefs;
        NID_TO_OID[ NID_id_smime_aa_ets_RevocationRefs ] = OBJ_id_smime_aa_ets_RevocationRefs;
        NID_TO_OID[ NID_id_smime_aa_ets_certValues ] = OBJ_id_smime_aa_ets_certValues;
        NID_TO_OID[ NID_id_smime_aa_ets_revocationValues ] = OBJ_id_smime_aa_ets_revocationValues;
        NID_TO_OID[ NID_id_smime_aa_ets_escTimeStamp ] = OBJ_id_smime_aa_ets_escTimeStamp;
        NID_TO_OID[ NID_id_smime_aa_ets_certCRLTimestamp ] = OBJ_id_smime_aa_ets_certCRLTimestamp;
        NID_TO_OID[ NID_id_smime_aa_ets_archiveTimeStamp ] = OBJ_id_smime_aa_ets_archiveTimeStamp;
        NID_TO_OID[ NID_id_smime_aa_signatureType ] = OBJ_id_smime_aa_signatureType;
        NID_TO_OID[ NID_id_smime_aa_dvcs_dvc ] = OBJ_id_smime_aa_dvcs_dvc;
        NID_TO_OID[ NID_id_smime_alg_ESDHwith3DES ] = OBJ_id_smime_alg_ESDHwith3DES;
        NID_TO_OID[ NID_id_smime_alg_ESDHwithRC2 ] = OBJ_id_smime_alg_ESDHwithRC2;
        NID_TO_OID[ NID_id_smime_alg_3DESwrap ] = OBJ_id_smime_alg_3DESwrap;
        NID_TO_OID[ NID_id_smime_alg_RC2wrap ] = OBJ_id_smime_alg_RC2wrap;
        NID_TO_OID[ NID_id_smime_alg_ESDH ] = OBJ_id_smime_alg_ESDH;
        NID_TO_OID[ NID_id_smime_alg_CMS3DESwrap ] = OBJ_id_smime_alg_CMS3DESwrap;
        NID_TO_OID[ NID_id_smime_alg_CMSRC2wrap ] = OBJ_id_smime_alg_CMSRC2wrap;
        NID_TO_OID[ NID_id_alg_PWRI_KEK ] = OBJ_id_alg_PWRI_KEK;
        NID_TO_OID[ NID_id_smime_cd_ldap ] = OBJ_id_smime_cd_ldap;
        NID_TO_OID[ NID_id_smime_spq_ets_sqt_uri ] = OBJ_id_smime_spq_ets_sqt_uri;
        NID_TO_OID[ NID_id_smime_spq_ets_sqt_unotice ] = OBJ_id_smime_spq_ets_sqt_unotice;
        NID_TO_OID[ NID_id_smime_cti_ets_proofOfOrigin ] = OBJ_id_smime_cti_ets_proofOfOrigin;
        NID_TO_OID[ NID_id_smime_cti_ets_proofOfReceipt ] = OBJ_id_smime_cti_ets_proofOfReceipt;
        NID_TO_OID[ NID_id_smime_cti_ets_proofOfDelivery ] = OBJ_id_smime_cti_ets_proofOfDelivery;
        NID_TO_OID[ NID_id_smime_cti_ets_proofOfSender ] = OBJ_id_smime_cti_ets_proofOfSender;
        NID_TO_OID[ NID_id_smime_cti_ets_proofOfApproval ] = OBJ_id_smime_cti_ets_proofOfApproval;
        NID_TO_OID[ NID_id_smime_cti_ets_proofOfCreation ] = OBJ_id_smime_cti_ets_proofOfCreation;
        NID_TO_OID[ NID_friendlyName ] = OBJ_friendlyName;
        NID_TO_OID[ NID_localKeyID ] = OBJ_localKeyID;
        NID_TO_OID[ NID_ms_csp_name ] = OBJ_ms_csp_name;
        NID_TO_OID[ NID_LocalKeySet ] = OBJ_LocalKeySet;
        NID_TO_OID[ NID_x509Certificate ] = OBJ_x509Certificate;
        NID_TO_OID[ NID_sdsiCertificate ] = OBJ_sdsiCertificate;
        NID_TO_OID[ NID_x509Crl ] = OBJ_x509Crl;
        NID_TO_OID[ NID_pbe_WithSHA1And128BitRC4 ] = OBJ_pbe_WithSHA1And128BitRC4;
        NID_TO_OID[ NID_pbe_WithSHA1And40BitRC4 ] = OBJ_pbe_WithSHA1And40BitRC4;
        NID_TO_OID[ NID_pbe_WithSHA1And3_Key_TripleDES_CBC ] = OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC;
        NID_TO_OID[ NID_pbe_WithSHA1And2_Key_TripleDES_CBC ] = OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC;
        NID_TO_OID[ NID_pbe_WithSHA1And128BitRC2_CBC ] = OBJ_pbe_WithSHA1And128BitRC2_CBC;
        NID_TO_OID[ NID_pbe_WithSHA1And40BitRC2_CBC ] = OBJ_pbe_WithSHA1And40BitRC2_CBC;
        NID_TO_OID[ NID_keyBag ] = OBJ_keyBag;
        NID_TO_OID[ NID_pkcs8ShroudedKeyBag ] = OBJ_pkcs8ShroudedKeyBag;
        NID_TO_OID[ NID_certBag ] = OBJ_certBag;
        NID_TO_OID[ NID_crlBag ] = OBJ_crlBag;
        NID_TO_OID[ NID_secretBag ] = OBJ_secretBag;
        NID_TO_OID[ NID_safeContentsBag ] = OBJ_safeContentsBag;
        NID_TO_OID[ NID_md2 ] = OBJ_md2;
        NID_TO_OID[ NID_md4 ] = OBJ_md4;
        NID_TO_OID[ NID_md5 ] = OBJ_md5;
        NID_TO_OID[ NID_hmacWithMD5 ] = OBJ_hmacWithMD5;
        NID_TO_OID[ NID_hmacWithSHA1 ] = OBJ_hmacWithSHA1;
        NID_TO_OID[ NID_hmacWithSHA224 ] = OBJ_hmacWithSHA224;
        NID_TO_OID[ NID_hmacWithSHA256 ] = OBJ_hmacWithSHA256;
        NID_TO_OID[ NID_hmacWithSHA384 ] = OBJ_hmacWithSHA384;
        NID_TO_OID[ NID_hmacWithSHA512 ] = OBJ_hmacWithSHA512;
        NID_TO_OID[ NID_rc2_cbc ] = OBJ_rc2_cbc;
        NID_TO_OID[ NID_rc4 ] = OBJ_rc4;
        NID_TO_OID[ NID_des_ede3_cbc ] = OBJ_des_ede3_cbc;
        NID_TO_OID[ NID_rc5_cbc ] = OBJ_rc5_cbc;
        NID_TO_OID[ NID_ms_ext_req ] = OBJ_ms_ext_req;
        NID_TO_OID[ NID_ms_code_ind ] = OBJ_ms_code_ind;
        NID_TO_OID[ NID_ms_code_com ] = OBJ_ms_code_com;
        NID_TO_OID[ NID_ms_ctl_sign ] = OBJ_ms_ctl_sign;
        NID_TO_OID[ NID_ms_sgc ] = OBJ_ms_sgc;
        NID_TO_OID[ NID_ms_efs ] = OBJ_ms_efs;
        NID_TO_OID[ NID_ms_smartcard_login ] = OBJ_ms_smartcard_login;
        NID_TO_OID[ NID_ms_upn ] = OBJ_ms_upn;
        NID_TO_OID[ NID_idea_cbc ] = OBJ_idea_cbc;
        NID_TO_OID[ NID_bf_cbc ] = OBJ_bf_cbc;
        NID_TO_OID[ NID_id_pkix ] = OBJ_id_pkix;
        NID_TO_OID[ NID_id_pkix_mod ] = OBJ_id_pkix_mod;
        NID_TO_OID[ NID_id_pe ] = OBJ_id_pe;
        NID_TO_OID[ NID_id_qt ] = OBJ_id_qt;
        NID_TO_OID[ NID_id_kp ] = OBJ_id_kp;
        NID_TO_OID[ NID_id_it ] = OBJ_id_it;
        NID_TO_OID[ NID_id_pkip ] = OBJ_id_pkip;
        NID_TO_OID[ NID_id_alg ] = OBJ_id_alg;
        NID_TO_OID[ NID_id_cmc ] = OBJ_id_cmc;
        NID_TO_OID[ NID_id_on ] = OBJ_id_on;
        NID_TO_OID[ NID_id_pda ] = OBJ_id_pda;
        NID_TO_OID[ NID_id_aca ] = OBJ_id_aca;
        NID_TO_OID[ NID_id_qcs ] = OBJ_id_qcs;
        NID_TO_OID[ NID_id_cct ] = OBJ_id_cct;
        NID_TO_OID[ NID_id_ppl ] = OBJ_id_ppl;
        NID_TO_OID[ NID_id_ad ] = OBJ_id_ad;
        NID_TO_OID[ NID_id_pkix1_explicit_88 ] = OBJ_id_pkix1_explicit_88;
        NID_TO_OID[ NID_id_pkix1_implicit_88 ] = OBJ_id_pkix1_implicit_88;
        NID_TO_OID[ NID_id_pkix1_explicit_93 ] = OBJ_id_pkix1_explicit_93;
        NID_TO_OID[ NID_id_pkix1_implicit_93 ] = OBJ_id_pkix1_implicit_93;
        NID_TO_OID[ NID_id_mod_crmf ] = OBJ_id_mod_crmf;
        NID_TO_OID[ NID_id_mod_cmc ] = OBJ_id_mod_cmc;
        NID_TO_OID[ NID_id_mod_kea_profile_88 ] = OBJ_id_mod_kea_profile_88;
        NID_TO_OID[ NID_id_mod_kea_profile_93 ] = OBJ_id_mod_kea_profile_93;
        NID_TO_OID[ NID_id_mod_cmp ] = OBJ_id_mod_cmp;
        NID_TO_OID[ NID_id_mod_qualified_cert_88 ] = OBJ_id_mod_qualified_cert_88;
        NID_TO_OID[ NID_id_mod_qualified_cert_93 ] = OBJ_id_mod_qualified_cert_93;
        NID_TO_OID[ NID_id_mod_attribute_cert ] = OBJ_id_mod_attribute_cert;
        NID_TO_OID[ NID_id_mod_timestamp_protocol ] = OBJ_id_mod_timestamp_protocol;
        NID_TO_OID[ NID_id_mod_ocsp ] = OBJ_id_mod_ocsp;
        NID_TO_OID[ NID_id_mod_dvcs ] = OBJ_id_mod_dvcs;
        NID_TO_OID[ NID_id_mod_cmp2000 ] = OBJ_id_mod_cmp2000;
        NID_TO_OID[ NID_info_access ] = OBJ_info_access;
        NID_TO_OID[ NID_biometricInfo ] = OBJ_biometricInfo;
        NID_TO_OID[ NID_qcStatements ] = OBJ_qcStatements;
        NID_TO_OID[ NID_ac_auditEntity ] = OBJ_ac_auditEntity;
        NID_TO_OID[ NID_ac_targeting ] = OBJ_ac_targeting;
        NID_TO_OID[ NID_aaControls ] = OBJ_aaControls;
        NID_TO_OID[ NID_sbgp_ipAddrBlock ] = OBJ_sbgp_ipAddrBlock;
        NID_TO_OID[ NID_sbgp_autonomousSysNum ] = OBJ_sbgp_autonomousSysNum;
        NID_TO_OID[ NID_sbgp_routerIdentifier ] = OBJ_sbgp_routerIdentifier;
        NID_TO_OID[ NID_ac_proxying ] = OBJ_ac_proxying;
        NID_TO_OID[ NID_sinfo_access ] = OBJ_sinfo_access;
        NID_TO_OID[ NID_proxyCertInfo ] = OBJ_proxyCertInfo;
        NID_TO_OID[ NID_id_qt_cps ] = OBJ_id_qt_cps;
        NID_TO_OID[ NID_id_qt_unotice ] = OBJ_id_qt_unotice;
        NID_TO_OID[ NID_textNotice ] = OBJ_textNotice;
        NID_TO_OID[ NID_server_auth ] = OBJ_server_auth;
        NID_TO_OID[ NID_client_auth ] = OBJ_client_auth;
        NID_TO_OID[ NID_code_sign ] = OBJ_code_sign;
        NID_TO_OID[ NID_email_protect ] = OBJ_email_protect;
        NID_TO_OID[ NID_ipsecEndSystem ] = OBJ_ipsecEndSystem;
        NID_TO_OID[ NID_ipsecTunnel ] = OBJ_ipsecTunnel;
        NID_TO_OID[ NID_ipsecUser ] = OBJ_ipsecUser;
        NID_TO_OID[ NID_time_stamp ] = OBJ_time_stamp;
        NID_TO_OID[ NID_OCSP_sign ] = OBJ_OCSP_sign;
        NID_TO_OID[ NID_dvcs ] = OBJ_dvcs;
        NID_TO_OID[ NID_id_it_caProtEncCert ] = OBJ_id_it_caProtEncCert;
        NID_TO_OID[ NID_id_it_signKeyPairTypes ] = OBJ_id_it_signKeyPairTypes;
        NID_TO_OID[ NID_id_it_encKeyPairTypes ] = OBJ_id_it_encKeyPairTypes;
        NID_TO_OID[ NID_id_it_preferredSymmAlg ] = OBJ_id_it_preferredSymmAlg;
        NID_TO_OID[ NID_id_it_caKeyUpdateInfo ] = OBJ_id_it_caKeyUpdateInfo;
        NID_TO_OID[ NID_id_it_currentCRL ] = OBJ_id_it_currentCRL;
        NID_TO_OID[ NID_id_it_unsupportedOIDs ] = OBJ_id_it_unsupportedOIDs;
        NID_TO_OID[ NID_id_it_subscriptionRequest ] = OBJ_id_it_subscriptionRequest;
        NID_TO_OID[ NID_id_it_subscriptionResponse ] = OBJ_id_it_subscriptionResponse;
        NID_TO_OID[ NID_id_it_keyPairParamReq ] = OBJ_id_it_keyPairParamReq;
        NID_TO_OID[ NID_id_it_keyPairParamRep ] = OBJ_id_it_keyPairParamRep;
        NID_TO_OID[ NID_id_it_revPassphrase ] = OBJ_id_it_revPassphrase;
        NID_TO_OID[ NID_id_it_implicitConfirm ] = OBJ_id_it_implicitConfirm;
        NID_TO_OID[ NID_id_it_confirmWaitTime ] = OBJ_id_it_confirmWaitTime;
        NID_TO_OID[ NID_id_it_origPKIMessage ] = OBJ_id_it_origPKIMessage;
        NID_TO_OID[ NID_id_it_suppLangTags ] = OBJ_id_it_suppLangTags;
        NID_TO_OID[ NID_id_regCtrl ] = OBJ_id_regCtrl;
        NID_TO_OID[ NID_id_regInfo ] = OBJ_id_regInfo;
        NID_TO_OID[ NID_id_regCtrl_regToken ] = OBJ_id_regCtrl_regToken;
        NID_TO_OID[ NID_id_regCtrl_authenticator ] = OBJ_id_regCtrl_authenticator;
        NID_TO_OID[ NID_id_regCtrl_pkiPublicationInfo ] = OBJ_id_regCtrl_pkiPublicationInfo;
        NID_TO_OID[ NID_id_regCtrl_pkiArchiveOptions ] = OBJ_id_regCtrl_pkiArchiveOptions;
        NID_TO_OID[ NID_id_regCtrl_oldCertID ] = OBJ_id_regCtrl_oldCertID;
        NID_TO_OID[ NID_id_regCtrl_protocolEncrKey ] = OBJ_id_regCtrl_protocolEncrKey;
        NID_TO_OID[ NID_id_regInfo_utf8Pairs ] = OBJ_id_regInfo_utf8Pairs;
        NID_TO_OID[ NID_id_regInfo_certReq ] = OBJ_id_regInfo_certReq;
        NID_TO_OID[ NID_id_alg_des40 ] = OBJ_id_alg_des40;
        NID_TO_OID[ NID_id_alg_noSignature ] = OBJ_id_alg_noSignature;
        NID_TO_OID[ NID_id_alg_dh_sig_hmac_sha1 ] = OBJ_id_alg_dh_sig_hmac_sha1;
        NID_TO_OID[ NID_id_alg_dh_pop ] = OBJ_id_alg_dh_pop;
        NID_TO_OID[ NID_id_cmc_statusInfo ] = OBJ_id_cmc_statusInfo;
        NID_TO_OID[ NID_id_cmc_identification ] = OBJ_id_cmc_identification;
        NID_TO_OID[ NID_id_cmc_identityProof ] = OBJ_id_cmc_identityProof;
        NID_TO_OID[ NID_id_cmc_dataReturn ] = OBJ_id_cmc_dataReturn;
        NID_TO_OID[ NID_id_cmc_transactionId ] = OBJ_id_cmc_transactionId;
        NID_TO_OID[ NID_id_cmc_senderNonce ] = OBJ_id_cmc_senderNonce;
        NID_TO_OID[ NID_id_cmc_recipientNonce ] = OBJ_id_cmc_recipientNonce;
        NID_TO_OID[ NID_id_cmc_addExtensions ] = OBJ_id_cmc_addExtensions;
        NID_TO_OID[ NID_id_cmc_encryptedPOP ] = OBJ_id_cmc_encryptedPOP;
        NID_TO_OID[ NID_id_cmc_decryptedPOP ] = OBJ_id_cmc_decryptedPOP;
        NID_TO_OID[ NID_id_cmc_lraPOPWitness ] = OBJ_id_cmc_lraPOPWitness;
        NID_TO_OID[ NID_id_cmc_getCert ] = OBJ_id_cmc_getCert;
        NID_TO_OID[ NID_id_cmc_getCRL ] = OBJ_id_cmc_getCRL;
        NID_TO_OID[ NID_id_cmc_revokeRequest ] = OBJ_id_cmc_revokeRequest;
        NID_TO_OID[ NID_id_cmc_regInfo ] = OBJ_id_cmc_regInfo;
        NID_TO_OID[ NID_id_cmc_responseInfo ] = OBJ_id_cmc_responseInfo;
        NID_TO_OID[ NID_id_cmc_queryPending ] = OBJ_id_cmc_queryPending;
        NID_TO_OID[ NID_id_cmc_popLinkRandom ] = OBJ_id_cmc_popLinkRandom;
        NID_TO_OID[ NID_id_cmc_popLinkWitness ] = OBJ_id_cmc_popLinkWitness;
        NID_TO_OID[ NID_id_cmc_confirmCertAcceptance ] = OBJ_id_cmc_confirmCertAcceptance;
        NID_TO_OID[ NID_id_on_personalData ] = OBJ_id_on_personalData;
        NID_TO_OID[ NID_id_on_permanentIdentifier ] = OBJ_id_on_permanentIdentifier;
        NID_TO_OID[ NID_id_pda_dateOfBirth ] = OBJ_id_pda_dateOfBirth;
        NID_TO_OID[ NID_id_pda_placeOfBirth ] = OBJ_id_pda_placeOfBirth;
        NID_TO_OID[ NID_id_pda_gender ] = OBJ_id_pda_gender;
        NID_TO_OID[ NID_id_pda_countryOfCitizenship ] = OBJ_id_pda_countryOfCitizenship;
        NID_TO_OID[ NID_id_pda_countryOfResidence ] = OBJ_id_pda_countryOfResidence;
        NID_TO_OID[ NID_id_aca_authenticationInfo ] = OBJ_id_aca_authenticationInfo;
        NID_TO_OID[ NID_id_aca_accessIdentity ] = OBJ_id_aca_accessIdentity;
        NID_TO_OID[ NID_id_aca_chargingIdentity ] = OBJ_id_aca_chargingIdentity;
        NID_TO_OID[ NID_id_aca_group ] = OBJ_id_aca_group;
        NID_TO_OID[ NID_id_aca_role ] = OBJ_id_aca_role;
        NID_TO_OID[ NID_id_aca_encAttrs ] = OBJ_id_aca_encAttrs;
        NID_TO_OID[ NID_id_qcs_pkixQCSyntax_v1 ] = OBJ_id_qcs_pkixQCSyntax_v1;
        NID_TO_OID[ NID_id_cct_crs ] = OBJ_id_cct_crs;
        NID_TO_OID[ NID_id_cct_PKIData ] = OBJ_id_cct_PKIData;
        NID_TO_OID[ NID_id_cct_PKIResponse ] = OBJ_id_cct_PKIResponse;
        NID_TO_OID[ NID_id_ppl_anyLanguage ] = OBJ_id_ppl_anyLanguage;
        NID_TO_OID[ NID_id_ppl_inheritAll ] = OBJ_id_ppl_inheritAll;
        NID_TO_OID[ NID_Independent ] = OBJ_Independent;
        NID_TO_OID[ NID_ad_OCSP ] = OBJ_ad_OCSP;
        NID_TO_OID[ NID_ad_ca_issuers ] = OBJ_ad_ca_issuers;
        NID_TO_OID[ NID_ad_timeStamping ] = OBJ_ad_timeStamping;
        NID_TO_OID[ NID_ad_dvcs ] = OBJ_ad_dvcs;
        NID_TO_OID[ NID_caRepository ] = OBJ_caRepository;
        NID_TO_OID[ NID_id_pkix_OCSP_basic ] = OBJ_id_pkix_OCSP_basic;
        NID_TO_OID[ NID_id_pkix_OCSP_Nonce ] = OBJ_id_pkix_OCSP_Nonce;
        NID_TO_OID[ NID_id_pkix_OCSP_CrlID ] = OBJ_id_pkix_OCSP_CrlID;
        NID_TO_OID[ NID_id_pkix_OCSP_acceptableResponses ] = OBJ_id_pkix_OCSP_acceptableResponses;
        NID_TO_OID[ NID_id_pkix_OCSP_noCheck ] = OBJ_id_pkix_OCSP_noCheck;
        NID_TO_OID[ NID_id_pkix_OCSP_archiveCutoff ] = OBJ_id_pkix_OCSP_archiveCutoff;
        NID_TO_OID[ NID_id_pkix_OCSP_serviceLocator ] = OBJ_id_pkix_OCSP_serviceLocator;
        NID_TO_OID[ NID_id_pkix_OCSP_extendedStatus ] = OBJ_id_pkix_OCSP_extendedStatus;
        NID_TO_OID[ NID_id_pkix_OCSP_valid ] = OBJ_id_pkix_OCSP_valid;
        NID_TO_OID[ NID_id_pkix_OCSP_path ] = OBJ_id_pkix_OCSP_path;
        NID_TO_OID[ NID_id_pkix_OCSP_trustRoot ] = OBJ_id_pkix_OCSP_trustRoot;
        NID_TO_OID[ NID_algorithm ] = OBJ_algorithm;
        NID_TO_OID[ NID_md5WithRSA ] = OBJ_md5WithRSA;
        NID_TO_OID[ NID_des_ecb ] = OBJ_des_ecb;
        NID_TO_OID[ NID_des_cbc ] = OBJ_des_cbc;
        NID_TO_OID[ NID_des_ofb64 ] = OBJ_des_ofb64;
        NID_TO_OID[ NID_des_cfb64 ] = OBJ_des_cfb64;
        NID_TO_OID[ NID_rsaSignature ] = OBJ_rsaSignature;
        NID_TO_OID[ NID_dsa_2 ] = OBJ_dsa_2;
        NID_TO_OID[ NID_dsaWithSHA ] = OBJ_dsaWithSHA;
        NID_TO_OID[ NID_shaWithRSAEncryption ] = OBJ_shaWithRSAEncryption;
        NID_TO_OID[ NID_des_ede_ecb ] = OBJ_des_ede_ecb;
        NID_TO_OID[ NID_sha ] = OBJ_sha;
        NID_TO_OID[ NID_sha1 ] = OBJ_sha1;
        NID_TO_OID[ NID_dsaWithSHA1_2 ] = OBJ_dsaWithSHA1_2;
        NID_TO_OID[ NID_sha1WithRSA ] = OBJ_sha1WithRSA;
        NID_TO_OID[ NID_ripemd160 ] = OBJ_ripemd160;
        NID_TO_OID[ NID_ripemd160WithRSA ] = OBJ_ripemd160WithRSA;
        NID_TO_OID[ NID_sxnet ] = OBJ_sxnet;
        NID_TO_OID[ NID_X500 ] = OBJ_X500;
        NID_TO_OID[ NID_X509 ] = OBJ_X509;
        NID_TO_OID[ NID_commonName ] = OBJ_commonName;
        NID_TO_OID[ NID_surname ] = OBJ_surname;
        NID_TO_OID[ NID_serialNumber ] = OBJ_serialNumber;
        NID_TO_OID[ NID_countryName ] = OBJ_countryName;
        NID_TO_OID[ NID_localityName ] = OBJ_localityName;
        NID_TO_OID[ NID_stateOrProvinceName ] = OBJ_stateOrProvinceName;
        NID_TO_OID[ NID_streetAddress ] = OBJ_streetAddress;
        NID_TO_OID[ NID_organizationName ] = OBJ_organizationName;
        NID_TO_OID[ NID_organizationalUnitName ] = OBJ_organizationalUnitName;
        NID_TO_OID[ NID_title ] = OBJ_title;
        NID_TO_OID[ NID_description ] = OBJ_description;
        NID_TO_OID[ NID_searchGuide ] = OBJ_searchGuide;
        NID_TO_OID[ NID_businessCategory ] = OBJ_businessCategory;
        NID_TO_OID[ NID_postalAddress ] = OBJ_postalAddress;
        NID_TO_OID[ NID_postalCode ] = OBJ_postalCode;
        NID_TO_OID[ NID_postOfficeBox ] = OBJ_postOfficeBox;
        NID_TO_OID[ NID_physicalDeliveryOfficeName ] = OBJ_physicalDeliveryOfficeName;
        NID_TO_OID[ NID_telephoneNumber ] = OBJ_telephoneNumber;
        NID_TO_OID[ NID_telexNumber ] = OBJ_telexNumber;
        NID_TO_OID[ NID_teletexTerminalIdentifier ] = OBJ_teletexTerminalIdentifier;
        NID_TO_OID[ NID_facsimileTelephoneNumber ] = OBJ_facsimileTelephoneNumber;
        NID_TO_OID[ NID_x121Address ] = OBJ_x121Address;
        NID_TO_OID[ NID_internationaliSDNNumber ] = OBJ_internationaliSDNNumber;
        NID_TO_OID[ NID_registeredAddress ] = OBJ_registeredAddress;
        NID_TO_OID[ NID_destinationIndicator ] = OBJ_destinationIndicator;
        NID_TO_OID[ NID_preferredDeliveryMethod ] = OBJ_preferredDeliveryMethod;
        NID_TO_OID[ NID_presentationAddress ] = OBJ_presentationAddress;
        NID_TO_OID[ NID_supportedApplicationContext ] = OBJ_supportedApplicationContext;
        NID_TO_OID[ NID_member ] = OBJ_member;
        NID_TO_OID[ NID_owner ] = OBJ_owner;
        NID_TO_OID[ NID_roleOccupant ] = OBJ_roleOccupant;
        NID_TO_OID[ NID_seeAlso ] = OBJ_seeAlso;
        NID_TO_OID[ NID_userPassword ] = OBJ_userPassword;
        NID_TO_OID[ NID_userCertificate ] = OBJ_userCertificate;
        NID_TO_OID[ NID_cACertificate ] = OBJ_cACertificate;
        NID_TO_OID[ NID_authorityRevocationList ] = OBJ_authorityRevocationList;
        NID_TO_OID[ NID_certificateRevocationList ] = OBJ_certificateRevocationList;
        NID_TO_OID[ NID_crossCertificatePair ] = OBJ_crossCertificatePair;
        NID_TO_OID[ NID_name ] = OBJ_name;
        NID_TO_OID[ NID_givenName ] = OBJ_givenName;
        NID_TO_OID[ NID_initials ] = OBJ_initials;
        NID_TO_OID[ NID_generationQualifier ] = OBJ_generationQualifier;
        NID_TO_OID[ NID_x500UniqueIdentifier ] = OBJ_x500UniqueIdentifier;
        NID_TO_OID[ NID_dnQualifier ] = OBJ_dnQualifier;
        NID_TO_OID[ NID_enhancedSearchGuide ] = OBJ_enhancedSearchGuide;
        NID_TO_OID[ NID_protocolInformation ] = OBJ_protocolInformation;
        NID_TO_OID[ NID_distinguishedName ] = OBJ_distinguishedName;
        NID_TO_OID[ NID_uniqueMember ] = OBJ_uniqueMember;
        NID_TO_OID[ NID_houseIdentifier ] = OBJ_houseIdentifier;
        NID_TO_OID[ NID_supportedAlgorithms ] = OBJ_supportedAlgorithms;
        NID_TO_OID[ NID_deltaRevocationList ] = OBJ_deltaRevocationList;
        NID_TO_OID[ NID_dmdName ] = OBJ_dmdName;
        NID_TO_OID[ NID_pseudonym ] = OBJ_pseudonym;
        NID_TO_OID[ NID_role ] = OBJ_role;
        NID_TO_OID[ NID_X500algorithms ] = OBJ_X500algorithms;
        NID_TO_OID[ NID_rsa ] = OBJ_rsa;
        NID_TO_OID[ NID_mdc2WithRSA ] = OBJ_mdc2WithRSA;
        NID_TO_OID[ NID_mdc2 ] = OBJ_mdc2;
        NID_TO_OID[ NID_id_ce ] = OBJ_id_ce;
        NID_TO_OID[ NID_subject_directory_attributes ] = OBJ_subject_directory_attributes;
        NID_TO_OID[ NID_subject_key_identifier ] = OBJ_subject_key_identifier;
        NID_TO_OID[ NID_key_usage ] = OBJ_key_usage;
        NID_TO_OID[ NID_private_key_usage_period ] = OBJ_private_key_usage_period;
        NID_TO_OID[ NID_subject_alt_name ] = OBJ_subject_alt_name;
        NID_TO_OID[ NID_issuer_alt_name ] = OBJ_issuer_alt_name;
        NID_TO_OID[ NID_basic_constraints ] = OBJ_basic_constraints;
        NID_TO_OID[ NID_crl_number ] = OBJ_crl_number;
        NID_TO_OID[ NID_crl_reason ] = OBJ_crl_reason;
        NID_TO_OID[ NID_invalidity_date ] = OBJ_invalidity_date;
        NID_TO_OID[ NID_delta_crl ] = OBJ_delta_crl;
        NID_TO_OID[ NID_issuing_distribution_point ] = OBJ_issuing_distribution_point;
        NID_TO_OID[ NID_certificate_issuer ] = OBJ_certificate_issuer;
        NID_TO_OID[ NID_name_constraints ] = OBJ_name_constraints;
        NID_TO_OID[ NID_crl_distribution_points ] = OBJ_crl_distribution_points;
        NID_TO_OID[ NID_certificate_policies ] = OBJ_certificate_policies;
        NID_TO_OID[ NID_any_policy ] = OBJ_any_policy;
        NID_TO_OID[ NID_policy_mappings ] = OBJ_policy_mappings;
        NID_TO_OID[ NID_authority_key_identifier ] = OBJ_authority_key_identifier;
        NID_TO_OID[ NID_policy_constraints ] = OBJ_policy_constraints;
        NID_TO_OID[ NID_ext_key_usage ] = OBJ_ext_key_usage;
        NID_TO_OID[ NID_freshest_crl ] = OBJ_freshest_crl;
        NID_TO_OID[ NID_inhibit_any_policy ] = OBJ_inhibit_any_policy;
        NID_TO_OID[ NID_target_information ] = OBJ_target_information;
        NID_TO_OID[ NID_no_rev_avail ] = OBJ_no_rev_avail;
        NID_TO_OID[ NID_anyExtendedKeyUsage ] = OBJ_anyExtendedKeyUsage;
        NID_TO_OID[ NID_netscape ] = OBJ_netscape;
        NID_TO_OID[ NID_netscape_cert_extension ] = OBJ_netscape_cert_extension;
        NID_TO_OID[ NID_netscape_data_type ] = OBJ_netscape_data_type;
        NID_TO_OID[ NID_netscape_cert_type ] = OBJ_netscape_cert_type;
        NID_TO_OID[ NID_netscape_base_url ] = OBJ_netscape_base_url;
        NID_TO_OID[ NID_netscape_revocation_url ] = OBJ_netscape_revocation_url;
        NID_TO_OID[ NID_netscape_ca_revocation_url ] = OBJ_netscape_ca_revocation_url;
        NID_TO_OID[ NID_netscape_renewal_url ] = OBJ_netscape_renewal_url;
        NID_TO_OID[ NID_netscape_ca_policy_url ] = OBJ_netscape_ca_policy_url;
        NID_TO_OID[ NID_netscape_ssl_server_name ] = OBJ_netscape_ssl_server_name;
        NID_TO_OID[ NID_netscape_comment ] = OBJ_netscape_comment;
        NID_TO_OID[ NID_netscape_cert_sequence ] = OBJ_netscape_cert_sequence;
        NID_TO_OID[ NID_ns_sgc ] = OBJ_ns_sgc;
        NID_TO_OID[ NID_org ] = OBJ_org;
        NID_TO_OID[ NID_dod ] = OBJ_dod;
        NID_TO_OID[ NID_iana ] = OBJ_iana;
        NID_TO_OID[ NID_Directory ] = OBJ_Directory;
        NID_TO_OID[ NID_Management ] = OBJ_Management;
        NID_TO_OID[ NID_Experimental ] = OBJ_Experimental;
        NID_TO_OID[ NID_Private ] = OBJ_Private;
        NID_TO_OID[ NID_Security ] = OBJ_Security;
        NID_TO_OID[ NID_SNMPv2 ] = OBJ_SNMPv2;
        NID_TO_OID[ NID_Mail ] = OBJ_Mail;
        NID_TO_OID[ NID_Enterprises ] = OBJ_Enterprises;
        NID_TO_OID[ NID_dcObject ] = OBJ_dcObject;
        NID_TO_OID[ NID_mime_mhs ] = OBJ_mime_mhs;
        NID_TO_OID[ NID_mime_mhs_headings ] = OBJ_mime_mhs_headings;
        NID_TO_OID[ NID_mime_mhs_bodies ] = OBJ_mime_mhs_bodies;
        NID_TO_OID[ NID_id_hex_partial_message ] = OBJ_id_hex_partial_message;
        NID_TO_OID[ NID_id_hex_multipart_message ] = OBJ_id_hex_multipart_message;
        NID_TO_OID[ NID_rle_compression ] = OBJ_rle_compression;
        NID_TO_OID[ NID_zlib_compression ] = OBJ_zlib_compression;
        NID_TO_OID[ NID_aes_128_ecb ] = OBJ_aes_128_ecb;
        NID_TO_OID[ NID_aes_128_cbc ] = OBJ_aes_128_cbc;
        NID_TO_OID[ NID_aes_128_ofb128 ] = OBJ_aes_128_ofb128;
        NID_TO_OID[ NID_aes_128_cfb128 ] = OBJ_aes_128_cfb128;
        NID_TO_OID[ NID_id_aes128_wrap ] = OBJ_id_aes128_wrap;
        NID_TO_OID[ NID_aes_128_gcm ] = OBJ_aes_128_gcm;
        NID_TO_OID[ NID_aes_128_ccm ] = OBJ_aes_128_ccm;
        NID_TO_OID[ NID_id_aes128_wrap_pad ] = OBJ_id_aes128_wrap_pad;
        NID_TO_OID[ NID_aes_192_ecb ] = OBJ_aes_192_ecb;
        NID_TO_OID[ NID_aes_192_cbc ] = OBJ_aes_192_cbc;
        NID_TO_OID[ NID_aes_192_ofb128 ] = OBJ_aes_192_ofb128;
        NID_TO_OID[ NID_aes_192_cfb128 ] = OBJ_aes_192_cfb128;
        NID_TO_OID[ NID_id_aes192_wrap ] = OBJ_id_aes192_wrap;
        NID_TO_OID[ NID_aes_192_gcm ] = OBJ_aes_192_gcm;
        NID_TO_OID[ NID_aes_192_ccm ] = OBJ_aes_192_ccm;
        NID_TO_OID[ NID_id_aes192_wrap_pad ] = OBJ_id_aes192_wrap_pad;
        NID_TO_OID[ NID_aes_256_ecb ] = OBJ_aes_256_ecb;
        NID_TO_OID[ NID_aes_256_cbc ] = OBJ_aes_256_cbc;
        NID_TO_OID[ NID_aes_256_ofb128 ] = OBJ_aes_256_ofb128;
        NID_TO_OID[ NID_aes_256_cfb128 ] = OBJ_aes_256_cfb128;
        NID_TO_OID[ NID_id_aes256_wrap ] = OBJ_id_aes256_wrap;
        NID_TO_OID[ NID_aes_256_gcm ] = OBJ_aes_256_gcm;
        NID_TO_OID[ NID_aes_256_ccm ] = OBJ_aes_256_ccm;
        NID_TO_OID[ NID_id_aes256_wrap_pad ] = OBJ_id_aes256_wrap_pad;
        NID_TO_OID[ NID_sha256 ] = OBJ_sha256;
        NID_TO_OID[ NID_sha384 ] = OBJ_sha384;
        NID_TO_OID[ NID_sha512 ] = OBJ_sha512;
        NID_TO_OID[ NID_sha224 ] = OBJ_sha224;
        NID_TO_OID[ NID_dsa_with_SHA224 ] = OBJ_dsa_with_SHA224;
        NID_TO_OID[ NID_dsa_with_SHA256 ] = OBJ_dsa_with_SHA256;
        NID_TO_OID[ NID_hold_instruction_code ] = OBJ_hold_instruction_code;
        NID_TO_OID[ NID_hold_instruction_none ] = OBJ_hold_instruction_none;
        NID_TO_OID[ NID_hold_instruction_call_issuer ] = OBJ_hold_instruction_call_issuer;
        NID_TO_OID[ NID_hold_instruction_reject ] = OBJ_hold_instruction_reject;
        NID_TO_OID[ NID_data ] = OBJ_data;
        NID_TO_OID[ NID_pss ] = OBJ_pss;
        NID_TO_OID[ NID_ucl ] = OBJ_ucl;
        NID_TO_OID[ NID_pilot ] = OBJ_pilot;
        NID_TO_OID[ NID_pilotAttributeType ] = OBJ_pilotAttributeType;
        NID_TO_OID[ NID_pilotAttributeSyntax ] = OBJ_pilotAttributeSyntax;
        NID_TO_OID[ NID_pilotObjectClass ] = OBJ_pilotObjectClass;
        NID_TO_OID[ NID_pilotGroups ] = OBJ_pilotGroups;
        NID_TO_OID[ NID_iA5StringSyntax ] = OBJ_iA5StringSyntax;
        NID_TO_OID[ NID_caseIgnoreIA5StringSyntax ] = OBJ_caseIgnoreIA5StringSyntax;
        NID_TO_OID[ NID_pilotObject ] = OBJ_pilotObject;
        NID_TO_OID[ NID_pilotPerson ] = OBJ_pilotPerson;
        NID_TO_OID[ NID_account ] = OBJ_account;
        NID_TO_OID[ NID_document ] = OBJ_document;
        NID_TO_OID[ NID_room ] = OBJ_room;
        NID_TO_OID[ NID_documentSeries ] = OBJ_documentSeries;
        NID_TO_OID[ NID_Domain ] = OBJ_Domain;
        NID_TO_OID[ NID_rFC822localPart ] = OBJ_rFC822localPart;
        NID_TO_OID[ NID_dNSDomain ] = OBJ_dNSDomain;
        NID_TO_OID[ NID_domainRelatedObject ] = OBJ_domainRelatedObject;
        NID_TO_OID[ NID_friendlyCountry ] = OBJ_friendlyCountry;
        NID_TO_OID[ NID_simpleSecurityObject ] = OBJ_simpleSecurityObject;
        NID_TO_OID[ NID_pilotOrganization ] = OBJ_pilotOrganization;
        NID_TO_OID[ NID_pilotDSA ] = OBJ_pilotDSA;
        NID_TO_OID[ NID_qualityLabelledData ] = OBJ_qualityLabelledData;
        NID_TO_OID[ NID_userId ] = OBJ_userId;
        NID_TO_OID[ NID_textEncodedORAddress ] = OBJ_textEncodedORAddress;
        NID_TO_OID[ NID_rfc822Mailbox ] = OBJ_rfc822Mailbox;
        NID_TO_OID[ NID_info ] = OBJ_info;
        NID_TO_OID[ NID_favouriteDrink ] = OBJ_favouriteDrink;
        NID_TO_OID[ NID_roomNumber ] = OBJ_roomNumber;
        NID_TO_OID[ NID_photo ] = OBJ_photo;
        NID_TO_OID[ NID_userClass ] = OBJ_userClass;
        NID_TO_OID[ NID_host ] = OBJ_host;
        NID_TO_OID[ NID_manager ] = OBJ_manager;
        NID_TO_OID[ NID_documentIdentifier ] = OBJ_documentIdentifier;
        NID_TO_OID[ NID_documentTitle ] = OBJ_documentTitle;
        NID_TO_OID[ NID_documentVersion ] = OBJ_documentVersion;
        NID_TO_OID[ NID_documentAuthor ] = OBJ_documentAuthor;
        NID_TO_OID[ NID_documentLocation ] = OBJ_documentLocation;
        NID_TO_OID[ NID_homeTelephoneNumber ] = OBJ_homeTelephoneNumber;
        NID_TO_OID[ NID_secretary ] = OBJ_secretary;
        NID_TO_OID[ NID_otherMailbox ] = OBJ_otherMailbox;
        NID_TO_OID[ NID_lastModifiedTime ] = OBJ_lastModifiedTime;
        NID_TO_OID[ NID_lastModifiedBy ] = OBJ_lastModifiedBy;
        NID_TO_OID[ NID_domainComponent ] = OBJ_domainComponent;
        NID_TO_OID[ NID_aRecord ] = OBJ_aRecord;
        NID_TO_OID[ NID_pilotAttributeType27 ] = OBJ_pilotAttributeType27;
        NID_TO_OID[ NID_mXRecord ] = OBJ_mXRecord;
        NID_TO_OID[ NID_nSRecord ] = OBJ_nSRecord;
        NID_TO_OID[ NID_sOARecord ] = OBJ_sOARecord;
        NID_TO_OID[ NID_cNAMERecord ] = OBJ_cNAMERecord;
        NID_TO_OID[ NID_associatedDomain ] = OBJ_associatedDomain;
        NID_TO_OID[ NID_associatedName ] = OBJ_associatedName;
        NID_TO_OID[ NID_homePostalAddress ] = OBJ_homePostalAddress;
        NID_TO_OID[ NID_personalTitle ] = OBJ_personalTitle;
        NID_TO_OID[ NID_mobileTelephoneNumber ] = OBJ_mobileTelephoneNumber;
        NID_TO_OID[ NID_pagerTelephoneNumber ] = OBJ_pagerTelephoneNumber;
        NID_TO_OID[ NID_friendlyCountryName ] = OBJ_friendlyCountryName;
        NID_TO_OID[ NID_organizationalStatus ] = OBJ_organizationalStatus;
        NID_TO_OID[ NID_janetMailbox ] = OBJ_janetMailbox;
        NID_TO_OID[ NID_mailPreferenceOption ] = OBJ_mailPreferenceOption;
        NID_TO_OID[ NID_buildingName ] = OBJ_buildingName;
        NID_TO_OID[ NID_dSAQuality ] = OBJ_dSAQuality;
        NID_TO_OID[ NID_singleLevelQuality ] = OBJ_singleLevelQuality;
        NID_TO_OID[ NID_subtreeMinimumQuality ] = OBJ_subtreeMinimumQuality;
        NID_TO_OID[ NID_subtreeMaximumQuality ] = OBJ_subtreeMaximumQuality;
        NID_TO_OID[ NID_personalSignature ] = OBJ_personalSignature;
        NID_TO_OID[ NID_dITRedirect ] = OBJ_dITRedirect;
        NID_TO_OID[ NID_audio ] = OBJ_audio;
        NID_TO_OID[ NID_documentPublisher ] = OBJ_documentPublisher;
        NID_TO_OID[ NID_id_set ] = OBJ_id_set;
        NID_TO_OID[ NID_set_ctype ] = OBJ_set_ctype;
        NID_TO_OID[ NID_set_msgExt ] = OBJ_set_msgExt;
        NID_TO_OID[ NID_set_attr ] = OBJ_set_attr;
        NID_TO_OID[ NID_set_policy ] = OBJ_set_policy;
        NID_TO_OID[ NID_set_certExt ] = OBJ_set_certExt;
        NID_TO_OID[ NID_set_brand ] = OBJ_set_brand;
        NID_TO_OID[ NID_setct_PANData ] = OBJ_setct_PANData;
        NID_TO_OID[ NID_setct_PANToken ] = OBJ_setct_PANToken;
        NID_TO_OID[ NID_setct_PANOnly ] = OBJ_setct_PANOnly;
        NID_TO_OID[ NID_setct_OIData ] = OBJ_setct_OIData;
        NID_TO_OID[ NID_setct_PI ] = OBJ_setct_PI;
        NID_TO_OID[ NID_setct_PIData ] = OBJ_setct_PIData;
        NID_TO_OID[ NID_setct_PIDataUnsigned ] = OBJ_setct_PIDataUnsigned;
        NID_TO_OID[ NID_setct_HODInput ] = OBJ_setct_HODInput;
        NID_TO_OID[ NID_setct_AuthResBaggage ] = OBJ_setct_AuthResBaggage;
        NID_TO_OID[ NID_setct_AuthRevReqBaggage ] = OBJ_setct_AuthRevReqBaggage;
        NID_TO_OID[ NID_setct_AuthRevResBaggage ] = OBJ_setct_AuthRevResBaggage;
        NID_TO_OID[ NID_setct_CapTokenSeq ] = OBJ_setct_CapTokenSeq;
        NID_TO_OID[ NID_setct_PInitResData ] = OBJ_setct_PInitResData;
        NID_TO_OID[ NID_setct_PI_TBS ] = OBJ_setct_PI_TBS;
        NID_TO_OID[ NID_setct_PResData ] = OBJ_setct_PResData;
        NID_TO_OID[ NID_setct_AuthReqTBS ] = OBJ_setct_AuthReqTBS;
        NID_TO_OID[ NID_setct_AuthResTBS ] = OBJ_setct_AuthResTBS;
        NID_TO_OID[ NID_setct_AuthResTBSX ] = OBJ_setct_AuthResTBSX;
        NID_TO_OID[ NID_setct_AuthTokenTBS ] = OBJ_setct_AuthTokenTBS;
        NID_TO_OID[ NID_setct_CapTokenData ] = OBJ_setct_CapTokenData;
        NID_TO_OID[ NID_setct_CapTokenTBS ] = OBJ_setct_CapTokenTBS;
        NID_TO_OID[ NID_setct_AcqCardCodeMsg ] = OBJ_setct_AcqCardCodeMsg;
        NID_TO_OID[ NID_setct_AuthRevReqTBS ] = OBJ_setct_AuthRevReqTBS;
        NID_TO_OID[ NID_setct_AuthRevResData ] = OBJ_setct_AuthRevResData;
        NID_TO_OID[ NID_setct_AuthRevResTBS ] = OBJ_setct_AuthRevResTBS;
        NID_TO_OID[ NID_setct_CapReqTBS ] = OBJ_setct_CapReqTBS;
        NID_TO_OID[ NID_setct_CapReqTBSX ] = OBJ_setct_CapReqTBSX;
        NID_TO_OID[ NID_setct_CapResData ] = OBJ_setct_CapResData;
        NID_TO_OID[ NID_setct_CapRevReqTBS ] = OBJ_setct_CapRevReqTBS;
        NID_TO_OID[ NID_setct_CapRevReqTBSX ] = OBJ_setct_CapRevReqTBSX;
        NID_TO_OID[ NID_setct_CapRevResData ] = OBJ_setct_CapRevResData;
        NID_TO_OID[ NID_setct_CredReqTBS ] = OBJ_setct_CredReqTBS;
        NID_TO_OID[ NID_setct_CredReqTBSX ] = OBJ_setct_CredReqTBSX;
        NID_TO_OID[ NID_setct_CredResData ] = OBJ_setct_CredResData;
        NID_TO_OID[ NID_setct_CredRevReqTBS ] = OBJ_setct_CredRevReqTBS;
        NID_TO_OID[ NID_setct_CredRevReqTBSX ] = OBJ_setct_CredRevReqTBSX;
        NID_TO_OID[ NID_setct_CredRevResData ] = OBJ_setct_CredRevResData;
        NID_TO_OID[ NID_setct_PCertReqData ] = OBJ_setct_PCertReqData;
        NID_TO_OID[ NID_setct_PCertResTBS ] = OBJ_setct_PCertResTBS;
        NID_TO_OID[ NID_setct_BatchAdminReqData ] = OBJ_setct_BatchAdminReqData;
        NID_TO_OID[ NID_setct_BatchAdminResData ] = OBJ_setct_BatchAdminResData;
        NID_TO_OID[ NID_setct_CardCInitResTBS ] = OBJ_setct_CardCInitResTBS;
        NID_TO_OID[ NID_setct_MeAqCInitResTBS ] = OBJ_setct_MeAqCInitResTBS;
        NID_TO_OID[ NID_setct_RegFormResTBS ] = OBJ_setct_RegFormResTBS;
        NID_TO_OID[ NID_setct_CertReqData ] = OBJ_setct_CertReqData;
        NID_TO_OID[ NID_setct_CertReqTBS ] = OBJ_setct_CertReqTBS;
        NID_TO_OID[ NID_setct_CertResData ] = OBJ_setct_CertResData;
        NID_TO_OID[ NID_setct_CertInqReqTBS ] = OBJ_setct_CertInqReqTBS;
        NID_TO_OID[ NID_setct_ErrorTBS ] = OBJ_setct_ErrorTBS;
        NID_TO_OID[ NID_setct_PIDualSignedTBE ] = OBJ_setct_PIDualSignedTBE;
        NID_TO_OID[ NID_setct_PIUnsignedTBE ] = OBJ_setct_PIUnsignedTBE;
        NID_TO_OID[ NID_setct_AuthReqTBE ] = OBJ_setct_AuthReqTBE;
        NID_TO_OID[ NID_setct_AuthResTBE ] = OBJ_setct_AuthResTBE;
        NID_TO_OID[ NID_setct_AuthResTBEX ] = OBJ_setct_AuthResTBEX;
        NID_TO_OID[ NID_setct_AuthTokenTBE ] = OBJ_setct_AuthTokenTBE;
        NID_TO_OID[ NID_setct_CapTokenTBE ] = OBJ_setct_CapTokenTBE;
        NID_TO_OID[ NID_setct_CapTokenTBEX ] = OBJ_setct_CapTokenTBEX;
        NID_TO_OID[ NID_setct_AcqCardCodeMsgTBE ] = OBJ_setct_AcqCardCodeMsgTBE;
        NID_TO_OID[ NID_setct_AuthRevReqTBE ] = OBJ_setct_AuthRevReqTBE;
        NID_TO_OID[ NID_setct_AuthRevResTBE ] = OBJ_setct_AuthRevResTBE;
        NID_TO_OID[ NID_setct_AuthRevResTBEB ] = OBJ_setct_AuthRevResTBEB;
        NID_TO_OID[ NID_setct_CapReqTBE ] = OBJ_setct_CapReqTBE;
        NID_TO_OID[ NID_setct_CapReqTBEX ] = OBJ_setct_CapReqTBEX;
        NID_TO_OID[ NID_setct_CapResTBE ] = OBJ_setct_CapResTBE;
        NID_TO_OID[ NID_setct_CapRevReqTBE ] = OBJ_setct_CapRevReqTBE;
        NID_TO_OID[ NID_setct_CapRevReqTBEX ] = OBJ_setct_CapRevReqTBEX;
        NID_TO_OID[ NID_setct_CapRevResTBE ] = OBJ_setct_CapRevResTBE;
        NID_TO_OID[ NID_setct_CredReqTBE ] = OBJ_setct_CredReqTBE;
        NID_TO_OID[ NID_setct_CredReqTBEX ] = OBJ_setct_CredReqTBEX;
        NID_TO_OID[ NID_setct_CredResTBE ] = OBJ_setct_CredResTBE;
        NID_TO_OID[ NID_setct_CredRevReqTBE ] = OBJ_setct_CredRevReqTBE;
        NID_TO_OID[ NID_setct_CredRevReqTBEX ] = OBJ_setct_CredRevReqTBEX;
        NID_TO_OID[ NID_setct_CredRevResTBE ] = OBJ_setct_CredRevResTBE;
        NID_TO_OID[ NID_setct_BatchAdminReqTBE ] = OBJ_setct_BatchAdminReqTBE;
        NID_TO_OID[ NID_setct_BatchAdminResTBE ] = OBJ_setct_BatchAdminResTBE;
        NID_TO_OID[ NID_setct_RegFormReqTBE ] = OBJ_setct_RegFormReqTBE;
        NID_TO_OID[ NID_setct_CertReqTBE ] = OBJ_setct_CertReqTBE;
        NID_TO_OID[ NID_setct_CertReqTBEX ] = OBJ_setct_CertReqTBEX;
        NID_TO_OID[ NID_setct_CertResTBE ] = OBJ_setct_CertResTBE;
        NID_TO_OID[ NID_setct_CRLNotificationTBS ] = OBJ_setct_CRLNotificationTBS;
        NID_TO_OID[ NID_setct_CRLNotificationResTBS ] = OBJ_setct_CRLNotificationResTBS;
        NID_TO_OID[ NID_setct_BCIDistributionTBS ] = OBJ_setct_BCIDistributionTBS;
        NID_TO_OID[ NID_setext_genCrypt ] = OBJ_setext_genCrypt;
        NID_TO_OID[ NID_setext_miAuth ] = OBJ_setext_miAuth;
        NID_TO_OID[ NID_setext_pinSecure ] = OBJ_setext_pinSecure;
        NID_TO_OID[ NID_setext_pinAny ] = OBJ_setext_pinAny;
        NID_TO_OID[ NID_setext_track2 ] = OBJ_setext_track2;
        NID_TO_OID[ NID_setext_cv ] = OBJ_setext_cv;
        NID_TO_OID[ NID_set_policy_root ] = OBJ_set_policy_root;
        NID_TO_OID[ NID_setCext_hashedRoot ] = OBJ_setCext_hashedRoot;
        NID_TO_OID[ NID_setCext_certType ] = OBJ_setCext_certType;
        NID_TO_OID[ NID_setCext_merchData ] = OBJ_setCext_merchData;
        NID_TO_OID[ NID_setCext_cCertRequired ] = OBJ_setCext_cCertRequired;
        NID_TO_OID[ NID_setCext_tunneling ] = OBJ_setCext_tunneling;
        NID_TO_OID[ NID_setCext_setExt ] = OBJ_setCext_setExt;
        NID_TO_OID[ NID_setCext_setQualf ] = OBJ_setCext_setQualf;
        NID_TO_OID[ NID_setCext_PGWYcapabilities ] = OBJ_setCext_PGWYcapabilities;
        NID_TO_OID[ NID_setCext_TokenIdentifier ] = OBJ_setCext_TokenIdentifier;
        NID_TO_OID[ NID_setCext_Track2Data ] = OBJ_setCext_Track2Data;
        NID_TO_OID[ NID_setCext_TokenType ] = OBJ_setCext_TokenType;
        NID_TO_OID[ NID_setCext_IssuerCapabilities ] = OBJ_setCext_IssuerCapabilities;
        NID_TO_OID[ NID_setAttr_Cert ] = OBJ_setAttr_Cert;
        NID_TO_OID[ NID_setAttr_PGWYcap ] = OBJ_setAttr_PGWYcap;
        NID_TO_OID[ NID_setAttr_TokenType ] = OBJ_setAttr_TokenType;
        NID_TO_OID[ NID_setAttr_IssCap ] = OBJ_setAttr_IssCap;
        NID_TO_OID[ NID_set_rootKeyThumb ] = OBJ_set_rootKeyThumb;
        NID_TO_OID[ NID_set_addPolicy ] = OBJ_set_addPolicy;
        NID_TO_OID[ NID_setAttr_Token_EMV ] = OBJ_setAttr_Token_EMV;
        NID_TO_OID[ NID_setAttr_Token_B0Prime ] = OBJ_setAttr_Token_B0Prime;
        NID_TO_OID[ NID_setAttr_IssCap_CVM ] = OBJ_setAttr_IssCap_CVM;
        NID_TO_OID[ NID_setAttr_IssCap_T2 ] = OBJ_setAttr_IssCap_T2;
        NID_TO_OID[ NID_setAttr_IssCap_Sig ] = OBJ_setAttr_IssCap_Sig;
        NID_TO_OID[ NID_setAttr_GenCryptgrm ] = OBJ_setAttr_GenCryptgrm;
        NID_TO_OID[ NID_setAttr_T2Enc ] = OBJ_setAttr_T2Enc;
        NID_TO_OID[ NID_setAttr_T2cleartxt ] = OBJ_setAttr_T2cleartxt;
        NID_TO_OID[ NID_setAttr_TokICCsig ] = OBJ_setAttr_TokICCsig;
        NID_TO_OID[ NID_setAttr_SecDevSig ] = OBJ_setAttr_SecDevSig;
        NID_TO_OID[ NID_set_brand_IATA_ATA ] = OBJ_set_brand_IATA_ATA;
        NID_TO_OID[ NID_set_brand_Diners ] = OBJ_set_brand_Diners;
        NID_TO_OID[ NID_set_brand_AmericanExpress ] = OBJ_set_brand_AmericanExpress;
        NID_TO_OID[ NID_set_brand_JCB ] = OBJ_set_brand_JCB;
        NID_TO_OID[ NID_set_brand_Visa ] = OBJ_set_brand_Visa;
        NID_TO_OID[ NID_set_brand_MasterCard ] = OBJ_set_brand_MasterCard;
        NID_TO_OID[ NID_set_brand_Novus ] = OBJ_set_brand_Novus;
        NID_TO_OID[ NID_des_cdmf ] = OBJ_des_cdmf;
        NID_TO_OID[ NID_rsaOAEPEncryptionSET ] = OBJ_rsaOAEPEncryptionSET;
        NID_TO_OID[ NID_whirlpool ] = OBJ_whirlpool;
        NID_TO_OID[ NID_cryptopro ] = OBJ_cryptopro;
        NID_TO_OID[ NID_cryptocom ] = OBJ_cryptocom;
        NID_TO_OID[ NID_id_GostR3411_94_with_GostR3410_2001 ] = OBJ_id_GostR3411_94_with_GostR3410_2001;
        NID_TO_OID[ NID_id_GostR3411_94_with_GostR3410_94 ] = OBJ_id_GostR3411_94_with_GostR3410_94;
        NID_TO_OID[ NID_id_GostR3411_94 ] = OBJ_id_GostR3411_94;
        NID_TO_OID[ NID_id_HMACGostR3411_94 ] = OBJ_id_HMACGostR3411_94;
        NID_TO_OID[ NID_id_GostR3410_2001 ] = OBJ_id_GostR3410_2001;
        NID_TO_OID[ NID_id_GostR3410_94 ] = OBJ_id_GostR3410_94;
        NID_TO_OID[ NID_id_Gost28147_89 ] = OBJ_id_Gost28147_89;
        NID_TO_OID[ NID_id_Gost28147_89_MAC ] = OBJ_id_Gost28147_89_MAC;
        NID_TO_OID[ NID_id_GostR3411_94_prf ] = OBJ_id_GostR3411_94_prf;
        NID_TO_OID[ NID_id_GostR3410_2001DH ] = OBJ_id_GostR3410_2001DH;
        NID_TO_OID[ NID_id_GostR3410_94DH ] = OBJ_id_GostR3410_94DH;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_KeyMeshing ] = OBJ_id_Gost28147_89_CryptoPro_KeyMeshing;
        NID_TO_OID[ NID_id_Gost28147_89_None_KeyMeshing ] = OBJ_id_Gost28147_89_None_KeyMeshing;
        NID_TO_OID[ NID_id_GostR3411_94_TestParamSet ] = OBJ_id_GostR3411_94_TestParamSet;
        NID_TO_OID[ NID_id_GostR3411_94_CryptoProParamSet ] = OBJ_id_GostR3411_94_CryptoProParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_TestParamSet ] = OBJ_id_Gost28147_89_TestParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_A_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_A_ParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_B_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_B_ParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_C_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_C_ParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_D_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_D_ParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet;
        NID_TO_OID[ NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet ] = OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_TestParamSet ] = OBJ_id_GostR3410_94_TestParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_A_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_A_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_B_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_B_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_C_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_C_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_D_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_D_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_XchA_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_XchB_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_CryptoPro_XchC_ParamSet ] = OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_2001_TestParamSet ] = OBJ_id_GostR3410_2001_TestParamSet;
        NID_TO_OID[ NID_id_GostR3410_2001_CryptoPro_A_ParamSet ] = OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_2001_CryptoPro_B_ParamSet ] = OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_2001_CryptoPro_C_ParamSet ] = OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet ] = OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet ] = OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet;
        NID_TO_OID[ NID_id_GostR3410_94_a ] = OBJ_id_GostR3410_94_a;
        NID_TO_OID[ NID_id_GostR3410_94_aBis ] = OBJ_id_GostR3410_94_aBis;
        NID_TO_OID[ NID_id_GostR3410_94_b ] = OBJ_id_GostR3410_94_b;
        NID_TO_OID[ NID_id_GostR3410_94_bBis ] = OBJ_id_GostR3410_94_bBis;
        NID_TO_OID[ NID_id_Gost28147_89_cc ] = OBJ_id_Gost28147_89_cc;
        NID_TO_OID[ NID_id_GostR3410_94_cc ] = OBJ_id_GostR3410_94_cc;
        NID_TO_OID[ NID_id_GostR3410_2001_cc ] = OBJ_id_GostR3410_2001_cc;
        NID_TO_OID[ NID_id_GostR3411_94_with_GostR3410_94_cc ] = OBJ_id_GostR3411_94_with_GostR3410_94_cc;
        NID_TO_OID[ NID_id_GostR3411_94_with_GostR3410_2001_cc ] = OBJ_id_GostR3411_94_with_GostR3410_2001_cc;
        NID_TO_OID[ NID_id_GostR3410_2001_ParamSet_cc ] = OBJ_id_GostR3410_2001_ParamSet_cc;
        NID_TO_OID[ NID_camellia_128_cbc ] = OBJ_camellia_128_cbc;
        NID_TO_OID[ NID_camellia_192_cbc ] = OBJ_camellia_192_cbc;
        NID_TO_OID[ NID_camellia_256_cbc ] = OBJ_camellia_256_cbc;
        NID_TO_OID[ NID_id_camellia128_wrap ] = OBJ_id_camellia128_wrap;
        NID_TO_OID[ NID_id_camellia192_wrap ] = OBJ_id_camellia192_wrap;
        NID_TO_OID[ NID_id_camellia256_wrap ] = OBJ_id_camellia256_wrap;
        NID_TO_OID[ NID_camellia_128_ecb ] = OBJ_camellia_128_ecb;
        NID_TO_OID[ NID_camellia_128_ofb128 ] = OBJ_camellia_128_ofb128;
        NID_TO_OID[ NID_camellia_128_cfb128 ] = OBJ_camellia_128_cfb128;
        NID_TO_OID[ NID_camellia_192_ecb ] = OBJ_camellia_192_ecb;
        NID_TO_OID[ NID_camellia_192_ofb128 ] = OBJ_camellia_192_ofb128;
        NID_TO_OID[ NID_camellia_192_cfb128 ] = OBJ_camellia_192_cfb128;
        NID_TO_OID[ NID_camellia_256_ecb ] = OBJ_camellia_256_ecb;
        NID_TO_OID[ NID_camellia_256_ofb128 ] = OBJ_camellia_256_ofb128;
        NID_TO_OID[ NID_camellia_256_cfb128 ] = OBJ_camellia_256_cfb128;
        NID_TO_OID[ NID_kisa ] = OBJ_kisa;
        NID_TO_OID[ NID_seed_ecb ] = OBJ_seed_ecb;
        NID_TO_OID[ NID_seed_cbc ] = OBJ_seed_cbc;
        NID_TO_OID[ NID_seed_cfb128 ] = OBJ_seed_cfb128;
        NID_TO_OID[ NID_seed_ofb128 ] = OBJ_seed_ofb128;
        NID_TO_OID[ NID_dhpublicnumber ] = OBJ_dhpublicnumber;
        NID_TO_OID[ NID_brainpoolP160r1 ] = OBJ_brainpoolP160r1;
        NID_TO_OID[ NID_brainpoolP160t1 ] = OBJ_brainpoolP160t1;
        NID_TO_OID[ NID_brainpoolP192r1 ] = OBJ_brainpoolP192r1;
        NID_TO_OID[ NID_brainpoolP192t1 ] = OBJ_brainpoolP192t1;
        NID_TO_OID[ NID_brainpoolP224r1 ] = OBJ_brainpoolP224r1;
        NID_TO_OID[ NID_brainpoolP224t1 ] = OBJ_brainpoolP224t1;
        NID_TO_OID[ NID_brainpoolP256r1 ] = OBJ_brainpoolP256r1;
        NID_TO_OID[ NID_brainpoolP256t1 ] = OBJ_brainpoolP256t1;
        NID_TO_OID[ NID_brainpoolP320r1 ] = OBJ_brainpoolP320r1;
        NID_TO_OID[ NID_brainpoolP320t1 ] = OBJ_brainpoolP320t1;
        NID_TO_OID[ NID_brainpoolP384r1 ] = OBJ_brainpoolP384r1;
        NID_TO_OID[ NID_brainpoolP384t1 ] = OBJ_brainpoolP384t1;
        NID_TO_OID[ NID_brainpoolP512r1 ] = OBJ_brainpoolP512r1;
        NID_TO_OID[ NID_brainpoolP512t1 ] = OBJ_brainpoolP512t1;
        NID_TO_OID[ NID_dhSinglePass_stdDH_sha1kdf_scheme ] = OBJ_dhSinglePass_stdDH_sha1kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_stdDH_sha224kdf_scheme ] = OBJ_dhSinglePass_stdDH_sha224kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_stdDH_sha256kdf_scheme ] = OBJ_dhSinglePass_stdDH_sha256kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_stdDH_sha384kdf_scheme ] = OBJ_dhSinglePass_stdDH_sha384kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_stdDH_sha512kdf_scheme ] = OBJ_dhSinglePass_stdDH_sha512kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_cofactorDH_sha1kdf_scheme ] = OBJ_dhSinglePass_cofactorDH_sha1kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_cofactorDH_sha224kdf_scheme ] = OBJ_dhSinglePass_cofactorDH_sha224kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_cofactorDH_sha256kdf_scheme ] = OBJ_dhSinglePass_cofactorDH_sha256kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_cofactorDH_sha384kdf_scheme ] = OBJ_dhSinglePass_cofactorDH_sha384kdf_scheme;
        NID_TO_OID[ NID_dhSinglePass_cofactorDH_sha512kdf_scheme ] = OBJ_dhSinglePass_cofactorDH_sha512kdf_scheme;
        NID_TO_OID[ NID_ct_precert_scts ] = OBJ_ct_precert_scts;
        NID_TO_OID[ NID_ct_precert_poison ] = OBJ_ct_precert_poison;
        NID_TO_OID[ NID_ct_precert_signer ] = OBJ_ct_precert_signer;
        NID_TO_OID[ NID_ct_cert_scts ] = OBJ_ct_cert_scts;
        NID_TO_OID[ NID_jurisdictionLocalityName ] = OBJ_jurisdictionLocalityName;
        NID_TO_OID[ NID_jurisdictionStateOrProvinceName ] = OBJ_jurisdictionStateOrProvinceName;
        NID_TO_OID[ NID_jurisdictionCountryName ] = OBJ_jurisdictionCountryName;
    }

}
