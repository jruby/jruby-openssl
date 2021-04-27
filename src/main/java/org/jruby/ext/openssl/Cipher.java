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

import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.common.IRubyWarnings.ID;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;
import org.jruby.util.ByteList;
import org.jruby.util.TypeConverter;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.jruby.ext.openssl.OpenSSL.*;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Cipher extends RubyObject {
    private static final long serialVersionUID = -5390983669951165103L;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public Cipher allocate(Ruby runtime, RubyClass klass) { return new Cipher(runtime, klass); }
    };

    static void createCipher(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyClass Cipher = OpenSSL.defineClassUnder("Cipher", runtime.getObject(), ALLOCATOR);
        Cipher.defineClassUnder("CipherError", OpenSSLError, OpenSSLError.getAllocator());
        Cipher.defineAnnotatedMethods(Cipher.class);

        String cipherName;

        cipherName = "AES"; // OpenSSL::Cipher::AES
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "CAST5"; // OpenSSL::Cipher::CAST5
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "BF"; // OpenSSL::Cipher::BF
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "DES"; // OpenSSL::Cipher::DES
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "IDEA"; // OpenSSL::Cipher::IDEA
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "RC2"; // OpenSSL::Cipher::RC2
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "RC4"; // OpenSSL::Cipher::RC4
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        cipherName = "RC5"; // OpenSSL::Cipher::RC5
        Cipher.defineClassUnder(cipherName, Cipher, new NamedCipherAllocator(cipherName))
              .defineAnnotatedMethods(Named.class);

        String keyLength;

        keyLength = "128"; // OpenSSL::Cipher::AES128
        Cipher.defineClassUnder("AES" + keyLength, Cipher, new AESCipherAllocator(keyLength))
              .defineAnnotatedMethods(AES.class);
        keyLength = "192"; // OpenSSL::Cipher::AES192
        Cipher.defineClassUnder("AES" + keyLength, Cipher, new AESCipherAllocator(keyLength))
              .defineAnnotatedMethods(AES.class);
        keyLength = "256"; // OpenSSL::Cipher::AES256
        Cipher.defineClassUnder("AES" + keyLength, Cipher, new AESCipherAllocator(keyLength))
              .defineAnnotatedMethods(AES.class);
    }

    static RubyClass _Cipher(final Ruby runtime) {
        return (RubyClass) runtime.getModule("OpenSSL").getConstantAt("Cipher");
    }

    @JRubyMethod(meta = true)
    public static IRubyObject ciphers(final ThreadContext context, final IRubyObject self) {
        final Ruby runtime = context.runtime;

        final Collection<String> ciphers = Algorithm.AllSupportedCiphers.CIPHERS_MAP.keySet();
        final RubyArray result = runtime.newArray( ciphers.size() * 2 );
        for ( final String cipher : ciphers ) {
            result.append( runtime.newString(cipher) ); // upper-case
        }
        for ( final String cipher : ciphers ) { // than lower-case OpenSSL compatibility
            result.append( runtime.newString(cipher.toLowerCase()) );
        }
        return result;
    }

    public static boolean isSupportedCipher(final String name) {
        final String osslName = name.toUpperCase();
        //
        if ( Algorithm.AllSupportedCiphers.CIPHERS_MAP.get( osslName ) != null ) {
            return true;
        }
        //
        final Algorithm alg = Algorithm.osslToJava(osslName);
        if ( isDebug() ) debug("isSupportedCipher( "+ name +" ) try new cipher = " + alg.getRealName());
        try {
            return getCipherInstance(alg.getRealName(), true) != null;
        }
        catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static String[] cipherModes(final String alg) {
        final String[] modes = providerCipherModes(alg);
        return modes == null ? registeredCipherModes(alg) : modes;
    }

    private static String[] providerCipherModes(final String alg) {
        final Provider.Service service = providerCipherService(alg);
        if ( service != null ) {
            final String supportedModes = service.getAttribute("SupportedModes");
            if ( supportedModes == null ) return Algorithm.OPENSSL_BLOCK_MODES;
            return StringHelper.split(supportedModes, '|');
        }
        return null;
    }

    private static Provider.Service providerCipherService(final String alg) {
        Provider securityProvider = SecurityHelper.securityProvider;
        if ( securityProvider != null ) {
            return securityProvider.getService("Cipher", alg);
        }
        return null;
    }

    private static String[] registeredCipherModes(final String alg) { // e.g. "AES"
        /*
        if ( SecurityHelper.securityProvider != null && ! SecurityHelper.isProviderRegistered() ) {
            final Provider provider = SecurityHelper.securityProvider;
            for ( Provider.Service service : provider.getServices() ) {
                if ( "Cipher".equals( service.getType() ) ) {
                    services.add(service);
                }
            }
        } */
        boolean serviceFound = false;

        final Provider[] providers = java.security.Security.getProviders();
        for ( int i = 0; i < providers.length; i++ ) {
            final Provider provider = providers[i];
            final String name = provider.getName() == null ? "" : provider.getName();
            // skip those that are known to provide no Cipher engines :
            if ( name.contains("JGSS") ) continue; // SunJGSS
            if ( name.contains("SASL") ) continue; // SunSASL
            if ( name.contains("XMLD") ) continue; // XMLDSig
            if ( name.contains("PCSC") ) continue; // SunPCSC
            if ( name.contains("JSSE") ) continue; // SunJSSE

            final Provider.Service service = provider.getService("Cipher", alg);
            if ( service != null ) {
                serviceFound = true;
                final String supportedModes = service.getAttribute("SupportedModes");
                if ( supportedModes != null ) return StringHelper.split(supportedModes, '|');
            }
        }
        // if a service is found but has no SupportedModes configuration included
        // e.g. BC provider does not provide those - assume all modes that OpenSSL
        // supports (and are mappable to JSE) work with the cipher algorithm :
        return serviceFound ? Algorithm.OPENSSL_BLOCK_MODES : null;
    }

    public static final class Algorithm {

        final String base; // e.g. DES, AES
        final String version; // e.g. EDE3, 256
        final String mode; // CBC (default)
        private String padding; // PKCS5Padding (default)
        private String realName;
        private boolean realNameNeedsPadding;

        private int keyLength = -1, ivLength = -1;

        Algorithm(String cryptoBase, String cryptoVersion, String cryptoMode) {
            this.base = cryptoBase;
            this.version = cryptoVersion;
            this.mode = cryptoMode;
            //this.padding = padding;
        }

        private static final Set<String> KNOWN_BLOCK_MODES;
        // NOTE: CFB1 does not work as (OpenSSL) expects with BC (@see GH-35)
        private static final String[] OPENSSL_BLOCK_MODES = {
            "CBC", "CFB", /* "CFB1", */ "CFB8", "ECB", "OFB" // that Java supports
        };

        static {
            KNOWN_BLOCK_MODES = new HashSet<>(10, 1);
            for ( String mode : OPENSSL_BLOCK_MODES ) KNOWN_BLOCK_MODES.add(mode);
            KNOWN_BLOCK_MODES.add("CTR");
            KNOWN_BLOCK_MODES.add("CTS"); // not supported by OpenSSL
            KNOWN_BLOCK_MODES.add("PCBC"); // not supported by OpenSSL
            KNOWN_BLOCK_MODES.add("NONE"); // valid to pass into JCE
        }

        // Subset of KNOWN_BLOCK_MODES that do not require padding (and shouldn't have it by default).
        private static final Set<String> NO_PADDING_BLOCK_MODES;
        static {
            NO_PADDING_BLOCK_MODES = new HashSet<>(6, 1);
            NO_PADDING_BLOCK_MODES.add("CFB");
            NO_PADDING_BLOCK_MODES.add("CFB8");
            NO_PADDING_BLOCK_MODES.add("OFB");
            NO_PADDING_BLOCK_MODES.add("CTR");
            NO_PADDING_BLOCK_MODES.add("GCM");
        }

        final static class AllSupportedCiphers {

            // Ruby to Java name String
            static final HashMap<String, String[]> CIPHERS_MAP = new LinkedHashMap<String, String[]>(120, 1);
            static {
                // cleanup all FALSE keys :
                //for ( String key: supportedCiphers.keySet() ) {
                //if ( supportedCiphers.get(key) == Boolean.FALSE ) supportedCiphers.remove(key);
                //}

                // OpenSSL: all the block ciphers normally use PKCS#5 padding
                String[] modes;
                modes = cipherModes("AES"); // null if not supported
                if (modes != null) {
                    for (final String mode : modes) {
                        final String realName = "AES/" + mode; // + "/PKCS5Padding"
                        CIPHERS_MAP.put("AES-128-" + mode, new String[]{"AES", mode, "128", realName});
                        CIPHERS_MAP.put("AES-192-" + mode, new String[]{"AES", mode, "192", realName});
                        CIPHERS_MAP.put("AES-256-" + mode, new String[]{"AES", mode, "256", realName});
                    }
                    final String realName = "AES/CBC";
                    CIPHERS_MAP.put("AES128", new String[]{"AES", "CBC", "128", realName});
                    CIPHERS_MAP.put("AES192", new String[]{"AES", "CBC", "192", realName});
                    CIPHERS_MAP.put("AES256", new String[]{"AES", "CBC", "256", realName});
                }

                modes = cipherModes("Blowfish");
                if (modes != null) {
                    CIPHERS_MAP.put("BF", new String[]{"BF", "CBC", null, "Blowfish/CBC"});
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("BF-" + mode, new String[]{"BF", mode, null, "Blowfish/" + mode});
                    }
                }

                modes = cipherModes("Camellia");
                if (modes != null) {
                    for (final String mode : modes) {
                        final String realName = "Camellia/" + mode;
                        CIPHERS_MAP.put("CAMELLIA-128-" + mode, new String[]{"CAMELLIA", mode, "128", realName});
                        CIPHERS_MAP.put("CAMELLIA-192-" + mode, new String[]{"CAMELLIA", mode, "192", realName});
                        CIPHERS_MAP.put("CAMELLIA-256-" + mode, new String[]{"CAMELLIA", mode, "256", realName});
                    }
                    final String realName = "Camellia/CBC";
                    CIPHERS_MAP.put("CAMELLIA128", new String[]{"CAMELLIA", "CBC", "128", realName});
                    CIPHERS_MAP.put("CAMELLIA192", new String[]{"CAMELLIA", "CBC", "192", realName});
                    CIPHERS_MAP.put("CAMELLIA256", new String[]{"CAMELLIA", "CBC", "256", realName});
                }

                modes = cipherModes("CAST5");
                if (modes != null) {
                    CIPHERS_MAP.put("CAST", new String[]{"CAST", "CBC", null, "CAST5/CBC"});
                    CIPHERS_MAP.put("CAST-CBC", CIPHERS_MAP.get("CAST"));
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("CAST5-" + mode, new String[]{"CAST", mode, null, "CAST5/" + mode});
                    }
                }

                modes = cipherModes("CAST6");
                if (modes != null) {
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("CAST6-" + mode, new String[]{"CAST6", mode, null, "CAST6/" + mode});
                    }
                }

                modes = cipherModes("DES");
                if (modes != null) {
                    CIPHERS_MAP.put("DES", new String[]{"DES", "CBC", null, "DES/CBC"});
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("DES-" + mode, new String[]{"DES", mode, null, "DES/" + mode});
                    }
                }

                modes = cipherModes("DESede");
                if (modes != null) {
                    CIPHERS_MAP.put("DES-EDE", new String[]{"DES", "ECB", "EDE", "DESede/ECB"});
                    CIPHERS_MAP.put("DES-EDE-CBC", new String[]{"DES", "CBC", "EDE", "DESede/CBC"});
                    CIPHERS_MAP.put("DES-EDE-CFB", new String[]{"DES", "CBC", "EDE", "DESede/CFB"});
                    CIPHERS_MAP.put("DES-EDE-OFB", new String[]{"DES", "CBC", "EDE", "DESede/OFB"});
                    CIPHERS_MAP.put("DES-EDE3", new String[]{"DES", "ECB", "EDE3", "DESede/ECB"});
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("DES-EDE3-" + mode, new String[]{"DES", mode, "EDE3", "DESede/" + mode});
                    }
                    CIPHERS_MAP.put("DES3", new String[]{"DES", "CBC", "EDE3", "DESede/CBC"});
                }

                modes = cipherModes("RC2");
                if (modes != null) {
                    CIPHERS_MAP.put("RC2", new String[]{"RC2", "CBC", null, "RC2/CBC"});
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("RC2-" + mode, new String[]{"RC2", mode, null, "RC2/" + mode});
                    }
                    CIPHERS_MAP.put("RC2-40-CBC", new String[]{"RC2", "CBC", "40", "RC2/CBC"});
                    CIPHERS_MAP.put("RC2-64-CBC", new String[]{"RC2", "CBC", "64", "RC2/CBC"});
                }

                modes = cipherModes("RC4"); // NOTE: stream cipher (BC supported)
                if (modes != null) {
                    CIPHERS_MAP.put("RC4", new String[]{"RC4", null, null, "RC4"});
                    CIPHERS_MAP.put("RC4-40", new String[]{"RC4", null, "40", "RC4"});
                    //supportedCiphers.put( "RC2-HMAC-MD5", new String[] { "RC4", null, null, "RC4" });
                }

                modes = cipherModes("SEED");
                if (modes != null) {
                    CIPHERS_MAP.put("SEED", new String[]{"SEED", "CBC", null, "SEED/CBC"});
                    for (final String mode : modes) {
                        CIPHERS_MAP.put("SEED-" + mode, new String[]{"SEED", mode, null, "SEED/" + mode});
                    }
                }
            }
        }

        @Deprecated
        public static String jsseToOssl(final String cipherName, final int keyLength) {
            return javaToOssl(cipherName, keyLength);
        }

        public static String javaToOssl(final String cipherName, final int keyLength) {
            String cryptoBase;
            String cryptoVersion = null;
            String cryptoMode = null;
            final List parts = StringHelper.split((CharSequence) cipherName, '/');
            final int partsLength = parts.size();
            if ( partsLength != 1 && partsLength != 3 ) return null;
            if ( partsLength > 2 ) {
                cryptoMode = (String) parts.get(1); // padding: parts[2] not used
            }
            cryptoBase = (String) parts.get(0);
            if ( ! KNOWN_BLOCK_MODES.contains(cryptoMode) ) {
                cryptoVersion = cryptoMode;
                cryptoMode = "CBC";
            }
            if (cryptoMode == null) {
                cryptoMode = "CBC";
            }
            if ( "DESede".equals(cryptoBase) ) {
                cryptoBase = "DES"; cryptoVersion = "EDE3";
            }
            else if ( "Blowfish".equals(cryptoBase) ) {
                cryptoBase = "BF";
            }
            if (cryptoVersion == null) {
                cryptoVersion = String.valueOf(keyLength);
            }
            return cryptoBase + '-' + cryptoVersion + '-' + cryptoMode;
        }

        static Algorithm osslToJava(final String osslName) {
            return osslToJava(osslName, null); // assume PKCS5Padding
        }

        private static Algorithm osslToJava(final String osslName, final String padding) {

            final String[] algVals = AllSupportedCiphers.CIPHERS_MAP.get(osslName);
            if ( algVals != null ) {
                final String cryptoMode = algVals[1];
                Algorithm alg = new Algorithm(algVals[0], algVals[2], cryptoMode);
                alg.realName = algVals[3];
                alg.realNameNeedsPadding = true;
                alg.padding = getPaddingType(padding, cryptoMode);
                return alg;
            }

            String cryptoBase, cryptoVersion = null, cryptoMode, realName;
            String paddingType = null;

            // EXPERIMENTAL: if there's '/' assume it's a "real" JCE name :
            if ( osslName.indexOf('/') != -1 ) {
                // e.g. "DESedeWrap/CBC/NOPADDING"
                final List names = StringHelper.split((CharSequence) osslName, '/');
                cryptoBase = (String) names.get(0);
                cryptoMode = names.size() > 1 ? (String) names.get(1) : "CBC";
                paddingType = getPaddingType(padding, cryptoMode);
                if ( names.size() > 2 ) paddingType = (String) names.get(2);
                Algorithm alg = new Algorithm(cryptoBase, null, cryptoMode);
                alg.realName = osslName;
                alg.padding = paddingType;
                return alg;
            }

            int s = osslName.indexOf('-'); int i = 0;
            if (s == -1) {
                cryptoBase = osslName; cryptoMode = null;
            }
            else {
                cryptoBase = osslName.substring(i, s);

                s = osslName.indexOf('-', i = s + 1);
                if (s == -1) cryptoMode = osslName.substring(i); // "base-mode"
                else { // two separators :  "base-version-mode"
                    cryptoVersion = osslName.substring(i, s);
                    s = osslName.indexOf('-', i = s + 1);
                    if (s == -1) {
                        cryptoMode = osslName.substring(i);
                    }
                    else {
                        cryptoMode = osslName.substring(i, s);
                    }
                }
            }

            cryptoBase = cryptoBase.toUpperCase(); // allways upper e.g. "AES"
            if ( cryptoMode != null ) cryptoMode = cryptoMode.toUpperCase();

            boolean realNameSet = false; boolean setDefaultCryptoMode = true;

            if ( "BF".equals(cryptoBase) ) realName = "Blowfish";
            else if ( "CAST".equals(cryptoBase) ) realName = "CAST5";
            else if ( cryptoBase.startsWith("DES") ) {
                if ( "DES3".equals(cryptoBase) ) {
                    cryptoBase = "DES"; realName = "DESede"; cryptoVersion = "EDE3"; // cryptoMode = "CBC";
                }
                else if ( "EDE3".equalsIgnoreCase(cryptoVersion) || "EDE".equalsIgnoreCase(cryptoVersion) ) {
                    realName = "DESede"; if ( cryptoMode == null ) cryptoMode = "ECB";
                }
                else if ( "EDE3".equalsIgnoreCase(cryptoMode) || "EDE".equalsIgnoreCase(cryptoMode) ) {
                    realName = "DESede"; cryptoVersion = cryptoMode; cryptoMode = "ECB";
                }
                else realName = "DES";
            }
            else if ( cryptoBase.length() > 3 && cryptoBase.startsWith("AES") ) {
                try { // try parsing e.g. "AES256"
                    final String version = cryptoBase.substring(3);
                    Integer.parseInt( version );
                    realName = cryptoBase = "AES"; cryptoVersion = version;
                }
                catch (NumberFormatException e) { realName = cryptoBase;  }
            }
            else if ( cryptoBase.length() > 8 && cryptoBase.startsWith("CAMELLIA") ) {
                try { // try parsing e.g. "CAMELLIA192"
                    final String version = cryptoBase.substring(8);
                    Integer.parseInt( version );
                    realName = cryptoBase = "CAMELLIA"; cryptoVersion = version;
                }
                catch (NumberFormatException e) { realName = cryptoBase;  }
            }
            else {
                realName = cryptoBase;

                // streaming ciphers - no padding/mode to be used ...
                // e.g. only SecurityHelper.getCipherInstance("RC4") will work
                if ( "RC4".equals(cryptoBase) ) {
                    if ( ! KNOWN_BLOCK_MODES.contains(cryptoMode) ) {
                        cryptoVersion = cryptoMode;
                    }
                    cryptoMode = null; // padding = null;
                    setDefaultCryptoMode = false;
                    // cryptoMode = "NONE"; paddingType = "NoPadding";
                    realNameSet = true;
                }
            }

            if ( cryptoMode == null && setDefaultCryptoMode ) cryptoMode = "CBC";
            if ( paddingType == null ) paddingType = getPaddingType(padding, cryptoMode);

            if ( cryptoMode != null ) {
                //if ( ! KNOWN_BLOCK_MODES.contains(cryptoMode) ) {
                //    if ( ! "XTS".equals(cryptoMode) ) {
                //        // valid but likely not supported by JCE/provider
                //        //cryptoVersion = cryptoMode; cryptoMode = "CBC";
                //    }
                //}

                if ( ! realNameSet ) {
                    realName = realName + '/' + cryptoMode + '/' + paddingType;
                }
            }
            else if ( ! realNameSet ) {
                if ( padding != null ) {
                    realName = realName + '/' + "NONE" + '/' + paddingType;
                }
                //else paddingType = null; // else realName is cryptoBase
            }

            Algorithm alg = new Algorithm(cryptoBase, cryptoVersion, cryptoMode);
            alg.realName = realName;
            alg.padding = paddingType;
            return alg;
        }

        String getPadding() {
            if ( mode == null ) return null; // if ( "RC4".equals(base) ) return null;
            return padding;
        }

        private static String getPaddingType(final String padding, final String cryptoMode) {
            final String defaultPadding = "PKCS5Padding";

            if ( padding == null ) {
                if ( NO_PADDING_BLOCK_MODES.contains(cryptoMode) ) {
                    return "NoPadding";
                }
                return defaultPadding;
            }
            if ( padding.equalsIgnoreCase("PKCS5Padding") ) {
                return "PKCS5Padding";
            }
            if ( padding.equals("0") || padding.equalsIgnoreCase("NoPadding") ) {
                return "NoPadding";
            }
            if ( padding.equalsIgnoreCase("ISO10126Padding") ) {
                return "ISO10126Padding";
            }
            if ( padding.equalsIgnoreCase("PKCS1Padding") ) {
                return "PKCS1Padding";
            }
            if ( padding.equalsIgnoreCase("SSL3Padding") ) {
                return "SSL3Padding";
            }
            if (padding.equalsIgnoreCase("OAEPPadding")) {
                return "OAEPPadding";
            }
            return defaultPadding; // "PKCS5Padding"; // default
        }

        String getRealName() {
            if ( realName != null ) {
                if ( realNameNeedsPadding ) {
                    final String padding = getPadding();
                    if ( padding != null ) {
                        realName = realName + '/' + padding;
                    }
                    realNameNeedsPadding = false;
                }
                return realName;
            }
            return realName = base + '/' + (mode == null ? "NONE" : mode) + '/' + padding;
        }

        public static String getAlgorithmBase(javax.crypto.Cipher cipher) {
            final String algorithm = cipher.getAlgorithm();
            final int idx = algorithm.indexOf('/');
            if ( idx != -1 ) return algorithm.substring(0, idx);
            return algorithm;
        }

        public static String getRealName(final String osslName) {
            return osslToJava(osslName).getRealName();
        }

        public int getIvLength() {
            if ( ivLength != -1 ) return ivLength;

            getKeyLength();

            if ( ivLength == -1 ) {
                if ( "AES".equals(base) ) {
                    ivLength = 16; // OpenSSL defaults to 12
                    // NOTE: we can NOT handle 12 for non GCM mode
                    if ( "GCM".equals(mode) || "CCM".equals(mode) ) ivLength = 12;
                }
                //else if ( "DES".equals(base) ) {
                //    ivLength = 8;
                //}
                //else if ( "RC4".equals(base) ) {
                //    ivLength = 8;
                //}
                else if ( "ECB".equals(mode) ) {
                    ivLength = 0;
                }
                else {
                    ivLength = 8;
                }
            }
            return ivLength;
        }

        public int getKeyLength() {
            if ( keyLength != -1 ) return keyLength;

            int keyLen = -1;
            if ( version != null ) {
                try {
                    keyLen = Integer.parseInt(version) / 8;
                }
                catch (NumberFormatException e) {
                    keyLen = -1;
                }
            }
            if ( keyLen == -1 ) {
                if ( "DES".equals(base) ) {
                    if ( "EDE".equalsIgnoreCase(version) ) keyLen = 16;
                    else if ( "EDE3".equalsIgnoreCase(version) ) keyLen = 24;
                    else keyLen = 8;
                }
                else if ( "RC4".equals(base) ) {
                    keyLen = 16;
                }
                else {
                    keyLen = 16;
                    try {
                        final String name = getRealName();
                        int maxLen = javax.crypto.Cipher.getMaxAllowedKeyLength(name) / 8;
                        if (maxLen < keyLen) keyLen = maxLen;
                    }
                    catch (NoSuchAlgorithmException e) { }
                }
            }

            return keyLength = keyLen;
        }

        @Deprecated
        public static int[] osslKeyIvLength(final String cipherName) {
            final Algorithm alg = Algorithm.osslToJava(cipherName);
            return new int[] { alg.getKeyLength(), alg.getIvLength() };
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + '@' + Integer.toHexString(hashCode()) +
            "<base="+ base + " mode="+ mode +" version="+ version +" padding="+ padding +
            " realName="+ realName +" realNameNeedsPadding="+ realNameNeedsPadding +">";
        }

    }

    private static javax.crypto.Cipher getCipherInstance(final String transformation, boolean silent)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        try {
            return SecurityHelper.getCipher(transformation); // tries BC if it's available
        }
        catch (NoSuchAlgorithmException e) {
            if ( silent ) return null;
            throw e;
        }
        catch (NoSuchPaddingException e) {
            if ( silent ) return null;
            throw e;
        }
    }

    public Cipher(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    private javax.crypto.Cipher cipher; // the "real" (Java) Cipher object
    private String name;
    private String cryptoBase;
    private String cryptoVersion;
    private String cryptoMode;
    private String paddingType;
    private String realName; // Cipher's "real" (Java) name - used to instantiate
    private int keyLength = -1;
    private int generateKeyLength = -1;
    private int ivLength = -1;
    private boolean encryptMode = true;
    //private IRubyObject[] modeParams;
    private boolean cipherInited = false;
    private byte[] key;
    private byte[] realIV;
    private byte[] orgIV;
    private String padding;

    private void dumpVars(final PrintStream out, final String header) {
        out.println(this.toString() + ' ' + header +
                    "\n" +
                    " name = " + name +
                    " cryptoBase = " + cryptoBase +
                    " cryptoVersion = " + cryptoVersion +
                    " cryptoMode = " + cryptoMode +
                    " padding_type = " + paddingType +
                    " realName = " + realName +
                    " keyLength = " + keyLength +
                    " ivLength = " + ivLength +
                    "\n" +
                    " cipher.alg = " + (cipher == null ? null : cipher.getAlgorithm()) +
                    " cipher.blockSize = " + (cipher == null ? null : cipher.getBlockSize()) +
                    " encryptMode = " + encryptMode + " cipherInited = " + cipherInited +
                    " key.length = " + (key == null ? 0 : key.length) +
                    " iv.length = " + (realIV == null ? 0 : realIV.length) +
                    " padding = " + padding);
    }

    @JRubyMethod(required = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject name) {
        initializeImpl(context.runtime, name.toString());
        return this;
    }

    final void initializeImpl(final Ruby runtime, final String name) {
        //if ( ! isSupportedCipher(name) ) {
        //    throw newCipherError(runtime, "unsupported cipher algorithm ("+ name +")");
        //}
        if ( cipher != null ) {
            throw runtime.newRuntimeError("Cipher already inititalized!");
        }
        updateCipher(name, padding);
    }


    @Override
    @JRubyMethod(required = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();

        final Cipher other = (Cipher) obj;
        cryptoBase = other.cryptoBase;
        cryptoVersion = other.cryptoVersion;
        cryptoMode = other.cryptoMode;
        paddingType = other.paddingType;
        realName = other.realName;
        name = other.name;
        keyLength = other.keyLength;
        ivLength = other.ivLength;
        encryptMode = other.encryptMode;
        cipherInited = false;
        if ( other.key != null ) {
            key = Arrays.copyOf(other.key, other.key.length);
        } else {
            key = null;
        }
        if (other.realIV != null) {
            realIV = Arrays.copyOf(other.realIV, other.realIV.length);
        } else {
            realIV = null;
        }
        this.orgIV = this.realIV;
        padding = other.padding;

        cipher = getCipherInstance();

        return this;
    }

    @JRubyMethod
    public final RubyString name() {
        return getRuntime().newString(name);
    }

    @JRubyMethod
    public final RubyInteger key_len() {
        return getRuntime().newFixnum(keyLength);
    }

    @JRubyMethod
    public final RubyInteger iv_len() {
        return getRuntime().newFixnum(ivLength);
    }

    @JRubyMethod(name = "iv_len=", required = 1)
    public final IRubyObject set_iv_len(IRubyObject len) {
      this.ivLength = RubyNumeric.fix2int(len);
      return len;
    }

    @JRubyMethod(name = "key_len=", required = 1)
    public final IRubyObject set_key_len(IRubyObject len) {
        this.keyLength = RubyNumeric.fix2int(len);
        return len;
    }

    @JRubyMethod(name = "key=", required = 1)
    public IRubyObject set_key(final ThreadContext context, final IRubyObject key) {
        final ByteList keyBytes;
        try {
            keyBytes = key.asString().getByteList();
        }
        catch (Exception e) {
            final Ruby runtime = context.runtime;
            debugStackTrace(runtime, e);
            throw newCipherError(runtime, e);
        }
        if ( keyBytes.getRealSize() < keyLength ) {
            throw newCipherError(context.runtime, "key length too short");
        }

        final byte[] k = new byte[keyLength];
        System.arraycopy(keyBytes.unsafeBytes(), keyBytes.getBegin(), k, 0, keyLength);
        this.key = k;

        return key;
    }

    @JRubyMethod(name = "iv=", required = 1)
    public IRubyObject set_iv(final ThreadContext context, final IRubyObject iv) {
        final ByteList ivBytes;
        try {
            ivBytes = iv.asString().getByteList();
        }
        catch (Exception e) {
            final Ruby runtime = context.runtime;
            debugStackTrace(runtime, e);
            throw newCipherError(runtime, e);
        }
        if ( ivBytes.getRealSize() < ivLength ) {
            throw newCipherError(context.runtime, "iv length too short");
        }
        // EVP_CipherInit_ex uses leading IV length of given sequence.
        final byte[] i = new byte[ivLength];
        System.arraycopy(ivBytes.unsafeBytes(), ivBytes.getBegin(), i, 0, ivLength);
        this.realIV = i;
        this.orgIV = this.realIV;

        if ( ! isStreamCipher() ) cipherInited = false;

        return iv;
    }

    @JRubyMethod
    public IRubyObject block_size(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        checkCipherNotNull(runtime);
        if ( isStreamCipher() ) {
            // getBlockSize() returns 0 for stream cipher in JCE
            // OpenSSL returns 1 for RC4.
            return runtime.newFixnum(1);
        }
        return runtime.newFixnum(cipher.getBlockSize());
    }

    private void init(final ThreadContext context, final IRubyObject[] args, final boolean encrypt) {
        final Ruby runtime = context.runtime;
        Arity.checkArgumentCount(runtime, args, 0, 2);

        encryptMode = encrypt;
        cipherInited = false;

        if ( args.length > 0 ) {
            /*
             * oops. this code mistakes salt for IV.
             * We deprecated the arguments for this method, but we decided
             * keeping this behaviour for backward compatibility.
             */
            byte[] pass = args[0].asString().getBytes();
            byte[] iv = null;
            try {
                iv = "OpenSSL for Ruby rulez!".getBytes("ISO8859-1");
                byte[] iv2 = new byte[this.ivLength];
                System.arraycopy(iv, 0, iv2, 0, this.ivLength);
                iv = iv2;
            } catch (Exception e) {
            }

            if ( args.length > 1 && ! args[1].isNil() ) {
                runtime.getWarnings().warning(ID.MISCELLANEOUS, "key derivation by " + getMetaClass().getRealClass().getName() + "#encrypt is deprecated; use " + getMetaClass().getRealClass().getName() + "::pkcs5_keyivgen instead");
                iv = args[1].asString().getBytes();
                if (iv.length > this.ivLength) {
                    byte[] iv2 = new byte[this.ivLength];
                    System.arraycopy(iv, 0, iv2, 0, this.ivLength);
                    iv = iv2;
                }
            }

            final MessageDigest digest = Digest.getDigest(runtime, "MD5");
            KeyAndIv result = evpBytesToKey(keyLength, ivLength, digest, iv, pass, 2048);
            this.key = result.key;
            this.realIV = iv;
            this.orgIV = this.realIV;
        }
    }

    @JRubyMethod(optional = 2)
    public IRubyObject encrypt(final ThreadContext context, IRubyObject[] args) {
        this.realIV = orgIV;
        init(context, args, true);
        return this;
    }

    @JRubyMethod(optional = 2)
    public IRubyObject decrypt(final ThreadContext context, IRubyObject[] args) {
        this.realIV = orgIV;
        init(context, args, false);
        return this;
    }

    @JRubyMethod
    public IRubyObject reset(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        checkCipherNotNull(runtime);
        if ( ! isStreamCipher() ) {
            this.realIV = orgIV;
            doInitCipher(runtime);
        }
        return this;
    }

    private void updateCipher(final String name, final String padding) {
        // given 'rc4' must be 'RC4' here. OpenSSL checks it as a LN of object
        // ID and set SN. We don't check 'name' is allowed as a LN in ASN.1 for
        // the possibility of JCE specific algorithm so just do upperCase here
        // for OpenSSL compatibility.
        this.name = name.toUpperCase();
        this.padding = padding;

        final Algorithm alg = Algorithm.osslToJava(this.name, this.padding);
        cryptoBase = alg.base;
        cryptoVersion = alg.version;
        cryptoMode = alg.mode;
        realName = alg.getRealName();
        paddingType = alg.getPadding();

        keyLength = alg.getKeyLength();
        ivLength = alg.getIvLength();
        if ( "DES".equalsIgnoreCase(cryptoBase) ) {
            generateKeyLength = keyLength / 8 * 7;
        }

        cipher = getCipherInstance();
    }

    final javax.crypto.Cipher getCipherInstance() {
        try {
            return getCipherInstance(realName, false);
        }
        catch (NoSuchAlgorithmException e) {
            throw newCipherError(getRuntime(), "unsupported cipher algorithm (" + realName + ")");
        }
        catch (NoSuchPaddingException e) {
            throw newCipherError(getRuntime(), "unsupported cipher padding (" + realName + ")");
        }
    }

    @JRubyMethod(required = 1, optional = 3)
    public IRubyObject pkcs5_keyivgen(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        Arity.checkArgumentCount(runtime, args, 1, 4);

        byte[] pass = args[0].asString().getBytes();
        byte[] salt = null;
        int iter = 2048;
        IRubyObject vdigest = context.nil;
        if ( args.length > 1 ) {
            if ( args[1] != context.nil ) {
                salt = args[1].asString().getBytes();
            }
            if ( args.length > 2 ) {
                if ( args[2] != context.nil ) {
                    iter = RubyNumeric.num2int(args[2]);
                    if (iter <= 0) {
                        throw runtime.newArgumentError("iterations must be a positive integer");
                    }
                }
                if ( args.length > 3 ) {
                    vdigest = args[3];
                }
            }
        }
        if ( salt != null && salt.length != 8 ) {
            throw newCipherError(runtime, "salt must be an 8-octet string");
        }

        final String algorithm;
        if ( vdigest.isNil() ) algorithm = "MD5";
        else {
            algorithm = (vdigest instanceof Digest) ? ((Digest) vdigest).getAlgorithm() : vdigest.asJavaString();
        }
        final MessageDigest digest = Digest.getDigest(runtime, algorithm);
        KeyAndIv result = evpBytesToKey(keyLength, ivLength, digest, salt, pass, iter);
        this.key = result.key;
        this.realIV = result.iv;
        this.orgIV = this.realIV;

        doInitCipher(runtime);

        return runtime.getNil();
    }

    private void doInitCipher(final Ruby runtime) {
        if ( isDebug(runtime) ) {
            dumpVars( runtime.getOut(), "doInitCipher()" );
        }
        checkCipherNotNull(runtime);
        if ( key == null ) { //key = emptyKey(keyLength);
            throw newCipherError(runtime, "key not specified");
        }
        try {
            // ECB mode is the only mode that does not require an IV
            if ( "ECB".equalsIgnoreCase(cryptoMode) ) {
                cipher.init(encryptMode ? ENCRYPT_MODE : DECRYPT_MODE,
                        new SimpleSecretKey(getCipherAlgorithm(), this.key)
                );
            }
            else {
                // if no IV yet, start out with all \0s
                if ( realIV == null ) realIV = new byte[ivLength];

                if ( "RC2".equalsIgnoreCase(cryptoBase) ) {
                    cipher.init(encryptMode ? ENCRYPT_MODE : DECRYPT_MODE,
                        new SimpleSecretKey("RC2", this.key),
                        new RC2ParameterSpec(this.key.length * 8, this.realIV)
                    );
                }
                else if ( "RC4".equalsIgnoreCase(cryptoBase) ) {
                    cipher.init(encryptMode ? ENCRYPT_MODE : DECRYPT_MODE,
                        new SimpleSecretKey("RC4", this.key)
                    );
                }
                else {
                    final AlgorithmParameterSpec ivSpec;
                    if ( "GCM".equalsIgnoreCase(cryptoMode) ) { // e.g. 'aes-128-gcm'
                        ivSpec = new GCMParameterSpec(getAuthTagLength() * 8, this.realIV);
                    }
                    else {
                        ivSpec = new IvParameterSpec(this.realIV);
                    }
                    cipher.init(encryptMode ? ENCRYPT_MODE : DECRYPT_MODE,
                        new SimpleSecretKey(getCipherAlgorithm(), this.key),
                        ivSpec
                    );
                }
            }
        }
        catch (InvalidKeyException e) {
            throw newCipherError(runtime, e + "\n possibly you need to install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files for your JRE");
        }
        catch (Exception e) {
            debugStackTrace(runtime, e);
            throw newCipherError(runtime, e);
        }
        cipherInited = true;
        processedDataBytes = 0;
    }

    private String getCipherAlgorithm() {
        final int idx = realName.indexOf('/');
        return idx <= 0 ? realName : realName.substring(0, idx);
    }

    private int processedDataBytes = 0;
    private byte[] lastIV;

    @JRubyMethod
    public IRubyObject update(final ThreadContext context, final IRubyObject arg) {
        return update(context, arg, null);
    }

    @JRubyMethod
    public IRubyObject update(final ThreadContext context, final IRubyObject arg, IRubyObject buffer) {
        final Ruby runtime = context.runtime;

        if ( isDebug(runtime) ) dumpVars( runtime.getOut(), "update()" );

        checkCipherNotNull(runtime);
        checkAuthTag(runtime);

        final ByteList data = arg.asString().getByteList();
        final int length = data.getRealSize();
        if ( length == 0 ) {
            throw runtime.newArgumentError("data must not be empty");
        }

        if ( ! cipherInited ) doInitCipher(runtime);

        final ByteList str;
        try {
            updateAuthData(runtime); // if any

            final byte[] in = data.getUnsafeBytes();
            final int offset = data.begin();
            final byte[] out = cipher.update(in, offset, length);
            if ( out != null ) {
                str = new ByteList(out, false);
                if ( realIV != null ) {
                    if ( encryptMode ) setLastIVIfNeeded( out );
                    else setLastIVIfNeeded( in, offset, length );
                }

                processedDataBytes += length;
            }
            else {
                str = new ByteList(ByteList.NULL_ARRAY);
            }
        }
        catch (Exception e) {
            debugStackTrace( runtime, e );
            throw newCipherError(runtime, e);
        }

        if ( buffer == null ) return RubyString.newString(runtime, str);

        buffer = TypeConverter.convertToType(buffer, context.runtime.getString(), "to_str", true);
        ((RubyString) buffer).setValue(str);
        return buffer;
    }

    @JRubyMethod(name = "<<")
    public IRubyObject update_deprecated(final ThreadContext context, final IRubyObject data) {
        context.runtime.getWarnings().warn(ID.DEPRECATED_METHOD, getMetaClass().getRealClass().getName() + "#<< is deprecated; use #update instead");
        return update(context, data);
    }

    @JRubyMethod(name = "final")
    public IRubyObject do_final(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        checkCipherNotNull(runtime);
        checkAuthTag(runtime);

        if ( ! cipherInited ) doInitCipher(runtime);
        // trying to allow update after final like cruby-openssl. Bad idea.
        if ( "RC4".equalsIgnoreCase(cryptoBase) ) return runtime.newString("");

        final ByteList str;
        try {
            if ( isAuthDataMode() ) {
                str = do_final_with_auth(runtime);
            }
            else {
                final byte[] out = cipher.doFinal();
                if ( out != null ) {
                    // TODO: Modifying this line appears to fix the issue, but I do
                    // not have a good reason for why. Best I can tell, lastIv needs
                    // to be set regardless of encryptMode, so we'll go with this
                    // for now. JRUBY-3335.
                    //if ( realIV != null && encryptMode ) ...
                    str = new ByteList(out, false);
                    if ( realIV != null ) setLastIVIfNeeded(out);
                }
                else {
                    str = new ByteList(ByteList.NULL_ARRAY);
                }
            }

            //if ( ! isStreamCipher() ) {
                //if ( str.length() > processedDataBytes && processedDataBytes > 0 ) {
                    // MRI compatibility only trailing bytes :
                    //str.setRealSize(processedDataBytes);
                //}
            //}

            if (realIV != null) {
                realIV = lastIV;
                doInitCipher(runtime);
            }
        }
        catch (GeneralSecurityException e) { // cipher.doFinal
            debugStackTrace(runtime, e);
            throw newCipherError(runtime, e);
        }
        catch (RuntimeException e) {
            debugStackTrace(runtime, e);
            throw newCipherError(runtime, e);
        }
        return RubyString.newString(runtime, str);
    }

    private ByteList do_final_with_auth(final Ruby runtime) throws GeneralSecurityException {
        updateAuthData(runtime); // if any

        final ByteList str;
        // if GCM/CCM is being used, the authentication tag is appended
        // in the case of encryption, or verified in the case of decryption.
        // The result is stored in a new buffer.
        if ( encryptMode ) {
            final byte[] out = cipher.doFinal();

            final int len = getAuthTagLength(); int strLen;
            if ( ( strLen = out.length - len ) > 0 ) {
                str = new ByteList(out, 0, strLen, false);
            }
            else {
                str = new ByteList(ByteList.NULL_ARRAY); strLen = 0;
            }
            auth_tag = new ByteList(out, strLen, out.length - strLen);
            return str;
        }
        else {
            final byte[] out;
            if ( auth_tag != null ) {
                final byte[] tag = auth_tag.getUnsafeBytes();
                out = cipher.doFinal(tag, auth_tag.getBegin(), auth_tag.getRealSize());
            }
            else {
                out = cipher.doFinal();
            }
            return new ByteList(out, false);
        }
    }

    private void checkAuthTag(final Ruby runtime) {
        if ( auth_tag != null && encryptMode ) {
            throw newCipherError(runtime, "authentication tag already generated by cipher");
        }
    }

    private void setLastIVIfNeeded(final byte[] tmpIV) {
        setLastIVIfNeeded(tmpIV, 0, tmpIV.length);
    }

    private void setLastIVIfNeeded(final byte[] tmpIV, final int offset, final int length) {
        final int ivLen = this.ivLength;
        if ( lastIV == null ) lastIV = new byte[ivLen];
        if ( length >= ivLen ) {
            System.arraycopy(tmpIV, offset + (length - ivLen), lastIV, 0, ivLen);
        }
    }

    @JRubyMethod(name = "padding=")
    public IRubyObject set_padding(IRubyObject padding) {
        updateCipher(name, padding.toString());
        return padding;
    }

    private transient ByteList auth_tag;

    @JRubyMethod(name = "auth_tag")
    public IRubyObject auth_tag(final ThreadContext context) {
        if ( auth_tag != null ) {
            return RubyString.newString(context.runtime, auth_tag);
        }
        if ( ! isAuthDataMode() ) {
            throw newCipherError(context.runtime, "authentication tag not supported by this cipher");
        }
        return context.nil;
    }

    @JRubyMethod(name = "auth_tag=")
    public IRubyObject set_auth_tag(final ThreadContext context, final IRubyObject tag) {
        if ( ! isAuthDataMode() ) {
            throw newCipherError(context.runtime, "authentication tag not supported by this cipher");
        }
        final RubyString auth_tag = tag.asString();
        this.auth_tag = StringHelper.setByteListShared(auth_tag);
        return auth_tag;
    }

    private boolean isAuthDataMode() { // Authenticated Encryption with Associated Data (AEAD)
        return "GCM".equalsIgnoreCase(cryptoMode) || "CCM".equalsIgnoreCase(cryptoMode);
    }

    private static final int MAX_AUTH_TAG_LENGTH = 16;

    private int getAuthTagLength() {
        return Math.min(MAX_AUTH_TAG_LENGTH, this.key.length); // in bytes
    }

    private transient ByteList auth_data;

    @JRubyMethod(name = "auth_data=")
    public IRubyObject set_auth_data(final ThreadContext context, final IRubyObject data) {
        if ( ! isAuthDataMode() ) {
            throw newCipherError(context.runtime, "authentication data not supported by this cipher");
        }
        final RubyString auth_data = data.asString();
        this.auth_data = StringHelper.setByteListShared(auth_data);
        return auth_data;
    }

    private boolean updateAuthData(final Ruby runtime) {
        if ( auth_data == null ) return false; // only to be set if auth-mode
        //try {
            final byte[] data = auth_data.getUnsafeBytes();
            cipher.updateAAD(data, auth_data.getBegin(), auth_data.getRealSize());
        //}
        //catch (RuntimeException e) {
        //    debugStackTrace( runtime, e );
        //    throw newCipherError(runtime, e);
        //}
        auth_data = null;
        return true;
    }

    @JRubyMethod(name = "authenticated?")
    public RubyBoolean authenticated_p(final ThreadContext context) {
        return context.runtime.newBoolean( isAuthDataMode() );
    }

    @JRubyMethod
    public IRubyObject random_key(final ThreadContext context) {
        // str = OpenSSL::Random.random_bytes(self.key_len)
        // self.key = str
        // return str
        RubyString str = Random.random_bytes(context, this.keyLength);
        this.set_key(context, str); return str;
    }

    @JRubyMethod
    public IRubyObject random_iv(final ThreadContext context) {
        // str = OpenSSL::Random.random_bytes(self.iv_len)
        // self.iv = str
        // return str
        RubyString str = Random.random_bytes(context, this.ivLength);
        this.set_iv(context, str); return str;
    }

    //String getAlgorithm() {
    //    return this.cipher.getAlgorithm();
    //}

    final String getName() {
        return this.name;
    }

    //String getCryptoBase() {
    //    return this.cryptoBase;
    //}

    //String getCryptoMode() {
    //    return this.cryptoMode;
    //}

    final int getKeyLength() {
        return keyLength;
    }

    final int getGenerateKeyLength() {
        return (generateKeyLength == -1) ? keyLength : generateKeyLength;
    }

    private void checkCipherNotNull(final Ruby runtime) {
        if ( cipher == null ) {
            throw runtime.newRuntimeError("Cipher not inititalized!");
        }
    }

    private boolean isStreamCipher() {
        return cipher.getBlockSize() == 0;
    }

    private static RaiseException newCipherError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _Cipher(runtime).getClass("CipherError"), e);
    }

    private static RaiseException newCipherError(Ruby runtime, String message) {
        return Utils.newError(runtime, _Cipher(runtime).getClass("CipherError"), message);
    }

    private static class KeyAndIv {

        final byte[] key;
        final byte[] iv;

        KeyAndIv(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }

    }

    private static KeyAndIv evpBytesToKey(
            final int key_len, final int iv_len,
            final MessageDigest md,
            final byte[] salt,
            final byte[] data,
            final int count) {

        final byte[] key = new byte[key_len]; final byte[] iv = new byte[iv_len];

        if ( data == null ) return new KeyAndIv(key, iv);

        int key_ix = 0; int iv_ix = 0;
        byte[] md_buf = null;
        int nkey = key_len; int niv = iv_len;
        int i; int addmd = 0;

        for(;;) {
            md.reset();
            if ( addmd++ > 0 ) md.update(md_buf);
            md.update(data);
            if ( salt != null ) md.update(salt, 0, 8);

            md_buf = md.digest();

            for ( i = 1; i < count; i++ ) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }

            i = 0;
            if ( nkey > 0 ) {
                for(;;) {
                    if ( nkey == 0) break;
                    if ( i == md_buf.length ) break;
                    key[ key_ix++ ] = md_buf[i];
                    nkey--; i++;
                }
            }
            if ( niv > 0 && i != md_buf.length ) {
                for(;;) {
                    if ( niv == 0 ) break;
                    if ( i == md_buf.length ) break;
                    iv[ iv_ix++ ] = md_buf[i];
                    niv--; i++;
                }
            }
            if ( nkey == 0 && niv == 0 ) break;
        }
        return new KeyAndIv(key,iv);
    }

    private static class NamedCipherAllocator implements ObjectAllocator {

        private final String cipherBase;

        NamedCipherAllocator(final String cipherBase) {
            this.cipherBase = cipherBase;
        }

        public Named allocate(Ruby runtime, RubyClass klass) {
            return new Named(runtime, klass, cipherBase);
        }
    };

    public static class Named extends Cipher {
        private static final long serialVersionUID = 5599069534014317221L;

        final String cipherBase;

        Named(Ruby runtime, RubyClass type, String cipherBase) {
            super(runtime, type);
            this.cipherBase = cipherBase; // e.g. "AES"
        }

        /*
        AES = Class.new(Cipher) do
          define_method(:initialize) do |*args|
            cipher_name = args.inject('AES'){|n, arg| "#{n}-#{arg}" }
            super(cipher_name)
          end
        end
         */
        @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final StringBuilder name = new StringBuilder();
            name.append(cipherBase);
            if ( args != null ) {
                for ( int i = 0; i < args.length; i++ ) {
                    name.append('-').append( args[i].asString() );
                }
            }
            initializeImpl(context.runtime, name.toString());
            return this;
        }

    }

    private static class AESCipherAllocator implements ObjectAllocator {

        private final String keyLength;

        AESCipherAllocator(final String keyLength) {
            this.keyLength = keyLength;
        }

        public AES allocate(Ruby runtime, RubyClass klass) {
            return new AES(runtime, klass, keyLength);
        }
    };

    public static class AES extends Cipher {
        private static final long serialVersionUID = -3627749495034257750L;

        final String keyLength;

        AES(Ruby runtime, RubyClass type, String keyLength) {
            super(runtime, type);
            this.keyLength = keyLength; // e.g. "256"
        }

        /*
        AES256 = Class.new(Cipher) do
          define_method(:initialize) do |mode|
            mode ||= "CBC"
            cipher_name = "AES-256-#{mode}"
            super(cipher_name)
          end
        end
         */
        @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            final String mode;
            if ( args != null && args.length > 0 ) {
                mode = args[0].toString();
            }
            else {
                mode = "CBC";
            }
            initializeImpl(context.runtime, "AES-" + keyLength + '-' + mode);
            return this;
        }

    }

}
