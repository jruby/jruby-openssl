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
 * Copyright (C) 2017 Karol Bucek <self@kares.org>
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
package org.jruby.ext.openssl.util;

import org.jruby.ext.openssl.OpenSSL;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;

/**
 * JCE security helper for disabling (default) imposed cryptographic restrictions.
 *
 * Using this class might be in **contrast with the license agreement** that came with your JRE.
 *
 * It's preferable to install:
 *
 * "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files"
 *
 * specific to your Java version!
 *
 * @see http://www.oracle.com/technetwork/java/javase/downloads/index.html
 */
public final class CryptoSecurity {

    private CryptoSecurity() { /* no instances */ }

    public static void disableJceRestrictions() {
        unrestrictSecurity();
        setAllPermissionPolicy();
    }

    public static Boolean setAllPermissionPolicy() {
        if ( ! OpenSSL.javaHotSpot() ) return false;
        try {
            final Class JceSecurity = Class.forName("javax.crypto.JceSecurity");

            final Class CryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class CryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            Field defaultPolicy = JceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicy.setAccessible(true);

            Field perms = CryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);

            Field INSTANCE = CryptoAllPermission.getDeclaredField("INSTANCE");
            INSTANCE.setAccessible(true);

            synchronized (Security.class) {
                final PermissionCollection defPolicy = (PermissionCollection) defaultPolicy.get(null);
                final java.util.Map permsMap = (java.util.Map) perms.get(defPolicy);
                if ( ! permsMap.isEmpty() ) {
                    permsMap.clear();
                    defPolicy.add((Permission) INSTANCE.get(null));
                    return true;
                }
                return false;
            }
        }
        catch (ClassNotFoundException e) {
            OpenSSL.debug("unable un-restrict jce security: ", e);
            return null;
        }
        catch (Exception e) {
            OpenSSL.debug("unable un-restrict jce security: ");
            OpenSSL.debugStackTrace(e);
            return null;
        }
    }

    public static Boolean unrestrictSecurity() {
        if ( ! OpenSSL.javaHotSpot() ) return false;
        if ( OpenSSL.javaVersion9(true) ) {
            return unrestrictJceSecurity9();
        }
        return unrestrictJceSecurity8();
    }

    static Boolean unrestrictJceSecurity9() {
        try {
            if (Security.getProperty("crypto.policy") == null) {
                Security.setProperty("crypto.policy", "unlimited");
                return true;
            }
            return false;
        }
        catch (Exception e) {
            OpenSSL.debug("unable un-restrict jce security: ", e);
            return null;
        }
    }

    static Boolean unrestrictJceSecurity8() {
        try {
            final Class JceSecurity = Class.forName("javax.crypto.JceSecurity");

            Field isRestricted = JceSecurity.getDeclaredField("isRestricted");

            if (Modifier.isFinal(isRestricted.getModifiers())) {
                Field modifiers = Field.class.getDeclaredField("modifiers");
                modifiers.setAccessible(true);
                modifiers.setInt(isRestricted, isRestricted.getModifiers() & ~Modifier.FINAL);
            }

            isRestricted.setAccessible(true);
            if (isRestricted.getBoolean(null) == true) {
                isRestricted.setBoolean(null, false); // isRestricted = false;
                return true;
            }
            return false;
        }
        catch (ClassNotFoundException e) {
            OpenSSL.debug("unable un-restrict jce security: ", e);
            return null;
        }
        catch (Exception e) {
            OpenSSL.debug("unable un-restrict jce security: ");
            OpenSSL.debugStackTrace(e);
            return null;
        }
    }

}
