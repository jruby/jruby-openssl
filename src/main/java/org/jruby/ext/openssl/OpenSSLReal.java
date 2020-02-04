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
package org.jruby.ext.openssl;

import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.Provider;

/**
 * @deprecated no longer used
 * @see OpenSSL
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class OpenSSLReal {

    private OpenSSLReal() { /* no instances */ }

    @Deprecated
    public interface Runnable {
        void run() throws GeneralSecurityException;
    }

    public interface Callable<T> {
        T call() throws GeneralSecurityException;
    }

    /**
     * Run a block of code with 'BC' provider installed.
     *
     * @deprecated No longer used within the JRuby-OpenSSL code-base, please avoid!
     *
     * @param block
     * @throws GeneralSecurityException
     */
    @Deprecated
    public static void doWithBCProvider(final Runnable block) throws GeneralSecurityException {
        getWithBCProvider(new Callable<Void>() {
            public Void call() throws GeneralSecurityException {
                block.run(); return null;
            }
        });
    }

    /**
     * Adds BouncyCastleProvider if it's allowed (no security exceptions thrown)
     * and runs the block of code. Once added the provider will stay registered
     * within <code>java.security.Security</code> API. This might lead to memory
     * leaks e.g. when the Ruby runtime that loaded BC is teared down.
     *
     * Removing the 'BC' provided (once the block run) can remove pre-installed
     * or another runtime-added BC provider thus causing unknown runtime errors.
     *
     * @deprecated No longer used within the JRuby-OpenSSL code-base, please avoid!
     *
     * @param <T>
     * @param block
     * @return
     * @throws GeneralSecurityException
     */
    @Deprecated
    public static <T> T getWithBCProvider(final Callable<T> block) throws GeneralSecurityException {
        try {
            final Provider provider = SecurityHelper.getSecurityProvider(); // BC
            if (provider != null && java.security.Security.getProvider(provider.getName()) == null) {
                java.security.Security.addProvider(provider);
            }
            return block.call();
        } catch (NoSuchProviderException nspe) {
            throw new GeneralSecurityException(OpenSSL.bcExceptionMessage(nspe), nspe);
        } catch (Exception e) {
            throw new GeneralSecurityException(e.getMessage(), e);
        }
    }

}