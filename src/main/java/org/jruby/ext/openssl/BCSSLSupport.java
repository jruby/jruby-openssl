/*
 * The MIT License
 *
 * Copyright (C) 2026 Karol Bucek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl;

import java.util.List;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCSSLEngine;

abstract class BCSSLSupport {

    static SSLSession getBCSession(final SSLEngine engine) {
        // BCSSLEngine.getBCSession() returns the unwrapped BCExtendedSSLSession;
        // engine.getSession() would wrap it in a package-private ExportSSLSession
        if (engine instanceof BCSSLEngine) return ((BCSSLEngine) engine).getBCSession();
        return engine.getSession();
    }

    static boolean setBCSessionToResume(final SSLEngine engine, final SSLSession session) {
        if (engine instanceof BCSSLEngine && session instanceof BCExtendedSSLSession) {
            try {
                ((BCSSLEngine) engine).setBCSessionToResume((BCExtendedSSLSession) session);
                return true;
            } catch (IllegalArgumentException e) {
                // This can happen when a Java gem's post-install hook (e.g. fast-rsa-engine)
                // downloads BC JARs via Maven and loads them under a new classloader. At that
                // point there are two copies of BC in the JVM, and ProvSSLEngine rejects the
                // stored session because it came from a different classloader context.
                // Just fall through and let the caller do a fresh handshake.
            }
        }
        return false;
    }

    // extract SNI hostname from the negotiated session (server-side)
    static String getRequestedServerName(final SSLEngine engine) {
        SSLSession session = getBCSession(engine);
        if (session instanceof BCExtendedSSLSession) {
            return getServerNameFrom((BCExtendedSSLSession) session);
        }
        if (session instanceof ExtendedSSLSession) {
            return getServerNameFrom((ExtendedSSLSession) session);
        }
        return null;
    }

    private static String getServerNameFrom(final BCExtendedSSLSession session) {
        try {
            List<BCSNIServerName> names = session.getRequestedServerNames();
            if (names != null) {
                for (BCSNIServerName name : names) {
                    if (name instanceof BCSNIHostName) return ((BCSNIHostName) name).getAsciiName();
                }
            }
        } catch (UnsupportedOperationException e) { /* ignore */ }
        return null;
    }

    private static String getServerNameFrom(final ExtendedSSLSession session) {
        try {
            List<SNIServerName> names = session.getRequestedServerNames();
            if (names != null) {
                for (SNIServerName name : names) {
                    if (name instanceof SNIHostName) return ((SNIHostName) name).getAsciiName();
                }
            }
        } catch (UnsupportedOperationException e) { /* ignore */ }
        return null;
    }
}
