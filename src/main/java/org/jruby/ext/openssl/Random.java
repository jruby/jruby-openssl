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

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.util.SafePropertyAccessor;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Random {

    // thread-local (default), shared, strong
    static final String HOLDER_TYPE = SafePropertyAccessor.getProperty("jruby.openssl.random", "");

    private static Holder createHolderImpl() {
        if (HOLDER_TYPE.equals("default") || HOLDER_TYPE.equals("thread-local")) {
            return new ThreadLocalHolder();
        }
        if (HOLDER_TYPE.equals("shared")) {
            return new SharedHolder();
        }
        if (HOLDER_TYPE.equals("strong")) { // TODO strong (thread-local) makes sense
            return new StrongHolder();
        }
        if (ThreadLocalHolder.secureRandomField == null) {
            return new SharedHolder(); // fall-back on (older) JRuby <= 1.7.4
        }
        return new ThreadLocalHolder();
    }

    static abstract class Holder {

        abstract java.util.Random getPlainRandom() ;

        abstract java.security.SecureRandom getSecureRandom(ThreadContext context) ;

        void seedSecureRandom(ThreadContext context, byte[] seed) {
            getSecureRandom(context).setSeed(seed);
        }

        void seedPlainRandom(long seed) {
            getPlainRandom().setSeed(seed);
        }

    }

    private static class SharedHolder extends Holder {

        private volatile java.util.Random plainRandom;
        private volatile java.security.SecureRandom secureRandom;

        java.util.Random getPlainRandom() {
            if (plainRandom == null) {
                synchronized(this) {
                    if (plainRandom == null) {
                        plainRandom = new java.util.Random();
                    }
                }
            }
            return plainRandom;
        }

        java.security.SecureRandom getSecureRandom(ThreadContext context) {
            if (secureRandom == null) {
                synchronized(this) {
                    if (secureRandom == null) {
                        secureRandom = SecurityHelper.getSecureRandom();
                    }
                }
            }
            return secureRandom;
        }

    }

    private static class ThreadLocalHolder extends Holder {

        @Override
        java.util.Random getPlainRandom() {
            return ThreadLocalRandom.current();
        }

        @Override
        void seedPlainRandom(long seed) {
            return; // NO-OP - UnsupportedOperationException
        }

        @Override
        java.security.SecureRandom getSecureRandom(ThreadContext context) {
            java.security.SecureRandom secureRandom = context.secureRandom;
            if (secureRandom == null) {
                secureRandom = getSecureRandomImpl();
                setSecureRandom(context, secureRandom); // context.secureRandom = ...
            }
            return secureRandom;
        }

        private static final Field secureRandomField;

        private static void setSecureRandom(ThreadContext context, java.security.SecureRandom secureRandom) {
            if (secureRandomField != null) {
                try {
                    secureRandomField.set(context, secureRandom);
                }
                catch (IllegalAccessException ex) { Utils.throwException(ex); /* should not happen */ }
            }
        }

        private static final String PREFERRED_PRNG;
        static {
            String prng = SafePropertyAccessor.getProperty("jruby.preferred.prng", null);

            if (prng == null) { // make sure the default experience is non-blocking for users
                prng = "NativePRNGNonBlocking";
                if (SafePropertyAccessor.getProperty("os.name") != null) {
                    if (jnr.posix.util.Platform.IS_WINDOWS) { // System.getProperty("os.name") won't fail
                        prng = "Windows-PRNG";
                    }
                }
            }
            // setting it to "" (empty) or "default" should just use new SecureRandom() :
            if (prng.isEmpty() || prng.equalsIgnoreCase("default")) {
                prng = null; tryPreferredPRNG = false; trySHA1PRNG = false;
            }

            PREFERRED_PRNG = prng;

            Field secureRandom = null;
            try {
                secureRandom = ThreadContext.class.getField("secureRandom");
                if ( ! secureRandom.isAccessible() || Modifier.isFinal(secureRandom.getModifiers()) ) {
                    secureRandom = null;
                }
            }
            catch (Exception ex) { /* ignore NoSuchFieldException */ }
            secureRandomField = secureRandom;
        }

        private static boolean tryPreferredPRNG = true;
        private static boolean trySHA1PRNG = true;
        private static boolean tryStrongPRNG = false; // NOT-YET-IMPLEMENTED

        // copied from JRuby (not available in all 1.7.x) :
        public java.security.SecureRandom getSecureRandomImpl() {
            java.security.SecureRandom secureRandom = null;
            // Try preferred PRNG, which defaults to NativePRNGNonBlocking
            if (tryPreferredPRNG) {
                try {
                    secureRandom = java.security.SecureRandom.getInstance(PREFERRED_PRNG);
                }
                catch (Exception e) {
                    tryPreferredPRNG = false;
                    OpenSSL.debug("SecureRandom '"+ PREFERRED_PRNG +"' failed:", e);
                }
            }

            // Try SHA1PRNG
            if (secureRandom == null && trySHA1PRNG) {
                try {
                    secureRandom = java.security.SecureRandom.getInstance("SHA1PRNG");
                }
                catch (Exception e) {
                    trySHA1PRNG = false;
                    OpenSSL.debug("SecureRandom SHA1PRNG failed:", e);
                }
            }

            // Just let JDK do whatever it does
            if (secureRandom == null) {
                secureRandom = new java.security.SecureRandom();
            }

            return secureRandom;
        }

    }

    private static class StrongHolder extends Holder {

        static {
            Method method = null;
            if (OpenSSL.javaVersion8(true)) {
                try {
                    method = java.security.SecureRandom.class.getMethod("getInstanceStrong");
                }
                catch (NoSuchMethodException ex) { OpenSSL.debugStackTrace(ex); }
            }
            getInstanceStrong = method;
        }

        private static final Method getInstanceStrong;

        @Override
        java.util.Random getPlainRandom() {
            return new java.util.Random();
        }

        @Override
        java.security.SecureRandom getSecureRandom(ThreadContext context) {
            // return java.security.SecureRandom.getInstanceStrong(); (on Java 8)
            if (getInstanceStrong == null) return SecurityHelper.getSecureRandom();
            try {
                return (java.security.SecureRandom) getInstanceStrong.invoke(null);
            }
            catch (IllegalAccessException ex) {
                Utils.throwException(ex); return null; // won't happen
            }
            catch (InvocationTargetException ex) {
                Utils.throwException(ex.getTargetException()); return null;
            }
        }

        void seedSecureRandom(ThreadContext context, byte[] seed) {
            // NOOP - new instance returned for getSecureRandom
        }

        void seedPlainRandom(long seed) {
            // NOOP - new instance returned for getPlainRandom
        }

    }

    static void createRandom(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule Random = OpenSSL.defineModuleUnder("Random");

        Random.defineClassUnder("RandomError", OpenSSLError, OpenSSLError.getAllocator());

        Random.defineAnnotatedMethods(Random.class);

        Random.dataWrapStruct(createHolderImpl());
    }

    @JRubyMethod(meta = true)
    public static RubyString random_bytes(final ThreadContext context,
        final IRubyObject self, final IRubyObject arg) {
        return random_bytes(context, self, toInt(context.runtime, arg));
    }

    static RubyString random_bytes(final ThreadContext context, final int len) {
        final RubyModule Random = (RubyModule) context.runtime.getModule("OpenSSL").getConstantAt("Random");
        return generate(context, Random, len, true); // secure-random
    }

    private static RubyString random_bytes(final ThreadContext context,
        final IRubyObject self, final int len) {
        return generate(context, self, len, true); // secure-random
    }

    @JRubyMethod(meta = true)
    public static RubyString pseudo_bytes(final ThreadContext context,
        final IRubyObject self, final IRubyObject len) {
        return generate(context, self, toInt(context.runtime, len), false); // plain-random
    }

    private static int toInt(final Ruby runtime, final IRubyObject arg) {
        final long len = RubyNumeric.fix2long(arg);
        if ( len < 0 || len > Integer.MAX_VALUE ) {
            throw runtime.newArgumentError("negative string size (or size too big) " + len);
        }
        return (int) len;
    }

    private static RubyString generate(final ThreadContext context,
        final IRubyObject self, final int len, final boolean secure) {
        final Holder holder = retrieveHolder((RubyModule) self);
        final byte[] bytes = new byte[len];
        ( secure ? holder.getSecureRandom(context) : holder.getPlainRandom() ).nextBytes(bytes);
        return RubyString.newString(context.runtime, new ByteList(bytes, false));
    }

    static Holder getHolder(final Ruby runtime) {
        return retrieveHolder((RubyModule) runtime.getModule("OpenSSL").getConstantAt("Random"));
    }

    private static Holder retrieveHolder(final RubyModule Random) {
        return (Holder) Random.dataGetStruct();
    }

    @JRubyMethod(meta = true) // seed(str) -> str
    public static IRubyObject seed(final ThreadContext context,
        final IRubyObject self, IRubyObject str) {
        seedImpl(context, (RubyModule) self, str);
        return str;
    }

    private static void seedImpl(ThreadContext context, final RubyModule Random, final IRubyObject str) {
        final byte[] seed = str.asString().getBytes();
        final Holder holder = retrieveHolder(Random);

        holder.seedSecureRandom(context, seed); // seed supplements existing (secure) seeding mechanism

        long s; int l = seed.length;
        if ( l >= 4 ) {
            s = (seed[0] << 24) | (seed[1] << 16) | (seed[2] << 8) | seed[3];
            if ( l >= 8 ) {
                s = s ^ (seed[l-4] << 24) | (seed[l-3] << 16) | (seed[l-2] << 8) | seed[l-1];
            }
            holder.seedPlainRandom(s);
        }
    }

    // true if the PRNG has been seeded with enough data, false otherwise
    @JRubyMethod(meta = true, name = "status?") // status? => true | false
    public static IRubyObject status_p(final ThreadContext context, final IRubyObject self) {
        return context.runtime.newBoolean(true);
    }

    @JRubyMethod(meta = true, name = { "random_add", "add" }) // random_add(str, entropy) -> self
    public static IRubyObject random_add(final ThreadContext context,
        final IRubyObject self, IRubyObject str, IRubyObject entropy) {
        seedImpl(context, (RubyModule) self, str); // simply ignoring _entropy_ hint
        return self;
    }

    // C-Ruby OpenSSL::Random API stubs :

    @JRubyMethod(meta = true) // load_random_file(filename)
    public static IRubyObject load_random_file(final ThreadContext context,
        final IRubyObject self, IRubyObject fname) {
        return context.runtime.getNil();
    }

    @JRubyMethod(meta = true) // write_random_file(filename) -> true
    public static IRubyObject write_random_file(final ThreadContext context,
        final IRubyObject self, IRubyObject fname) {
        return context.runtime.getNil();
    }

    @JRubyMethod(meta = true) // egd(filename) -> true
    public static IRubyObject egd(final ThreadContext context,
        final IRubyObject self, IRubyObject fname) {
        // no-op let the JVM security infrastructure to its internal seeding
        return context.runtime.getTrue();
    }

    @JRubyMethod(meta = true) // egd_bytes(filename, length) -> true
    public static IRubyObject egd_bytes(final ThreadContext context,
        final IRubyObject self, IRubyObject fname, IRubyObject len) {
        // no-op let the JVM security infrastructure to its internal seeding
        return context.runtime.getTrue();
    }

}
