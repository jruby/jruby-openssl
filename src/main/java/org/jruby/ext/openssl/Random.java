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

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Random {

    private static class Holder {

        private volatile java.util.Random plainRandom;
        private volatile java.security.SecureRandom secureRandom;

        //RandomHolder(java.util.Random plainRandom, java.security.SecureRandom secureRandom) {
        //    this.plainRandom = plainRandom; this.secureRandom = secureRandom;
        //}

        final java.util.Random getPlainRandom() {
            if (plainRandom == null) {
                synchronized(this) {
                    if (plainRandom == null) {
                        plainRandom = new java.util.Random();
                    }
                }
            }
            return plainRandom;
        }

        final java.security.SecureRandom getSecureRandom() {
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

    public static void createRandom(final Ruby runtime, final RubyModule OpenSSL) {
        final RubyModule Random = OpenSSL.defineModuleUnder("Random");

        RubyClass OpenSSLError = (RubyClass) OpenSSL.getConstant("OpenSSLError");
        Random.defineClassUnder("RandomError", OpenSSLError, OpenSSLError.getAllocator());

        Random.defineAnnotatedMethods(Random.class);

        Random.dataWrapStruct(new Holder());
    }

    @JRubyMethod(meta = true)
    public static RubyString random_bytes(final ThreadContext context,
        final IRubyObject self, final IRubyObject arg) {
        final Ruby runtime = context.runtime;
        return random_bytes(runtime, self, toInt(runtime, arg));
    }

    static RubyString random_bytes(final Ruby runtime, final int len) {
        final RubyModule Random = (RubyModule) runtime.getModule("OpenSSL").getConstantAt("Random");
        return generate(runtime, Random, len, true); // secure-random
    }

    private static RubyString random_bytes(final Ruby runtime,
        final IRubyObject self, final int len) {
        return generate(runtime, self, len, true); // secure-random
    }

    @JRubyMethod(meta = true)
    public static RubyString pseudo_bytes(final ThreadContext context,
        final IRubyObject self, final IRubyObject len) {
        final Ruby runtime = context.runtime;
        return generate(runtime, self, toInt(runtime, len), false); // plain-random
    }

    private static int toInt(final Ruby runtime, final IRubyObject arg) {
        final long len = RubyNumeric.fix2long(arg);
        if ( len < 0 || len > Integer.MAX_VALUE ) {
            throw runtime.newArgumentError("negative string size (or size too big) " + len);
        }
        return (int) len;
    }

    private static RubyString generate(final Ruby runtime,
        final IRubyObject self, final int len, final boolean secure) {
        final Holder holder = unwrapStruct(self);
        final byte[] bytes = new byte[len];
        ( secure ? holder.getSecureRandom() : holder.getPlainRandom() ).nextBytes(bytes);
        return RubyString.newString(runtime, new ByteList(bytes, false));
    }

    private static Holder unwrapStruct(final IRubyObject Random) {
        return (Holder) ((RubyModule) Random).dataGetStruct();
    }

    @JRubyMethod(meta = true) // seed(str) -> str
    public static IRubyObject seed(final ThreadContext context,
        final IRubyObject self, IRubyObject str) {
        final byte[] seed = str.asString().getBytes();
        final Holder holder = unwrapStruct(self);

        holder.getSecureRandom().setSeed(seed); // seed supplements existing

        long s; int l = seed.length;
        if ( l >= 4 ) {
            s = (seed[0] << 24) | (seed[1] << 16) | (seed[2] << 8) | seed[3];
            holder.getPlainRandom().setSeed(s);
        }
        return str;
    }

    // true if the PRNG has been seeded with enough data, false otherwise
    @JRubyMethod(meta = true, name = "status?") // status? => true | false
    public static IRubyObject status_p(final ThreadContext context,
        final IRubyObject self) {
        //final Holder holder = unwrapStruct(self);
        //if ( holder.secureRandom == null ) {
        //    return context.runtime.newBoolean(false); // just a HINT
        //}
        return context.runtime.newBoolean(true);
    }

    // C-Ruby OpenSSL::Random API stubs :

    @JRubyMethod(meta = true) // random_add(str, entropy) -> self
    public static IRubyObject random_add(final ThreadContext context,
        final IRubyObject self, IRubyObject str, IRubyObject entropy) {
        return self;
    }

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
        return context.runtime.getNil();
    }

    @JRubyMethod(meta = true) // egd_bytes(filename, length) -> true
    public static IRubyObject egd_bytes(final ThreadContext context,
        final IRubyObject self, IRubyObject fname, IRubyObject len) {
        return context.runtime.getNil();
    }

}
