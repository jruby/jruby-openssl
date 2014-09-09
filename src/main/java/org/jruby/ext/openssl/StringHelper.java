/*
 * The MIT License
 *
 * Copyright 2014 Karol Bucek.
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

import org.jcodings.specific.UTF8Encoding;
import org.jruby.Ruby;
import org.jruby.RubyEncoding;
import org.jruby.RubyFile;
import org.jruby.RubyIO;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 *
 * @author kares
 */
abstract class StringHelper {

    static RubyString newString(final Ruby runtime, final byte[] bytes) {
        final ByteList byteList = new ByteList(bytes, false);
        return RubyString.newString(runtime, byteList);
    }

    static RubyString newUTF8String(final Ruby runtime, final ByteList bytes) {
        ByteList byteList = new ByteList(RubyEncoding.encodeUTF8(bytes), UTF8Encoding.INSTANCE, false);
        return new RubyString(runtime, runtime.getString(), byteList);
    }

    static RubyString newUTF8String(final Ruby runtime, final CharSequence chars) {
        ByteList byteList = new ByteList(RubyEncoding.encodeUTF8(chars), UTF8Encoding.INSTANCE, false);
        return new RubyString(runtime, runtime.getString(), byteList);
    }

    static RubyString newStringFrozen(final Ruby runtime, final ByteList bytes) {
        final RubyString str = RubyString.newStringShared(runtime, bytes);
        str.setFrozen(true); return str;
    }

    static RubyString newStringFrozen(final Ruby runtime, final CharSequence chars) {
        final RubyString str = RubyString.newString(runtime, chars);
        str.setFrozen(true); return str;
    }

    static RubyString readPossibleDERInput(final ThreadContext context, final IRubyObject arg) {
        return readInput(context, OpenSSLImpl.to_der_if_possible(context, arg));
    }

    static RubyString readInput(final ThreadContext context, final IRubyObject arg) {
        if ( arg instanceof RubyIO ) {
            final IRubyObject result;
            if ( arg instanceof RubyFile ) {
                result = ( (RubyFile) arg.dup() ).read(context);
            }
            else {
                result = ( (RubyIO) arg ).read(context);
            }
            if ( result instanceof RubyString ) return (RubyString) result;
            throw context.runtime.newArgumentError("IO `" + arg.inspect() + "' contained no data");
        }
        return arg.asString();
    }

    static final ByteList NEW_LINE = new ByteList(new byte[] { '\n' }, false);
    static final ByteList COMMA_SPACE = new ByteList(new byte[] { ',',' ' }, false);

    static void gsub(final Ruby runtime, final ByteList str, final byte match, final byte replace) {
        final int begin = str.getBegin();
        final int slen = str.getRealSize();
        final byte[] bytes = str.getUnsafeBytes();
        for ( int i = begin; i < begin + slen; i++ ) {
            if ( bytes[i] == match ) bytes[i] = replace;
        }
    }

}
