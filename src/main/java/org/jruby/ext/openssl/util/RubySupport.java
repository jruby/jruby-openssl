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
package org.jruby.ext.openssl.util;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.function.Function;

import org.jcodings.specific.ASCIIEncoding;
import org.jcodings.specific.UTF8Encoding;
import org.jruby.Ruby;
import org.jruby.RubyBasicObject;
import org.jruby.RubyClass;
import org.jruby.RubyEncoding;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.RubyTime;
import org.jruby.exceptions.RaiseException;
import org.jruby.util.ByteList;
import org.jruby.runtime.Block;
import org.jruby.runtime.Helpers;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

public abstract class RubySupport {

    public static RubyString newString(final Ruby runtime, final byte[] bytes) {
        final ByteList byteList = new ByteList(bytes, false);
        return RubyString.newString(runtime, byteList);
    }

    public static RubyString newString(final Ruby runtime, final byte[] bytes, final int count) {
        final ByteList byteList = new ByteList(bytes, 0, count, false);
        return RubyString.newString(runtime, byteList);
    }

    public static RubyString newString(final Ruby runtime, final CharSequence chars) {
        return RubyString.newString(runtime, chars, ASCIIEncoding.INSTANCE);
    }

    public static ByteList setByteListShared(final RubyString str) {
        str.setByteListShared();
        return str.getByteList();
    }

    public static RubyString newUTF8String(final Ruby runtime, final ByteList bytes) {
        ByteList byteList = new ByteList(RubyEncoding.encodeUTF8(bytes), UTF8Encoding.INSTANCE, false);
        return RubyString.newString(runtime, byteList);
    }

    public static RubyString newUTF8String(final Ruby runtime, final CharSequence chars) {
        ByteList byteList = new ByteList(RubyEncoding.encodeUTF8(chars), UTF8Encoding.INSTANCE, false);
        return RubyString.newString(runtime, byteList);
    }

    public static RubyString newStringFrozen(final Ruby runtime, final CharSequence chars) {
        final RubyString str = RubyString.newString(runtime, chars);
        str.setFrozen(true);
        return str;
    }

    public static Date timeToJavaDate(final ThreadContext context, final IRubyObject value) {
        if (!(value instanceof RubyTime)) {
            throw context.runtime.newTypeError(value, "Time");
        }
        return ((RubyTime) value).getJavaDate();
    }

    // error/exception factory helpers

    public static RaiseException newIOError(Ruby runtime, IOException e) {
        return newIOError(runtime, e.getMessage(), e);
    }

    public static RaiseException newIOError(Ruby runtime, String msg) {
        return new RaiseException(runtime, runtime.getIOError(), msg, true);
    }

    public static RaiseException newIOError(Ruby runtime, String msg, Exception e) {
        RaiseException ex = newIOError(runtime, msg);
        ex.initCause(e);
        return ex;
    }

    public static RaiseException newRuntimeError(Ruby runtime, Exception e) {
        return newRuntimeError(runtime, e.getMessage(), e);
    }

    public static RaiseException newRuntimeError(Ruby runtime, String msg) {
        return new RaiseException(runtime, runtime.getRuntimeError(), msg, true);
    }

    public static RaiseException newRuntimeError(Ruby runtime, String msg, Exception e) {
        RaiseException ex = newRuntimeError(runtime, msg);
        ex.initCause(e);
        return ex;
    }

    public static RaiseException newArgumentError(Ruby runtime, Exception e) {
        return newError(runtime, runtime.getArgumentError(), e);
    }

    public static RaiseException newErrorWithoutTrace(Ruby runtime, RubyClass errorClass, String message) {
        final IRubyObject backtrace = runtime.newEmptyArray();
        return new RaiseException(runtime, errorClass, message, backtrace, false);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, String message, boolean nativeException) {
        return new RaiseException(runtime, errorClass, message, nativeException);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, Throwable e) {
        return newError(runtime, errorClass, e.getMessage(), e);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, String msg) {
        return newError(runtime, errorClass, msg, true);
    }

    public static RaiseException newError(Ruby runtime, RubyClass errorClass, String msg, Throwable e) {
        RaiseException ex = newError(runtime, errorClass, msg);
        ex.initCause(e);
        return ex;
    }

    public static <T extends Throwable> RaiseException newError(Function<T, RaiseException> errorFunction, T e) {
        RaiseException ex = errorFunction.apply(e);
        ex.initCause(e);
        return ex;
    }

    public static RaiseException newSecurityError(Ruby runtime, Throwable e) {
        return newSecurityError(runtime, e.getMessage(), e);
    }

    public static RaiseException newSecurityError(Ruby runtime, String msg, Throwable e) {
        RaiseException ex = new RaiseException(runtime, runtime.getSecurityError(), msg, true);
        ex.initCause(e);
        return ex;
    }

    public static CharSequence callerTraceAt(final ThreadContext context, final int level) {
        final IRubyObject caller0 = context.runtime.getKernel().callMethod(
                "caller",
                context.runtime.newFixnum(level),
                context.runtime.newFixnum(1)
        );
        if (caller0.isNil()) return null;
        final IRubyObject first = caller0.convertToArray().eltInternal(0);
        return first instanceof RubyString ? (RubyString) first : first.asString();
    }

    //

    public static IRubyObject invokeSuper(ThreadContext context, IRubyObject self, IRubyObject[] args, Block block) {
        return Helpers.invokeSuper(context, self, args, block);
    }

    // extract **kwargs helpers (borrowed from JRuby's ArgsUtil)

    public static IRubyObject[] extractKeywordArgs(final ThreadContext context, RubyHash options, String... validKeys) {
        return extractKeywordArgs(context, options, validKeys, 0);
    }

    public static IRubyObject[] extractKeywordArgs(final ThreadContext context, RubyHash options, String[] validKeys, int offset) {
        final IRubyObject[] ret = new IRubyObject[offset + validKeys.length];

        final HashSet<RubySymbol> validKeySet = new HashSet<>(ret.length);

        for (int i = 0; i < validKeys.length; i++) {
            final String key = validKeys[i];
            RubySymbol keySym = context.runtime.newSymbol(key);
            IRubyObject val = options.fastARef(keySym);
            ret[offset + i] = val != null ? val : RubyBasicObject.UNDEF;
            validKeySet.add(keySym);
        }

        options.visitAll(new RubyHash.Visitor() {
            public void visit(IRubyObject key, IRubyObject value) {
                if (!validKeySet.contains(key)) {
                    throw context.runtime.newArgumentError("unknown keyword: " + key);
                }
            }
        });

        return ret;
    }

    public static String extractStringOpt(ThreadContext context, IRubyObject opts, String key) {
        return extractStringOpt(context, opts, key, false);
    }

    public static String extractStringOpt(ThreadContext context, IRubyObject opts,
                                          String key, boolean tryStringKey) {
        final IRubyObject val = extractOpt(context, opts, key, tryStringKey);
        return val == null ? null : val.convertToString().asJavaString();
    }

    public static RubyString extractRubyStringOpt(ThreadContext context, IRubyObject opts,
                                                  String key, boolean tryStringKey) {
        final IRubyObject val = extractOpt(context, opts, key, tryStringKey);
        return val == null ? null : val.convertToString();
    }

    public static int extractIntOpt(ThreadContext context, IRubyObject opts,
                                    String key, int defaultVal, boolean tryStringKey) {
        if (!(opts instanceof RubyHash)) return defaultVal;
        RubyHash hash = (RubyHash) opts;
        IRubyObject val = hash.fastARef(context.runtime.newSymbol(key));
        if (val == null && tryStringKey) val = hash.fastARef(context.runtime.newString(key));
        if (val == null || val.isNil()) return defaultVal;
        return RubyNumeric.fix2int(val);
    }

    public static IRubyObject extractOpt(ThreadContext context, IRubyObject opts,
                                         String key, boolean tryStringKey) {
        if (!(opts instanceof RubyHash)) return null;
        RubyHash hash = (RubyHash) opts;
        IRubyObject val = hash.fastARef(context.runtime.newSymbol(key));
        if (val == null && tryStringKey) val = hash.fastARef(context.runtime.newString(key));
        if (val == null || val.isNil()) return null;
        return val;
    }
}
