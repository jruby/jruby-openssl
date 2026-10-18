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

import org.jruby.ext.openssl.shim.ErrorShim;

import java.util.function.Function;

public abstract class ExceptionUtil {

    /**
     * Handle potential FIPS operation error
     * @param e exception to handle (or re-throw)
     * @param handler
     */
    public static void throwMappedOperationErrorOrOriginal(Throwable e, Function<Throwable, Throwable> handler) {
        throwMappedIfOperationError(e, handler);
        throwException(e);
    }

    public static void throwMappedIfOperationError(Throwable e, Function<Throwable, Throwable> handler) {
        if (ErrorShim.isFipsOperationError(e)) {
            Throwable ex = handler.apply(e);
            if (ex != null && ex != e) {
                if (ex.getCause() == null) ex.initCause(e);
                throwException(ex);
            }
        }
        // don't do anything
    }

    @SuppressWarnings("unchecked")
    public static <E extends Throwable> void throwException(Throwable ex) throws E {
        throw (E) ex;
    }
}
