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

import java.io.IOException;

import org.jruby.Ruby;
import org.jruby.RubyBasicObject;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.exceptions.RaiseException;
import org.jruby.internal.runtime.methods.DynamicMethod;
import org.jruby.internal.runtime.methods.UndefinedMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
final class Utils {

    private Utils() {}

    static RaiseException newIOError(Ruby runtime, IOException e) {
        RaiseException ex = newIOError(runtime, e.getMessage());
        ex.initCause(e);
        return ex;
    }

    static RaiseException newIOError(Ruby runtime, String msg) {
        return new RaiseException(runtime, runtime.getIOError(), msg, true);
    }

    static RaiseException newRuntimeError(Ruby runtime, Exception e) {
        RaiseException ex = newRuntimeError(runtime, e.getMessage());
        ex.initCause(e);
        return ex;
    }

    static RaiseException newArgumentError(Ruby runtime, Exception e) {
        return newError(runtime, runtime.getArgumentError(), e);
    }

    static RaiseException newRuntimeError(Ruby runtime, String msg) {
        return new RaiseException(runtime, runtime.getRuntimeError(), msg, true);
    }

    static RaiseException newError(Ruby runtime, RubyClass errorClass, String message, boolean nativeException) {
        return new RaiseException(runtime, errorClass, message, nativeException);
    }

    static RaiseException newError(Ruby runtime, RubyClass errorClass, Throwable e) {
        return newError(runtime, errorClass, e.getMessage(), e);
    }

    static RaiseException newError(Ruby runtime, RubyClass errorClass, String msg) {
        return newError(runtime, errorClass, msg, true);
    }

    static RaiseException newError(Ruby runtime, RubyClass errorClass, String msg, Throwable e) {
        RaiseException ex = newError(runtime, errorClass, msg);
        ex.initCause(e);
        return ex;
    }

    static boolean hasNonNilInstanceVariable(final IRubyObject self, final String var) {
        final IRubyObject val = self.getInstanceVariables().getInstanceVariable(var);
        return val != null && ! val.isNil();
    }

    // reinvented parts of org.jruby.runtime.Helpers for compatibility with "older" JRuby :

    static IRubyObject invoke(ThreadContext context, IRubyObject self, String name, Block block) {
        return self.getMetaClass().finvoke(context, self, name, block);
    }

    static IRubyObject invokeSuper(ThreadContext context, IRubyObject self, IRubyObject[] args, Block block) {
        return invokeSuper(context, self, context.getFrameKlazz(), context.getFrameName(), args, block);
    }

    static IRubyObject invokeSuper(ThreadContext context, IRubyObject self, RubyModule klass, String name, IRubyObject[] args, Block block) {
        checkSuperDisabledOrOutOfMethod(context, klass, name);

        RubyClass superClass = findImplementerIfNecessary(self.getMetaClass(), klass).getSuperClass();
        DynamicMethod method = superClass != null ? superClass.searchMethod(name) : UndefinedMethod.INSTANCE;
        // NOTE: method_missing not implemented !
        //if (method.isUndefined()) {
        //    return callMethodMissing(context, self, method.getVisibility(), name, CallType.SUPER, args, block);
        //}
        return method.call(context, self, superClass, name, args, block);
    }

    private static void checkSuperDisabledOrOutOfMethod(ThreadContext context, RubyModule klass, String name) {
        if (klass == null) {
            if (name != null) {
                throw context.runtime.newNameError("superclass method '" + name + "' disabled", name);
            } else {
                throw context.runtime.newNoMethodError("super called outside of method", null, context.nil);
            }
        }
    }

    private static RubyModule findImplementerIfNecessary(RubyModule clazz, RubyModule implementationClass) {
        if (implementationClass != null && implementationClass.needsImplementer()) {
            // modules are included with a shim class; we must find that shim to handle super() appropriately
            return clazz.findImplementer(implementationClass);
        } else {
            // classes are directly in the hierarchy, so no special logic is necessary for implementer
            return implementationClass;
        }
    }

}// Utils
