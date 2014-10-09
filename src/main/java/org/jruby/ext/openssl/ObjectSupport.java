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

import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyBasicObject;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.builtin.Variable;

/**
 * (Ruby) Object support.
 *
 * @author kares
 */
abstract class ObjectSupport {

    @SuppressWarnings("unchecked")
    static RubyString inspect(final RubyBasicObject self) {
        return inspect(self, (List) self.getInstanceVariableList());
    }

    static RubyString inspect(final RubyBasicObject self, final List<Variable> variableList) {
        final Ruby runtime = self.getRuntime();
        return RubyString.newString(runtime, inspect(runtime, self, variableList));
    }

    private static StringBuilder inspect(final Ruby runtime, final RubyBasicObject self,
        final List<Variable> variableList) {
        final StringBuilder part = new StringBuilder();
        String cname = self.getMetaClass().getRealClass().getName();
        part.append("#<").append(cname).append(":0x");
        part.append(Integer.toHexString(System.identityHashCode(self)));

        if (runtime.isInspecting(self)) {
            /* 6:tags 16:addr 1:eos */
            part.append(" ...>");
            return part;
        }
        try {
            runtime.registerInspecting(self);
            final ThreadContext context = runtime.getCurrentContext();
            return inspectObj(context, variableList, part);
        } finally {
            runtime.unregisterInspecting(self);
        }
    }

    private static StringBuilder inspectObj(final ThreadContext context,
        final List<Variable> variableList,
        final StringBuilder part) {
        String sep = "";

        for ( final Variable ivar : variableList ) {
            part.append(sep).append(' ').append( ivar.getName() ).append('=');
            final Object ival = ivar.getValue();
            if ( ival instanceof IRubyObject ) {
                part.append( ((IRubyObject) ival).callMethod(context, "inspect") );
            }
            else { // allow the variable to come formatted (as is) already :
                part.append( ival ); // ival == null ? "nil" : ival.toString()
            }
            sep = ",";
        }
        part.append('>');
        return part;
    }

}
