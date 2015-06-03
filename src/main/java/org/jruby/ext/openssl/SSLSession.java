/*
 * The MIT License
 *
 * Copyright 2015 Karol Bucek.
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

import java.util.Arrays;
import javax.net.ssl.SSLSessionContext;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.OpenSSL._OpenSSLError;
import static org.jruby.ext.openssl.OpenSSL.warn;
import static org.jruby.ext.openssl.SSL._SSL;

/**
 * OpenSSL::SSL::Session
 *
 * @author kares
 */
public class SSLSession extends RubyObject {

    private static final ObjectAllocator SESSION_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new SSLSession(runtime, klass);
        }
    };

    public static void createSession(final Ruby runtime, final RubyModule SSL) { // OpenSSL::SSL
        RubyClass Session = SSL.defineClassUnder("Session", runtime.getObject(), SESSION_ALLOCATOR);
        Session.defineAnnotatedMethods(SSLSession.class);
        // OpenSSL::SSL::Session::SessionError
        RubyClass OpenSSLError = _OpenSSLError(runtime);
        Session.defineClassUnder("SessionError", OpenSSLError, OpenSSLError.getAllocator());
    }

    private javax.net.ssl.SSLSession sslSession;

    SSLSession(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }

    SSLSession(Ruby runtime) {
        this(runtime, (RubyClass) _SSL(runtime).getConstantAt("Session"));
    }

    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject arg) {
        final Ruby runtime = context.runtime;

        if ( arg instanceof SSLSocket ) {
            return initializeImpl(context, (SSLSocket) arg);
        }

        throw runtime.newNotImplementedError("Session#initialize with " + arg.getMetaClass().getName());
    }

    SSLSession initializeImpl(final ThreadContext context, final SSLSocket socket) {
        sslSession = socket.getSession();
        return this;
    }

    final javax.net.ssl.SSLSession sslSession() {
        return sslSession;
    }

    @JRubyMethod(name = "==")
    public IRubyObject op_eqq(final ThreadContext context, final IRubyObject other) {
        if ( other instanceof SSLSession ) {
            final SSLSession that = (SSLSession) other;
            if ( this.sslSession.getProtocol().equals( that.sslSession.getProtocol() ) ) {
                if ( Arrays.equals( this.sslSession.getId(), that.sslSession.getId() ) ) {
                    return context.runtime.getTrue();
                }
            }
        }
        return context.runtime.getFalse();
    }

    @JRubyMethod(name = "id")
    public RubyString id(final ThreadContext context) {
        final byte[] id = sslSession().getId();
        return context.runtime.newString( new ByteList(id) );
    }

    @JRubyMethod(name = "id=")
    public IRubyObject set_id(final ThreadContext context, IRubyObject id) {
        warn(context, "WARNING: Session#id= is not supported (read-only)");
        return context.nil;
    }

    @JRubyMethod(name = "time")
    public RubyTime time(final ThreadContext context) {
        final long time = sslSession().getCreationTime();
        return RubyTime.newTime(context.runtime, time);
    }

    @JRubyMethod(name = "time=")
    public IRubyObject set_time(final ThreadContext context, IRubyObject time) {
        warn(context, "WARNING: Session#time= is not supported (read-only)");
        return context.nil;
    }

    @JRubyMethod(name = "timeout")
    public IRubyObject timeout(final ThreadContext context) {
        final SSLSessionContext sessionContext = sslSession().getSessionContext();
        if ( sessionContext == null ) return context.nil;
        return context.runtime.newFixnum(sessionContext.getSessionTimeout());
    }

    @JRubyMethod(name = "timeout=")
    public IRubyObject set_timeout(final ThreadContext context, IRubyObject timeout) {
        final SSLSessionContext sessionContext = sslSession().getSessionContext();
        if ( sessionContext == null ) {
            warn(context, "WARNING: can not set Session#timeout=("+ timeout +") no session context");
            return context.nil;
        }
        final long t = timeout.convertToInteger().getLongValue();
        sessionContext.setSessionTimeout((int) t); // in seconds as well
        return timeout;
    }

    @Override
    public Object toJava(Class target) {
        if ( javax.net.ssl.SSLSession.class.isAssignableFrom(target) ) {
            return sslSession();
        }
        return super.toJava(target);
    }

}
