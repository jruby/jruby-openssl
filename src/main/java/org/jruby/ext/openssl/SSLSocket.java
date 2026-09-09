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
 * Copyright (C) 2006, 2007 Ola Bini <ola@ologix.com>
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
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

import org.jruby.*;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.X509Utils;
import org.jruby.javasupport.JavaUtil;
import org.jruby.runtime.*;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.callsite.FunctionalCachingCallSite;
import org.jruby.runtime.callsite.RespondToCallSite;
import org.jruby.util.ByteList;
import org.jruby.ext.openssl.log.Logger;

import static org.jruby.ext.openssl.SSL.newSSLErrorWaitReadable;
import static org.jruby.ext.openssl.SSL.newSSLErrorWaitWritable;
import static org.jruby.ext.openssl.util.RubySupport.invokeSuper;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newIOError;
import static org.jruby.ext.openssl.util.RubySupport.newRuntimeError;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSLSocket extends RubyObject {

    private static final long serialVersionUID = -2084816623554406237L;
    private static final Logger LOG = Logger.getLogger(SSLSocket.class);

    private enum CallSiteIndex {
        // self
        //hostname("hostname"),
        verify_certificate_identity_internal("verify_certificate_identity_internal"),
        // io
        _respond_to_nonblock_w("nonblock="),
        nonblock_w("nonblock="),
        sync("sync"),
        sync_w("sync="),
        flush("flush"),
        // ssl_context
        verify_mode("verify_mode");

        final String method;

        CallSiteIndex(String method) { this.method = method; }

    }

    public static void createSSLSocket(final Ruby runtime, final RubyModule SSL) { // OpenSSL::SSL
        CallSiteIndex[] values = CallSiteIndex.values();
        CallSite[] extraCallSites = new CallSite[values.length];
        for (int i = 0; i < values.length; i++) {
            if (values[i].name().startsWith("_respond_to")) {
                extraCallSites[i] = new RespondToCallSite();
            }
            else {
                extraCallSites[i] = new FunctionalCachingCallSite(values[i].method);
            }
        }

        RubyClass SSLSocket = runtime.defineClassUnder("SSLSocket", runtime.getObject(),
                (r, klass) -> new SSLSocket(r, klass), SSL, extraCallSites);

        final ThreadContext context = runtime.getCurrentContext();

        SSLSocket.addReadWriteAttribute(context, "sync_close");
        SSLSocket.addReadWriteAttribute(context, "hostname");
        SSLSocket.defineAnnotatedMethods(SSLSocket.class);
        SSLSocket.undefineMethod("dup");
    }

    public SSLSocket(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    private static RaiseException newSSLError(Ruby runtime, Exception exception) {
        return SSL.newSSLError(runtime, exception);
    }

    private static RaiseException newSSLError(Ruby runtime, String message) {
        return SSL.newSSLError(runtime, message);
    }

    private static RaiseException newSSLErrorFromHandshake(Ruby runtime, SSLHandshakeException exception) {
        // SSLHandshakeException is always a wrap around another exception that
        // is the actual cause. In some cases the diagnostic message from the original
        // exception is also lost and the handshake exception reads "General SSLEngine problem"
        // Follow the cause chain until we get the real message and use that to ensure
        // we raise an exception that contains the real reason for failure
        Exception cause = exception;
        while (cause.getCause() != null && (cause instanceof SSLHandshakeException)) {
            cause = (Exception) cause.getCause();
        }
        return SSL.newSSLError(runtime, cause);
    }

    // JSSE may abort a handshake with a plain runtime exception (e.g. no protocol left enabled)
    private static RaiseException newSSLErrorFromException(Ruby runtime, Exception exception) {
        LOG.debugStack(runtime, null, exception);
        if ( "Could not generate DH keypair".equals( exception.getMessage() ) ) {
            return SSL.handleCouldNotGenerateDHKeyPairError(runtime, exception);
        }
        return SSL.newSSLError(runtime, exception);
    }

    private static CallSite callSite(final CallSite[] sites, final CallSiteIndex index) {
        return sites[ index.ordinal() ];
    }

    private static final ByteBuffer EMPTY_DATA = ByteBuffer.allocate(0).asReadOnlyBuffer();


    SSLContext sslContext;
    private SSLEngine engine;
    private RubyIO io;

    // concurrency contract (~ MRI SSLSocket): one reader + one writer thread at a time,
    // e.g. net/imap reads on a receiver thread while the main thread writes commands
    // MRI needs no locking since OpenSSL serializes all outbound bytes internally;
    // in JOSSL outbound side (netWriteData + engine.wrap + channel writes) is shared between
    // write() and read-triggered flushes/handshake wraps, so it is guarded by writeLock
    //
    // inbound side (netReadData/appReadData + engine.unwrap) is single-reader and lock-free
    ByteBuffer appReadData;
    ByteBuffer netReadData;
    ByteBuffer netWriteData;
    private final Object writeLock = new Object();

    private volatile boolean initialHandshake = false;
    private transient long initializeTime;

    // mutated by both the reader and writer thread (only writes are writeLock-guarded)
    private volatile SSLEngineResult.HandshakeStatus handshakeStatus; // != null after hand-shake starts
    private volatile SSLEngineResult.Status status;

    int verifyResult = X509Utils.V_OK;

    // client requested SNI host name, captured during server handshake
    private volatile String requestedServerName;

    @JRubyMethod(name = "initialize", rest = true, frame = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        if (Arity.checkArgumentCount(runtime, args, 1, 2) == 1) {
            this.sslContext = new SSLContext(runtime).initializeImpl();
        } else {
            if (!(args[1] instanceof SSLContext)) {
                throw runtime.newTypeError(args[1], "OpenSSL::SSL::SSLContext");
            }
            this.sslContext = (SSLContext) args[1];
        }

        if (!(args[0] instanceof RubyIO)) {
            throw runtime.newTypeError("IO expected but got " + args[0].getMetaClass().getName());
        }
        setInstanceVariable("@io", this.io = (RubyIO) args[0]); // RubyBasicSocket extends RubyIO
        set_io_nonblock_checked(context, runtime.getTrue());
        // This is a bit of a hack: SSLSocket should share code with
        // RubyBasicSocket, which always sets sync to true.
        // Instead we set it here for now.
        set_sync(context, runtime.getTrue()); // io.sync = true
        setInstanceVariable("@sync_close", runtime.getFalse()); // self.sync_close = false
        sslContext.doSetup(context);
        setInstanceVariable("@context", sslContext); // only compat (we do not use @context)

        this.initializeTime = System.currentTimeMillis();

        return invokeSuper(context, this, args, Block.NULL_BLOCK); // super()
    }

    private IRubyObject set_io_nonblock_checked(final ThreadContext context, RubyBoolean value) {
        // @io.nonblock = true if @io.respond_to?(:nonblock=)
        final CallSite[] sites = getMetaClass().getExtraCallSites();
        if (sites == null) return fallback_set_io_nonblock_checked(context, value);
        IRubyObject respond = callSite(sites, CallSiteIndex._respond_to_nonblock_w).call(context, io, io, context.runtime.newSymbol("nonblock="));
        if (respond.isTrue()) {
            return callSite(sites, CallSiteIndex.nonblock_w).call(context, io, io, value);
        }
        return context.nil;
    }

    private IRubyObject fallback_set_io_nonblock_checked(ThreadContext context, RubyBoolean value) {
        if (io.respondsTo("nonblock=")) {
            return io.callMethod(context, "nonblock=", value);
        }
        return context.nil;
    }

    private static final String SESSION_SOCKET_ID = "socket_id";

    SSLEngine ossl_ssl_setup(final ThreadContext context, final boolean server) {
        SSLEngine engine = this.engine;
        if ( engine != null ) return engine;

        // Server Name Indication (SNI) RFC 3546
        // SNI support will not be attempted unless hostname is explicitly set by the caller
        IRubyObject hostname = getInstanceVariable("@hostname");
        String peerHost = hostname == null ? null : hostname.toString();
        final int peerPort = socketChannelImpl().getRemotePort();
        engine = sslContext.createSSLEngine(peerHost, peerPort);

        final javax.net.ssl.SSLSession session = engine.getSession();
        netReadData = ByteBuffer.allocate(session.getPacketBufferSize());
        appReadData = ByteBuffer.allocate(session.getApplicationBufferSize());
        netWriteData = ByteBuffer.allocate(session.getPacketBufferSize());
        netReadData.limit(0);
        appReadData.limit(0);
        netWriteData.limit(0);

        this.engine = engine;
        tryResumeSessionIfSet(context);

        sslContext.setApplicationProtocolsOrSelector(engine);

        return engine;
    }

    @JRubyMethod(name = "io", alias = "to_io")
    public final RubyIO io() { return this.io; }

    @JRubyMethod(name = "context")
    public final SSLContext context() { return this.sslContext; }

    @JRubyMethod(name = "alpn_protocol")
    public IRubyObject alpn_protocol(final ThreadContext context) {
        if ( engine == null ) return context.nil;
        final String protocol = engine.getApplicationProtocol();
        // null if it has not yet been determined if alpn might be used for this connection,
        // an empty String if application protocols values will not be used,
        if (protocol == null || protocol.isEmpty()) return context.nil;
        return RubyString.newString(context.runtime, protocol);
    }

    @JRubyMethod(name = "sync")
    public IRubyObject sync(final ThreadContext context) {
        final CallSite[] sites = getMetaClass().getExtraCallSites();
        if (sites == null) return fallback_sync(context);
        return callSite(sites, CallSiteIndex.sync).call(context, io, io); // io.sync
    }

    private IRubyObject fallback_sync(final ThreadContext context) {
        return io.callMethod(context, "sync");
    }

    @JRubyMethod(name = "sync=")
    public IRubyObject set_sync(final ThreadContext context, final IRubyObject sync) {
        final CallSite[] sites = getMetaClass().getExtraCallSites();
        if (sites == null) return fallback_set_sync(context, sync);
        return callSite(sites, CallSiteIndex.sync_w).call(context, io, io, sync); // io.sync = sync
    }

    private IRubyObject fallback_set_sync(final ThreadContext context, final IRubyObject sync) {
        return io.callMethod(context, "sync=", sync);
    }

    @JRubyMethod
    public IRubyObject connect(final ThreadContext context) {
        return connectImpl(context, true, true);
    }

    @JRubyMethod
    public IRubyObject connect_nonblock(final ThreadContext context) {
        return connectImpl(context, false, true);
    }

    @JRubyMethod
    public IRubyObject connect_nonblock(final ThreadContext context, IRubyObject opts) {
        return connectImpl(context, false, getExceptionOpt(context, opts));
    }

    private IRubyObject connectImpl(final ThreadContext context, final boolean blocking, final boolean exception) {
        if ( ! sslContext.isProtocolForClient() ) {
            throw newSSLError(context.runtime, "called a function you should not call");
        }

        sslContext.sessionConnectCount++;

        try {
            if ( ! initialHandshake ) {
                SSLEngine engine = ossl_ssl_setup(context, false);
                engine.setUseClientMode(true);
                engine.beginHandshake();
                handshakeStatus = engine.getHandshakeStatus();
                initialHandshake = true;
            }
            // MRI only fires renegotiation_cb on the server (accept) side
            final IRubyObject ex = doHandshake(blocking, exception);
            if ( ex != null ) return ex; // :wait_readable | :wait_writable
        }
        catch (SSLHandshakeException e) {
            //debugStackTrace(runtime, e);
            // unlike server side, client should close outbound channel even if we have remaining data to be sent
            forceClose();
            throw newSSLErrorFromHandshake(context.runtime, e);
        }
        catch (IOException e) {
            //debugStackTrace(context.runtime, e);
            forceClose();
            throw newSSLError(context.runtime, e);
        }
        catch (NotYetConnectedException e) {
            throw newErrnoEPIPEError(context.runtime, "SSL_connect");
        }
        catch (RaiseException e) {
            throw e;
        }
        catch (Exception e) {
            forceClose();
            throw newSSLErrorFromException(context.runtime, e);
        }

        // MRI enforces verify_hostname inside OpenSSL ossl_ssl_verify_callback during the handshake
        // JSSE has no equivalent hook, so we check after the handshake completes
        verifyHostnameConnectionCheck(context);

        sslContext.sessionConnectGoodCount++;
        callSessionNewCallback(context);

        return this;
    }

    private static RaiseException newErrnoEPIPEError(final Ruby runtime, final String detail) {
        return newError(runtime, runtime.getErrno().getClass("EPIPE"), detail);
    }

    @JRubyMethod
    public IRubyObject accept(final ThreadContext context) {
        return acceptImpl(context, true, true);
    }

    @JRubyMethod
    public IRubyObject accept_nonblock(final ThreadContext context) {
        return acceptImpl(context, false, true);
    }

    @JRubyMethod
    public IRubyObject accept_nonblock(final ThreadContext context, IRubyObject opts) {
        return acceptImpl(context, false, getExceptionOpt(context, opts));
    }

    private IRubyObject acceptImpl(final ThreadContext context, final boolean blocking, final boolean exception) {
        if ( ! sslContext.isProtocolForServer() ) {
            throw newSSLError(context.runtime, "called a function you should not call");
        }

        sslContext.sessionAcceptCount++;

        try {
            if ( ! initialHandshake ) {
                final SSLEngine engine = ossl_ssl_setup(context, true);
                engine.setUseClientMode(false);
                final IRubyObject verify_mode = verify_mode(context);
                if ( verify_mode != context.nil ) {
                    final int verify = RubyNumeric.fix2int(verify_mode);
                    if ( verify == 0 ) { // VERIFY_NONE
                        engine.setNeedClientAuth(false);
                        engine.setWantClientAuth(false);
                    }
                    if ( ( verify & 1 ) != 0 ) { // VERIFY_PEER
                        engine.setWantClientAuth(true);
                    }
                    if ( ( verify & 2 ) != 0 ) { // VERIFY_FAIL_IF_NO_PEER_CERT
                        engine.setNeedClientAuth(true);
                    }
                }
                // BC-JSSE (unlike SunJSSE) only surfaces the client's SNI when a matcher is set
                final SSLParameters sslParams = engine.getSSLParameters();
                sslParams.setSNIMatchers(Collections.singletonList(new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
                    @Override
                    public boolean matches(SNIServerName serverName) {
                        if (serverName instanceof SNIHostName) {
                            requestedServerName = ((SNIHostName) serverName).getAsciiName();
                        }
                        return true;
                    }
                }));
                engine.setSSLParameters(sslParams);
                engine.beginHandshake();
                handshakeStatus = engine.getHandshakeStatus();
                initialHandshake = true;
            }
            callRenegotiationCallback(context);
            final IRubyObject ex = doHandshake(blocking, exception);
            if ( ex != null ) return ex; // :wait_readable | :wait_writable
        }
        catch (SSLHandshakeException e) {
            final String msg = e.getMessage();
            // updated JDK (>= 1.7.0_75) with deprecated SSL protocols :
            // javax.net.ssl.SSLHandshakeException: No appropriate protocol (protocol is disabled or cipher suites are inappropriate)
            if ( e.getCause() == null && msg != null &&
                 msg.contains("(protocol is disabled or cipher suites are inappropriate)") )  {
                LOG.debug(context.runtime, sslContext.getProtocol() + " protocol has been deactivated and is not available by default\n see the java.security.Security property jdk.tls.disabledAlgorithms in <JRE_HOME>/lib/security/java.security file");
            }
            else {
                LOG.debugStack(context.runtime, null, e);
            }
            throw newSSLErrorFromHandshake(context.runtime, e);
        }
        catch (IOException e) {
            LOG.debugStack(context.runtime, null, e);
            throw newSSLError(context.runtime, e);
        }
        catch (RaiseException e) {
            throw e;
        }
        catch (Exception e) {
            throw newSSLErrorFromException(context.runtime, e);
        }

        sslContext.sessionAcceptGoodCount++;
        callServernameCallback(context);
        callSessionNewCallback(context);

        return this;
    }

    // fires servername_cb on the server after handshake with the client's SNI hostname;
    // MRI fires during handshake via SSL_CTX_set_tlsext_servername_callback and can switch SSL_CTX;
    // JSSE does not support mid-handshake context switching so we fire after the handshake
    private void callServernameCallback(final ThreadContext context) {
        IRubyObject callback = sslContext.getInstanceVariable("@servername_cb");
        if (callback == null || callback.isNil()) return;

        String serverName = requestedServerName; // captured during the handshake
        if (serverName == null) serverName = BCSSLSupport.getRequestedServerName(engine);
        if (serverName == null) return;

        final Ruby runtime = context.runtime;
        final IRubyObject args = runtime.newArray(this, runtime.newString(serverName));
        final IRubyObject ret = callback.callMethod(context, "call", args);

        if (ret instanceof SSLContext) { // MRI stores returned context as @context
            // mostly useless: cannot switch engine's SSL context post-handshake
            setInstanceVariable("@context", ret);
            // this.sslContext = (SSLContext) ret;
        } else if (!ret.isNil()) {
            throw runtime.newArgumentError("servername_cb must return OpenSSL::SSL::SSLContext object or nil " +
                    "(got: " + ret.inspect() + ")");
         }
    }

    private void verifyHostnameConnectionCheck(final ThreadContext context) {
        final IRubyObject verifyHostname = sslContext.getInstanceVariable("@verify_hostname");
        if (verifyHostname == null || !verifyHostname.isTrue()) return;

        // MRI verifies hostname inside the OpenSSL verify callback, which only runs when peer
        // verification is enabled; under VERIFY_NONE nothing (incl. the hostname) is verified
        final IRubyObject verifyMode = verify_mode(context);
        if (verifyMode.isNil() || RubyNumeric.fix2int(verifyMode) == 0) return; // VERIFY_NONE

        final IRubyObject hostname = getInstanceVariable("@hostname");
        if (hostname == null || hostname.isNil()) return;

        // MRI calls verify_certificate_identity inside the OpenSSL verify callback
        // and sets V_ERR_HOSTNAME_MISMATCH only when it returns false
        final CallSite[] sites = getMetaClass().getExtraCallSites();
        final IRubyObject result = sites == null
                ? callMethod(context, "verify_certificate_identity_internal", hostname)
                : callSite(sites, CallSiteIndex.verify_certificate_identity_internal).call(context, this, this, hostname);

        if (result.isTrue()) {
            // stash verified hostname so a subsequent explicit post_connection_check
            // (e.g. from net/http) does not execute the check twice
            setInstanceVariable("@verified_hostname", hostname);
        } else if (!result.isNil()) { // false
            sslContext.setLastVerifyResult(verifyResult = X509Utils.V_ERR_HOSTNAME_MISMATCH);
            forceClose(); // tear down like the handshake-failure paths (client sends close_notify)
            throw newSSLError(context.runtime, // same as `post_connection_check(hostname)`
                    "hostname \"" + hostname + "\" does not match the server certificate");
        }
    }

    final IRubyObject verify_mode(final ThreadContext context) {
        final CallSite[] sites = getMetaClass().getExtraCallSites();
        if (sites == null) return fallback_verify_mode(context);
        return callSite(sites, CallSiteIndex.verify_mode).call(context, sslContext, sslContext);
    }

    private IRubyObject fallback_verify_mode(final ThreadContext context) {
        return sslContext.callMethod(context, "verify_mode");
    }

    @JRubyMethod
    public IRubyObject verify_result(final ThreadContext context) {
        if (engine == null) {
            LOG.warn(context.runtime, "verify_result SSL session is not started yet");
            return context.nil;
        }
        return context.runtime.newFixnum(verifyResult);
    }

    // This select impl is a copy of RubyThread.select, then blockingLock is
    // removed. This impl just set
    // SelectableChannel.configureBlocking(false) permanently instead of setting
    // temporarily. SSLSocket requires wrapping IO to be selectable so it should
    // be OK to set configureBlocking(false) permanently.
    private Object waitSelect(final int operations, final boolean blocking, final boolean exception)
        throws IOException {
        final SocketChannelImpl channel = socketChannelImpl();
        if ( ! channel.isSelectable() ) return Boolean.TRUE;

        final Ruby runtime = getRuntime();
        final RubyThread thread = runtime.getCurrentContext().getThread();

        channel.configureBlocking(false);
        final Selector selector = runtime.getSelectorPool().get();
        SelectionKey key = null;

        if ( blocking ) io.addBlockingThread(thread);

        try {
            key = channel.register(selector, operations);
            final int[] result = new int[1];

            if ( ! blocking ) {
                try {
                    result[0] = selector.selectNow();

                    if (result[0] == 0) {
                        if ((operations & SelectionKey.OP_READ) != 0 && (operations & SelectionKey.OP_WRITE) != 0) {
                            if (key.isReadable()) {
                                writeWouldBlock(runtime, exception, result);
                            }
                            //else if ( key.isWritable() ) {
                            //    readWouldBlock(runtime, exception, result);
                            //}
                            else { //neither, pick one
                                readWouldBlock(runtime, exception, result);
                            }
                        } else if ((operations & SelectionKey.OP_READ) != 0) {
                            readWouldBlock(runtime, exception, result);
                        } else if ((operations & SelectionKey.OP_WRITE) != 0) {
                            writeWouldBlock(runtime, exception, result);
                        }
                    }
                } catch (ClosedSelectorException ex) {
                    throw newRuntimeError(runtime, "selector closed", ex);
                } catch (IOException ex) {
                    throw newIOError(runtime, ex);
                }
            } else {
                thread.executeBlockingTask(new RubyThread.BlockingTask() {
                    public void run() {
                        try {
                            result[0] = selector.select();
                        } catch (ClosedSelectorException ex) {
                            throw newRuntimeError(runtime, "selector closed", ex);
                        } catch (IOException ex) {
                            throw newIOError(runtime, ex);
                        }
                    }

                    public void wakeup() {
                        selector.wakeup();
                    }
                });
            }

            switch ( result[0] ) {
                case READ_WOULD_BLOCK_RESULT :
                    return runtime.newSymbol("wait_readable"); // exception: false
                case WRITE_WOULD_BLOCK_RESULT :
                    return runtime.newSymbol("wait_writable"); // exception: false
                case 0 : return Boolean.FALSE;
                default :
                    //key should always be contained in selectedKeys() here, however there is a bug in
                    //JRuby <= 9.1.2.0 that makes this not always the case, so we have to check
                    return selector.selectedKeys().contains(key) ?  Boolean.TRUE : Boolean.FALSE;
            }
        } catch (InterruptedException interrupt) {
            LOG.debug(runtime, "waitSelect", interrupt);
            return Boolean.FALSE;
        } finally {
            // Note: I don't like ignoring these exceptions, but it's unclear how likely they are to happen or what
            // damage we might do by ignoring them. Note that the pieces are separate so that we can ensure one failing
            // does not affect the others running.

            // clean up the key in the selector
            try {
                if ( key != null ) key.cancel();
                if ( selector != null ) selector.selectNow();
            } catch (Exception e) { // ignore
                LOG.debugStack(runtime, "waitSelect (ignored)", e);
            }

            // shut down and null out the selector
            try {
                if ( selector != null ) runtime.getSelectorPool().put(selector);
            } catch (Exception e) { // ignore
                LOG.debugStack(runtime, "waitSelect (ignored)", e);
            }

            if (blocking) {
                // remove this thread as a blocker against the given IO
                io.removeBlockingThread(thread);

                // clear thread state from blocking call
                thread.afterBlockingCall();
            }
        }
    }

    // return values are -1 (EOF) and >= 0 (byte counts), so any value < -1 is safe to use
    private static final int READ_WOULD_BLOCK_RESULT  = -2;
    private static final int WRITE_WOULD_BLOCK_RESULT = -3;

    private static boolean isWouldBlockResult(final int result) {
        return result < -1;
    }

    private RubySymbol wouldBlockSymbol(final int result) {
        assert isWouldBlockResult(result) : "unexpected result: " + result;
        return getRuntime().newSymbol(result == READ_WOULD_BLOCK_RESULT ? "wait_readable" : "wait_writable");
    }

    private static void readWouldBlock(final Ruby runtime, final boolean exception, final int[] result) {
        if ( exception ) throw newSSLErrorWaitReadable(runtime, "read would block");
        result[0] = READ_WOULD_BLOCK_RESULT;
    }

    private static void writeWouldBlock(final Ruby runtime, final boolean exception, final int[] result) {
        if ( exception ) throw newSSLErrorWaitWritable(runtime, "write would block");
        result[0] = WRITE_WOULD_BLOCK_RESULT;
    }

    // might return :wait_readable | :wait_writable in case (true, false)
    private IRubyObject doHandshake(final boolean blocking, final boolean exception) throws IOException {
        while (true) {
            Object sel = waitSelect(SelectionKey.OP_READ | SelectionKey.OP_WRITE, blocking, exception);
            if ( sel instanceof IRubyObject ) return (IRubyObject) sel; // :wait_readable | :wait_writable

            // if not blocking, raise EAGAIN
            if ( ! blocking && sel != Boolean.TRUE ) {
                throw getRuntime().newErrnoEAGAINError("Resource temporarily unavailable");
            }

            // otherwise, proceed as before
            switch (handshakeStatus) {
            case FINISHED:
            case NOT_HANDSHAKING:
                if ( initialHandshake ) finishInitialHandshake();
                return null; // OK
            case NEED_TASK:
                doTasks();
                break;
            case NEED_UNWRAP:
                int unwrapResult = readAndUnwrap(blocking, exception);
                if (isWouldBlockResult(unwrapResult)) return wouldBlockSymbol(unwrapResult);
                if (unwrapResult == -1 && handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED) {
                    throw new SSLHandshakeException("Socket closed");
                }
                // during initialHandshake, calling readAndUnwrap that results UNDERFLOW does not mean writable.
                // we explicitly wait for readable channel to avoid busy loop.
                if (initialHandshake && status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    sel = waitSelect(SelectionKey.OP_READ, blocking, exception);
                    if ( sel instanceof IRubyObject ) return (IRubyObject) sel; // :wait_readable
                }
                break;
            case NEED_WRAP:
                synchronized (writeLock) { // post-handshake wraps (renegotiation) may race a write()
                    doWrap(blocking);
                    flushData(blocking);
                    assert status != SSLEngineResult.Status.BUFFER_UNDERFLOW;
                    if (status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        netWriteData.compact();
                        netWriteData = ensureCapacity(netWriteData, engine.getSession().getPacketBufferSize());
                        netWriteData.flip();
                        if (handshakeStatus != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                            sel = waitSelect(SelectionKey.OP_WRITE, blocking, exception);
                            if ( sel instanceof IRubyObject ) return (IRubyObject) sel; // :wait_writeable
                        }
                    }
                }
                break;
            default:
                throw new IllegalStateException("Unknown handshaking status: " + handshakeStatus);
            }
        }
    }

    private void doWrap(final boolean blocking) throws IOException {
        synchronized (writeLock) {
            // drain leftover encrypted bytes first
            // clear() would silently discard them, corrupting TLS record stream
            while ( netWriteData.hasRemaining() && flushData(blocking) ) { /* loop */ }
            netWriteData.clear();
            SSLEngineResult result = engine.wrap(EMPTY_DATA.duplicate(), netWriteData);
            netWriteData.flip();
            handshakeStatus = result.getHandshakeStatus();
            status = result.getStatus();
            if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK && status == SSLEngineResult.Status.OK) {
                doTasks();
            }
        }
    }

    private void doTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
        handshakeStatus = engine.getHandshakeStatus();
        verifyResult = sslContext.getLastVerifyResult();
    }

    /**
     * @param blocking
     * @return whether buffer has remaining data
     * @throws IOException
     */
    private boolean flushData(boolean blocking) throws IOException {
        synchronized (writeLock) {
            try {
                writeToChannel(netWriteData, blocking);
            }
            catch (IOException ex) {
                netWriteData.position(netWriteData.limit());
                throw ex;
            }
            return netWriteData.hasRemaining();
        }
    }

    final int writeToChannel(ByteBuffer buffer, boolean blocking) throws IOException {
        final SocketChannelImpl channel = socketChannelImpl();
        int totalWritten = 0;
        while ( buffer.hasRemaining() ) {
            final int written = channel.write(buffer);
            totalWritten += written;
            if ( written == 0 ) {
                if ( blocking && !channel.isBlocking() && channel.isSelectable() ) {
                    if (waitSelect(SelectionKey.OP_WRITE, true, true) != Boolean.TRUE) break;
                } else {
                    break;
                }
            }

            if ( ! blocking ) break; // don't continue attempting to read
        }
        return totalWritten;
    }

    private void finishInitialHandshake() {
        initialHandshake = false;
        // sync the verify result the trust manager recorded during the handshake
        // BCJSSE runs the trust check inline (no delegated task) so doTasks() misses
        verifyResult = sslContext.getLastVerifyResult();

        final javax.net.ssl.SSLSession session = engine.getSession();
        if (session.getValue(SESSION_SOCKET_ID) == null) {
            session.putValue(SESSION_SOCKET_ID, getObjectId());
        }
    }

    // fires renegotiation_cb on server-side handshake start (initial + renegotiation)
    private void callRenegotiationCallback(final ThreadContext context) throws RaiseException {
        IRubyObject callback = sslContext.getInstanceVariable("@renegotiation_cb");
        if (callback == null || callback.isNil()) return;
        // can throw ruby exception to "disallow" re-negotiations
        callback.callMethod(context, "call", this);
    }

    // fires session_new_cb after a successful handshake (both client and server)
    private void callSessionNewCallback(final ThreadContext context) {
        IRubyObject callback = sslContext.getInstanceVariable("@session_new_cb");
        if (callback == null || callback.isNil()) return;

        final javax.net.ssl.SSLSession javaSession = sslSession();
        if (javaSession == null || isNullSession(javaSession)) return;

        sslContext.sessionCacheNum++;

        final SSLSession session = getSession(context.runtime);
        final Ruby runtime = context.runtime;
        // MRI passes [ssl_socket, ssl_session] as a single Array argument
        callback.callMethod(context, "call", runtime.newArray(this, session));
    }

    public int write(ByteBuffer src, boolean blocking) throws IOException {
        if ( initialHandshake ) {
            throw new IOException("Writing not possible during handshake");
        }

        SocketChannelImpl channel = socketChannelImpl();
        final boolean blockingMode = channel.isBlocking();
        if ( ! blocking ) channel.configureBlocking(false);

        try {
            synchronized (writeLock) {
                if ( netWriteData.hasRemaining() ) {
                    flushData(blocking);
                }
                // compact() to preserve encrypted bytes flushData could not send (non-blocking partial write)
                // clear() would discard them, corrupting the TLS record stream:
                netWriteData.compact();
                final SSLEngineResult result = engine.wrap(src, netWriteData);
                if ( result.getStatus() == SSLEngineResult.Status.CLOSED ) {
                    throw getRuntime().newIOError("closed SSL engine");
                }
                netWriteData.flip();
                flushData(blocking);
                return result.bytesConsumed();
            }
        }
        finally {
            if ( ! blocking ) channel.configureBlocking(blockingMode);
        }
    }

    public int read(final ByteBuffer dst, final boolean blocking) throws IOException {
        return read(dst, blocking, true);
    }

    private int read(final ByteBuffer dst, final boolean blocking, final boolean exception) throws IOException {
        if ( initialHandshake ) return 0;
        if ( engine.isInboundDone() ) return -1;

        if ( ! appReadData.hasRemaining() ) {
            final int appBytesProduced = readAndUnwrap(blocking, exception);
            if (appBytesProduced == -1 || appBytesProduced == 0 || isWouldBlockResult(appBytesProduced)) {
                return appBytesProduced;
            }
        }
        int limit = Math.min(appReadData.remaining(), dst.remaining());
        appReadData.get(dst.array(), dst.arrayOffset(), limit);
        dst.position(dst.arrayOffset() + limit);
        return limit;
    }

    private int readAndUnwrap(final boolean blocking, final boolean exception) throws IOException {
        final int bytesRead = socketChannelImpl().read(netReadData);
        if ( bytesRead == -1 ) {
            if ( ! netReadData.hasRemaining() ||
                 ( status == SSLEngineResult.Status.BUFFER_UNDERFLOW ) ) {
                closeInbound();
                return -1;
            }
            // inbound channel has been already closed but closeInbound() must be defered till
            // the last engine.unwrap() call; peerNetData could not be empty
        }
        appReadData.clear();
        netReadData.flip();

        SSLEngineResult result;
        do {
            result = engine.unwrap(netReadData, appReadData);
            if ( result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW ) {
                // record produced more data - grow and retry, otherwise full appReadData
                // would make read() return 0 with buffered net data -> busy-loop
                appReadData = ensureCapacity(appReadData, appReadData.position() + engine.getSession().getApplicationBufferSize());
            }
        }
        while ( result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW ||
              ( result.getStatus() == SSLEngineResult.Status.OK &&
				result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP &&
				result.bytesProduced() == 0 ) );

        if ( result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ) {
            finishInitialHandshake();
        }
        if ( appReadData.position() == 0 &&
            result.getStatus() == SSLEngineResult.Status.OK &&
            netReadData.hasRemaining() ) {
            result = engine.unwrap(netReadData, appReadData);
        }
        status = result.getStatus();
        handshakeStatus = result.getHandshakeStatus();

        if ( bytesRead == -1 && ! netReadData.hasRemaining() ) {
            // now it's safe to call closeInbound().
            closeInbound();
        }
        if ( status == SSLEngineResult.Status.CLOSED ) {
            return -1;
        }

        netReadData.compact();
        appReadData.flip();
        if ( ! initialHandshake && (
                handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK ||
                handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP ||
                handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED ) ) {
            // peer-initiated renegotiation; fire callback (server-side only, matching CRuby)
            if (!engine.getUseClientMode()) {
                callRenegotiationCallback(getRuntime().getCurrentContext());
            }
            IRubyObject wouldBlock = doHandshake(blocking, exception);
            if ( wouldBlock != null ) {
                if ("wait_writable".equals(wouldBlock.asJavaString())) {
                    return WRITE_WOULD_BLOCK_RESULT;
                }
                return READ_WOULD_BLOCK_RESULT;
            }
        }
        return appReadData.remaining();
    }

    private void closeInbound() throws SSLException {
        try {
            engine.closeInbound();
        }
        catch (SSLException e) {
            if (!isIgnoreUnexpectedEOF()) throw e;
            LOG.debug(getRuntime(), "closeInbound", e);
        }
    }

    private boolean isIgnoreUnexpectedEOF() {
        return (sslContext.getOptions() & SSL.OP_IGNORE_UNEXPECTED_EOF) != 0;
    }

    /**
     * @throws IOException when data flushing fails
     */
    private void doShutdown() throws IOException {
        synchronized (writeLock) {
            if (flushData(false)) {
                LOG.debug(getRuntime(), "doShutdown remaining write data (can not close)");
                return;
            }

            netWriteData.clear();
            engine.closeOutbound();
            try {
                SSLEngineResult result;
                do {
                    result = engine.wrap(EMPTY_DATA.duplicate(), netWriteData); // send close (after engine.closeOutbound)
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        netWriteData = ensureCapacity(netWriteData, engine.getSession().getPacketBufferSize());
                        continue;
                    }
                    netWriteData.flip();
                    try {
                        flushData(true);
                    }
                    catch (IOException ex) {
                        LOG.debug(getRuntime(), "doShutdown", ex);
                        return;
                    }
                    netWriteData.clear();
                    if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        doTasks();
                    }
                }
                while (!engine.isOutboundDone() &&
                        (result.getStatus() == SSLEngineResult.Status.OK ||
                                result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP));
            }
            catch (SSLException e) {
                LOG.debug(getRuntime(), "doShutdown", e);
            }
            catch (RuntimeException e) {
                LOG.debugStack(getRuntime(), "doShutdown", e);
            }
        }
    }

    /**
     * @return the {@link RubyString} buffer or :wait_readable / :wait_writeable {@link RubySymbol}
     */
    private IRubyObject sysreadImpl(final ThreadContext context,
        final IRubyObject len, final IRubyObject buff, final boolean blocking, final boolean exception) {
        final Ruby runtime = context.runtime;

        final int length = RubyNumeric.fix2int(len);
        final RubyString buffStr;

        if ( !buff.isNil() ) {
            buffStr = buff.convertToString();
        } else {
            buffStr = RubyString.newEmptyString(runtime); // fine since we'll setValue
        }
        if ( length == 0 ) {
            buffStr.clear();
            return buffStr;
        }
        if ( length < 0 ) {
            throw runtime.newArgumentError("negative string size (or size too big)");
        }
        if ( engine == null ) { // connect/accept never ran: never read plaintext off the raw channel
            throw newSSLError(runtime, "SSL session is not started yet");
        }

        try {
            // flush pending write before reading (after write_nonblock bytes may be buffered)
            // writeLock: don't inspect/flush netWriteData while another thread is writing...
            synchronized (writeLock) {
                if ( engine != null && netWriteData.hasRemaining() ) {
                    if ( flushData(blocking) && ! blocking ) {
                        if ( exception ) throw newSSLErrorWaitWritable(runtime, "write would block");
                        return runtime.newSymbol("wait_writable");
                    }
                }
            }

            // So we need to make sure to only block when there is no data left to process
            if ( engine == null || ! ( appReadData.hasRemaining() || netReadData.position() > 0 ) ) {
                final Object ex = waitSelect(SelectionKey.OP_READ, blocking, exception);
                if ( ex instanceof IRubyObject ) return (IRubyObject) ex; // :wait_readable
            }

            final ByteBuffer dst = ByteBuffer.allocate(length);
            int read = -1;
            // ensure > 0 bytes read; sysread is blocking read
            while ( read <= 0 ) {
                read = read(dst, blocking, exception);

                if ( read == -1 ) {
                    if ( exception ) throw runtime.newEOFError();
                    return context.nil;
                }

                // post-handshake processing (e.g. TLS 1.3 NewSessionTicket) signaled would-block
                if ( isWouldBlockResult(read) ) return wouldBlockSymbol(read);

                if ( read == 0 && ( status == SSLEngineResult.Status.BUFFER_UNDERFLOW ||
                                    netReadData.position() == 0 ) ) {
                    // wait for more TLS record bytes or after a consumed non-application record
                    final Object ex = waitSelect(SelectionKey.OP_READ, blocking, exception);
                    if ( ex instanceof IRubyObject ) return (IRubyObject) ex; // :wait_readable
                }
            }
            final byte[] bytesRead = dst.array();
            final int offset = dst.position() - read;
            buffStr.setValue(new ByteList(bytesRead, offset, read, false));
            return buffStr;
        }
        catch (SSLException ex) {
            LOG.debugStack(runtime, "sysreadImpl", ex);
            throw newSSLError(runtime, ex);
        }
        catch (IOException ex) {
            LOG.debugStack(runtime, "sysreadImpl", ex);
            throw newError(runtime::newIOErrorFromException, ex);
        }
    }

    @JRubyMethod
    public IRubyObject sysread(ThreadContext context, IRubyObject len) {
        return sysreadImpl(context, len, context.nil, true, true);
    }

    @JRubyMethod
    public IRubyObject sysread(ThreadContext context, IRubyObject len, IRubyObject buff) {
        return sysreadImpl(context, len, buff, true, true);
    }

    @JRubyMethod
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject len) {
        return sysreadImpl(context, len, context.nil, false, true);
    }

    @JRubyMethod
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject len, IRubyObject arg) {
        if ( arg instanceof RubyHash ) { // exception: false
            // NOTE: on Ruby 2.3 this is expected to raise a TypeError (but not on 2.2)
            return sysreadImpl(context, len, context.nil, false, getExceptionOpt(context, arg));
        }
        return sysreadImpl(context, len, arg, false, true); // buffer arg
    }

    @JRubyMethod
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject len, IRubyObject buff, IRubyObject opts) {
        return sysreadImpl(context, len, buff, false, getExceptionOpt(context, opts));
    }

    private IRubyObject syswriteImpl(final ThreadContext context,
        final IRubyObject arg, final boolean blocking, final boolean exception)  {
        final Ruby runtime = context.runtime;
        try {
            checkClosed();
            if ( engine == null ) { // connect/accept never ran: never write plaintext to the raw channel
                throw newSSLError(runtime, "SSL session is not started yet");
            }

            final Object ex = waitSelect(SelectionKey.OP_WRITE, blocking, exception);
            if ( ex instanceof IRubyObject ) return (IRubyObject) ex; // :wait_writable

            ByteList bytes = arg.asString().getByteList();
            ByteBuffer buff = ByteBuffer.wrap(bytes.getUnsafeBytes(), bytes.getBegin(), bytes.getRealSize());
            final int written = write(buff, blocking);

            io_flush(context); // io.flush

            return runtime.newFixnum(written);
        }
        catch (IOException ex) {
            LOG.debugStack(runtime, "syswriteImpl", ex);
            throw newError(runtime::newIOErrorFromException, ex);
        }
    }

    private IRubyObject io_flush(final ThreadContext context) {
        final CallSite[] sites = getMetaClass().getExtraCallSites();
        if (sites == null) return fallback_io_flush(context);
        return callSite(sites, CallSiteIndex.flush).call(context, io, io);
    }

    private IRubyObject fallback_io_flush(final ThreadContext context) {
        return io.callMethod(context, "flush");
    }

    @JRubyMethod
    public IRubyObject syswrite(ThreadContext context, IRubyObject arg) {
        return syswriteImpl(context, arg, true, true);
    }

    @JRubyMethod
    public IRubyObject syswrite_nonblock(ThreadContext context, IRubyObject arg) {
        return syswriteImpl(context, arg, false, true);
    }

    @JRubyMethod
    public IRubyObject syswrite_nonblock(ThreadContext context, IRubyObject arg, IRubyObject opts) {
        return syswriteImpl(context, arg, false, getExceptionOpt(context, opts));
    }

    private static boolean getExceptionOpt(final ThreadContext context, final IRubyObject opts) {
        if ( opts instanceof RubyHash ) { // exception: true
            final Ruby runtime = context.runtime;
            IRubyObject exc = ((RubyHash) opts).op_aref(context, runtime.newSymbol("exception"));
            return exc != runtime.getFalse();
        }
        return true;
    }

    private void checkClosed() {
        if ( ! socketChannelImpl().isOpen() ) {
            throw getRuntime().newIOError("closed stream");
        }
    }

    // do shutdown even if we have remaining data to be sent.
    // call this when you get an exception from client side.
    private void forceClose() {
        close(true);
    }

    private void close(boolean force)  {
        if ( engine == null ) {
            // if ( force ) throw getRuntime().newEOFError();
            return;
        }

        if ( ! force && netWriteData.hasRemaining() ) return;

        try {
            doShutdown();
        }
        catch (IOException|NotYetConnectedException ex) {
            LOG.debug(getRuntime(), "close", ex);
        }
    }

    @JRubyMethod
    public IRubyObject stop(final ThreadContext context) {
        // no need to try shutdown when it's a server
        close( sslContext.isProtocolForClient() );
        return context.nil;
    }

    @JRubyMethod
    public IRubyObject cert(final ThreadContext context) {
        if ( engine == null ) return context.nil;

        try {
            Certificate[] cert = engine.getSession().getLocalCertificates();
            if ( cert != null && cert.length > 0 ) {
                return X509Cert.wrap(context, cert[0]);
            }
        }
        catch (CertificateEncodingException e) {
            throw X509Cert.newCertificateError(context.runtime, e);
        }
        return context.nil;
    }

    @JRubyMethod
    public IRubyObject peer_cert(final ThreadContext context) {
        if ( engine == null ) return context.nil;

        try {
            Certificate[] cert = engine.getSession().getPeerCertificates();
            if ( cert.length > 0 ) {
                return X509Cert.wrap(context, cert[0]);
            }
        }
        catch (CertificateEncodingException e) {
            throw X509Cert.newCertificateError(context.runtime, e);
        }
        catch (SSLPeerUnverifiedException e) {
            LOG.debug(context.runtime, "peer_cert", e);
        }
        return context.nil;
    }

    @JRubyMethod
    public IRubyObject peer_cert_chain(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        if ( engine == null ) return runtime.getNil();

        try {
            Certificate[] certs = engine.getSession().getPeerCertificates();
            IRubyObject[] cert_chain = new IRubyObject[ certs.length ];
            for ( int i = 0; i < certs.length; i++ ) {
                cert_chain[i] = X509Cert.wrap(context, certs[i]);
            }
            return runtime.newArrayNoCopy(cert_chain);
        }
        catch (CertificateEncodingException e) {
            throw X509Cert.newCertificateError(runtime, e);
        }
        catch (SSLPeerUnverifiedException e) {
            LOG.debug(runtime, "peer_cert_chain", e);
        }
        return runtime.getNil();
    }

    @JRubyMethod
    public IRubyObject cipher(final ThreadContext context) {
        if ( engine == null ) return context.nil;
        return sslContext.currentCipherInfo(context, engine.getSession().getCipherSuite());
    }

    @JRubyMethod
    public IRubyObject npn_protocol() {
        if ( engine == null ) return getRuntime().getNil();
        // NOTE: maybe a time to use https://github.com/benmmurphy/ssl_npn
        LOG.warn(getRuntime(), "npn_protocol is not supported");
        return getRuntime().getNil(); // throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject state() {
        LOG.warn(getRuntime(), "state is not implemented");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject pending(ThreadContext context) {
        // SSL_pending: number of decrypted bytes immediately available for reading
        if ( engine == null ) return context.runtime.newFixnum(0); // session not started
        return context.runtime.newFixnum(appReadData == null ? 0 : appReadData.remaining());
    }

    private boolean reusableSSLEngine() {
        if ( engine != null ) {
            final String peerHost = engine.getPeerHost();
            if ( peerHost != null && peerHost.length() > 0 ) {
                // getSSLContext().createSSLEngine() - no hints for session reuse
                return true;
            }
        }
        return false;
    }

    @JRubyMethod(name = "session_reused?")
    public IRubyObject session_reused_p() {
        if (engine == null) {
            throw getRuntime().newRuntimeError("SSL is not initialized");
        }
        if (reusableSSLEngine()) {
            if (!engine.getEnableSessionCreation()) {
                // if session creation is disabled we can be sure its to be re-used
                return getRuntime().getTrue();
            }
            // return getRuntime().getFalse(); // incorrect (we can not decide)
        }
        javax.net.ssl.SSLSession session = engine.getSession();
        if (!isNullSession(session)) {
            if (session.getCreationTime() < this.initializeTime) {
                return getRuntime().getTrue();
            }
            Object socketId = session.getValue(SESSION_SOCKET_ID);
            if (socketId != null && ((Long) socketId).longValue() != getObjectId()) {
                return getRuntime().getTrue();
            }
        }
        return getRuntime().getNil(); // can not decide - probably not
    }

    // JSSE: SSL Sessions can be reused only if connecting to the same host at the same port

    /**
     * @return session object (in case of BCJSSE the {@link org.bouncycastle.jsse.BCExtendedSSLSession})
     */
    final javax.net.ssl.SSLSession sslSession() {
        return engine == null ? null : BCSSLSupport.getBCSession(engine);
    }

    static boolean isNullSession(final javax.net.ssl.SSLSession session) {
        return session == null || "SSL_NULL_WITH_NULL_NULL".equals(session.getCipherSuite());
    }

    private transient SSLSession session;

    @JRubyMethod(name = "session")
    public IRubyObject session(final ThreadContext context) {
        if (sslSession() == null) return context.nil;
        return getSession(context.runtime);
    }

    private SSLSession getSession(final Ruby runtime) {
        if (session == null) {
            session = new SSLSession(runtime).initializeImpl(this);
        }
        return session;
    }

    private transient SSLSession setSession = null;

    @JRubyMethod(name = "session=")
    public IRubyObject set_session(final ThreadContext context, IRubyObject session) {
        if (session instanceof SSLSession) {
            setSession = (SSLSession) session;
            if (engine != null) tryResumeSessionIfSet(context);
            return session;
        }

        Object javaSession = JavaUtil.unwrapJavaValue(session);
        if (javaSession instanceof javax.net.ssl.SSLSession) {
            setSession = new SSLSession(context.runtime, (javax.net.ssl.SSLSession) javaSession);
            if (engine != null) tryResumeSessionIfSet(context);
            return session;
        }

        return context.nil;
    }

    private void tryResumeSessionIfSet(final ThreadContext context) {
        if (setSession == null) return;

        if (BCSSLSupport.setBCSessionToResume(engine, setSession.sslSession())) return;

        // can not support this without the (BC) SSL provider internals (e.g. on SunJSSE)
        // but we can assume setting a session= is meant to be a *forced* session re-use:
        if (reusableSSLEngine()) {
            engine.setEnableSessionCreation(false);
            final SSLSession session = getSession(context.runtime);
            if (!setSession.equals(session)) {
                session.set_timeout(context, setSession.timeout(context));
            }
        }
    }

    @JRubyMethod
    public IRubyObject ssl_version(ThreadContext context) {
        if ( engine == null ) return context.nil;
        return context.runtime.newString( engine.getSession().getProtocol() );
    }

    transient SocketChannelImpl socketChannel;

    private SocketChannelImpl socketChannelImpl() {
        if ( socketChannel != null ) return socketChannel;

        final Channel channel = io.getChannel();
        if ( channel instanceof SocketChannel ) {
            return socketChannel = new JavaSocketChannel((SocketChannel) channel);
        }

        // TODO JNR

        throw new IllegalStateException("unknow channel impl: " + channel + " of type " + channel.getClass().getName());
    }

    interface SocketChannelImpl {

        boolean isOpen() ;

        int read(ByteBuffer dst) throws IOException ;

        int write(ByteBuffer src) throws IOException ;

        int getRemotePort();

        boolean isSelectable() ;

        // SelectableChannel

        boolean isBlocking() ;

        void configureBlocking(boolean block) throws IOException ;

        SelectionKey register(Selector selector, int ops) throws IOException ;

        //boolean selectionOpsReadable(final int readyOps);

        //boolean selectionOpsWritable(final int readyOps) ;

    }

    private static final class JavaSocketChannel implements SocketChannelImpl {

        JavaSocketChannel(final SocketChannel channel) {
            this.channel = channel;
        }

        private final SocketChannel channel;

        public boolean isOpen() { return channel.isOpen(); }

        public int read(ByteBuffer dst) throws IOException {
            return channel.read(dst);
        }

        public int write(ByteBuffer src) throws IOException {
            return channel.write(src);
        }

        public int getRemotePort() { return channel.socket().getPort(); }

        public boolean isSelectable() {
            return true; // return channel instanceof SelectableChannel;
        }

        public boolean isBlocking() { return channel.isBlocking(); }

        public void configureBlocking(boolean block) throws IOException {
            channel.configureBlocking(block);
        }

        public SelectionKey register(Selector selector, int ops) throws ClosedChannelException {
            return channel.register(selector, ops);
        }

        public boolean selectionOpsReadable(final int readyOps) {
            return (readyOps & SelectionKey.OP_READ) != 0;
        }

        public boolean selectionOpsWritable(final int readyOps) {
            return (readyOps & SelectionKey.OP_WRITE) != 0;
        }

    }

    private static ByteBuffer ensureCapacity(final ByteBuffer buffer, final int size) {
        if (size <= buffer.capacity()) return buffer;
        buffer.flip();
        ByteBuffer newBuffer = ByteBuffer.allocate(size);
        newBuffer.put(buffer);
        return newBuffer;
    }

    private static boolean jnrChannel(final Channel channel) {
        return channel.getClass().getName().startsWith("jnr.");
    }

}// SSLSocket
