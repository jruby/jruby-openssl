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
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.jruby.*;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.X509Utils;
import org.jruby.runtime.*;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.callsite.FunctionalCachingCallSite;
import org.jruby.runtime.callsite.RespondToCallSite;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.SSL.newSSLErrorWaitReadable;
import static org.jruby.ext.openssl.SSL.newSSLErrorWaitWritable;
import static org.jruby.ext.openssl.OpenSSL.*;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSLSocket extends RubyObject {

    private static final long serialVersionUID = -2084816623554406237L;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new SSLSocket(runtime, klass);
        }
    };

    private enum CallSiteIndex {

        // self
        //hostname("hostname"),
        //sync_close("sync_close"),
        //sync_close_w("sync_close="),
        // io
        _respond_to_nonblock_w("nonblock="),
        nonblock_w("nonblock="),
        sync("sync"),
        sync_w("sync="),
        flush("flush"),
        //close("close"),
        //closed_p("closed?"),
        // ssl_context
        verify_mode("verify_mode");

        final String method;

        CallSiteIndex(String method) { this.method = method; }

    }

    public static void createSSLSocket(final Ruby runtime, final RubyModule SSL) { // OpenSSL::SSL
        CallSiteIndex[] values = CallSiteIndex.values();
        CallSite[] extraCallSites = new CallSite[values.length];
        for (int i=0; i<values.length; i++) {
            if (values[i].name().startsWith("_respond_to")) {
                extraCallSites[i] = new RespondToCallSite();
            }
            else {
                extraCallSites[i] = new FunctionalCachingCallSite(values[i].method);
            }
        }

        RubyClass SSLSocket = runtime.defineClassUnder("SSLSocket", runtime.getObject(), ALLOCATOR, SSL, extraCallSites);

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

    private static CallSite callSite(final CallSite[] sites, final CallSiteIndex index) {
        return sites[ index.ordinal() ];
    }

    private SSLContext sslContext;
    private SSLEngine engine;
    private RubyIO io;

    private ByteBuffer peerAppData;
    private ByteBuffer peerNetData;
    private ByteBuffer netData;
    private ByteBuffer dummy;

    private boolean initialHandshake = false;

    private SSLEngineResult.HandshakeStatus handshakeStatus;
    private SSLEngineResult.Status status;

    int verifyResult = X509Utils.V_OK;

    @JRubyMethod(name = "initialize", rest = true, frame = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        if ( Arity.checkArgumentCount(runtime, args, 1, 2) == 1 ) {
            sslContext = new SSLContext(runtime).initializeImpl();
        } else {
            sslContext = (SSLContext) args[1];
        }

        if ( ! ( args[0] instanceof RubyIO ) ) {
            throw runtime.newTypeError("IO expected but got " + args[0].getMetaClass().getName());
        }
        setInstanceVariable("@context", this.sslContext); // only compat (we do not use @context)
        setInstanceVariable("@io", this.io = (RubyIO) args[0]);
        set_io_nonblock_checked(context, runtime.getTrue());
        // This is a bit of a hack: SSLSocket should share code with
        // RubyBasicSocket, which always sets sync to true.
        // Instead we set it here for now.
        set_sync(context, runtime.getTrue()); // io.sync = true
        setInstanceVariable("@sync_close", runtime.getFalse()); // self.sync_close = false
        sslContext.setup(context);
        return Utils.invokeSuper(context, this, args, Block.NULL_BLOCK); // super()
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

    private SSLEngine ossl_ssl_setup(final ThreadContext context) {
        SSLEngine engine = this.engine;
        if ( engine != null ) return engine;

        // Server Name Indication (SNI) RFC 3546
        // SNI support will not be attempted unless hostname is explicitly set by the caller
        IRubyObject hostname = getInstanceVariable("@hostname");
        String peerHost = hostname == null ? null : hostname.toString();
        final int peerPort = socketChannelImpl().getRemotePort();
        engine = sslContext.createSSLEngine(peerHost, peerPort);

        final javax.net.ssl.SSLSession session = engine.getSession();
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        netData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerNetData.limit(0);
        peerAppData.limit(0);
        netData.limit(0);
        dummy = ByteBuffer.allocate(0);
        this.engine = engine;
        copySessionSetupIfSet(context);
        return engine;
    }

    @JRubyMethod(name = "io", alias = "to_io")
    public final RubyIO io() { return this.io; }

    @JRubyMethod(name = "context")
    public final SSLContext context() { return this.sslContext; }

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

        try {
            if ( ! initialHandshake ) {
                SSLEngine engine = ossl_ssl_setup(context);
                engine.setUseClientMode(true);
                engine.beginHandshake();
                handshakeStatus = engine.getHandshakeStatus();
                initialHandshake = true;
            }
            callRenegotiationCallback(context);
            final IRubyObject ex = doHandshake(blocking, exception);
            if ( ex != null ) return ex; // :wait_readable | :wait_writable
        }
        catch (SSLHandshakeException e) {
            //debugStackTrace(runtime, e);
            // unlike server side, client should close outbound channel even if
            // we have remaining data to be sent.
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
        return this;
    }

    private static RaiseException newErrnoEPIPEError(final Ruby runtime, final String detail) {
        return Utils.newError(runtime, runtime.getErrno().getClass("EPIPE"), detail);
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

    @Deprecated
    public SSLSocket acceptCommon(ThreadContext context, boolean blocking) {
        return (SSLSocket) acceptImpl(context, blocking, true);
    }

    private IRubyObject acceptImpl(final ThreadContext context, final boolean blocking, final boolean exception) {

        if ( ! sslContext.isProtocolForServer() ) {
            throw newSSLError(context.runtime, "called a function you should not call");
        }

        try {
            if ( ! initialHandshake ) {
                final SSLEngine engine = ossl_ssl_setup(context);
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
                debug(context.runtime, sslContext.getProtocol() + " protocol has been deactivated and is not available by default\n see the java.security.Security property jdk.tls.disabledAlgorithms in <JRE_HOME>/lib/security/java.security file");
            }
            else {
                debugStackTrace(context.runtime, e);
            }
            throw newSSLErrorFromHandshake(context.runtime, e);
        }
        catch (IOException e) {
            debugStackTrace(context.runtime, e);
            throw newSSLError(context.runtime, e);
        }
        catch (RaiseException e) {
            throw e;
        }
        catch (RuntimeException e) {
            debugStackTrace(context.runtime, e);
            if ( "Could not generate DH keypair".equals( e.getMessage() ) ) {
                throw SSL.handleCouldNotGenerateDHKeyPairError(context.runtime, e);
            }
            throw newSSLError(context.runtime, e);
        }
        return this;
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
            context.runtime.getWarnings().warn("SSL session is not started yet.");
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
        final SelectionKey key = channel.register(selector, operations);

        try {
            final int[] result = new int[1];

            if ( ! blocking ) {
                try {
                    result[0] = selector.selectNow();

                    if ( result[0] == 0 ) {
                        if ((operations & SelectionKey.OP_READ) != 0 && (operations & SelectionKey.OP_WRITE) != 0) {
                            if ( key.isReadable() ) {
                                writeWouldBlock(runtime, exception, result);
                            }
                            //else if ( key.isWritable() ) {
                            //    readWouldBlock(runtime, exception, result);
                            //}
                            else { //neither, pick one
                                readWouldBlock(runtime, exception, result);
                            }
                        }
                        else if ((operations & SelectionKey.OP_READ) != 0) {
                            readWouldBlock(runtime, exception, result);
                        }
                        else if ((operations & SelectionKey.OP_WRITE) != 0) {
                            writeWouldBlock(runtime, exception, result);
                        }
                    }
                }
                catch (IOException ioe) {
                    throw runtime.newRuntimeError("Error with selector: " + ioe.getMessage());
                }
            } else {
                io.addBlockingThread(thread);
                thread.executeBlockingTask(new RubyThread.BlockingTask() {
                    public void run() throws InterruptedException {
                        try {
                            result[0] = selector.select();
                        }
                        catch (IOException ioe) {
                            throw runtime.newRuntimeError("Error with selector: " + ioe.getMessage());
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
        }
        catch (InterruptedException interrupt) { return Boolean.FALSE; }
        finally {
            // Note: I don't like ignoring these exceptions, but it's
            // unclear how likely they are to happen or what damage we
            // might do by ignoring them. Note that the pieces are separate
            // so that we can ensure one failing does not affect the others
            // running.

            // clean up the key in the selector
            try {
                if ( key != null ) key.cancel();
                if ( selector != null ) selector.selectNow();
            }
            catch (Exception e) { // ignore
                debugStackTrace(runtime, e);
            }

            // shut down and null out the selector
            try {
                if ( selector != null ) {
                    runtime.getSelectorPool().put(selector);
                }
            }
            catch (Exception e) { // ignore
                debugStackTrace(runtime, e);
            }

            if (blocking) {
                // remove this thread as a blocker against the given IO
                io.removeBlockingThread(thread);

                // clear thread state from blocking call
                thread.afterBlockingCall();
            }
        }
    }

    private static final int READ_WOULD_BLOCK_RESULT = Integer.MIN_VALUE + 1;
    private static final int WRITE_WOULD_BLOCK_RESULT = Integer.MIN_VALUE + 2;

    private static void readWouldBlock(final Ruby runtime, final boolean exception, final int[] result) {
        if ( exception ) throw newSSLErrorWaitReadable(runtime, "read would block");
        result[0] = READ_WOULD_BLOCK_RESULT;
    }

    private static void writeWouldBlock(final Ruby runtime, final boolean exception, final int[] result) {
        if ( exception ) throw newSSLErrorWaitWritable(runtime, "write would block");
        result[0] = WRITE_WOULD_BLOCK_RESULT;
    }

    private void doHandshake(final boolean blocking) throws IOException {
        doHandshake(blocking, true);
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
                if (readAndUnwrap(blocking) == -1 && handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED) {
                    throw new SSLHandshakeException("Socket closed");
                }
                // during initialHandshake, calling readAndUnwrap that results UNDERFLOW
                // does not mean writable. we explicitly wait for readable channel to avoid
                // busy loop.
                if (initialHandshake && status == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    sel = waitSelect(SelectionKey.OP_READ, blocking, exception);
                    if ( sel instanceof IRubyObject ) return (IRubyObject) sel; // :wait_readable
                }
                break;
            case NEED_WRAP:
                if ( netData.hasRemaining() ) {
                    while ( flushData(blocking) ) { /* loop */ }
                }
                netData.clear();
                SSLEngineResult result = engine.wrap(dummy, netData);
                handshakeStatus = result.getHandshakeStatus();
                netData.flip();
                flushData(blocking);
                break;
            default:
                throw new IllegalStateException("Unknown handshaking status: " + handshakeStatus);
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

    private boolean flushData(boolean blocking) throws IOException {
        try {
            writeToChannel(netData, blocking);
        }
        catch (IOException ioe) {
            netData.position(netData.limit());
            throw ioe;
        }
        if ( netData.hasRemaining() ) {
            return true;
        }
        return false;
    }

    private int writeToChannel(ByteBuffer buffer, boolean blocking) throws IOException {
        int totalWritten = 0;
        while ( buffer.hasRemaining() ) {
            totalWritten += socketChannelImpl().write(buffer);
            if ( ! blocking ) break; // don't continue attempting to read
        }
        return totalWritten;
    }

    private void finishInitialHandshake() {
        initialHandshake = false;
    }
    
    private void callRenegotiationCallback(final ThreadContext context) throws RaiseException {
        IRubyObject renegotiationCallback = sslContext.getInstanceVariable("@renegotiation_cb");
        if(renegotiationCallback == null || renegotiationCallback.isNil()) {
            return;
        }
        else {
            // the return of the Proc is not important
            // Can throw ruby exception to "disallow" renegotiations
            renegotiationCallback.callMethod(context, "call", this);
        }    
    }

    public int write(ByteBuffer src, boolean blocking) throws SSLException, IOException {
        if ( initialHandshake ) {
            throw new IOException("Writing not possible during handshake");
        }

        SocketChannelImpl channel = socketChannelImpl();
        final boolean blockingMode = channel.isBlocking();
        if ( ! blocking ) channel.configureBlocking(false);

        try {
            if ( netData.hasRemaining() ) {
                flushData(blocking);
            }
            netData.clear();
            final SSLEngineResult result = engine.wrap(src, netData);
            if ( result.getStatus() == SSLEngineResult.Status.CLOSED ) {
                throw getRuntime().newIOError("closed SSL engine");
            }
            netData.flip();
            flushData(blocking);
            return result.bytesConsumed();
        }
        finally {
            if ( ! blocking ) channel.configureBlocking(blockingMode);
        }
    }

    public int read(final ByteBuffer dst, final boolean blocking) throws IOException {
        if ( initialHandshake ) return 0;
        if ( engine.isInboundDone() ) return -1;

        if ( ! peerAppData.hasRemaining() ) {
            int appBytesProduced = readAndUnwrap(blocking);
            if (appBytesProduced == -1 || appBytesProduced == 0) {
                return appBytesProduced;
            }
        }
        int limit = Math.min(peerAppData.remaining(), dst.remaining());
        peerAppData.get(dst.array(), dst.arrayOffset(), limit);
        dst.position(dst.arrayOffset() + limit);
        return limit;
    }

    private int readAndUnwrap(final boolean blocking) throws IOException {
        final int bytesRead = socketChannelImpl().read(peerNetData);
        if ( bytesRead == -1 ) {
            if ( ! peerNetData.hasRemaining() ||
                 ( status == SSLEngineResult.Status.BUFFER_UNDERFLOW ) ) {
                closeInbound();
                return -1;
            }
            // inbound channel has been already closed but closeInbound() must
            // be defered till the last engine.unwrap() call.
            // peerNetData could not be empty.
        }
        peerAppData.clear();
        peerNetData.flip();

        SSLEngineResult result;
        do {
            result = engine.unwrap(peerNetData, peerAppData);
        }
        while ( result.getStatus() == SSLEngineResult.Status.OK &&
				result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP &&
				result.bytesProduced() == 0 );

        if ( result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ) {
            finishInitialHandshake();
        }
        if ( peerAppData.position() == 0 &&
            result.getStatus() == SSLEngineResult.Status.OK &&
            peerNetData.hasRemaining() ) {
            result = engine.unwrap(peerNetData, peerAppData);
        }
        status = result.getStatus();
        handshakeStatus = result.getHandshakeStatus();

        if ( bytesRead == -1 && ! peerNetData.hasRemaining() ) {
            // now it's safe to call closeInbound().
            closeInbound();
        }
        if ( status == SSLEngineResult.Status.CLOSED ) {
            doShutdown();
            return -1;
        }

        peerNetData.compact();
        peerAppData.flip();
        if ( ! initialHandshake && (
                handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK ||
                handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP ||
                handshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED ) ) {
            doHandshake(blocking);
        }
        return peerAppData.remaining();
    }

    private void closeInbound() {
        try {
            engine.closeInbound();
        }
        catch (SSLException e) {
            debug(getRuntime(), "SSLSocket.closeInbound", e);
            // ignore any error on close. possibly an error like this;
            // Inbound closed before receiving peer's close_notify: possible truncation attack?
        }
    }

    private void doShutdown() throws IOException {
        if ( engine.isOutboundDone() ) return;

        netData.clear();
        try {
            engine.wrap(dummy, netData);
        }
        catch (SSLException e) {
            debug(getRuntime(), "SSLSocket.doShutdown", e);
            return;
        }
        catch (RuntimeException e) {
            debugStackTrace(getRuntime(), e);
            return;
        }
        netData.flip();
        flushData(true);
    }

    private IRubyObject sysreadImpl(final ThreadContext context,
        IRubyObject len, IRubyObject buff, final boolean blocking, final boolean exception) {
        final Ruby runtime = context.runtime;

        final int length = RubyNumeric.fix2int(len);
        final RubyString buffStr;

        if ( buff != null && ! buff.isNil() ) {
            buffStr = buff.asString();
        } else {
            buffStr = RubyString.newEmptyString(runtime); // fine since we're setValue
        }
        if ( length == 0 ) {
            buffStr.clear();
            return buffStr;
        }
        if ( length < 0 ) {
            throw runtime.newArgumentError("negative string size (or size too big)");
        }

        try {
            // So we need to make sure to only block when there is no data left to process
            if ( engine == null || ! ( peerAppData.hasRemaining() || peerNetData.position() > 0 ) ) {
                final Object ex = waitSelect(SelectionKey.OP_READ, blocking, exception);
                if ( ex instanceof IRubyObject ) return (IRubyObject) ex; // :wait_readable
            }

            final ByteBuffer dst = ByteBuffer.allocate(length);
            int read = -1;
            // ensure >0 bytes read; sysread is blocking read.
            while ( read <= 0 ) {
                if ( engine == null ) {
                    read = socketChannelImpl().read(dst);
                } else {
                    read = read(dst, blocking);
                }

                if ( read == -1 ) {
                    if ( exception ) throw runtime.newEOFError();
                    return runtime.getNil();
                }

                if ( read == 0 && status == SSLEngineResult.Status.BUFFER_UNDERFLOW ) {
                    // If we didn't get any data back because we only read in a partial TLS record,
                    // instead of spinning until the rest comes in, call waitSelect to either block
                    // until the rest is available, or throw a "read would block" error if we are in
                    // non-blocking mode.
                    final Object ex = waitSelect(SelectionKey.OP_READ, blocking, exception);
                    if ( ex instanceof IRubyObject ) return (IRubyObject) ex; // :wait_readable
                }
            }
            final byte[] bytesRead = dst.array();
            final int offset = dst.position() - read;
            buffStr.setValue(new ByteList(bytesRead, offset, read, false));
            return buffStr;
        }
        catch (IOException ioe) {
            throw runtime.newIOError(ioe.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject sysread(ThreadContext context, IRubyObject len) {
        return sysreadImpl(context, len, null, true, true);
    }

    @JRubyMethod
    public IRubyObject sysread(ThreadContext context, IRubyObject len, IRubyObject buff) {
        return sysreadImpl(context, len, buff, true, true);
    }

    @Deprecated // @JRubyMethod(rest = true, required = 1, optional = 1)
    public IRubyObject sysread(ThreadContext context, IRubyObject[] args) {
        switch ( args.length) {
            case 1 :
                return sysread(context, args[0]);
            case 2 :
                return sysread(context, args[0], args[1]);
        }
        Arity.checkArgumentCount(context.runtime, args.length, 1, 2);
        return null; // won't happen as checkArgumentCount raises
    }

    @JRubyMethod
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject len) {
        return sysreadImpl(context, len, null, false, true);
    }

    @JRubyMethod
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject len, IRubyObject arg) {
        if ( arg instanceof RubyHash ) { // exception: false
            // NOTE: on Ruby 2.3 this is expected to raise a TypeError (but not on 2.2)
            return sysreadImpl(context, len, null, false, getExceptionOpt(context, arg));
        }
        return sysreadImpl(context, len, arg, false, true); // buffer arg
    }

    @JRubyMethod
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject len, IRubyObject buff, IRubyObject opts) {
        return sysreadImpl(context, len, buff, false, getExceptionOpt(context, opts));
    }


    @Deprecated // @JRubyMethod(rest = true, required = 1, optional = 2)
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject[] args) {
        switch ( args.length) {
            case 1 :
                return sysread_nonblock(context, args[0]);
            case 2 :
                return sysread_nonblock(context, args[0], args[1]);
            case 3 :
                return sysread_nonblock(context, args[0], args[1], args[2]);
        }
        Arity.checkArgumentCount(context.runtime, args.length, 1, 3);
        return null; // won't happen as checkArgumentCount raises
    }

    private IRubyObject syswriteImpl(final ThreadContext context,
        final IRubyObject arg, final boolean blocking, final boolean exception)  {
        final Ruby runtime = context.runtime;
        try {
            checkClosed();

            final Object ex = waitSelect(SelectionKey.OP_WRITE, blocking, exception);
            if ( ex instanceof IRubyObject ) return (IRubyObject) ex; // :wait_writable

            ByteList bytes = arg.asString().getByteList();
            ByteBuffer buff = ByteBuffer.wrap(bytes.getUnsafeBytes(), bytes.getBegin(), bytes.getRealSize());
            final int written;
            if ( engine == null ) {
                written = writeToChannel(buff, blocking);
            } else {
                written = write(buff, blocking);
            }

            io_flush(context); // io.flush

            return runtime.newFixnum(written);
        }
        catch (IOException ioe) {
            throw runtime.newIOError(ioe.getMessage());
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

        engine.closeOutbound();

        if ( ! force && netData.hasRemaining() ) return;

        try {
            doShutdown();
        }
        catch (IOException e) { // ignore?
            debug(getRuntime(), "SSLSocket.close doShutdown failed", e);
        }
        catch (NotYetConnectedException e) {
            debug(getRuntime(), "SSLSocket.close doShutdown failed", e);
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

    @Deprecated
    public final IRubyObject cert() {
        return cert(getRuntime().getCurrentContext());
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
            if (OpenSSL.isDebug(context.runtime)) {
                context.runtime.getWarnings().warning(String.format("%s: %s", e.getClass().getName(), e.getMessage()));
            }
        }
        return context.nil;
    }

    @Deprecated
    public final IRubyObject peer_cert() {
        return peer_cert(getRuntime().getCurrentContext());
    }

    @JRubyMethod
    public IRubyObject peer_cert_chain(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        if ( engine == null ) return runtime.getNil();

        try {
            javax.security.cert.Certificate[] certs = engine.getSession().getPeerCertificateChain();
            IRubyObject[] cert_chain = new IRubyObject[ certs.length ];
            for ( int i = 0; i < certs.length; i++ ) {
                cert_chain[i] = X509Cert.wrap(context, certs[i]);
            }
            return runtime.newArrayNoCopy(cert_chain);
        }
        catch (javax.security.cert.CertificateEncodingException e) {
            throw X509Cert.newCertificateError(getRuntime(), e);
        }
        catch (SSLPeerUnverifiedException e) {
            if (runtime.isVerbose() || OpenSSL.isDebug(runtime)) {
                runtime.getWarnings().warning(String.format("%s: %s", e.getClass().getName(), e.getMessage()));
            }
        }
        return runtime.getNil();
    }

    @Deprecated
    public final IRubyObject peer_cert_chain() {
        return peer_cert_chain(getRuntime().getCurrentContext());
    }

    @JRubyMethod
    public IRubyObject cipher() {
        if ( engine == null ) return getRuntime().getNil();
        return getRuntime().newString( engine.getSession().getCipherSuite() );
    }

    @JRubyMethod
    public IRubyObject npn_protocol() {
        if ( engine == null ) return getRuntime().getNil();
        // NOTE: maybe a time to use https://github.com/benmmurphy/ssl_npn
        warn(getRuntime().getCurrentContext(), "OpenSSL::SSL::SSLSocket#npn_protocol is not supported");
        return getRuntime().getNil(); // throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject state() {
        warn(getRuntime().getCurrentContext(), "WARNING: unimplemented method called: OpenSSL::SSL::SSLSocket#state");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject pending() {
        warn(getRuntime().getCurrentContext(), "WARNING: unimplemented method called: OpenSSL::SSL::SSLSocket#pending");
        return getRuntime().getNil();
    }

    private boolean reusableSSLEngine() {
        if ( engine != null ) {
            final String peerHost = engine.getPeerHost();
            if ( peerHost != null && peerHost.length() > 0 ) {
                // NOT getSSLContext().createSSLEngine() - no hints for session reuse
                return true;
            }
        }
        return false;
    }

    @JRubyMethod(name = "session_reused?")
    public IRubyObject session_reused_p() {
        if ( reusableSSLEngine() ) {
            if ( ! engine.getEnableSessionCreation() ) {
                // if session creation is disabled we can be sure its to be re-used
                return getRuntime().getTrue();
            }
            //return getRuntime().getFalse(); // NOTE: likely incorrect (we can not decide)
        }
        //warn(getRuntime().getCurrentContext(), "WARNING: SSLSocket#session_reused? is not supported");
        return getRuntime().getNil(); // can not decide - probably not
    }

    // JSSE: SSL Sessions can be reused only if connecting to the same host at the same port

    final javax.net.ssl.SSLSession sslSession() {
        return engine == null ? null : engine.getSession();
    }

    private transient SSLSession session;

    @JRubyMethod(name = "session")
    public IRubyObject session(final ThreadContext context) {
        if ( sslSession() == null ) return context.nil;
        return getSession(context.runtime);
    }

    private SSLSession getSession(final Ruby runtime) {
        if ( session == null ) {
            return session = new SSLSession(runtime).initializeImpl(this);
        }
        return session;
    }

    private transient SSLSession setSession = null;

    @JRubyMethod(name = "session=")
    public IRubyObject set_session(final ThreadContext context, IRubyObject session) {
        // NOTE: we can not fully support this without the SSL provider internals
        // but we can assume setting a session= is meant as a forced session re-use
        if ( session instanceof SSLSession ) {
            setSession = (SSLSession) session;
            if ( engine != null ) copySessionSetupIfSet(context);
        }
        //warn(context, "WARNING: SSLSocket#session= has not effect");
        return context.nil;
    }

    @Deprecated
    public IRubyObject set_session(IRubyObject session) {
        return set_session(getRuntime().getCurrentContext(), session);
    }

    private void copySessionSetupIfSet(final ThreadContext context) {
        if ( setSession != null ) {
            if ( reusableSSLEngine() ) {
                engine.setEnableSessionCreation(false);
                if ( ! setSession.equals( getSession(context.runtime) ) ) {
                    getSession(context.runtime).set_timeout(context, setSession.timeout(context));
                }
            }
        }
    }

    @JRubyMethod
    public IRubyObject ssl_version(ThreadContext context) {
        if ( engine == null ) return context.nil;
        return context.runtime.newString( engine.getSession().getProtocol() );
    }

    private transient SocketChannelImpl socketChannel;

    private SocketChannelImpl socketChannelImpl() {
        if ( socketChannel != null ) return socketChannel;

        final Channel channel = io.getChannel();
        if ( channel instanceof SocketChannel ) {
            return socketChannel = new JavaSocketChannel((SocketChannel) channel);
        }

        // TODO JNR

        throw new IllegalStateException("unknow channel impl: " + channel + " of type " + channel.getClass().getName());
    }

    private interface SocketChannelImpl {

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

    private static boolean jnrChannel(final Channel channel) {
        return channel.getClass().getName().startsWith("jnr.");
    }

}// SSLSocket
