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
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Set;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyIO;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyThread;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.X509Utils;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.runtime.Visibility;

import static org.jruby.ext.openssl.SSL.newSSLErrorWaitReadable;
import static org.jruby.ext.openssl.SSL.newSSLErrorWaitWritable;
import static org.jruby.ext.openssl.OpenSSL.*;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SSLSocket extends RubyObject {

    private static final long serialVersionUID = -2084816623554406237L;

    private static ObjectAllocator SSLSOCKET_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new SSLSocket(runtime, klass);
        }
    };

    public static void createSSLSocket(final Ruby runtime, final RubyModule SSL) { // OpenSSL::SSL
        final ThreadContext context = runtime.getCurrentContext();
        RubyClass SSLSocket = SSL.defineClassUnder("SSLSocket", runtime.getObject(), SSLSOCKET_ALLOCATOR);
        // SSLSocket.addReadAttribute(context, "io");
        // SSLSocket.defineAlias("to_io", "io");
        // SSLSocket.addReadAttribute(context, "context");
        SSLSocket.addReadWriteAttribute(context, "sync_close");
        SSLSocket.addReadWriteAttribute(context, "hostname");
        SSLSocket.defineAnnotatedMethods(SSLSocket.class);
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

    @Deprecated
    public IRubyObject _initialize(final ThreadContext context,
        final IRubyObject[] args, final Block unused) {
        return initialize(context, args);
    }

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
        setInstanceVariable("@io", this.io = (RubyIO) args[0]); // compat (we do not read @io)
        setInstanceVariable("@context", this.sslContext); // only compat (we do not use @context)
        // This is a bit of a hack: SSLSocket should share code with
        // RubyBasicSocket, which always sets sync to true.
        // Instead we set it here for now.
        this.set_sync(context, runtime.getTrue()); // io.sync = true
        this.callMethod(context, "sync_close=", runtime.getFalse());
        sslContext.setup(context);
        return Utils.invokeSuper(context, this, args, Block.NULL_BLOCK); // super()
    }

    private SSLEngine ossl_ssl_setup(final ThreadContext context)
        throws NoSuchAlgorithmException, KeyManagementException, IOException {
        SSLEngine engine = this.engine;
        if ( engine != null ) return engine;

        // Server Name Indication (SNI) RFC 3546
        // SNI support will not be attempted unless hostname is explicitly set by the caller
        String peerHost = this.callMethod(context, "hostname").toString();
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
        return this.engine = engine;
    }

    @JRubyMethod(name = "io", alias = "to_io")
    public final RubyIO io() { return this.io; }

    @JRubyMethod(name = "context")
    public final SSLContext context() { return this.sslContext; }

    @JRubyMethod(name = "sync")
    public IRubyObject sync(final ThreadContext context) {
        return this.io.callMethod(context, "sync");
    }

    @JRubyMethod(name = "sync=")
    public IRubyObject set_sync(final ThreadContext context, final IRubyObject sync) {
        return this.io.callMethod(context, "sync=", sync);
    }

    @JRubyMethod
    public IRubyObject connect(final ThreadContext context) {
        return connectImpl(context, true);
    }

    @JRubyMethod
    public IRubyObject connect_nonblock(ThreadContext context) {
        return connectImpl(context, false);
    }

    private SSLSocket connectImpl(final ThreadContext context, final boolean blocking) {
        final Ruby runtime = context.runtime;

        if ( ! sslContext.isProtocolForClient() ) {
            throw newSSLError(runtime, "called a function you should not call");
        }

        try {
            if ( ! initialHandshake ) {
                SSLEngine engine = ossl_ssl_setup(context);
                engine.setUseClientMode(true);
                engine.beginHandshake();
                handshakeStatus = engine.getHandshakeStatus();
                initialHandshake = true;
            }
            doHandshake(blocking);
        }
        catch (SSLHandshakeException e) {
            //debugStackTrace(runtime, e);
            // unlike server side, client should close outbound channel even if
            // we have remaining data to be sent.
            forceClose();
            throw newSSLErrorFromHandshake(runtime, e);
        }
        catch (NoSuchAlgorithmException e) {
            debugStackTrace(runtime, e);
            forceClose();
            throw newSSLError(runtime, e);
        }
        catch (KeyManagementException e) {
            debugStackTrace(runtime, e);
            forceClose();
            throw newSSLError(runtime, e);
        }
        catch (IOException e) {
            //debugStackTrace(runtime, e);
            forceClose();
            throw newSSLError(runtime, e);
        }
        return this;
    }

    @JRubyMethod
    public IRubyObject accept(ThreadContext context) {
        return acceptImpl(context, true);
    }

    @JRubyMethod
    public IRubyObject accept_nonblock(ThreadContext context) {
        return acceptImpl(context, false);
    }

    @Deprecated
    public SSLSocket acceptCommon(ThreadContext context, boolean blocking) {
        return acceptImpl(context, blocking);
    }

    private SSLSocket acceptImpl(final ThreadContext context, final boolean blocking) {
        final Ruby runtime = context.runtime;

        if ( ! sslContext.isProtocolForServer() ) {
            throw newSSLError(runtime, "called a function you should not call");
        }

        try {
            if ( ! initialHandshake ) {
                final SSLEngine engine = ossl_ssl_setup(context);
                engine.setUseClientMode(false);
                final IRubyObject verify_mode = sslContext.callMethod(context, "verify_mode");
                if ( ! verify_mode.isNil() ) {
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
            doHandshake(blocking);
        }
        catch (SSLHandshakeException e) {
            final String msg = e.getMessage();
            // updated JDK (>= 1.7.0_75) with deprecated SSL protocols :
            // javax.net.ssl.SSLHandshakeException: No appropriate protocol (protocol is disabled or cipher suites are inappropriate)
            if ( e.getCause() == null && msg != null &&
                 msg.contains("(protocol is disabled or cipher suites are inappropriate)") )  {
                debug(runtime, sslContext.getProtocol() + " protocol has been deactivated and is not available by default\n see the java.security.Security property jdk.tls.disabledAlgorithms in <JRE_HOME>/lib/security/java.security file");
            }
            else {
                debugStackTrace(runtime, e);
            }
            throw newSSLErrorFromHandshake(runtime, e);
        }
        catch (NoSuchAlgorithmException e) {
            debugStackTrace(runtime, e);
            throw newSSLError(runtime, e);
        }
        catch (KeyManagementException e) {
            debugStackTrace(runtime, e);
            throw newSSLError(runtime, e);
        }
        catch (IOException e) {
            debugStackTrace(runtime, e);
            throw newSSLError(runtime, e);
        }
        catch (RaiseException e) {
            throw e;
        }
        catch (RuntimeException e) {
            debugStackTrace(runtime, e);
            if ( "Could not generate DH keypair".equals( e.getMessage() ) ) {
                throw SSL.handleCouldNotGenerateDHKeyPairError(runtime, e);
            }
            throw newSSLError(runtime, e);
        }
        return this;
    }

    @JRubyMethod
    public IRubyObject verify_result(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        if (engine == null) {
            runtime.getWarnings().warn("SSL session is not started yet.");
            return runtime.getNil();
        }
        return runtime.newFixnum(verifyResult);
    }

    // This select impl is a copy of RubyThread.select, then blockingLock is
    // removed. This impl just set
    // SelectableChannel.configureBlocking(false) permanently instead of setting
    // temporarily. SSLSocket requires wrapping IO to be selectable so it should
    // be OK to set configureBlocking(false) permanently.
    private boolean waitSelect(final int operations, final boolean blocking) throws IOException {
        final SocketChannelImpl channel = socketChannelImpl();
        if ( ! channel.isSelectable() ) return true;

        final Ruby runtime = getRuntime();
        final RubyThread thread = runtime.getCurrentContext().getThread();

        channel.configureBlocking(false);
        final Selector selector = runtime.getSelectorPool().get();
        final SelectionKey key = channel.register(selector, operations);

        try {
            io.addBlockingThread(thread);

            final int[] result = new int[1];

            thread.executeBlockingTask(new RubyThread.BlockingTask() {
                public void run() throws InterruptedException {
                    try {
                        if ( ! blocking ) {
                            result[0] = selector.selectNow();

                            if ( result[0] == 0 ) {
                                if ((operations & SelectionKey.OP_READ) != 0 && (operations & SelectionKey.OP_WRITE) != 0) {
                                    if ( key.isReadable() ) {
                                        writeWouldBlock(runtime);
                                    } else if ( key.isWritable() ) {
                                        readWouldBlock(runtime);
                                    } else { //neither, pick one
                                        readWouldBlock(runtime);
                                    }
                                } else if ((operations & SelectionKey.OP_READ) != 0) {
                                    readWouldBlock(runtime);
                                } else if ((operations & SelectionKey.OP_WRITE) != 0) {
                                    writeWouldBlock(runtime);
                                }
                            }
                        }
                        else {
                            result[0] = selector.select();
                        }
                    }
                    catch (IOException ioe) {
                        throw runtime.newRuntimeError("Error with selector: " + ioe.getMessage());
                    }
                }

                public void wakeup() {
                    selector.wakeup();
                }
            });

            if ( result[0] >= 1 ) {
                Set<SelectionKey> keySet = selector.selectedKeys();
                if ( keySet.iterator().next() == key ) return true;
            }

            return false;
        }
        catch (InterruptedException ie) {
            return false;
        }
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

            // remove this thread as a blocker against the given IO
            io.removeBlockingThread(thread);

            // clear thread state from blocking call
            thread.afterBlockingCall();
        }
    }

    private static void readWouldBlock(final Ruby runtime) {
        throw newSSLErrorWaitReadable(runtime, "read would block");
    }

    private static void writeWouldBlock(final Ruby runtime) {
        throw newSSLErrorWaitWritable(runtime, "write would block");
    }

    private void doHandshake(final boolean blocking) throws IOException {
        while (true) {
            boolean ready = waitSelect(SelectionKey.OP_READ | SelectionKey.OP_WRITE, blocking);

            // if not blocking, raise EAGAIN
            if ( ! blocking && ! ready ) {
                throw getRuntime().newErrnoEAGAINError("Resource temporarily unavailable");
            }

            // otherwise, proceed as before

            switch (handshakeStatus) {
            case FINISHED:
            case NOT_HANDSHAKING:
                if ( initialHandshake ) finishInitialHandshake();
                return;
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
                    waitSelect(SelectionKey.OP_READ, blocking);
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

    private RubyString sysreadImpl(final ThreadContext context,
        final IRubyObject[] args, final boolean blocking) {
        final Ruby runtime = context.runtime;

        final int len = RubyNumeric.fix2int(args[0]);
        final RubyString buff;

        if ( args.length == 2 && ! args[1].isNil() ) {
            buff = args[1].asString();
        } else {
            buff = runtime.newString();
        }
        if ( len == 0 ) {
            buff.clear();
            return buff;
        }
        if ( len < 0 ) {
            throw runtime.newArgumentError("negative string size (or size too big)");
        }

        try {
            // So we need to make sure to only block when there is no data left to process
            if ( engine == null || ! ( peerAppData.hasRemaining() || peerNetData.position() > 0 ) ) {
                waitSelect(SelectionKey.OP_READ, blocking);
            }

            ByteBuffer dst = ByteBuffer.allocate(len);
            int rr = -1;
            // ensure >0 bytes read; sysread is blocking read.
            while ( rr <= 0 ) {
                if ( engine == null ) {
                    rr = socketChannelImpl().read(dst);
                } else {
                    rr = read(dst, blocking);
                }

                if ( rr == -1 ) throw runtime.newEOFError();

                if ( rr == 0 && status == SSLEngineResult.Status.BUFFER_UNDERFLOW ) {
                    // If we didn't get any data back because we only read in a partial TLS record,
                    // instead of spinning until the rest comes in, call waitSelect to either block
                    // until the rest is available, or throw a "read would block" error if we are in
                    // non-blocking mode.
                    waitSelect(SelectionKey.OP_READ, blocking);
                }
            }
            byte[] bss = new byte[rr];
            dst.position(dst.position() - rr);
            dst.get(bss);
            buff.setValue(new ByteList(bss, false));
            return buff;
        }
        catch (IOException ioe) {
            throw runtime.newIOError(ioe.getMessage());
        }
    }

    @JRubyMethod(rest = true, required = 1, optional = 1)
    public IRubyObject sysread(ThreadContext context, IRubyObject[] args) {
        return sysreadImpl(context, args, true);
    }

    @JRubyMethod(rest = true, required = 1, optional = 2)
    public IRubyObject sysread_nonblock(ThreadContext context, IRubyObject[] args) {
        // TODO: options for exception raising
        return sysreadImpl(context, args, false);
    }

    private IRubyObject do_syswrite(final ThreadContext context,
        final IRubyObject arg, final boolean blocking)  {
        final Ruby runtime = context.runtime;
        try {
            checkClosed();

            waitSelect(SelectionKey.OP_WRITE, blocking);

            ByteList bls = arg.asString().getByteList();
            ByteBuffer b1 = ByteBuffer.wrap(bls.getUnsafeBytes(), bls.getBegin(), bls.getRealSize());
            final int written;
            if ( engine == null ) {
                written = writeToChannel(b1, blocking);
            } else {
                written = write(b1, blocking);
            }

            this.io.callMethod(context, "flush");

            return runtime.newFixnum(written);
        }
        catch (IOException ioe) {
            throw runtime.newIOError(ioe.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject syswrite(ThreadContext context, IRubyObject arg) {
        return do_syswrite(context, arg, true);
    }

    @JRubyMethod
    public IRubyObject syswrite_nonblock(ThreadContext context, IRubyObject arg) {
        return do_syswrite(context, arg, false);
    }

    @JRubyMethod
    public IRubyObject syswrite_nonblock(ThreadContext context, IRubyObject arg, IRubyObject options) {
        // TODO: options for exception raising
        return do_syswrite(context, arg, false);
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
        if ( engine == null ) throw getRuntime().newEOFError();

        engine.closeOutbound();

        if ( ! force && netData.hasRemaining() ) return;

        try {
            doShutdown();
        }
        catch (IOException e) {
            // ignore?
            debug(getRuntime(), "SSLSocket.close doShutdown failed", e);
        }
    }

    @JRubyMethod
    public IRubyObject sysclose(final ThreadContext context) {
        // no need to try shutdown when it's a server
        close( sslContext.isProtocolForClient() );

        if ( this.callMethod(context, "sync_close").isTrue() ) {
            this.io.callMethod(context, "close");
        }
        return context.runtime.getNil();
    }

    @JRubyMethod
    public IRubyObject cert() {
        final Ruby runtime = getRuntime();
        if ( engine == null ) return runtime.getNil();

        try {
            Certificate[] cert = engine.getSession().getLocalCertificates();
            if ( cert != null && cert.length > 0 ) {
                return X509Cert.wrap(runtime, cert[0]);
            }
        }
        catch (CertificateEncodingException e) {
            throw X509Cert.newCertificateError(runtime, e);
        }
        return runtime.getNil();
    }

    @JRubyMethod
    public IRubyObject peer_cert() {
        final Ruby runtime = getRuntime();
        if ( engine == null ) return runtime.getNil();

        try {
            Certificate[] cert = engine.getSession().getPeerCertificates();
            if ( cert.length > 0 ) {
                return X509Cert.wrap(runtime, cert[0]);
            }
        }
        catch (CertificateEncodingException e) {
            throw X509Cert.newCertificateError(runtime, e);
        }
        catch (SSLPeerUnverifiedException e) {
            if (runtime.isVerbose() || OpenSSL.isDebug(runtime)) {
                runtime.getWarnings().warning(String.format("%s: %s", e.getClass().getName(), e.getMessage()));
            }
        }
        return runtime.getNil();
    }

    @JRubyMethod
    public IRubyObject peer_cert_chain() {
        final Ruby runtime = getRuntime();
        if ( engine == null ) return runtime.getNil();

        try {
            javax.security.cert.Certificate[] certs = engine.getSession().getPeerCertificateChain();
            RubyArray arr = runtime.newArray(certs.length);
            for ( int i = 0; i < certs.length; i++ ) {
                arr.append( X509Cert.wrap(runtime, certs[i]) );
            }
            return arr;
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

    @JRubyMethod
    public IRubyObject cipher() {
        if ( engine == null ) return getRuntime().getNil();
        return getRuntime().newString( engine.getSession().getCipherSuite() );
    }

    @JRubyMethod
    public IRubyObject state() {
        warn(getRuntime().getCurrentContext(), "WARNING: unimplemented method called: SSLSocket#state");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject pending() {
        warn(getRuntime().getCurrentContext(), "WARNING: unimplemented method called: SSLSocket#pending");
        return getRuntime().getNil();
    }

    @JRubyMethod(name = "session_reused?")
    public IRubyObject session_reused_p() {
        warn(getRuntime().getCurrentContext(), "WARNING: SSLSocket#session_reused? is not supported");
        return getRuntime().getNil(); // throw new UnsupportedOperationException();
    }

    javax.net.ssl.SSLSession getSession() {
        return engine == null ? null : engine.getSession();
    }

    private transient SSLSession session;

    @JRubyMethod(name = "session")
    public IRubyObject session(final ThreadContext context) {
        if ( getSession() == null ) return context.nil;
        if ( session == null ) {
            return session = new SSLSession(context.runtime).initializeImpl(context, this);
        }
        return session;
    }

    @JRubyMethod(name = "session=")
    public IRubyObject set_session(IRubyObject session) {
        warn(getRuntime().getCurrentContext(), "WARNING: SSLSocket#session= is not supported");
        return getRuntime().getNil(); // throw new UnsupportedOperationException();
    }

    @JRubyMethod
    public IRubyObject ssl_version() {
        if ( engine == null ) return getRuntime().getNil();
        return getRuntime().newString( engine.getSession().getProtocol().replace('.', '_') );
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

    private static interface SocketChannelImpl {

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
