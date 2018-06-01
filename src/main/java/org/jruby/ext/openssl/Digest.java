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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.Visibility;
import org.jruby.util.ByteList;

import static org.jruby.ext.openssl.OpenSSL.*;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Digest extends RubyObject {
    private static final long serialVersionUID = 7409857414064319518L;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public Digest allocate(Ruby runtime, RubyClass klass) { return new Digest(runtime, klass); }
    };

    static void createDigest(Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        runtime.getLoadService().require("digest");

        final RubyModule coreDigest = runtime.getModule("Digest");
        final RubyClass DigestClass = coreDigest.getClass("Class"); // ::Digest::Class
        RubyClass Digest = OpenSSL.defineClassUnder("Digest", DigestClass, ALLOCATOR);
        OpenSSL.defineClassUnder("DigestError", OpenSSLError, OpenSSLError.getAllocator());
        Digest.defineAnnotatedMethods(Digest.class);

        String digestName;

        digestName = "DSS"; // OpenSSL::Digest::DSS
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "DSS1"; // OpenSSL::Digest::DSS1
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);

        digestName = "MD2"; // OpenSSL::Digest::MD2
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "MD4"; // OpenSSL::Digest::MD4
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "MD5"; // OpenSSL::Digest::MD5
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);

        digestName = "MDC2"; // OpenSSL::Digest::MDC2 NOTE: not really supported on Java
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);

        digestName = "RIPEMD160"; // OpenSSL::Digest::RIPEMD160
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);

        digestName = "SHA"; // OpenSSL::Digest::SHA
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "SHA1"; // OpenSSL::Digest::SHA1
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        //
        digestName = "SHA224"; // OpenSSL::Digest::SHA224
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "SHA256"; // OpenSSL::Digest::SHA256
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "SHA384"; // OpenSSL::Digest::SHA384
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
        digestName = "SHA512"; // OpenSSL::Digest::SHA512
        Digest.defineClassUnder(digestName, Digest, new NamedDigestAllocator(digestName))
              .defineAnnotatedMethods(Named.class);
    }

    static RubyClass _Digest(final Ruby runtime) {
        return (RubyClass) runtime.getModule("OpenSSL").getConstantAt("Digest");
    }

    static MessageDigest getDigest(final Ruby runtime, final String name) {
        final String algorithm = osslToJava( name );
        try {
            return SecurityHelper.getMessageDigest(algorithm);
        }
        catch (NoSuchAlgorithmException e) {
            debug(runtime, "getMessageDigest failed: " + e);
            throw runtime.newNotImplementedError("Unsupported digest algorithm (" + name + ")");
        }
    }

    private static Digest newInstance(final Ruby runtime, final IRubyObject name, final IRubyObject data) {
        final RubyClass klass = _Digest(runtime);
        final Digest instance = new Digest(runtime, klass);
        instance.initializeImpl(runtime, name.asString(), data);
        return instance;
    }

    public Digest(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private RubyString name;
    private MessageDigest digest;

    String getRealName() {
        return osslToJava(name.toString());
    }

    MessageDigest getDigestImpl() {
        return digest;
    }

    public String getName() {
        return name.toString();
    }

    @JRubyMethod(required = 1, optional = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject... args) {
        IRubyObject data = context.nil;
        if ( args.length > 1 ) data = args[1];
        initializeImpl(context.runtime, args[0].asString(), data);
        return this;
    }

    void initializeImpl(final Ruby runtime, final RubyString name, final IRubyObject data) {
        this.name = name; // e.g. "MD5"
        this.digest = getDigest(runtime, name.toString());
        if ( ! data.isNil() ) update( data.asString() );
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject obj) {
        checkFrozen();
        if ( this == obj ) return this;
        final Digest that = ((Digest) obj);
        this.name = (RubyString) that.name.dup();
        try {
            this.digest = (MessageDigest) that.digest.clone();
        }
        catch (CloneNotSupportedException e) {
            final Ruby runtime = getRuntime();
            debug(runtime, "MessageDigest.clone() failed: " + e);
            throw runtime.newTypeError("Could not initialize copy of digest (" + name + ")");
        }
        return this;
    }

    @JRubyMethod(name = "update", alias = "<<")
    public IRubyObject update(final IRubyObject obj) {
        final ByteList bytes = obj.asString().getByteList();
        digest.update(bytes.getUnsafeBytes(), bytes.getBegin(), bytes.getRealSize());
        return this;
    }

    @JRubyMethod
    public IRubyObject reset() {
        digest.reset();
        return this;
    }

    @JRubyMethod
    public RubyString finish() {
        final byte[] hash = digest.digest();
        digest.reset();
        return StringHelper.newString(getRuntime(), hash);
    }

    @JRubyMethod
    public RubyString name() { return name; }

    @JRubyMethod
    public IRubyObject digest_length() {
        return RubyFixnum.newFixnum(getRuntime(), digest.getDigestLength());
    }

    @JRubyMethod
    public RubyInteger block_length(final ThreadContext context) {
        final Ruby runtime = context.runtime;

        final int blockLength = getBlockLength( digest.getAlgorithm() );

        if ( blockLength == -1 ) {
            throw runtime.newRuntimeError(getMetaClass() + " doesn't implement block_length()");
        }
        return runtime.newFixnum(blockLength);
    }

    String getAlgorithm() {
        return this.digest.getAlgorithm();
    }

    String getShortAlgorithm() {
        return getAlgorithm().replace("-", "");
    }

    // name mapping for openssl -> JCE
    private static String osslToJava(final String digestName) {
        String name = digestName.toString();
        final String[] parts = name.split("::");
        if ( parts.length > 1 ) { // only want Digest names from the last part of class name
            name = parts[ parts.length - 1 ];
        }
        // DSS, DSS1 (Pseudo algorithms to be used for DSA signatures.
        // DSS is equal to SHA and DSS1 is equal to SHA1)
        if ( "DSS".equalsIgnoreCase(name) ) return "SHA";
        if ( "DSS1".equalsIgnoreCase(name) ) return "SHA-1";
        // BC accepts "SHA1" but it should be "SHA-1" per spec
        if ( "SHA1".equalsIgnoreCase(name) ) return "SHA-1";
        if ( name.toUpperCase().startsWith("SHA") &&
             name.length() > 4 && name.charAt(3) != '-' ) { // SHA512
            return "SHA-" + name.substring(3); // SHA-512
        }
        // BC handles MD2, MD4 and RIPEMD160 names fine ...
        return name;
    }

    private static int getBlockLength(final String algorithm) {
        final String alg = algorithm.toUpperCase();
        if ( alg.startsWith("SHA") ) {
            if ( alg.equals("SHA-384") ) return 128;
            if ( alg.equals("SHA-512") ) return 128;
            return 64; // others 224/256 have 512 bit blocks
        }

        if ( alg.equals("MD5") ) return 64;
        if ( alg.equals("MD4") ) return 64;
        if ( alg.equals("MD2") ) return 48;
        if ( alg.equals("RIPEMD160") ) return 64;

        return -1;
    }

    @JRubyMethod(meta = true) // OpenSSL::Digest.digest("SHA256, "abc")
    public static RubyString digest(final ThreadContext context, final IRubyObject self,
        final IRubyObject name, final IRubyObject data) {
        return newInstance(context.runtime, name, data).finish();
    }

    @JRubyMethod(meta = true) // OpenSSL::Digest.hexdigest("SHA1" "abc")
    public static RubyString hexdigest(final ThreadContext context, final IRubyObject self,
        final IRubyObject name, final IRubyObject data) {
        final Ruby runtime = context.runtime;
        return hexString( newInstance(runtime, name, data).finish() );
    }

    private final static byte[] HEX = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static RubyString hexString(final RubyString str) {
        final byte[] plain = str.getBytes(); final int len = plain.length;

        final ByteList bytes = str.getByteList(); // modify str in-place !
        bytes.length( len * 2 ); bytes.invalidate();

        final byte[] unsafeBytes = bytes.getUnsafeBytes();
        int index = bytes.getBegin();

        for ( int i = 0; i < len; i++ ) {
            final int b = plain[i] & 0xFF;
            unsafeBytes[ index++ ] = HEX[ b >> 4 ];
            unsafeBytes[ index++ ] = HEX[ b & 0xF ];
        }
        return str;
    }

    private static class NamedDigestAllocator implements ObjectAllocator {

        private final String digestName;

        NamedDigestAllocator(final String digestName) {
            this.digestName = digestName;
        }

        public Named allocate(Ruby runtime, RubyClass klass) {
            return new Named(runtime, klass, digestName);
        }
    };

    public static class Named extends Digest {
        private static final long serialVersionUID = -8794569678070129828L;

        private final RubyString digestName;

        Named(Ruby runtime, RubyClass type, String digestName) {
            super(runtime, type);
            this.digestName = RubyString.newString(runtime, digestName); // e.g. "MD5"
        }

        /*
        MD5 = Class.new(Digest) do
          define_method(:initialize) do |*data|
            if data.length > 1
              raise ArgumentError, "wrong number of arguments (#{data.length} for 1)"
            end
            super(name, data.first)
          end
        end
         */
        @Override
        @JRubyMethod(required = 0, optional = 1, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            IRubyObject data = context.nil;
            if ( args.length > 0 ) data = args[0];
            initializeImpl(context.runtime, digestName, data); // super(name, args[0])
            return this;
        }

        /*
        define_method(:digest){ |data| Digest.digest(name, data) }
        define_method(:hexdigest){ |data| Digest.hexdigest(name, data) }
         */

        @JRubyMethod(meta = true)
        public static RubyString digest(final ThreadContext context, final IRubyObject self,
            final IRubyObject data) {
            return newInstance(context.runtime, (RubyClass) self, data).finish();
        }

        @JRubyMethod(meta = true)
        public static RubyString hexdigest(final ThreadContext context, final IRubyObject self,
            final IRubyObject data) {
            final Ruby runtime = context.runtime;
            return hexString( newInstance(runtime, (RubyClass) self, data).finish() );
        }

        private static Named newInstance(final Ruby runtime,
            final RubyClass klass, final IRubyObject data) {
            final String name = klass.getBaseName();
            final Named instance = new Named(runtime, klass, name);
            instance.initializeImpl(runtime, instance.digestName, data);
            return instance;
        }

    }

}

