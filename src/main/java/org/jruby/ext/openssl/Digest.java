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

    private static ObjectAllocator DIGEST_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new Digest(runtime, klass);
        }
    };

    public static void createDigest(Ruby runtime, RubyModule OpenSSL) {
        runtime.getLoadService().require("digest");

        final RubyModule coreDigest = runtime.getModule("Digest");
        final RubyClass DigestClass = coreDigest.getClass("Class"); // ::Digest::Class
        RubyClass Digest = OpenSSL.defineClassUnder("Digest", DigestClass, DIGEST_ALLOCATOR);
        Digest.defineAnnotatedMethods(Digest.class);
        RubyClass OpenSSLError = OpenSSL.getClass("OpenSSLError");
        OpenSSL.defineClassUnder("DigestError", OpenSSLError, OpenSSLError.getAllocator());
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

    public Digest(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private RubyString name;
    private MessageDigest digest;

    String getRealName() {
        return osslToJava(name.toString());
    }

    public String getName() {
        return name.toString();
    }

    @JRubyMethod(required = 1, optional = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        IRubyObject type = args[0]; // e.g. "MD5"
        IRubyObject data = context.nil;
        if ( args.length > 1 ) data = args[1];
        this.name = type.asString();
        this.digest = getDigest(context.runtime, name.toString());
        if ( ! data.isNil() ) update( data.asString() );
        return this;
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
    public IRubyObject update(IRubyObject obj) {
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

}

