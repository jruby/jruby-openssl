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
 * Copyright (C) 2007 William N Dortch <bill.dortch@gmail.com>
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
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.jruby.Ruby;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.runtime.Visibility;

import static org.jruby.ext.openssl.OpenSSL.bcExceptionMessage;

/**
 * OpenSSL::PKey::DH implementation.
 *
 * @author <a href="mailto:bill.dortch@gmail.com">Bill Dortch</a>
 */
public class PKeyDH extends PKey {

    private static final long serialVersionUID = -1893518804744046740L;

    private static final BigInteger TWO = BN.TWO;

    // from [ossl]/crypto/dh/dh.h
    private static final int OPENSSL_DH_MAX_MODULUS_BITS = 10000;

    private static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public PKeyDH allocate(Ruby runtime, RubyClass klass) { return new PKeyDH(runtime, klass); }
    };

    static void createPKeyDH(final Ruby runtime, final RubyModule PKey, final RubyClass PKeyPKey, final RubyClass PKeyError) {
        RubyClass DH = PKey.defineClassUnder("DH", PKeyPKey, ALLOCATOR);
        PKey.defineClassUnder("DHError", PKeyError, PKeyError.getAllocator());
        DH.defineAnnotatedMethods(PKeyDH.class);
    }

    public static RaiseException newDHError(Ruby runtime, String message) {
        return Utils.newError(runtime, _PKey(runtime).getClass("DHError"), message);
    }

    // transient because: we do not want these value serialized (insecure)
    // volatile because: permits unsynchronized reads in some cases
    private transient volatile BigInteger dh_p;
    private transient volatile BigInteger dh_g;
    private transient volatile BigInteger dh_y;
    private transient volatile BigInteger dh_x;

    // FIXME! need to figure out what it means in MRI/OSSL code to
    // claim a DH is(/has) private if an engine is present -- doesn't really
    // map to Java implementation.

    //private volatile boolean haveEngine;

    public PKeyDH(Ruby runtime, RubyClass clazz) {
        super(runtime, clazz);
    }

    @Override
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final PKeyDH that = (PKeyDH) original;
        this.dh_p = that.dh_p;
        this.dh_g = that.dh_g;
        this.dh_y = that.dh_y;
        this.dh_x = that.dh_x;
        return this;
    }

    @JRubyMethod(name="initialize", rest=true, visibility = Visibility.PRIVATE)
    public synchronized IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        if (this.dh_p != null || this.dh_g != null || this.dh_y != null || this.dh_x != null) {
            throw newDHError(runtime, "illegal initialization");
        }

        final int argc = Arity.checkArgumentCount(runtime, args, 0, 2);
        if ( argc > 0 ) {
            IRubyObject arg0 = args[0];
            if ( argc == 1 && arg0 instanceof RubyString ) {
                try {
                    DHParameterSpec spec = PEMInputOutput.readDHParameters(new StringReader(arg0.toString()));
                    if (spec == null) {
                        spec = org.jruby.ext.openssl.impl.PKey.readDHParameter(arg0.asString().getByteList().bytes());
                    }
                    if (spec == null) {
                        throw runtime.newArgumentError("invalid DH PARAMETERS");
                    }
                    this.dh_p = spec.getP();
                    this.dh_g = spec.getG();
                }
                catch (NoClassDefFoundError e) {
                    throw newDHError(runtime, bcExceptionMessage(e));
                }
                catch (IOException e) {
                    throw runtime.newIOErrorFromException(e);
                }
            } else {
                int bits = RubyNumeric.fix2int(arg0);
                // g defaults to 2
                int gval = argc == 2 ? RubyNumeric.fix2int(args[1]) : 2;
                BigInteger p;
                try {
                    p = generateP(bits, gval);
                }
                catch(IllegalArgumentException e) {
                    throw runtime.newArgumentError(e.getMessage());
                }
                BigInteger g = BigInteger.valueOf(gval);
                BigInteger x = generateX(p);
                BigInteger y = generateY(p, g, x);
                this.dh_p = p;
                this.dh_g = g;
                this.dh_x = x; // private key
                this.dh_y = y; // public key
            }
        }
        return this;
    }

    public static BigInteger generateP(int bits, int g) {

        // FIXME? I'm following algorithms used in OpenSSL, could use JCE provider instead.
        // (Note that I tried that, but got mystifying values of g returned by the param generator.
        // In any case, in OpenSSL/MRI-OpenSSL, the caller supplies g, or it defaults to 2.)

        // see [ossl]/crypto/dh/dh_gen.c #dh_builtin_genparams

        if (bits < 2) throw new IllegalArgumentException("invalid bit length");
        if (g < 2) throw new IllegalArgumentException("invalid generator");

        // generate safe prime meeting appropriate add/rem (mod) criteria

        switch (g) {
        // parameters used in generating 'p'; see [ossl]/crypto/dh/dh_gen.c #dh_builtin_genparams
        case 2 : // add = 24, rem = 11
            return BN.generatePrime(bits, true, BigInteger.valueOf(24), BigInteger.valueOf(11));
        case 5 : // add = 10, rem = 3
            return BN.generatePrime(bits, true, BigInteger.valueOf(10), BigInteger.valueOf(3));
        default: // add = 2, rem = 1
            return BN.generatePrime(bits, true, TWO, BigInteger.ONE);
        }
    }

    public static BigInteger generateX(BigInteger p, int limit) {
        if (limit < 0) throw new IllegalArgumentException("invalid limit");

        BigInteger x;
        SecureRandom secureRandom = new SecureRandom();
        // adapting algorithm from org.bouncycastle.crypto.generators.DHKeyGeneratorHelper,
        // which seems a little stronger (?) than OpenSSL's (OSSL just generates a random,
        // while BC generates a random potential prime [for limit > 0], though it's not
        // subject to Miller-Rabin [certainty = 0], but is subject to other constraints)
        // see also [ossl]/crypto/dh/dh_key.c #generate_key
        if (limit == 0) {
            final BigInteger pSub2 = p.subtract(TWO);
            do {
                x = BN.randomIntegerInRange(pSub2, secureRandom);
            } while (x.equals(BigInteger.ZERO));
        } else {
            do {
                // generate potential prime, though with 0 certainty (no Miller-Rabin tests)
                x = new BigInteger(limit, 0, secureRandom);
            } while (x.equals(BigInteger.ZERO));
        }
        return x;
    }

    public static BigInteger generateX(BigInteger p) {
        // OpenSSL default l(imit) is p bits - 1 -- see [ossl]/crypto/dh/dh_key.c #generate_key
        return generateX(p, p.bitLength() - 1);
    }

    public static BigInteger generateY(BigInteger p, BigInteger g, BigInteger x) {
        return g.modPow(x, p);
    }

    public static BigInteger generateY(BigInteger p, int g, BigInteger x) {
        return generateY(p, BigInteger.valueOf(g), x);
    }

    @JRubyMethod(name = "generate_key!")
    public synchronized IRubyObject generate_key() {
        BigInteger p, g, x, y;
        if ((p = this.dh_p) == null || (g = this.dh_g) == null) {
            throw newDHError(getRuntime(), "can't generate key");
        }
        if ((x = this.dh_x) == null) {
            x = generateX(p);
        }
        y = generateY(p, g, x);
        this.dh_x = x;
        this.dh_y = y;
        return this;
    }

    @JRubyMethod(name = "compute_key")
    public synchronized IRubyObject compute_key(IRubyObject other_pub_key) {
        BigInteger x, y, p;
        if ((y = BN.asBigInteger(other_pub_key)) == null) {
            throw getRuntime().newArgumentError("invalid public key");
        }
        if ((x = this.dh_x) == null || (p = this.dh_p) == null) {
            throw newDHError(getRuntime(), "incomplete DH");
        }
        int plen;
        if ((plen = p.bitLength()) == 0 || plen > OPENSSL_DH_MAX_MODULUS_BITS) {
            throw newDHError(getRuntime(), "can't compute key");
        }
        return getRuntime().newString(new ByteList(computeKey(y, x, p), false));
    }

    public static byte[] computeKey(BigInteger y, BigInteger x, BigInteger p) {
        return y.modPow(x, p).toByteArray();
    }

    @JRubyMethod(name = "public?")
    public RubyBoolean public_p() {
        return getRuntime().newBoolean(dh_y != null);
    }

    @Override
    public boolean isPrivateKey() {
        return dh_x != null /* || haveEngine */;
    }

    @JRubyMethod(name = "private?")
    public RubyBoolean private_p() {
        // FIXME! need to figure out what it means in MRI/OSSL code to
        // claim a DH is private if an engine is present -- doesn't really
        // map to Java implementation.
        return getRuntime().newBoolean(isPrivateKey());
    }

    @Override
    @JRubyMethod(name = { "to_pem", "to_s" }, alias = "export", rest = true)
    public RubyString to_pem(ThreadContext context, final IRubyObject[] args) {
        //Arity.checkArgumentCount(getRuntime(), args, 0, 2);

        //CipherSpec spec = null; char[] passwd = null;
        //if ( args.length > 0 ) {
        //    spec = cipherSpec( args[0] );
        //    if ( args.length > 1 ) passwd = password(args[1]);
        //}

        BigInteger p, g;
        synchronized(this) {
            p = this.dh_p;
            g = this.dh_g;
        }
        final StringWriter writer = new StringWriter();
        try {
            PEMInputOutput.writeDHParameters(writer, new DHParameterSpec(p, g));
        }
        catch (NoClassDefFoundError e) {
            throw newDHError(getRuntime(), bcExceptionMessage(e));
        }
        catch (IOException e) { // shouldn't happen (string/buffer io only)
            throw getRuntime().newIOErrorFromException(e);
        }
        return RubyString.newString(getRuntime(), writer.getBuffer());
    }

    @Override
    @JRubyMethod(name = "to_der")
    public RubyString to_der() {
        BigInteger p, g;
        synchronized (this) {
            p = this.dh_p;
            g = this.dh_g;
        }
        try {
            byte[] bytes = org.jruby.ext.openssl.impl.PKey.toDerDHKey(p, g);
            return StringHelper.newString(getRuntime(), bytes);
        } catch (NoClassDefFoundError e) {
            throw newDHError(getRuntime(), bcExceptionMessage(e));
        } catch (IOException ioe) {
            throw newDHError(getRuntime(), ioe.getMessage());
        }
    }

    @JRubyMethod(name = "params")
    public IRubyObject params() {
        BigInteger p, g, x, y;
        synchronized(this) {
            p = this.dh_p;
            g = this.dh_g;
            x = this.dh_x;
            y = this.dh_y;
        }
        final Ruby runtime = getRuntime();
        HashMap<IRubyObject, IRubyObject> params = new HashMap<IRubyObject, IRubyObject>();

        params.put(runtime.newString("p"), BN.newBN(runtime, p));
        params.put(runtime.newString("g"), BN.newBN(runtime, g));
        params.put(runtime.newString("pub_key"), BN.newBN(runtime, x));
        params.put(runtime.newString("priv_key"), BN.newBN(runtime, y));

        return RubyHash.newHash(runtime, params, runtime.getNil());
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "p")
    public IRubyObject get_p() {
        return newBN(dh_p);
    }

    @JRubyMethod(name = "p=")
    public synchronized IRubyObject set_p(IRubyObject arg) {
        this.dh_p = BN.asBigInteger(arg);
        return arg;
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "g")
    public IRubyObject get_g() {
        return newBN(dh_g);
    }

    @JRubyMethod(name = "g=")
    public synchronized IRubyObject set_g(IRubyObject arg) {
        this.dh_g = BN.asBigInteger(arg);
        return arg;
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "pub_key")
    public IRubyObject pub_key() {
        return newBN(dh_y);
    }

    @Override
    public PublicKey getPublicKey() {
        try {
            return getKeyFactory().generatePublic(new DHPublicKeySpec(dh_y, dh_p, dh_g));
        }
        catch (InvalidKeySpecException ex) { throw new RuntimeException(ex); }
    }

    @JRubyMethod(name = "pub_key=")
    public synchronized IRubyObject set_pub_key(IRubyObject arg) {
        this.dh_y = BN.asBigInteger(arg);
        return arg;
    }

    // don't need synchronized as value is volatile
    @JRubyMethod(name = "priv_key")
    public IRubyObject priv_key() {
        return newBN(dh_x);
    }

    @Override
    public PrivateKey getPrivateKey() {
        try {
            return getKeyFactory().generatePrivate(new DHPrivateKeySpec(dh_x, dh_p, dh_g));
        }
        catch (InvalidKeySpecException ex) { throw new RuntimeException(ex); }
    }

    @JRubyMethod(name = "priv_key=")
    public synchronized IRubyObject set_priv_key(IRubyObject arg) {
        this.dh_x = BN.asBigInteger(arg);
        return arg;
    }

    private IRubyObject newBN(BigInteger value) {
        if (value == null) return getRuntime().getNil();
        return BN.newBN(getRuntime(), value);
    }

    private static KeyFactory getKeyFactory() {
        try {
            return SecurityHelper.getKeyFactory("DiffieHellman");
        }
        catch (NoSuchAlgorithmException ex) { throw new RuntimeException(ex); }
    }

}
