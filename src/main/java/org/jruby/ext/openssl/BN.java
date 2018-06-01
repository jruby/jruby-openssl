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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Random;

import org.jruby.Ruby;
import org.jruby.RubyBignum;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.runtime.Visibility;

/**
 * OpenSSL::BN implementation. Wraps java.math.BigInteger, which provides
 * most functionality directly; the rest is easily derived.
 *
 * Beware that BN's are mutable -- I don't agree with this approach, but
 * must conform for compatibility with MRI's implementation. The offending methods
 * are set_bit!, clear_bit!, mask_bits! and copy.<p>
 *
 * I've included a few operations (& | ^ ~) that aren't defined by MRI/OpenSSL.
 * These are non-portable (i.e., won't work in C-Ruby), so use at your own risk.<p>
 *
 * @author <a href="mailto:bill.dortch@gmail.com">Bill Dortch</a>
 */
@JRubyClass(name = "OpenSSL::BN", include = "Comparable")
public class BN extends RubyObject {
    private static final long serialVersionUID = -5660938062191525498L;

    private static final BigInteger MAX_INT = BigInteger.valueOf(Integer.MAX_VALUE);
    static final BigInteger TWO = BigInteger.valueOf(2);

    private static final BigInteger MIN_LONG = BigInteger.valueOf(Long.MIN_VALUE);
    private static final BigInteger MAX_LONG = BigInteger.valueOf(Long.MAX_VALUE);

    private static final int DEFAULT_CERTAINTY = 100;

    private static final ObjectAllocator BN_ALLOCATOR = new ObjectAllocator() {
        public BN allocate(Ruby runtime, RubyClass klass) { return new BN(runtime, klass); }
    };

    public static BN newBN(Ruby runtime, BigInteger value) {
        return newInstance(runtime, value);
    }

    static BN newInstance(final Ruby runtime, BigInteger value) {
        return new BN(runtime, value != null ? value : BigInteger.ZERO);
    }

    static void createBN(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        OpenSSL.defineClassUnder("BNError", OpenSSLError, OpenSSLError.getAllocator());

        RubyClass BN = OpenSSL.defineClassUnder("BN", runtime.getObject(), BN_ALLOCATOR);
        BN.includeModule( runtime.getModule("Comparable") );
        BN.defineAnnotatedMethods(BN.class);
    }

    private volatile BigInteger value;

    private BN(Ruby runtime, RubyClass clazz) {
        super(runtime, clazz);
        this.value = BigInteger.ZERO;
    }

    protected BN(Ruby runtime, BigInteger value) {
        super(runtime, (RubyClass) runtime.getModule("OpenSSL").getConstantAt("BN"));
        this.value = value;
    }

    public final BigInteger getValue() {
        return value;
    }

    @JRubyMethod(name="initialize", required=1, optional=1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        if (this.value != BigInteger.ZERO) { // already initialized
            throw newBNError(runtime, "illegal initialization");
        }
        int argc = Arity.checkArgumentCount(runtime, args, 1, 2);
        int base = argc == 2 ? RubyNumeric.num2int(args[1]) : 10;
        final RubyString str = args[0].asString();
        switch (base) {
        case 0:
            this.value = initBigIntegerMPI(runtime, str);
            break;
        case 2:
            // this seems wrong to me, but is the behavior of the
            // MRI implementation. rather than interpreting the string
            // as ASCII-encoded binary digits, the raw binary value of
            // the string is used instead. the value is always interpreted
            // as positive, hence the use of the signum version of the BI
            // constructor here:
            this.value = new BigInteger(1, str.getBytes());
            break;
        case 10:
        case 16:
            // here, the ASCII-encoded decimal or hex string is used
            this.value = initBigIntegerBase(runtime, str, base);
            break;
        default:
            throw runtime.newArgumentError("illegal radix: " + base);
        }
        return this;
    }

    private static BigInteger initBigIntegerMPI(final Ruby runtime, RubyString str) {
        final ByteList byteList = str.getByteList();
        final int off = byteList.getBegin();
        final byte[] b = byteList.getUnsafeBytes();

        long len = ((b[off] & 0xFFl) << 24) | ((b[off+1] & 0xFF) << 16) | ((b[off+2] & 0xFF) << 8) | (b[off+3] & 0xFF);
        final byte[] bytes = new byte[(int) len];
        System.arraycopy(b, off + 4, bytes, 0, bytes.length);

        final int signum;
        if ( (bytes[0] & 0x80) == 0x80 ) {
            signum = -1; bytes[0] &= 0x7f;
        }
        else {
            signum = +1;
        }
        return new BigInteger(signum, bytes);

    }

    private static BigInteger initBigIntegerBase(final Ruby runtime, RubyString str, final int base) {
        // here, the ASCII-encoded decimal or hex string is used
        try {
            return new BigInteger(str.toString(), base);
        }
        catch (NumberFormatException e) {
            throw runtime.newArgumentError("value " + str + " is not legal for radix " + base);
        }
    }

    @Override
    public IRubyObject initialize_copy(final IRubyObject that) {
        super.initialize_copy(that);
        if ( this != that ) this.value = ((BN) that).value;
        return this;
    }

    @JRubyMethod(name = "copy")
    public IRubyObject copy(IRubyObject other) {
        if (this != other) {
            this.value = asBigInteger(other);
        }
        return this;
    }

    @Deprecated
    public RubyString to_s(IRubyObject[] args) {
        int argc = Arity.checkArgumentCount(getRuntime(), args, 0, 1);
        return to_s( argc == 1 ? RubyNumeric.num2int(args[0]) : 10 );
    }

    @Override
    @JRubyMethod(name = "to_s")
    public RubyString to_s() { return to_s(10); }

    @JRubyMethod(name = "to_s")
    public RubyString to_s(IRubyObject base) {
        return to_s( RubyNumeric.num2int(base) );
    }

    private RubyString to_s(final int base) {
        final Ruby runtime = getRuntime();

        byte[] bytes;
        switch (base) {
        case 0:
            bytes = this.value.abs().toByteArray();
            int offset = 0;
            if (bytes[0] == 0) {
                offset = 1;
            }
            int length = bytes.length - offset;
            boolean negative = BigInteger.ZERO.compareTo(this.value) > 0;
            // for positive values with most significant bit in first byte,
            // add leading '\0'
            boolean need0 = !negative && (bytes[offset] & 0x80) != 0;
            if (negative) {
                // for negative values, set most significant bit in first byte
                bytes[offset] |= 0x80;
            } else if (need0) {
                length++;
            }
            byte[] data = new byte[5 + length];
            data[0] = (byte)(0xff & (length >> 24));
            data[1] = (byte)(0xff & (length >> 16));
            data[2] = (byte)(0xff & (length >>  8));
            data[3] = (byte)(0xff & (length >>  0));
            if (need0) {
                data[4] = 0;
                System.arraycopy(bytes, offset, data, 5, length - 1);
            } else {
                System.arraycopy(bytes, offset, data, 4, length);
            }
            return runtime.newString(new ByteList(data, 0, 4 + length, false));
        case 2:
            // again, following MRI implementation, wherein base 2 deals
            // with strings as byte arrays rather than ASCII-encoded binary
            // digits.  note that negative values are returned as though positive:
            bytes = this.value.abs().toByteArray();
            // suppress leading 0 byte to conform to MRI behavior
            if (bytes[0] == 0) {
                return runtime.newString(new ByteList(bytes, 1, bytes.length - 1, false));
            }
            return runtime.newString(new ByteList(bytes, false));
        case 10:
            return runtime.newString(value.toString(10));
        case 16:
            final String hex = value.toString(16);
            final int len = hex.length();
            final ByteList val = new ByteList(len + 1);
            if ( value.signum() == 1 && len % 2 != 0 ) val.append('0');
            for ( int i = 0; i < len ; i++ ) {
                val.append( Character.toUpperCase(hex.charAt(i)) );
            }
            return runtime.newString(val);
        default:
            throw runtime.newArgumentError("illegal radix: " + base);
        }
    }

    @Override
    public String toString() {
        return to_s().toString();
    }

    public String toString(int base) {
        return to_s(base).toString();
    }

    @Override
    @SuppressWarnings("unchecked")
    @JRubyMethod
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this, Collections.EMPTY_LIST);
    }

    @Override
    public boolean equals(Object other) {
        return (other instanceof BN) ? this.value.equals(((BN) other).value) : false;
    }

    @Override
    public int hashCode() {
        return 997 * value.hashCode();
    }

    @JRubyMethod(name = "hash")
    public RubyInteger hash(final ThreadContext context) {
        return context.runtime.newFixnum(hashCode());
    }

    @JRubyMethod(name = "to_i")
    public RubyInteger to_i() {
        if ( value.compareTo( MAX_LONG ) > 0 || value.compareTo( MIN_LONG ) < 0 ) {
            return RubyBignum.newBignum(getRuntime(), value);
        }
        return RubyFixnum.newFixnum(getRuntime(), value.longValue());
    }

    @JRubyMethod(name = "to_bn")
    public BN to_bn() {
        return this;
    }

    @JRubyMethod(name="coerce")
    // FIXME: is this right? don't see how it would be useful...
    public IRubyObject coerce(IRubyObject other) {
        final Ruby runtime = getRuntime();
        IRubyObject self;
        if ( other instanceof RubyString ) {
            self = runtime.newString(value.toString());
        }
        else if ( other instanceof RubyInteger ) {
            self = to_i();
        }
        else if ( other instanceof BN ) {
            self = this;
        }
        else {
            throw runtime.newTypeError("don't know how to coerce to " + other.getMetaClass().getName());
        }
        return runtime.newArray(other, self);
    }

    @JRubyMethod(name="zero?")
    public RubyBoolean zero_p(final ThreadContext context) {
        return context.runtime.newBoolean( value.equals(BigInteger.ZERO) );
    }

    @JRubyMethod(name="one?")
    public RubyBoolean one_p(final ThreadContext context) {
        return context.runtime.newBoolean( value.equals(BigInteger.ONE) );
    }

    @JRubyMethod(name="odd?")
    public RubyBoolean odd_p(final ThreadContext context) {
        return context.runtime.newBoolean( value.testBit(0) );
    }

    @JRubyMethod(name={"cmp", "<=>"})
    public IRubyObject cmp(final ThreadContext context, IRubyObject other) {
        return context.runtime.newFixnum( value.compareTo( asBigInteger(other) ) );
    }

    @JRubyMethod(name="ucmp")
    public IRubyObject ucmp(final ThreadContext context, IRubyObject other) {
        return context.runtime.newFixnum( value.abs().compareTo( asBigInteger(other).abs() ) );
    }

    @JRubyMethod(name = "eql?")
    public IRubyObject eql_p(ThreadContext context, IRubyObject other) {
        return context.runtime.newBoolean(eql(other));
    }

    @Override
    public boolean eql(IRubyObject other) {
        return equals(other);
    }

    @JRubyMethod(name = "==")
    public IRubyObject op_equal(ThreadContext context, IRubyObject other) {
        return context.runtime.newBoolean( value.equals( asBigInteger(other) ) );
    }

    @JRubyMethod(name="sqr")
    public BN sqr(final ThreadContext context) {
        // TODO: check whether mult n * n is faster
        return newBN(context.runtime, value.pow(2));
    }

    @JRubyMethod(name="~")
    public BN not(final ThreadContext context) {
        return newBN(context.runtime, value.not());
    }

    @JRubyMethod(name="+")
    public BN add(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.add(asBigInteger(other)));
    }

    @JRubyMethod(name="-")
    public BN sub(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.subtract(asBigInteger(other)));
    }

    @JRubyMethod(name="*")
    public BN mul(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.multiply(asBigInteger(other)));
    }

    @JRubyMethod(name="%")
    public BN mod(final ThreadContext context, IRubyObject other) {
        try {
            return newBN(context.runtime, value.mod(asBigInteger(other)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="/")
    public IRubyObject div(final ThreadContext context, IRubyObject other) {
        final Ruby runtime = context.runtime;
        try {
            BigInteger[] result = value.divideAndRemainder(asBigInteger(other));
            return runtime.newArray(newBN(runtime, result[0]), newBN(runtime, result[1]));
        }
        catch (ArithmeticException e) {
            throw runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="&")
    public BN and(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.and(asBigInteger(other)));
    }

    @JRubyMethod(name="|")
    public BN or(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.or(asBigInteger(other)));
    }

    @JRubyMethod(name="^")
    public BN xor(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.xor(asBigInteger(other)));
    }

    @JRubyMethod(name="**")
    public BN exp(final ThreadContext context, IRubyObject other) {
        // somewhat strangely, BigInteger takes int rather than BigInteger
        // as the argument to pow.  so we'll have to narrow the value, and
        // raise an exception if data would be lost. (on the other hand, an
        // exponent even approaching Integer.MAX_VALUE would be silly big, and
        // the value would take a very, very long time to calculate.)
        // we'll check for values < 0 (illegal) while we're at it
        int exp = -1;

        if ( other instanceof RubyInteger ) {
            long val = ((RubyInteger) other).getLongValue();
            if ( val >= 0 && val <= Integer.MAX_VALUE ) {
                exp = (int) val;
            }
            else if ( other instanceof RubyBignum ) { // inherently too big
                throw newBNError(context.runtime, "invalid exponent");
            }
        }

        if ( exp == -1 ) {
            if ( ! (other instanceof BN) ) {
                throw context.runtime.newTypeError("Cannot convert into " + other.getMetaClass().getName());
            }
            BigInteger val = ((BN) other).value;
            if (val.compareTo(BigInteger.ZERO) < 0 || val.compareTo(MAX_INT) > 0) {
                throw newBNError(context.runtime, "invalid exponent");
            }
            exp = val.intValue();
        }

        try {
            return newBN(context.runtime, value.pow(exp));
        }
        catch (ArithmeticException e) {
            // shouldn't happen, we've already checked for < 0
            throw newBNError(context.runtime, "invalid exponent");
        }
    }

    @JRubyMethod(name="gcd")
    public BN gcd(final ThreadContext context, IRubyObject other) {
        return newBN(context.runtime, value.gcd(asBigInteger(other)));
    }

    @JRubyMethod(name="mod_sqr")
    public BN mod_sqr(final ThreadContext context, IRubyObject other) {
        try {
            return newBN(context.runtime, value.modPow(TWO, asBigInteger(other)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="mod_inverse")
    public BN mod_inverse(final ThreadContext context, IRubyObject other) {
        try {
            return newBN(context.runtime, value.modInverse(asBigInteger(other)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="mod_add")
    public BN mod_add(final ThreadContext context, IRubyObject other, IRubyObject mod) {
        try {
            return newBN(context.runtime, value.add(asBigInteger(other)).mod(asBigInteger(mod)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="mod_sub")
    public BN mod_sub(final ThreadContext context, IRubyObject other, IRubyObject mod) {
        try {
            return newBN(context.runtime, value.subtract(asBigInteger(other)).mod(asBigInteger(mod)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="mod_mul")
    public BN mod_mul(final ThreadContext context, IRubyObject other, IRubyObject mod) {
        try {
            return newBN(context.runtime, value.multiply(asBigInteger(other)).mod(asBigInteger(mod)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="mod_exp")
    public BN mod_exp(final ThreadContext context, IRubyObject other, IRubyObject mod) {
        try {
            return newBN(context.runtime, value.modPow(asBigInteger(other), asBigInteger(mod)));
        }
        catch (ArithmeticException e) {
            throw context.runtime.newZeroDivisionError();
        }
    }

    @JRubyMethod(name="set_bit!")
    public synchronized IRubyObject set_bit(IRubyObject n) {
        // evil mutable BN
        int pos = RubyNumeric.num2int(n);
        BigInteger oldValue = this.value;
        // FIXME? in MRI/OSSL-BIGNUM, the original sign of a BN is remembered, so if
        // you set the value of an (originally) negative number to zero (through some
        // combination of clear_bit! and/or mask_bits! calls), and later call set_bit!,
        // the resulting value will be negative.  this seems unintuitive and, frankly,
        // wrong, not to mention expensive to carry the extra sign field.
        // I'm not duplicating this behavior here at this time. -BD
        try {
            if (oldValue.signum() >= 0) {
                this.value = oldValue.setBit(pos);
            } else {
                this.value = oldValue.abs().setBit(pos).negate();
            }
        } catch (ArithmeticException e) {
            throw newBNError(getRuntime(), "invalid pos");
        }
        return this;
    }

    @JRubyMethod(name="clear_bit!")
    public synchronized IRubyObject clear_bit(IRubyObject n) {
        // evil mutable BN
        int pos = RubyNumeric.num2int(n);
        BigInteger oldValue = this.value;
        try {
            if (oldValue.signum() >= 0) {
                this.value = oldValue.clearBit(pos);
            } else {
                this.value = oldValue.abs().clearBit(pos).negate();
            }
        } catch (ArithmeticException e) {
            throw newBNError(getRuntime(), "invalid pos");
        }
        return this;
    }

    /**
     * Truncates value to n bits
     */
    @JRubyMethod(name="mask_bits!")
    public synchronized IRubyObject mask_bits(IRubyObject n) {
        // evil mutable BN

        int pos = RubyNumeric.num2int(n);
        if (pos < 0) throw newBNError(getRuntime(), "invalid pos");

        BigInteger oldValue = this.value;

        // TODO: cache 2 ** n values?
        if (oldValue.signum() >= 0) {
            if (oldValue.bitLength() < pos) throw newBNError(getRuntime(), "invalid pos");
            this.value = oldValue.mod(TWO.pow(pos));
        } else {
            BigInteger absValue = oldValue.abs();
            if (absValue.bitLength() < pos) throw newBNError(getRuntime(), "invalid pos");
            this.value = absValue.mod(TWO.pow(pos)).negate();
        }

        return this;
    }

    @JRubyMethod(name="bit_set?")
    public RubyBoolean bit_set_p(final ThreadContext context, IRubyObject n) {
        int pos = RubyNumeric.num2int(n);
        BigInteger val = this.value;
        try {
            if (val.signum() >= 0) {
                return context.runtime.newBoolean(val.testBit(pos));
            }
            return context.runtime.newBoolean(val.abs().testBit(pos));
        }
        catch (ArithmeticException e) {
            throw newBNError(context.runtime, "invalid pos");
        }
    }

    @JRubyMethod(name="<<")
    public BN lshift(final ThreadContext context, IRubyObject n) {
        int nbits = RubyNumeric.num2int(n);
        BigInteger val = this.value;
        if (val.signum() >= 0) {
            return newBN(context.runtime, val.shiftLeft(nbits));
        }
        return newBN(context.runtime, val.abs().shiftLeft(nbits).negate());
    }

    @JRubyMethod(name=">>")
    public BN rshift(final ThreadContext context, IRubyObject n) {
        int nbits = RubyNumeric.num2int(n);
        BigInteger val = this.value;
        if (val.signum() >= 0) {
            return newBN(context.runtime, val.shiftRight(nbits));
        }
        return newBN(context.runtime, val.abs().shiftRight(nbits).negate());
    }

    @JRubyMethod(name="num_bits")
    public RubyFixnum num_bits(final ThreadContext context) {
        return context.runtime.newFixnum( this.value.abs().bitLength() );
    }

    @JRubyMethod(name="num_bytes")
    public RubyFixnum num_bytes(final ThreadContext context) {
        return context.runtime.newFixnum( (this.value.abs().bitLength() + 7) / 8 );
    }

    @JRubyMethod(name="num_bits_set")
    public RubyFixnum num_bits_set(final ThreadContext context) {
        return context.runtime.newFixnum( this.value.abs().bitCount() );
    }

    // note that there is a bug in the MRI version, in argument handling,
    // so apparently no one ever calls this...
    @JRubyMethod(name = "prime?", rest = true)
    public IRubyObject prime_p(IRubyObject[] args) {
        final Ruby runtime = getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 0, 1);

        // negative numbers are always considered non-prime
        if (this.value.signum() < 0) return runtime.getFalse();

        int certainty = argc == 0 ? DEFAULT_CERTAINTY : RubyNumeric.fix2int(args[0]);

        // BigInteger#isProbablePrime will actually limit checks to a maximum of 50,
        // depending on bit count.
        return runtime.newBoolean(this.value.isProbablePrime(certainty));
    }

    // NOTE: BigInteger doesn't supply this, so right now this is
    // ... (essentially) the same as prime?
    @JRubyMethod(name = "prime_fasttest?", rest = true)
    public IRubyObject prime_fasttest_p(IRubyObject[] args) {
        final Ruby runtime = getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 0, 2);

        // negative numbers are always considered non-prime
        if (this.value.signum() < 0) return runtime.getFalse();

        int certainty = argc == 0 ? DEFAULT_CERTAINTY : RubyNumeric.fix2int(args[0]);
        
        // BigInteger#isProbablePrime will actually limit checks to a maximum of 50,
        // depending on bit count.
        return runtime.newBoolean(this.value.isProbablePrime(certainty));
    }

    @JRubyMethod(name = "generate_prime", meta = true, rest = true)
    public static IRubyObject generate_prime(IRubyObject recv, IRubyObject[] args) {
        Ruby runtime = recv.getRuntime();
        int argc = Arity.checkArgumentCount(runtime, args, 1, 4);
        int bits = RubyNumeric.num2int(args[0]);
        boolean safe = argc > 1 ? args[1] != runtime.getFalse() : true;
        BigInteger add = argc > 2 ? asBigInteger(args[2]) : null;
        BigInteger rem = argc > 3 ? asBigInteger(args[3]) : null;
        if (bits < 3) {
            if (safe) throw runtime.newArgumentError("bits < 3");
            if (bits < 2) throw runtime.newArgumentError("bits < 2");
        }
        return newBN(runtime, generatePrime(bits, safe, add, rem));
    }

    public static BigInteger generatePrime(int bits, boolean safe, BigInteger add, BigInteger rem) {
        // From OpenSSL man page BN_generate_prime(3):
        //
        // "If add is not NULL, the prime will fulfill the condition p % add == rem
        // (p % add == 1 if rem == NULL) in order to suit a given generator."
        //
        // "If safe is true, it will be a safe prime (i.e. a prime p so that
        // (p-1)/2 is also prime)."
        //
        // see [ossl]/crypto/bn/bn_prime.c #BN_generate_prime_ex
        //

        if (add != null && rem == null) {
            rem = BigInteger.ONE;
        }

        // borrowing technique from org.bouncycastle.crypto.generators.DHParametersHelper
        // (unfortunately the code has package visibility), wherein for safe primes,
        // we'll use the lowest useful certainty (2) for generation of q, then if
        // p ( = 2q + 1) is prime to our required certainty (100), we'll verify that q
        // is as well.
        //
        // for typical bit lengths ( >= 1024), this should speed things up by reducing
        // initial Miller-Rabin iterations from 2 to 1 for candidate values of q.
        //
        // it's still painfully slow...
        //
        BigInteger p, q;
        int qbits = bits - 1;
        SecureRandom secureRandom = getSecureRandom();
        do {
            if (safe) {
                do {
                    q = new BigInteger(qbits, 2, secureRandom);
                    p = q.shiftLeft(1).setBit(0);
                } while (!(p.isProbablePrime(DEFAULT_CERTAINTY) && q.isProbablePrime(DEFAULT_CERTAINTY)));
            } else {
                p = BigInteger.probablePrime(bits, secureRandom);
            }
        } while (add != null && !p.mod(add).equals(rem));
        return p;
    }

    public static BigInteger generatePrime(int bits, boolean safe) {
        return generatePrime(bits, safe, null, null);
    }

    @JRubyMethod(name = "rand", meta = true, rest = true)
    public static IRubyObject rand(IRubyObject recv, IRubyObject[] args) {
        return getRandomBN(recv.getRuntime(), args, getSecureRandom());
    }

    @JRubyMethod(name = "pseudo_rand", meta = true, rest = true)
    public static IRubyObject pseudo_rand(IRubyObject recv, IRubyObject[] args) {
        return getRandomBN(recv.getRuntime(), args, getRandom());
    }

    public static BN getRandomBN(Ruby runtime, IRubyObject[] args, Random random) {
        int argc = Arity.checkArgumentCount(runtime, args, 1, 3);
        int bits = RubyNumeric.num2int(args[0]);
        int top;
        boolean bottom;
        if (argc > 1) {
            top = RubyNumeric.fix2int(args[1]);
            bottom = argc == 3 ? args[2].isTrue() : false;
        } else {
            top = 0;
            bottom = false;
        }

        BigInteger value;
        try {
            value = getRandomBI(bits, top, bottom, random);
        } catch (IllegalArgumentException e) {
            throw runtime.newArgumentError(e.getMessage());
        }
        return newBN(runtime, value);
    }

    public static BigInteger getRandomBI(int bits, int top, boolean bottom, Random random) {
        // From OpenSSL man page BN_rand(3):
        //
        // "If top is -1, the most significant bit of the random number can be zero.
        // If top is 0, it is set to 1, and if top is 1, the two most significant bits
        // of the number will be set to 1, so that the product of two such random numbers
        // will always have 2*bits length."
        //
        // "If bottom is true, the number will be odd."
        //
        if (bits <= 0) {
            if (bits == 0) return BigInteger.ZERO;
            throw new IllegalArgumentException("Illegal bit length");
        }
        if (top < -1 || top > 1) {
            throw new IllegalArgumentException("Illegal top value");
        }

        // top/bottom handling adapted from OpenSSL's crypto/bn/bn_rand.c
        int bytes = (bits + 7) / 8;
        int bit = (bits - 1) % 8;
        int mask = 0xff << (bit + 1);

        byte[] buf;
        random.nextBytes(buf = new byte[bytes]);
        if (top >= 0) {
            if (top == 0) {
                buf[0] |= (1 << bit);
            } else {
                if (bit == 0) {
                    buf[0] = 1;
                    buf[1] |= 0x80;
                }
                else {
                    buf[0] |= (3 << (bit - 1));
                }
            }
        }
        buf[0] &= ~mask;
        if (bottom) {
            buf[bytes-1] |= 1;
        }

        // treating result as unsigned
        return new BigInteger(1, buf);
    }

    @JRubyMethod(name = "rand_range", meta = true)
    public static IRubyObject rand_range(IRubyObject recv, IRubyObject arg) {
        return randomValueInRange(recv.getRuntime(), asBigInteger(arg), getSecureRandom());
    }

    @JRubyMethod(name = "pseudo_rand_range", meta = true)
    public static IRubyObject pseudo_rand_range(IRubyObject recv, IRubyObject arg) {
        return randomValueInRange(recv.getRuntime(), asBigInteger(arg), getRandom());
    }

    private static BN randomValueInRange(Ruby runtime, BigInteger limit, Random random) {
        BigInteger value;
        try {
            value = randomIntegerInRange(limit, random);
        }
        catch (IllegalArgumentException e) {
            throw newBNError(runtime, e.getMessage());
        }
        return newInstance(runtime, value);
    }

    public static BigInteger randomIntegerInRange(BigInteger limit, Random random) {
        if (limit.signum() < 0) {
            throw new IllegalArgumentException("illegal range: " + limit);
        }
        int bits = limit.bitLength();
        BigInteger value;
        do {
            value = new BigInteger(bits, random);
        } while (value.compareTo(limit) >= 0);
        return value;
    }

    private static Random random;

    private static Random getRandom() {
        final Random rnd;
        if ( ( rnd = BN.random ) != null ) {
            return rnd;
        }
        return BN.random = new Random();
    }

    private static SecureRandom secureRandom;

    private static SecureRandom getSecureRandom() {
        final SecureRandom rnd;
        if ( ( rnd = BN.secureRandom ) != null ) {
            return rnd;
        }
        // NOTE: will use (default) Sun's even if BC provider is set
        return BN.secureRandom = new SecureRandom();
    }

    public static RaiseException newBNError(Ruby runtime, String message) {
        return new RaiseException(runtime, runtime.getModule("OpenSSL").getClass("BNError"), message, true);
    }

    public static BigInteger asBigInteger(final IRubyObject arg) {
        if ( arg.isNil() ) return null;

        if ( arg instanceof RubyInteger ) {
            return ((RubyInteger) arg).getBigIntegerValue();
        }

        if ( arg instanceof BN ) return ((BN) arg).value;

        throw arg.getRuntime().newTypeError("Cannot convert into OpenSSL::BN");
    }

    public static BigInteger asBigInteger(final BN arg) {
        return arg.isNil() ? null : arg.value;
    }

    @Deprecated
    public static BigInteger getBigInteger(final IRubyObject arg) {
        return asBigInteger(arg);
    }

    @Override
    public Object toJava(Class target) {
        if ( target.isAssignableFrom(BigInteger.class) || target == Number.class ) return value;
        if ( target == Long.class || target == Long.TYPE ) return value.longValue();
        if ( target == Integer.class || target == Integer.TYPE ) return value.intValue();
        if ( target == Double.class || target == Double.TYPE ) return value.doubleValue();
        if ( target == Float.class || target == Float.TYPE ) return value.floatValue();
        return super.toJava(target);
    }

}
