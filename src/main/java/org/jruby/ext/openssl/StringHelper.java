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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Locale;

import org.jcodings.specific.UTF8Encoding;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.jruby.Ruby;
import org.jruby.RubyEncoding;
import org.jruby.RubyFile;
import org.jruby.RubyIO;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.x509store.PEMInputOutput;

/**
 *
 * @author kares
 */
abstract class StringHelper {

    static RubyString newString(final Ruby runtime, final byte[] bytes) {
        final ByteList byteList = new ByteList(bytes, false);
        return RubyString.newString(runtime, byteList);
    }

    static RubyString newString(final Ruby runtime, final byte[] bytes, final int count) {
        final ByteList byteList = new ByteList(bytes, 0, count, false);
        return RubyString.newString(runtime, byteList);
    }

    static ByteList setByteListShared(final RubyString str) {
        str.setByteListShared();
        return str.getByteList();
    }

    static RubyString newUTF8String(final Ruby runtime, final ByteList bytes) {
        ByteList byteList = new ByteList(RubyEncoding.encodeUTF8(bytes), UTF8Encoding.INSTANCE, false);
        return new RubyString(runtime, runtime.getString(), byteList);
    }

    static RubyString newUTF8String(final Ruby runtime, final CharSequence chars) {
        ByteList byteList = new ByteList(RubyEncoding.encodeUTF8(chars), UTF8Encoding.INSTANCE, false);
        return new RubyString(runtime, runtime.getString(), byteList);
    }

    static RubyString newStringFrozen(final Ruby runtime, final ByteList bytes) {
        final RubyString str = RubyString.newStringShared(runtime, bytes);
        str.setFrozen(true); return str;
    }

    static RubyString newStringFrozen(final Ruby runtime, final CharSequence chars) {
        final RubyString str = RubyString.newString(runtime, chars);
        str.setFrozen(true); return str;
    }

    static byte[] readX509PEM(final ThreadContext context, IRubyObject arg) {
        final RubyString str = StringHelper.readPossibleDERInput(context, arg);
        final ByteList bytes = str.getByteList();
        return readX509PEM(bytes.unsafeBytes(), bytes.getBegin(), bytes.getRealSize());
    }

    static byte[] readX509PEM(final byte[] bytes, final int offset, final int length) {
        InputStreamReader in = new InputStreamReader(new ByteArrayInputStream(bytes, offset, length));
        try {
            byte[] readBytes = PEMInputOutput.readX509PEM(in);
            if ( readBytes != null ) return readBytes;
        }
        catch (IOException e) {
            // this is not PEM encoded, let's use the default argument
        }
        if ( offset == 0 && length == bytes.length ) return bytes;
        byte[] copy = new byte[length];
        System.arraycopy(bytes, offset, copy, 0, length);
        return copy;
    }

    static RubyString readPossibleDERInput(final ThreadContext context, final IRubyObject arg) {
        return readInput(context, OpenSSL.to_der_if_possible(context, arg));
    }

    static RubyString readInput(final ThreadContext context, final IRubyObject arg) {
        if ( arg instanceof RubyIO ) {
            final IRubyObject result;
            if ( arg instanceof RubyFile ) {
                result = ( (RubyFile) arg.dup() ).read(context);
            }
            else {
                result = ( (RubyIO) arg ).read(context);
            }
            if ( result instanceof RubyString ) return (RubyString) result;
            throw context.runtime.newArgumentError("IO `" + arg.inspect() + "' contained no data");
        }
        return arg.asString();
    }

    static final ByteList NEW_LINE = new ByteList(new byte[] { '\n' }, false);
    static final ByteList COMMA_SPACE = new ByteList(new byte[] { ',',' ' }, false);

    static final char[] S20 = new char[] {
        ' ',' ',' ',' ',  ' ',' ',' ',' ',
        ' ',' ',' ',' ',  ' ',' ',' ',' ',
        ' ',' ',' ',' ',
    };

    private static final DateTimeFormatter ASN_DATE_NO_ZONE =
        DateTimeFormat.forPattern("MMM dd HH:mm:ss yyyy") // + " zzz"
                      .withLocale(Locale.US)
                      .withZone(DateTimeZone.UTC);

    static StringBuilder appendGMTDateTime(final StringBuilder text, final DateTime time) {
        final String date = ASN_DATE_NO_ZONE.print( time.getMillis() );
        final int len = text.length();
        text.append(date).append(' ').append("GMT");
        if ( date.charAt(4) == '0' ) { // Jul 07 -> Jul  7
            text.setCharAt(len + 4, ' ');
        }
        return text;
    }

    //static StringBuilder lowerHexBytes(final BigInteger bytes) {
    //    return lowerHexBytes(bytes.toByteArray(), 1); // skip the sign bit
    //}

    static StringBuilder lowerHexBytes(final byte[] bytes, final int offset) {
        final int len = bytes.length;
        final StringBuilder hex = new StringBuilder(len * 3);
        for (int i = offset; i < bytes.length; i++ ) {
            final String h = Integer.toHexString( bytes[i] & 0xFF );
            if ( h.length() == 1 ) hex.append('0');
            hex.append( h ).append(':');
        }
        if ( hex.length() > 0 ) hex.setLength( hex.length() - 1 );
        return hex;
    }

    static void appendLowerHexValue(final StringBuilder text, final byte[] hex,
        final int indent, final int rowLength) {
        final StringBuilder hexStr = lowerHexBytes( hex, 0 );
        final int len = hexStr.length(); int left = len;
        while ( left > 0 ) {
            int print = rowLength; if ( left < rowLength ) print = left;
            final int start = len - left;
            text.append(S20,0,indent).append( hexStr, start, start + print ).append('\n');
            left -= print;
        }
    }

    @SuppressWarnings("unchecked")
    static <T extends CharSequence> ArrayList<T> split(final T string, final char separator) {
        final ArrayList<T> split = new ArrayList<T>(8); int last = 0;
        for ( int i = 0; i < string.length(); i++ ) {
            if ( string.charAt(i) == separator ) {
                split.add( (T) string.subSequence(last, i) ); last = ++i;
            }
        }
        if ( last == 0 ) split.add(string); // split.isEmpty
        else split.add( (T) string.subSequence(last, string.length()) );
        return split;
    }

    public static String[] split(final String string, final char separator) {
        final ArrayList<CharSequence> split = split((CharSequence) string, separator);
        return split.toArray( new String[ split.size() ] );
    }

}
