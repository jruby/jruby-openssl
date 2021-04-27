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
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import org.jruby.ext.openssl.x509store.Name;
import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.StringHelper.newString;

/**
 *
 * TODO member variables and methods are based on BC X509 way of doing things (now deprecated). Change
 * it to do it the X500 way, with RDN and X500NameBuilder.
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Name extends RubyObject {
    private static final long serialVersionUID = -226196051911335103L;

    private static ObjectAllocator X509NAME_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509Name(runtime, klass);
        }
    };

    static void createX509Name(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass _Name = X509.defineClassUnder("Name", runtime.getObject(), X509NAME_ALLOCATOR);
        X509.defineClassUnder("NameError", OpenSSLError, OpenSSLError.getAllocator());

        _Name.defineAnnotatedMethods(X509Name.class);
        _Name.includeModule(runtime.getComparable());

        _Name.setConstant("COMPAT", runtime.newFixnum(COMPAT));
        _Name.setConstant("RFC2253", runtime.newFixnum(RFC2253));
        _Name.setConstant("ONELINE", runtime.newFixnum(ONELINE));
        _Name.setConstant("MULTILINE", runtime.newFixnum(MULTILINE));

        final RubyFixnum UTF8_STRING = runtime.newFixnum(BERTags.UTF8_STRING);
        _Name.setConstant("DEFAULT_OBJECT_TYPE", UTF8_STRING);

        final RubyFixnum PRINTABLE_STRING = runtime.newFixnum(BERTags.PRINTABLE_STRING);
        final RubyFixnum IA5_STRING = runtime.newFixnum(BERTags.IA5_STRING);

        final ThreadContext context = runtime.getCurrentContext();
        final RubyHash hash = new RubyHash(runtime, UTF8_STRING);
        hash.op_aset(context, newString(runtime, new byte[] { 'C' }), PRINTABLE_STRING);
        final byte[] countryName = { 'c','o','u','n','t','r','y','N','a','m','e' };
        hash.op_aset(context, newString(runtime, countryName), PRINTABLE_STRING);
        final byte[] serialNumber = { 's','e','r','i','a','l','N','u','m','b','e','r' };
        hash.op_aset(context, newString(runtime, serialNumber), PRINTABLE_STRING);
        final byte[] dnQualifier = { 'd','n','Q','u','a','l','i','f','i','e','r' };
        hash.op_aset(context, newString(runtime, dnQualifier), PRINTABLE_STRING);
        hash.op_aset(context, newString(runtime, new byte[] { 'D','C' }), IA5_STRING);
        final byte[] domainComponent = { 'd','o','m','a','i','n','C','o','m','p','o','n','e','n','t' };
        hash.op_aset(context, newString(runtime, domainComponent), IA5_STRING);
        final byte[] emailAddress = { 'e','m','a','i','l','A','d','d','r','e','s','s' };
        hash.op_aset(context, newString(runtime, emailAddress), IA5_STRING);

        _Name.setConstant("OBJECT_TYPE_TEMPLATE", hash);
    }

    static X509Name newName(final Ruby runtime) {
        return new X509Name(runtime, _Name(runtime));
    }

    static X509Name newName(final Ruby runtime, final X500Principal principal) {
        final X509Name name = newName(runtime);
        name.fromASN1Sequence( principal.getEncoded() );
        return name;
    }

    static X509Name newName(final Ruby runtime, org.bouncycastle.asn1.x500.X500Name realName) {
        final X509Name name = newName(runtime);
        name.fromASN1Sequence((ASN1Sequence) realName.toASN1Primitive());
        return name;
    }

    @Deprecated
    public static X509Name create(final Ruby runtime, org.bouncycastle.asn1.x500.X500Name realName) {
        return newName(runtime, realName);
    }

    static RubyClass _Name(final Ruby runtime) {
        return _X509(runtime).getClass("Name");
    }

    public static final int COMPAT = 0;
    public static final int RFC2253 = 17892119;
    public static final int ONELINE = 8520479;
    public static final int MULTILINE = 44302342;

    public X509Name(Ruby runtime, RubyClass type) {
        super(runtime,type);
        oids = new ArrayList<ASN1ObjectIdentifier>();
        values = new ArrayList<ASN1Encodable>();
        types = new ArrayList<RubyInteger>();
    }

    private final List<ASN1ObjectIdentifier> oids;
    private final List<ASN1Encodable> values; // <ASN1String>
    private final List<RubyInteger> types;

    private transient X500Name name;
    private transient X500Name canonicalName;

    private void fromASN1Sequence(final byte[] encoded) {
        try {
            fromASN1Sequence((ASN1Sequence) new ASN1InputStream(encoded).readObject());
        }
        catch (IOException e) {
            throw newNameError(getRuntime(), e.getClass().getName() + ":" + e.getMessage());
        }
    }

    void fromASN1Sequence(final ASN1Sequence seq) {
        oids.clear(); values.clear(); types.clear();
        if ( seq != null ) {
            for ( Enumeration e = seq.getObjects(); e.hasMoreElements(); ) {
                ASN1Object element = (ASN1Object) e.nextElement();
                if ( element instanceof RDN ) {
                    fromRDNElement((RDN) element);
                }
                else if ( element instanceof ASN1Sequence ) {
                    fromASN1Sequence(element);
                }
                else {
                    fromASN1Set(element);
                }
            }
        }
    }

    private void fromRDNElement(final RDN rdn) {
        final Ruby runtime = getRuntime();
        for( AttributeTypeAndValue tv: rdn.getTypesAndValues() ) {
            oids.add( tv.getType() );
            final ASN1Encodable val = tv.getValue();
            addValue( val );
            addType( runtime, val );
        }
    }

    private void fromASN1Set(final ASN1Object element) {
        ASN1Set typeAndValue = ASN1Set.getInstance(element);
        for ( int i = 0; i < typeAndValue.size(); i++ ) {
            fromASN1Sequence( typeAndValue.getObjectAt(i) );
        }
    }

    private void fromASN1Sequence(final ASN1Encodable element) {
        ASN1Sequence typeAndValue = ASN1Sequence.getInstance(element);
        oids.add( (ASN1ObjectIdentifier) typeAndValue.getObjectAt(0) );
        final ASN1Encodable val = typeAndValue.getObjectAt(1);
        addValue( val );
        addType( getRuntime(), val );
    }

    private void addValue(final ASN1Encodable value) {
        if ( value instanceof ASN1String ) {
            this.values.add( value );
        }
        else {
            warn(getRuntime().getCurrentContext(), this + " addValue() value not an ASN1 string = '" + value + "' (" + ( value == null ? "" : value.getClass().getName()) + ")");
            this.values.add( value ); // TODO should not happen?!
        }
    }

    @SuppressWarnings("unchecked")
    private void addType(final Ruby runtime, final ASN1Encodable value) {
        this.name = null; // NOTE: each fromX factory calls this ...
        this.canonicalName = null;
        final Integer type = ASN1.typeId(value);
        if ( type == null ) {
            warn(runtime.getCurrentContext(), this + " addType() could not resolve type for: " +
                 value + " (" + (value == null ? "" : value.getClass().getName()) + ")");
            ((List) this.types).add( runtime.getNil() );
        }
        else {
            this.types.add( runtime.newFixnum( type.intValue() ) );
        }
    }

    private void addEntry(ASN1ObjectIdentifier oid, RubyString value, RubyInteger type)
        throws IOException {
        this.name = null;
        this.canonicalName = null;
        this.oids.add(oid);
        final ASN1Encodable convertedValue = getNameEntryConverted().
                getConvertedValue(oid, value.toString()
        );
        this.values.add( convertedValue );
        this.types.add(type);
    }

    private static X509NameEntryConverter getNameEntryConverted() {
        return new X509DefaultEntryConverter();
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context) {
        return this;
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context, IRubyObject str_or_dn) {
        return initialize(context, str_or_dn, context.nil);
    }

    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject dn, IRubyObject template) {
        final Ruby runtime = context.runtime;

        if ( dn instanceof RubyArray ) {
            RubyArray ary = (RubyArray) dn;

            final RubyClass _Name = _Name(runtime);

            if ( template.isNil() ) template = _Name.getConstant("OBJECT_TYPE_TEMPLATE");

            for (int i = 0; i < ary.size(); i++) {
                IRubyObject obj = ary.eltOk(i);

                if ( ! (obj instanceof RubyArray) ) {
                    throw runtime.newTypeError(obj, runtime.getArray());
                }

                RubyArray arr = (RubyArray)obj;

                IRubyObject entry0, entry1, entry2;
                entry0 = arr.size() > 0 ? arr.eltOk(0) : context.nil;
                entry1 = arr.size() > 1 ? arr.eltOk(1) : context.nil;
                entry2 = arr.size() > 2 ? arr.eltOk(2) : context.nil;

                if (entry2.isNil()) entry2 = template.callMethod(context, "[]", entry0);
                if (entry2.isNil()) entry2 = _Name.getConstant("DEFAULT_OBJECT_TYPE");

                add_entry(context, entry0, entry1, entry2);
            }
        }
        else {
            IRubyObject enc = to_der_if_possible(context, dn);
            fromASN1Sequence( enc.asString().getBytes() );
        }
        return this;
    }

    /*
    private static void printASN(final ASN1Encodable obj, final StringBuilder out) {
        printASN(obj, 0, out);
    }

    private static void printASN(final ASN1Encodable obj, final int indent, final StringBuilder out) {
        for( int i = 0; i < indent; i++ ) out.append(' ');
        if ( obj instanceof ASN1Sequence ) {
            out.append("- Sequence:");
            for ( Enumeration e = ((ASN1Sequence) obj).getObjects(); e.hasMoreElements(); ) {
                printASN((ASN1Encodable) e.nextElement(), indent + 1, out);
            }
        }
        else if ( obj instanceof ASN1Set ) {
            out.append("- Set:");
            for ( Enumeration e = ((ASN1Set) obj).getObjects(); e.hasMoreElements(); ) {
                printASN((ASN1Encodable) e.nextElement(), indent + 1, out);
            }
        }
        else {
            if ( obj instanceof ASN1String ) {
                out.append("- ").append(obj).
                    append('=').append( ((ASN1String) obj).getString() ).
                    append('[').append( obj.getClass().getName() ).append(']');
            } else {
                out.append("- ").append(obj).
                    append('[').append( obj.getClass().getName() ).append(']');
            }
        }
    } */

    @JRubyMethod
    public IRubyObject add_entry(ThreadContext context, IRubyObject oid, IRubyObject value) {
        return add_entry(context, oid, value, null);
    }

    @JRubyMethod
    public IRubyObject add_entry(final ThreadContext context,
        final IRubyObject oid, final IRubyObject value, IRubyObject type) {
        final Ruby runtime = context.runtime;

        final RubyString oidStr = oid.asString();

        if ( type == null || type.isNil() ) type = getDefaultType(context, oidStr);

        final ASN1ObjectIdentifier objectId;
        try {
            objectId = ASN1.getObjectID( runtime, oidStr.toString() );
        }
        catch (IllegalArgumentException e) {
            throw newNameError(runtime, "invalid field name: " + oidStr, e);
        }
        // NOTE: won't reach here :
        if ( objectId == null ) throw newNameError(runtime, "invalid field name");

        try {
            addEntry(objectId, value.asString(), (RubyInteger) type);
        }
        catch (IOException e) {
            throw newNameError(runtime, "invalid value", e);
        }
        return this;
    }

    private static IRubyObject getDefaultType(final ThreadContext context, final RubyString oid) {
        IRubyObject template = _Name(context.runtime).getConstant("OBJECT_TYPE_TEMPLATE");
        if ( template instanceof RubyHash ) {
            return ((RubyHash) template).op_aref(context, oid);
        }
        return template.callMethod(context, "[]", oid);
    }

    @SuppressWarnings("unchecked")
    @JRubyMethod(name = "to_s", rest = true)
    public IRubyObject to_s(IRubyObject[] args) {
        final Ruby runtime = getRuntime();

        int flag = 0;
        if ( args.length > 0 && ! args[0].isNil() ) {
            flag = RubyNumeric.fix2int( args[0] );
        }

        /* Should follow parameters like this:
        if 0 (COMPAT):
        irb(main):025:0> x.to_s(OpenSSL::X509::Name::COMPAT)
        => "CN=ola.bini, O=sweden/streetAddress=sweden, O=sweden/2.5.4.43343=sweden"
        irb(main):026:0> x.to_s(OpenSSL::X509::Name::ONELINE)
        => "CN = ola.bini, O = sweden, streetAddress = sweden, O = sweden, 2.5.4.43343 = sweden"
        irb(main):027:0> x.to_s(OpenSSL::X509::Name::MULTILINE)
        => "commonName                = ola.bini\norganizationName          = sweden\nstreetAddress             = sweden\norganizationName          = sweden\n2.5.4.43343 = sweden"
        irb(main):028:0> x.to_s(OpenSSL::X509::Name::RFC2253)
        => "2.5.4.43343=#0C0673776564656E,O=sweden,streetAddress=sweden,O=sweden,CN=ola.bini"
        else
        => /CN=ola.bini/O=sweden/streetAddress=sweden/O=sweden/2.5.4.43343=sweden
         */

        final Iterator<ASN1ObjectIdentifier> oidsIter;
        final Iterator<Object> valuesIter;
        if ( flag == RFC2253 ) {
            ArrayList<ASN1ObjectIdentifier> reverseOids = new ArrayList<ASN1ObjectIdentifier>(oids);
            ArrayList<Object> reverseValues = new ArrayList<Object>(values);
            Collections.reverse(reverseOids);
            Collections.reverse(reverseValues);
            oidsIter = reverseOids.iterator();
            valuesIter = reverseValues.iterator();
        } else {
            oidsIter = oids.iterator();
            valuesIter = (Iterator) values.iterator();
        }

        final StringBuilder str = new StringBuilder(48); String sep = "";
        while( oidsIter.hasNext() ) {
            final ASN1ObjectIdentifier oid = oidsIter.next();
            String oName = name(runtime, oid);
            if ( oName == null ) oName = oid.toString();
            final Object value = valuesIter.next();

            switch(flag) {
                case RFC2253:
                    str.append(sep).append(oName).append('=').append(value);
                    sep = ",";
                    break;
                case ONELINE:
                    str.append(sep).append(oName).append(" = ").append(value);
                    sep = ",";
                    break;
                case MULTILINE:
                    final Integer nid = ASN1.oid2nid(runtime, oid);
                    if ( nid != null ) {
                        final String ln = ASN1.nid2ln(runtime, nid);
                        if ( ln != null ) oName = ln;
                    } // TODO need indention :
                    str.append(sep).append(oName).append(" = ").append(value);
                    sep = "\n";
                    break;
                case COMPAT:
                default:
                    str.append('/').append(oName).append('=').append(value);
            }
        }

        return runtime.newString( str.toString() );
    }

    @Override
    @SuppressWarnings("unchecked")
    @JRubyMethod
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this, Collections.EMPTY_LIST);
    }

    @Override
    @JRubyMethod
    public RubyArray to_a() {
        final Ruby runtime = getRuntime();
        final RubyArray entries = runtime.newArray( oids.size() );
        final Iterator<ASN1ObjectIdentifier> oidsIter = oids.iterator();
        @SuppressWarnings("unchecked")
        final Iterator<Object> valuesIter = (Iterator) values.iterator();
        final Iterator<RubyInteger> typesIter = types.iterator();
        while ( oidsIter.hasNext() ) {
            final ASN1ObjectIdentifier oid = oidsIter.next();
            String oName = name(runtime, oid);
            if ( oName == null ) oName = oid.toString();
            final String value = valuesIter.next().toString();
            final IRubyObject type = typesIter.next();
            final IRubyObject[] entry = new IRubyObject[] {
                runtime.newString(oName), runtime.newString(value), type
            };
            entries.append( runtime.newArrayNoCopy(entry) );
        }
        return entries;
    }

    private static String name(final Ruby runtime, final ASN1ObjectIdentifier oid) {
        return ASN1.oid2name(runtime, oid, true);
    }

    @Deprecated
    @SuppressWarnings("unchecked")
    org.bouncycastle.asn1.x509.X509Name getRealName() {
        final java.util.Vector strValues = new java.util.Vector();
        for ( ASN1Encodable value : values ) strValues.add( value.toString() );
        return new org.bouncycastle.asn1.x509.X509Name(
            new java.util.Vector<Object>(oids), strValues
        );
    }

    final X500Name getX500Name() {
        if ( name != null ) return name;

        final X500NameBuilder builder = new X500NameBuilder( BCStyle.INSTANCE );
        for ( int i = 0; i < oids.size(); i++ ) {
            builder.addRDN( oids.get(i), values.get(i) );
        }
        return name = builder.build();
    }

    final X500Name getCanonicalX500Name() {
        if ( canonicalName != null ) return canonicalName;

        final X500NameBuilder builder = new X500NameBuilder( BCStyle.INSTANCE );
        for ( int i = 0; i < oids.size(); i++ ) {
            ASN1Encodable value = values.get(i);
            value = canonicalize(value);
            builder.addRDN( oids.get(i), value );
        }
        return canonicalName = builder.build();
    }

    private ASN1Encodable canonicalize(ASN1Encodable value) {
        if (value instanceof ASN1String) {
            ASN1String string = (ASN1String) value;
            return new DERUTF8String(canonicalize(string.getString()));
        }
        return value;
    }

    private String canonicalize(String string) {
        //asn1_string_canon (trim, to lower case, collapse multiple spaces)
        string = string.trim();
        if (string.length() == 0) {
            return string;
        }

        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < string.length()) {
            char c = string.charAt(i);
            if (Character.isWhitespace(c)){
                out.append(' ');
                while (i < string.length() && Character.isWhitespace(string.charAt(i))) {
                    i++;
                }
            } else {
                out.append(Character.toLowerCase(c));
                i++;
            }
        }
        return out.toString();
    }

    @JRubyMethod(name = { "cmp", "<=>" })
    public RubyFixnum cmp(IRubyObject other) {
        if ( equals(other) ) {
            return RubyFixnum.zero( getRuntime() );
        }
        // TODO: do we really need cmp - if so what order huh?
        if ( other instanceof X509Name ) {
            final X509Name that = (X509Name) other;
            final X500Name thisName = this.getCanonicalX500Name();
            final X500Name thatName = that.getCanonicalX500Name();
            int cmp = thisName.toString().compareTo( thatName.toString() );
            return RubyFixnum.newFixnum( getRuntime(), cmp );
        }
        return RubyFixnum.one( getRuntime() );
    }

    @Override
    public boolean equals(Object other) {
        if ( this == other ) return true;
        if ( other instanceof X509Name ) {
            final X509Name that = (X509Name) other;
            final X500Name thisName = this.getCanonicalX500Name();
            final X500Name thatName = that.getCanonicalX500Name();
            return thisName.equals(thatName);
        }
        return false;
    }

    @Override
    public int hashCode() {
        try {
            return (int) Name.hash( getCanonicalX500Name() );
        }
        catch (IOException e) {
            debugStackTrace(getRuntime(), e); return 0;
        }
        catch (RuntimeException e) {
            debugStackTrace(getRuntime(), e); return 0;
        }
    }

    @JRubyMethod(name = "eql?")
    public RubyBoolean eql_p(final ThreadContext context, final IRubyObject other) {
        if ( ! (other instanceof X509Name) ) return getRuntime().getFalse();
        return getRuntime().newBoolean( equals(other) );
    }

    @Override
    public IRubyObject eql_p(final IRubyObject obj) {
        return eql_p(getRuntime().getCurrentContext(), obj);
    }

    @Override
    @JRubyMethod
    public RubyFixnum hash() {
        long hash;
        try {
            hash = Name.hash( getCanonicalX500Name() );
        }
        catch (IOException e) {
            debugStackTrace(getRuntime(), e); hash = 0;
        }
        catch (RuntimeException e) {
            debugStackTrace(getRuntime(), e); hash = 0;
        }
        return getRuntime().newFixnum(hash);
    }

    @JRubyMethod
    public RubyFixnum hash_old() {
        long hash;
        try {
            hash = Name.hashOld( getX500Name() );
        }
        catch (IOException e) {
            debugStackTrace(getRuntime(), e); hash = 0;
        }
        catch (RuntimeException e) {
            debugStackTrace(getRuntime(), e); hash = 0;
        }
        return getRuntime().newFixnum( hash );
    }

    @JRubyMethod
    public RubyString to_der(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final DLSequence seq;
        if ( oids.size() > 0 ) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            ASN1EncodableVector sVec = new ASN1EncodableVector();
            ASN1ObjectIdentifier lastOid = null;
            for ( int i = 0; i != oids.size(); i++ ) {
                final ASN1ObjectIdentifier oid = oids.get(i);
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(oid);
                // TODO DO NOT USE DL types !
                //final String value = values.get(i);
                //final int type = RubyNumeric.fix2int(types.get(i));
                //v.add( convert(oid, value, type) );
                v.add( values.get(i) );

                if ( lastOid == null ) {
                    sVec.add(new DLSequence(v));
                }
                else {
                    vec.add(new DLSet(sVec));
                    sVec = new ASN1EncodableVector();
                    sVec.add(new DLSequence(v));
                }
                lastOid = oid;
            }
            vec.add(new DLSet(sVec));
            seq = new DLSequence(vec);
        } else {
            seq = new DLSequence();
        }
        try {
            return StringHelper.newString(runtime, seq.getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e) {
            throw newNameError(runtime, e);
        }
    }

    private ASN1Primitive convert(ASN1ObjectIdentifier oid, String value, int type) {
        final Class<? extends ASN1Encodable> clazz = ASN1.typeClass(type);
        try {
            if ( clazz != null ) {
                Constructor<?> ctor = clazz.getConstructor(new Class[]{ String.class });
                if (null != ctor) {
                    return (ASN1Primitive) ctor.newInstance(new Object[]{ value });
                }
            }
            return new X509DefaultEntryConverter().getConvertedValue(oid, value);
        }
        catch (NoSuchMethodException e) {
            throw newNameError(getRuntime(), e);
        }
        catch (InstantiationException e) {
            throw newNameError(getRuntime(), e);
        }
        catch (IllegalAccessException e) {
            throw newNameError(getRuntime(), e);
        }
        catch (IllegalArgumentException e) {
            throw newNameError(getRuntime(), e);
        }
        catch (InvocationTargetException e) {
            throw newNameError(getRuntime(), e.getTargetException());
        }
        catch (RuntimeException e) {
            debugStackTrace(getRuntime(), e);
            throw newNameError(getRuntime(), e);
        }
    }

    private static RaiseException newNameError(Ruby runtime, String msg, Throwable e) {
        return Utils.newError(runtime, _X509(runtime).getClass("NameError"), msg, e);
    }

    private static RaiseException newNameError(Ruby runtime, Throwable e) {
        return Utils.newError(runtime, _X509(runtime).getClass("NameError"), e);
    }

    private static RaiseException newNameError(Ruby runtime, String message) {
        return Utils.newError(runtime, _X509(runtime).getClass("NameError"), message);
    }

}// X509Name
