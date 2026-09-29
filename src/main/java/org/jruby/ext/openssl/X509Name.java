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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERGraphicString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNumericString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DERVideotexString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.util.encoders.Hex;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBasicObject;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.x509store.Name;
import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.extractKeywordArgs;
import static org.jruby.ext.openssl.util.RubySupport.newString;
import static org.jruby.ext.openssl.util.RubySupport.newUTF8String;

/**
 *
 * TODO member variables and methods are based on BC X509 way of doing things (now deprecated). Change
 * it to do it the X500 way, with RDN and X500NameBuilder.
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509Name extends RubyObject {
    private static final long serialVersionUID = -226196051911335103L;
    private static final Logger LOG = Logger.getLogger(X509Name.class);

    static void createX509Name(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) {
        RubyClass _Name = X509.defineClassUnder("Name", runtime.getObject(), (r, klass) -> new X509Name(r, klass));
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
        final RubyHash hash = RubyHash.newHash(runtime);
        // NOTE: using dynamic dispatch for compat with JRuby < 9.2.10
        // (default_value_set(ThreadContext, IRubyObject) was added in 9.2.10.0)
        hash.callMethod(context, "default=", UTF8_STRING);
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

    static RubyClass _Name(final Ruby runtime) {
        return _X509(runtime).getClass("Name");
    }

    public static final int COMPAT = 0;
    public static final int RFC2253 = 17892119;
    public static final int ONELINE = 8520479;
    public static final int MULTILINE = 44302342;

    public X509Name(Ruby runtime, RubyClass type) {
        super(runtime,type);
        oids = new ArrayList<>(4);
        values = new ArrayList<>(4);
        types = new ArrayList<>(4);
        rdnEnds = new ArrayList<>(4);
    }

    private final List<ASN1ObjectIdentifier> oids;
    private final List<ASN1Encodable> values; // <ASN1String>
    private final List<Integer> types;
    private final List<Integer> rdnEnds;

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
        oids.clear(); values.clear(); types.clear(); rdnEnds.clear();
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
        rdnEnds.add(oids.size());
    }

    private void fromASN1Set(final ASN1Object element) {
        ASN1Set typeAndValue = ASN1Set.getInstance(element);
        for ( int i = 0; i < typeAndValue.size(); i++ ) {
            fromASN1Sequence( typeAndValue.getObjectAt(i) );
        }
        rdnEnds.add(oids.size());
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
            LOG.warn(getRuntime(), "addValue value is not an ASN1 string = '" +
                    value + "' (" + ( value == null ? "" : value.getClass().getName()) + ")");
            this.values.add( value ); // TODO should not happen?!
        }
    }

    private void addType(final Ruby runtime, final ASN1Encodable value) {
        this.name = null; // NOTE: each fromX factory calls this ...
        this.canonicalName = null;
        final Integer type = ASN1.typeId(value);
        if (type == null) {
            LOG.warn(runtime, "addType could not resolve type for: " +
                 value + " (" + (value == null ? "" : value.getClass().getName()) + ")");
        }
        this.types.add(type);
    }

    private void addEntry(ASN1ObjectIdentifier oid, RubyString value, final int type) throws IOException {
        this.name = null;
        this.canonicalName = null;
        this.values.add(convertNameEntryValue(oid, value, type));
        this.oids.add(oid);
        this.types.add(type);
    }

    // replacement for X509DefaultEntryConverter (due BC-FIPS)
    private static ASN1Primitive convertNameEntryValue(final ASN1ObjectIdentifier oid, final RubyString value, final int type)
        throws IOException {
        switch (type) {
            case ASN1.BIT_STRING:
                return new DERBitString(value.getBytes());
            case ASN1.OCTET_STRING:
                return new DEROctetString(value.getBytes());
            case ASN1.UTF8STRING:
                return new DERUTF8String(valueAsUTF8(value));
            case ASN1.NUMERICSTRING:
                return new DERNumericString(value.asJavaString()); // validate?
            case ASN1.PRINTABLESTRING:
                return new DERPrintableString(value.asJavaString());
            case ASN1.T61STRING:
                return new DERT61String(value.asJavaString());
            case ASN1.VIDEOTEXSTRING:
                return new DERVideotexString(value.getBytes());
            case ASN1.IA5STRING:
                return new DERIA5String(value.asJavaString());
            case ASN1.GENERALIZEDTIME:
                return new DERGeneralizedTime(value.asJavaString());
            case ASN1.UTCTIME:
                return new DERUTCTime(value.asJavaString());
            case ASN1.GRAPHICSTRING:
                return new DERGraphicString(value.getBytes());
            //case ASN1.ISO64STRING:
                //return new DERVisibleString(value.asJavaString());
            case ASN1.GENERALSTRING:
                return new DERGeneralString(value.asJavaString());
            case ASN1.UNIVERSALSTRING:
                return new DERUniversalString(value.getBytes());
            case ASN1.BMPSTRING:
                return new DERBMPString(value.asJavaString());
        }

        return defaultConvertedValue(oid, valueAsUTF8(value));
    }

    private static String valueAsUTF8(final RubyString value) {
        final ByteList bytes = value.getByteList();
        return new String(bytes.unsafeBytes(), bytes.getBegin(), bytes.getRealSize(), StandardCharsets.UTF_8);
    }

    // inlined from X509DefaultEntryConverter.getConvertedValue (not available in BC-FIPS)
    private static ASN1Primitive defaultConvertedValue(final ASN1ObjectIdentifier oid, String value)
        throws IOException {
        if (value.length() != 0 && value.charAt(0) == '#') {
            return ASN1Primitive.fromByteArray(Hex.decodeStrict(value, 1, value.length() - 1));
        }
        if (value.length() != 0 && value.charAt(0) == '\\') {
            value = value.substring(1);
        }
        if (BCStyle.EmailAddress.equals(oid) || BCStyle.DC.equals(oid)) {
            return new DERIA5String(value);
        }
        if (BCStyle.DATE_OF_BIRTH.equals(oid)) {
            return new DERGeneralizedTime(value);
        }
        if (BCStyle.C.equals(oid) || BCStyle.SERIALNUMBER.equals(oid) ||
            BCStyle.DN_QUALIFIER.equals(oid) || BCStyle.TELEPHONE_NUMBER.equals(oid)) {
            return new DERPrintableString(value);
        }
        return new DERUTF8String(value);
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

            if (template.isNil()) template = _Name(runtime).getConstant("OBJECT_TYPE_TEMPLATE");

            for (int i = 0; i < ary.size(); i++) {
                IRubyObject obj = ary.eltOk(i);

                if ( ! (obj instanceof RubyArray) ) {
                    throw runtime.newTypeError(obj, runtime.getArray());
                }

                RubyArray arr = (RubyArray)obj;

                IRubyObject name, value, type;
                name  = arr.size() > 0 ? arr.eltOk(0) : context.nil;
                value = arr.size() > 1 ? arr.eltOk(1) : context.nil;
                type  = arr.size() > 2 ? arr.eltOk(2) : context.nil;

                if (type.isNil()) type = getDefaultType(context, name, template);

                addEntry(context, name, value, type, -1, 0);
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

    @JRubyMethod(name = "add_entry", rest = true)
    public IRubyObject add_entry(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        if (args.length < 2 || args.length > 3) {
            throw runtime.newArgumentError(args.length, 2);
        }

        final IRubyObject oid = args[0];
        final IRubyObject value = args[1];
        IRubyObject type = context.nil;
        int loc = -1;
        int set = 0;
        if (args.length == 3) {
            if (args[2] instanceof RubyHash) {
                final IRubyObject[] options = extractKeywordArgs(context, (RubyHash) args[2], "type", "loc", "set");
                if (options[0] != RubyBasicObject.UNDEF) type = options[0];
                if (options[1] != RubyBasicObject.UNDEF) loc = options[1].convertToInteger().getIntValue();
                if (options[2] != RubyBasicObject.UNDEF) set = options[2].convertToInteger().getIntValue();
            }
            else {
                type = args[2];
            }
        }

        return addEntry(context, oid, value, type, loc, set);
    }

    private IRubyObject addEntry(final ThreadContext context,
                                 final IRubyObject oid, final IRubyObject value,
                                 IRubyObject type, final int loc, final int set) {
        final Ruby runtime = context.runtime;

        final RubyString oidStr = oid.asString();

        if ( type.isNil() ) type = getDefaultType(context, oidStr);

        final ASN1ObjectIdentifier objectId;
        try {
            objectId = ASN1.getObjectID( runtime, oidStr.toString() );
        }
        catch (IllegalArgumentException e) {
            throw newNameError(runtime, "invalid field name: " + oidStr, e);
        }
        // NOTE: won't reach here :
        if ( objectId == null ) throw newNameError(runtime, "invalid field name");

        final int typeInt = type.convertToInteger().getIntValue();
        if (ASN1.typeClassSafe(typeInt) == null) {
            throw newNameError(runtime, "invalid type: " + typeInt);
        }

        try {
            addEntry(objectId, value.asString(), typeInt, loc, set);
        }
        catch (RuntimeException | IOException e) {
            LOG.debugStack(runtime, null, e);
            String msg = e.getMessage(); // X509DefaultEntryConverted: "can't recode value for oid " + oid.getId()
            throw newNameError(runtime, msg == null ? "invalid value" : msg, e);
        }
        return this;
    }

    private void addEntry(final ASN1ObjectIdentifier oid, final RubyString value,
                          final int type, final int loc, final int set) throws IOException {
        final ASN1Encodable converted = convertNameEntryValue(oid, value, type);
        final int rdnCount = rdnEnds.size();
        final int index = loc < 0 ? rdnCount : loc;
        if (index < 0 || index > rdnCount) throw newNameError(getRuntime(), "invalid entry location");

        if (set == 0 || rdnCount == 0) {
            final int entryIndex = index == rdnCount ? oids.size() : rdnStart(index);
            insertEntry(oid, entryIndex, converted, type);
            rdnEnds.add(index, entryIndex + 1);
            incrementRdnEnds(index + 1);
            return;
        }

        final int rdnIndex = set < 0 ? (index == rdnCount ? rdnCount - 1 : index - 1) :
                (index == rdnCount ? rdnCount - 1 : index);
        if (rdnIndex < 0 || rdnIndex >= rdnCount) throw newNameError(getRuntime(), "invalid entry location");

        final int entryIndex = set < 0 && index < rdnCount ? rdnStart(rdnIndex) : rdnEnds.get(rdnIndex);
        insertEntry(oid, entryIndex, converted, type);
        incrementRdnEnds(rdnIndex);
    }

    private void insertEntry(final ASN1ObjectIdentifier oid, final int index,
                             final ASN1Encodable value, final int type) {
        this.name = null;
        this.canonicalName = null;
        oids.add(index, oid);
        values.add(index, value);
        types.add(index, type);
    }

    private int rdnStart(final int rdnIndex) {
        return rdnIndex == 0 ? 0 : rdnEnds.get(rdnIndex - 1);
    }

    private void incrementRdnEnds(final int start) {
        for (int i = start; i < rdnEnds.size(); i++) {
            rdnEnds.set(i, rdnEnds.get(i) + 1);
        }
    }

    private static IRubyObject getDefaultType(final ThreadContext context, final RubyString oid) {
        return getDefaultType(context, oid, _Name(context.runtime).getConstant("OBJECT_TYPE_TEMPLATE"));
    }

    private static IRubyObject getDefaultType(final ThreadContext context,
                                              final IRubyObject oid, final IRubyObject template) {
        final IRubyObject type = template instanceof RubyHash ?
                ((RubyHash) template).op_aref(context, oid) :
                    template.callMethod(context, "[]", oid);
        return type.isNil() ? _Name(context.runtime).getConstant("DEFAULT_OBJECT_TYPE") : type;
    }

    @JRubyMethod(name = "to_s", rest = true)
    public IRubyObject to_s(IRubyObject[] args) {
        int flag = 0;
        if ( args.length > 0 && ! args[0].isNil() ) {
            flag = RubyNumeric.fix2int( args[0] );
        }
        final Ruby runtime = getRuntime();
        return newString(runtime, toFormat(runtime, flag, true).toString().getBytes(StandardCharsets.UTF_8));
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
    private StringBuilder toFormat(final Ruby runtime, final int format, final boolean escapeNonAscii) {
        final StringBuilder str = new StringBuilder(48); String sep = "";
        for (int rdn = format == RFC2253 ? rdnEnds.size() - 1 : 0;
             format == RFC2253 ? rdn >= 0 : rdn < rdnEnds.size(); rdn += format == RFC2253 ? -1 : 1) {
            final int start = rdnStart(rdn);
            final int end = rdnEnds.get(rdn);
            for (int i = format == RFC2253 ? end - 1 : start;
                 format == RFC2253 ? i >= start : i < end; i += format == RFC2253 ? -1 : 1) {
                final ASN1ObjectIdentifier oid = oids.get(i);
                String oName = name(runtime, oid);
                if ( oName == null ) oName = oid.toString();
                final Object value = values.get(i);

                switch (format) {
                    case RFC2253:
                        str.append(sep).append(oName).append('=');
                        appendValueRFC2253(str, value, escapeNonAscii);
                        sep = i == start ? "," : "+";
                        break;
                    case ONELINE:
                        str.append(sep).append(oName).append(" = ");
                        appendValueOneline(str, value);
                        sep = i == end - 1 ? ", " : " + ";
                        break;
                    case MULTILINE:
                        final Integer nid = ASN1.oid2nid(runtime, oid);
                        if ( nid != null ) {
                            final String ln = ASN1.nid2ln(runtime, nid);
                            if ( ln != null ) oName = ln;
                        } // TODO need indention :
                        str.append(sep).append(oName).append(" = ").append(value);
                        sep = i == end - 1 ? "\n" : "+";
                        break;
                    case COMPAT:
                    default:
                        str.append('/').append(oName).append('=');
                        appendValueOpenSSL(str, value);
                }
            }
        }

        return str;
    }

    private static void appendValueRFC2253(final StringBuilder str, final Object value,
        final boolean escapeNonAscii) {
        if (!escapeNonAscii) {
            appendValueRFC2253UTF8(str, value.toString());
            return;
        }
        final byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) {
            char c = (char) (bytes[i] & 0xff);
            if (escapeNonAscii && c >= 0x80) {
                str.append('\\').append(String.format("%02X", (int) c));
                continue;
            }
            if ((i == 0 && (c == ' ' || c == '#')) || (i == bytes.length - 1 && c == ' ')) {
                str.append('\\').append(c);
                continue;
            }
            switch (c) {
                case ',' :
                case '+' :
                case '"' :
                case '<' :
                case '>' :
                case ';' :
                case '\\' :
                    str.append('\\').append(c);
                    break;
                default :
                    str.append(c);
            }
        }
    }

    private static void appendValueRFC2253UTF8(final StringBuilder str, final String value) {
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            if ((i == 0 && (c == ' ' || c == '#')) || (i == value.length() - 1 && c == ' ')) {
                str.append('\\').append(c);
                continue;
            }
            switch (c) {
                case ',' :
                case '+' :
                case '"' :
                case '<' :
                case '>' :
                case ';' :
                case '\\' :
                    str.append('\\').append(c);
                    break;
                default :
                    str.append(c);
            }
        }
    }

    private static void appendValueOpenSSL(final StringBuilder str, final Object value) {
        final byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        for (byte valueByte : bytes) {
            final int c = valueByte & 0xff;
            if (c >= 0x80) {
                str.append("\\x").append(String.format("%02X", c));
            }
            else {
                str.append((char) c);
            }
        }
    }

    private static void appendValueOneline(final StringBuilder str, final Object value) {
        final byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        final boolean quote = bytes.length > 0 && (
                bytes[0] == ' ' || bytes[bytes.length - 1] == ' ' ||
                containsAnyQuoteChar(bytes)
        );
        if (quote) str.append('"');
        for (byte val : bytes) {
            final int c = val & 0xFF;
            if (c < 0x20 || c >= 0x80) {
                str.append('\\').append(String.format("%02X", c));
            }
            else if (c == '"' || c == '\\') {
                str.append('\\').append((char) c);
            }
            else {
                str.append((char) c);
            }
        }
        if (quote) str.append('"');
    }

    private static boolean containsAnyQuoteChar(final byte[] value) {
        for (byte val : value) {
            if (val == ',' || val == '+' || val == ';' || val == '<' || val == '>') return true;
        }
        return false;
    }

    @JRubyMethod
    public IRubyObject to_utf8(ThreadContext context) {
        return newUTF8String(context.runtime, toFormat(context.runtime, RFC2253, false));
    }

    @Override
    @JRubyMethod
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this, toFormat(getRuntime(), RFC2253, false));
    }

    @Override
    @JRubyMethod
    public RubyArray to_a() {
        final Ruby runtime = getRuntime();
        final RubyArray entries = runtime.newArray( oids.size() );
        final Iterator<ASN1ObjectIdentifier> oidsIter = oids.iterator();
        final Iterator<ASN1Encodable> valuesIter = values.iterator();
        final Iterator<Integer> typesIter = types.iterator();
        while ( oidsIter.hasNext() ) {
            final ASN1ObjectIdentifier oid = oidsIter.next();
            String oName = name(runtime, oid);
            if ( oName == null ) oName = oid.toString();
            final String value = valuesIter.next().toString();
            final Integer type = typesIter.next();
            final IRubyObject[] entry = new IRubyObject[] {
                    newUTF8String(runtime, oName),
                    newUTF8String(runtime, value),
                    type == null ? runtime.getNil() : runtime.newFixnum(type)
            };
            entries.append( runtime.newArrayNoCopy(entry) );
        }
        return entries;
    }

    private static String name(final Ruby runtime, final ASN1ObjectIdentifier oid) {
        return ASN1.oid2name(runtime, oid, true);
    }

    final X500Name getX500Name() {
        if ( name != null ) return name;

        final X500NameBuilder builder = new X500NameBuilder( BCStyle.INSTANCE );
        for (int rdn = 0; rdn < rdnEnds.size(); rdn++) {
            addRDN(builder, rdn, false);
        }
        return name = builder.build();
    }

    final X500Name getCanonicalX500Name() {
        if ( canonicalName != null ) return canonicalName;

        final X500NameBuilder builder = new X500NameBuilder( BCStyle.INSTANCE );
        for (int rdn = 0; rdn < rdnEnds.size(); rdn++) {
            addRDN(builder, rdn, true);
        }
        return canonicalName = builder.build();
    }

    private void addRDN(final X500NameBuilder builder, final int rdn, final boolean canonical) {
        final int start = rdnStart(rdn);
        final int end = rdnEnds.get(rdn);
        if (end - start == 1) {
            final ASN1Encodable value = values.get(start);
            builder.addRDN(oids.get(start), canonical ? Name.canonicalize(value) : value);
            return;
        }
        final ASN1ObjectIdentifier[] rdnOids = new ASN1ObjectIdentifier[end - start];
        final ASN1Encodable[] rdnValues = new ASN1Encodable[end - start];
        for (int i = start; i < end; i++) {
            rdnOids[i - start] = oids.get(i);
            final ASN1Encodable value = values.get(i);
            rdnValues[i - start] = canonical ? Name.canonicalize(value) : value;
        }
        builder.addMultiValuedRDN(rdnOids, rdnValues);
    }

    @JRubyMethod(name = { "cmp", "<=>" })
    public IRubyObject cmp(IRubyObject other) {
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
        return getRuntime().getNil();
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
            LOG.debugStack(getRuntime(), null, e); return 0;
        }
        catch (RuntimeException e) {
            LOG.debugStack(getRuntime(), null, e); return 0;
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
            LOG.debugStack(getRuntime(), null, e); hash = 0;
        }
        catch (RuntimeException e) {
            LOG.debugStack(getRuntime(), null, e); hash = 0;
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
            LOG.debugStack(getRuntime(), null, e); hash = 0;
        }
        catch (RuntimeException e) {
            LOG.debugStack(getRuntime(), null, e); hash = 0;
        }
        return getRuntime().newFixnum( hash );
    }

    @JRubyMethod
    public RubyString to_der(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final DLSequence seq;
        if ( oids.size() > 0 ) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (int rdn = 0; rdn < rdnEnds.size(); rdn++) {
                ASN1EncodableVector sVec = new ASN1EncodableVector();
                for (int i = rdnStart(rdn); i < rdnEnds.get(rdn); i++) {
                    ASN1EncodableVector v = new ASN1EncodableVector();
                    v.add(oids.get(i));
                    v.add(values.get(i));
                    sVec.add(new DLSequence(v));
                }
                vec.add(new DERSet(sVec));
            }
            seq = new DLSequence(vec);
        } else {
            seq = new DLSequence();
        }
        try {
            return newString(runtime, seq.getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e) {
            throw newNameError(runtime, e);
        }
    }

    @Override
    @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(final IRubyObject original) {
        super.initialize_copy(original);
        final X509Name name = (X509Name) original;
        oids.clear(); oids.addAll(name.oids);
        values.clear(); values.addAll(name.values);
        types.clear(); types.addAll(name.types);
        rdnEnds.clear(); rdnEnds.addAll(name.rdnEnds);
        this.name = null;
        this.canonicalName = null;
        return this;
    }

    private ASN1Primitive convert(ASN1ObjectIdentifier oid, String value, int type) {
        final Class<? extends ASN1Encodable> clazz = ASN1.typeClass(type);
        try {
            if ( clazz != null ) {
                Constructor<?> ctor = clazz.getConstructor(String.class);
                if (null != ctor) {
                    return (ASN1Primitive) ctor.newInstance(new Object[] { value });
                }
            }
            return defaultConvertedValue(oid, value);
        }
        catch (NoSuchMethodException | InstantiationException | IllegalAccessException e) {
            throw newNameError(getRuntime(), e);
        }
        catch (InvocationTargetException e) {
            throw newNameError(getRuntime(), e.getTargetException());
        }
        catch (IllegalArgumentException e) {
            throw newNameError(getRuntime(), e);
        }
        catch (Exception e) {
            LOG.debugStack(getRuntime(), null, e);
            throw newNameError(getRuntime(), e);
        }
    }

    @Override
    public Object toJava(Class target) {
        // explicit-target only (Object keeps returning the Ruby object as with other RubyObjects)
        if ( target != Object.class && target.isAssignableFrom(X500Principal.class) ) {
            return new X500Principal( to_der(getRuntime().getCurrentContext()).getBytes() );
        }
        return super.toJava(target);
    }

    private static RaiseException newNameError(Ruby runtime, String msg, Throwable e) {
        return newError(runtime, _X509(runtime).getClass("NameError"), msg, e);
    }

    private static RaiseException newNameError(Ruby runtime, Throwable e) {
        return newError(runtime, _X509(runtime).getClass("NameError"), e);
    }

    private static RaiseException newNameError(Ruby runtime, String message) {
        return newError(runtime, _X509(runtime).getClass("NameError"), message);
    }

}// X509Name
