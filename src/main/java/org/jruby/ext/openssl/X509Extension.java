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
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.encoders.Hex;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
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
import org.jruby.util.ByteList;
import org.jruby.util.ConvertBytes;

import static org.jruby.ext.openssl.ASN1._ASN1;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.StringHelper.*;

/**
 * OpenSSL::X509::Extension
 * @author kares
 */
public class X509Extension extends RubyObject {
    private static final long serialVersionUID = 6463713017143658305L;

    private static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509Extension(runtime, klass);
        }
    };

    static void createX509Extension(final Ruby runtime, final RubyModule X509, final RubyClass OpenSSLError) { // OpenSSL::X509
        X509.defineClassUnder("ExtensionError", OpenSSLError, OpenSSLError.getAllocator());

        RubyClass _Extension = X509.defineClassUnder("Extension", runtime.getObject(), X509Extension.ALLOCATOR);
        _Extension.defineAnnotatedMethods(X509Extension.class);

        X509ExtensionFactory.createX509ExtensionFactory(runtime, X509);
    }

    private ASN1ObjectIdentifier objectID;
    private Object value;
    private boolean critical;

    protected X509Extension(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    static RubyClass _Extension(final Ruby runtime) {
        return _X509(runtime).getClass("Extension");
    }

    static final byte[] critical__ = new byte[] { 'c','r','i','t','i','c','a','l',',',' ' };

    static X509Extension newExtension(final ThreadContext context,
        final String oid, final java.security.cert.X509Extension ext,
        final boolean critical)
        throws IOException {

        final byte[] extValue = ext.getExtensionValue(oid); // DER encoded
        // TODO: wired. J9 returns null for an OID given in getNonCriticalExtensionOIDs()
        if ( extValue == null ) {
            warn(context, ext + " getExtensionValue returns null for '"+ oid +"'");
            return null;
        }

        final Ruby runtime = context.runtime;
        final ASN1Encodable value = ASN1.readObject(extValue);
        return newExtension(runtime, ASN1.getObjectID(runtime, oid), value, critical);
    }

    static X509Extension[] newExtension(final ThreadContext context,
        final String oid, final byte[] extValue, final boolean critical)
        throws IOException {

        final Ruby runtime = context.runtime;
        final ASN1ObjectIdentifier objectId = ASN1.getObjectID(runtime, oid);
        final ASN1Encodable value = ASN1.readObject(extValue);

        return new X509Extension[] { newExtension(runtime, objectId, value, critical) };
    }

    static X509Extension newExtension(final Ruby runtime, ASN1ObjectIdentifier objectId,
        final ASN1Encodable value, final boolean critical) {
        X509Extension ext = new X509Extension(runtime, _Extension(runtime));
        ext.setRealObjectID(objectId);
        ext.setRealValue(value);
        ext.setRealCritical(critical);
        return ext;
    }

    static X509Extension newExtension(final Ruby runtime, ASN1ObjectIdentifier objectId,
        final Extension extension) {
        X509Extension ext = new X509Extension(runtime, _Extension(runtime));
        ext.setRealObjectID(objectId);
        ext.setRealValue(extension.getParsedValue());
        ext.setRealCritical(extension.isCritical());
        return ext;
    }

    ASN1ObjectIdentifier getRealObjectID() {
        return objectID;
    }

    void setRealObjectID(ASN1ObjectIdentifier oid) {
        this.objectID = oid;
    }

    void setRealObjectID(final String oid) {
        setRealObjectID( ASN1.getObjectID(getRuntime(), oid) );
    }

    final ASN1Encodable getRealValue() throws IOException {
        if ( value instanceof ASN1Encodable ) {
            return (ASN1Encodable) value;
        }
        if ( value instanceof ASN1.ASN1Data ) {
            return ((ASN1.ASN1Data) value).toASN1(getRuntime().getCurrentContext());
        }

        if ( value == null ) throw new IllegalStateException("null extension value");

        return ASN1.readObject( getRealValueEncoded() );
    }

    final byte[] getRealValueEncoded() throws IOException {
        if ( value instanceof byte[] ) return (byte[]) value;
        if ( value instanceof RubyString ) return ((RubyString) value).getBytes();
        if ( value instanceof String ) return ByteList.plain((String) value);
        
        if ( value instanceof ASN1OctetString ) { // initialize
            return ((ASN1OctetString) value).getOctets();
        }

        return getRealValue().toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    private IRubyObject getValue(final Ruby runtime) throws IOException {
        if ( value instanceof RubyString ) {
            return (RubyString) value; // explicitly set value
        }
        final ThreadContext context = runtime.getCurrentContext();
        final byte[] enc = getRealValueEncoded();
        IRubyObject extValue = runtime.newString( new ByteList(enc, false) );
        extValue = ASN1.decodeImpl(context, _ASN1(runtime), extValue);
        return extValue.callMethod(context, "value");
    }

    void setRealValue(final ASN1Encodable value) {
        if ( value == null ) {
            throw new IllegalStateException("null extension value");
        }
        this.value = value;
    }

    //private void setRealValueEncoded(final byte[] value) {
    //    this.value = value;
    //}

    boolean isRealCritical() { return critical; }

    void setRealCritical(boolean critical) {
        this.critical = critical;
    }

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        if ( args.length == 1 ) {
            final byte[] bytes = to_der_if_possible(context, args[0]).asString().getBytes();
            try {
                ASN1Sequence seq = (ASN1Sequence) ASN1.readObject(bytes);
                setRealObjectID( (ASN1ObjectIdentifier) seq.getObjectAt(0) );
                final ASN1Encodable criticalOrValue = seq.getObjectAt(1);
                if ( criticalOrValue instanceof ASN1Boolean ) {
                    setRealCritical( ((ASN1Boolean) criticalOrValue).isTrue() );
                    this.value = ( (DEROctetString) seq.getObjectAt(2) ).getOctets(); // byte[]
                }
                else {
                    this.value = ( (DEROctetString) criticalOrValue ).getOctets(); // byte[]
                }
            }
            catch (IOException e) {
                throw newExtensionError(context.runtime, e);
            }
        }
        else if ( args.length > 1 ) {
            setRealObjectID( ASN1.getObjectID(context.runtime, args[0].toString()) );
            this.value = args[1]; // a RubyString
        }
        else { // args.length < 1
            throw context.runtime.newArgumentError("wrong number of arguments (0 for 1..3)");
        }

        if ( args.length > 2 ) setRealCritical( args[2].isTrue() );

        return this;
    }

    @Override
    public IRubyObject initialize_copy(final IRubyObject original) {
        if (this == original) return this;
        checkFrozen();

        final X509Extension that = (X509Extension) original;
        this.value = that.value;
        this.objectID = that.objectID;
        this.critical = that.critical;
        return this;
    }

    @JRubyMethod
    public IRubyObject oid(final ThreadContext context) {
        return context.runtime.newString( oidSym(context.runtime) );
    }

    private String oidSym(final Ruby runtime) {
        final String name = ASN1.oid2Sym(runtime, objectID, true);
        return name == null ? objectID.toString() : name;
    }

    @JRubyMethod(name = "oid=")
    public IRubyObject set_oid(final ThreadContext context, IRubyObject arg) {
        if ( arg instanceof RubyString ) {
            setRealObjectID( arg.toString() ); return arg;
        }
        throw context.runtime.newTypeError(arg, context.runtime.getString());
    }

    private static final byte[] NULL = ByteList.NULL_ARRAY;

    private static final byte[] CA_ = {'C', 'A', ':'};
    private static final byte[] TRUE = {'T', 'R', 'U', 'E'};
    private static final byte[] FALSE = {'F', 'A', 'L', 'S', 'E'};
    private static final byte[] SEP = {',', ' '};
    private static final byte[] Decipher_Only = {'D', 'e', 'c', 'i', 'p', 'h', 'e', 'r', ' ', 'O', 'n', 'l', 'y'};
    private static final byte[] Digital_Signature = {'D', 'i', 'g', 'i', 't', 'a', 'l', ' ', 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e'};
    private static final byte[] Non_Repudiation = {'N', 'o', 'n', ' ', 'R', 'e', 'p', 'u', 'd', 'i', 'a', 't', 'i', 'o', 'n'};
    private static final byte[] Key_Encipherment = {'K', 'e', 'y', ' ', 'E', 'n', 'c', 'i', 'p', 'h', 'e', 'r', 'm', 'e', 'n', 't'};
    private static final byte[] Data_Encipherment = {'D', 'a', 't', 'a', ' ', 'E', 'n', 'c', 'i', 'p', 'h', 'e', 'r', 'm', 'e', 'n', 't'};
    private static final byte[] Key_Agreement = {'K', 'e', 'y', ' ', 'A', 'g', 'r', 'e', 'e', 'm', 'e', 'n', 't'};
    private static final byte[] Certificate_Sign = {'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e', ' ', 'S', 'i', 'g', 'n'};
    private static final byte[] CRL_Sign = {'C', 'R', 'L', ' ', 'S', 'i', 'g', 'n'};
    private static final byte[] Encipher_Only = {'E', 'n', 'c', 'i', 'p', 'h', 'e', 'r', ' ', 'O', 'n', 'l', 'y'};
    private static final byte[] SSL_Client = {'S', 'S', 'L', ' ', 'C', 'l', 'i', 'e', 'n', 't'};
    private static final byte[] SSL_Server = {'S', 'S', 'L', ' ', 'S', 'e', 'r', 'v', 'e', 'r'};
    private static final byte[] SSL_CA = {'S', 'S', 'L', ' ', 'C', 'A'};
    private static final byte[] SMIME = {'S', '/', 'M', 'I', 'M', 'E'};
    private static final byte[] SMIME_CA = {'S', '/', 'M', 'I', 'M', 'E', ' ', 'C', 'A'};
    private static final byte[] Object_Signing = {'O', 'b', 'j', 'e', 'c', 't', ' ', 'S', 'i', 'g', 'n', 'i', 'n', 'g'};
    private static final byte[] Object_Signing_CA = {'O', 'b', 'j', 'e', 'c', 't', ' ', 'S', 'i', 'g', 'n', 'i', 'n', 'g', ' ', 'C', 'A'};
    private static final byte[] Unused = {'U', 'n', 'u', 's', 'e', 'd'};
    private static final byte[] Unspecified = {'U', 'n', 's', 'p', 'e', 'c', 'i', 'f', 'i', 'e', 'd'};
    //private static final byte[] Key_Compromise = { 'K','e','y',' ','C','o','m','p','r','o','m','i','s','e' };
    //private static final byte[] CA_Compromise = { 'C','A',' ','C','o','m','p','r','o','m','i','s','e' };
    //private static final byte[] Affiliation_Changed = { 'A','f','f','i','l','i','a','t','i','o','n',' ','C','h','a','n','g','e','d' };
    private static final byte[] keyid_ = {'k', 'e', 'y', 'i', 'd', ':'};

    @JRubyMethod
    public RubyString value(final ThreadContext context) {
        if ( this.value instanceof RubyString ) { // return the same as set
            return (RubyString) this.value;
        }

        final Ruby runtime = context.runtime;
        final String oid = getRealObjectID().getId();
        try {
            if ( oid.equals("2.5.29.19") ) { // basicConstraints
                ASN1Sequence seq2 = (ASN1Sequence) ASN1.readObject( getRealValueEncoded() );
                final ByteList val = new ByteList(32);
                if (seq2.size() > 0) {
                    val.append(CA_);
                    ASN1Encodable obj0 = seq2.getObjectAt(0);
                    final boolean bool = ((ASN1Boolean) obj0).isTrue();
                    val.append( bool ? TRUE : FALSE );
                }
                if (seq2.size() > 1) {
                    val.append(", pathlen:".getBytes());
                    val.append(seq2.getObjectAt(1).toString().getBytes());
                }
                return runtime.newString(val);
            }
            if ( oid.equals("2.5.29.15") ) { // keyUsage
                final byte[] enc = getRealValueEncoded();
                byte b3 = 0; byte b2 = enc[2]; if ( enc.length > 3 ) b3 = enc[3];
                final ByteList val = new ByteList(64); byte[] sep = NULL;
                if ((b2 & (byte) 128) != 0) {
                    val.append(sep); val.append(Decipher_Only); sep = SEP;
                }
                if ((b3 & (byte) 128) != 0) {
                    val.append(sep); val.append(Digital_Signature); sep = SEP;
                }
                if ((b3 & (byte) 64) != 0) {
                    val.append(sep); val.append(Non_Repudiation); sep = SEP;
                }
                if ((b3 & (byte) 32) != 0) {
                    val.append(sep); val.append(Key_Encipherment); sep = SEP;
                }
                if ((b3 & (byte) 16) != 0) {
                    val.append(sep); val.append(Data_Encipherment); sep = SEP;
                }
                if ((b3 & (byte) 8) != 0) {
                    val.append(sep); val.append(Key_Agreement); sep = SEP;
                }
                if ((b3 & (byte) 4) != 0) {
                    val.append(sep); val.append(Certificate_Sign); sep = SEP;
                }
                if ((b3 & (byte) 2) != 0) {
                    val.append(sep); val.append(CRL_Sign); sep = SEP;
                }
                if ((b3 & (byte) 1) != 0) {
                    val.append(sep); val.append(Encipher_Only); // sep = SEP;
                }
                return runtime.newString(val);
            }
            if ( oid.equals("2.16.840.1.113730.1.1") ) { // nsCertType
                final byte b0 = getRealValueEncoded()[0];
                final ByteList val = new ByteList(64); byte[] sep = NULL;
                if ((b0 & (byte) 128) != 0) {
                    val.append(sep); val.append(SSL_Client); sep = SEP;
                }
                if ((b0 & (byte) 64) != 0) {
                    val.append(sep); val.append(SSL_Server); sep = SEP;
                }
                if ((b0 & (byte) 32) != 0) {
                    val.append(sep); val.append(SMIME); sep = SEP;
                }
                if ((b0 & (byte) 16) != 0) {
                    val.append(sep); val.append(Object_Signing); sep = SEP;
                }
                if ((b0 & (byte) 8) != 0) {
                    val.append(sep); val.append(Unused); sep = SEP;
                }
                if ((b0 & (byte) 4) != 0) {
                    val.append(sep); val.append(SSL_CA); sep = SEP;
                }
                if ((b0 & (byte) 2) != 0) {
                    val.append(sep); val.append(SMIME_CA); sep = SEP;
                }
                if ((b0 & (byte) 1) != 0) {
                    val.append(sep); val.append(Object_Signing_CA);
                }
                return runtime.newString(val);
            }

            if ( oid.equals("2.5.29.14") ) { // subjectKeyIdentifier
                ASN1Encodable value = getRealValue();
                if ( value instanceof ASN1OctetString ) {
                    byte[] octets = ((ASN1OctetString) value).getOctets();
                    if ( octets.length > 0 && octets[0] == BERTags.OCTET_STRING ) {
                        value = ASN1.readObject( octets ); // read nested octets
                    }
                }
                return runtime.newString( hexBytes( keyidBytes(value.toASN1Primitive()), 0 ) );
            }

            if ( oid.equals("2.5.29.35") ) { // authorityKeyIdentifier
                ASN1Encodable value = getRealValue();

                if (value instanceof ASN1OctetString) {
                    value = ASN1.readObject( ((ASN1OctetString) value).getOctets() );
                }

                final ByteList val = new ByteList(72);

                if (value instanceof ASN1Sequence) {
                    final ASN1Sequence seq = (ASN1Sequence) value;
                    final int size = seq.size();
                    if ( size == 0 ) return RubyString.newEmptyString(runtime);

                    for ( int i = 0; i < size; i++ ) {
                        final ASN1Encodable enc = seq.getObjectAt(i);
                        if (enc instanceof ASN1TaggedObject) {
                            ASN1Primitive obj = ((ASN1TaggedObject) enc).getObject();
                            switch( ((ASN1TaggedObject) enc).getTagNo() ) {
                                case 0 :
                                    ASN1Primitive keyid = obj;
                                    val.append(keyid_);
                                    hexBytes( keyidBytes(keyid), val );
                                    break;
                                case 1 :
                                    GeneralName name;
                                    if (obj instanceof ASN1Sequence) { // GeneralNames -> toASN1Primitive()
                                        GeneralName[] names = GeneralNames.getInstance(obj).getNames();
                                        name = names.length > 0 ? names[0] : null;
                                    } else {
                                        name = GeneralName.getInstance(obj);
                                    }
                                    if (name != null) formatGeneralName(name, val, true);
                                    break;
                                case 2 : // serial
                                    val.append(new byte[] { 's','e','r','i','a','l',':' });
                                    if (obj instanceof ASN1Integer) {
                                        hexBytes( ((ASN1Integer) obj).getValue().toByteArray(), val);
                                    }
                                    else {
                                        hexBytes( ((ASN1OctetString) obj ).getOctets(), val );
                                    }
                                    break;
                            }
                        } else if (size == 1) {
                            ASN1Primitive keyid = enc.toASN1Primitive();
                            hexBytes( keyidBytes(keyid), val );
                        }
                        val.append('\n');
                    }
                    return runtime.newString( val );
                }

                hexBytes( keyidBytes(value.toASN1Primitive()), val ).append('\n');
                return runtime.newString( val );
            }

            if ( oid.equals("2.5.29.21") ) { // CRLReason
                final IRubyObject value = getValue(runtime);
                switch ( RubyNumeric.fix2int(value) ) {
                    case 0:
                        return runtime.newString(new ByteList(Unspecified));
                    case 1:
                        return RubyString.newString(runtime, "Key Compromise");
                    case 2:
                        return RubyString.newString(runtime, "CA Compromise");
                    case 3:
                        return RubyString.newString(runtime, "Affiliation Changed");
                    case 4:
                        return RubyString.newString(runtime, "Superseded");
                    case 5:
                        return RubyString.newString(runtime, "Cessation Of Operation");
                    case 6:
                        return RubyString.newString(runtime, "Certificate Hold");
                    case 8:
                        return RubyString.newString(runtime, "Remove From CRL");
                    case 9:
                        return RubyString.newString(runtime, "Privilege Withdrawn");
                    default:
                        return runtime.newString(new ByteList(Unspecified));
                }
            }

            if ( oid.equals("2.5.29.17") || oid.equals("2.5.29.18") ) { // subjectAltName || issuerAltName
                try {
                    ASN1Encodable value = getRealValue();
                    final ByteList val = new ByteList(64);
                    if ( value instanceof ASN1TaggedObject ) {
                        formatGeneralName(GeneralName.getInstance(value), val, false);
                        return runtime.newString( val );
                    }
                    if ( value instanceof GeneralName ) {
                        formatGeneralName((GeneralName) value, val, false);
                        return runtime.newString( val );
                    }
                    if ( value instanceof ASN1OctetString ) {
                        // decoded octets will end up as an ASN1Sequence instance :
                        value = ASN1.readObject( ((ASN1OctetString) value).getOctets());
                    }
                    if ( value instanceof ASN1TaggedObject ) { // DERTaggedObject (issuerAltName wrapping)
                        formatGeneralName(GeneralName.getInstance(value), val, false);
                        return runtime.newString( val );
                    }

                    final GeneralName[] names = GeneralNames.getInstance(value).getNames();
                    for ( int i = 0; i < names.length; i++ ) {
                        boolean other = formatGeneralName(names[i], val, false);
                        if ( i < names.length - 1 ) {
                            if ( other ) val.append(';'); else val.append(',').append(' ');
                        }
                    }
                    return runtime.newString( val );
                }
                catch (IllegalArgumentException e) {
                    debugStackTrace(runtime, e);
                    return rawValueAsString(context);
                }
            }

            if ( oid.equals("2.5.29.37") ) { // extendedKeyUsage
                final ByteList val = new ByteList(64);

                if ( this.value instanceof ASN1Sequence ) { // opt "short" path
                    final ASN1Sequence seq = (ASN1Sequence) this.value;
                    final int size = seq.size();
                    for ( int i = 0; i < size; i++ ) {
                        ASN1Encodable o = seq.getObjectAt(i);
                        String name = o.toString();
                        Integer nid = ASN1.oid2nid(runtime, new ASN1ObjectIdentifier(name));
                        if ( nid != null ) name = ASN1.nid2ln(runtime, nid);
                        if ( name == null ) name = o.toString();
                        val.append( ByteList.plain(name) );
                        if ( i < size - 1 ) val.append(',').append(' ');
                    }
                    return runtime.newString( val );
                }

                final IRubyObject value = getValue(runtime);
                if ( value instanceof RubyArray ) {
                    final RubyArray arr = (RubyArray) value;
                    final int size = arr.size();
                    for ( int i = 0; i < size; i++ ) {
                        IRubyObject entry = arr.eltInternal(i);
                        if ( "ObjectId".equals(entry.getMetaClass().getBaseName()) ) {
                            entry = entry.callMethod(context, "ln");
                        }
                        else if ( entry.respondsTo("value") ) {
                            entry = entry.callMethod(context, "value");
                        }
                        val.append( entry.asString().getByteList() );
                        if ( i < size - 1 ) val.append(',').append(' ');
                    }
                }
                return runtime.newString( val );
            }

            return rawValueAsString(context);
        }
        catch (IOException e) {
            debugStackTrace(runtime, e);
            throw newExtensionError(runtime, e);
        }
    }

    private RubyString rawValueAsString(final ThreadContext context) throws IOException {
        final Ruby runtime = context.runtime;
        final IRubyObject value = getValue(runtime); // e.g. [ ASN1::UTF8String, ... ]
        if ( value instanceof RubyArray ) {
            final RubyArray arr = (RubyArray) value;
            final ByteList strVal = new ByteList(64);
            final int len = arr.size();
            for ( int i = 0; i < len; i++ ) {
                IRubyObject entry = arr.eltInternal(i);
                if ( entry.respondsTo("value") ) {
                    entry = entry.callMethod(context, "value");
                }
                strVal.append( entry.asString().getByteList() );
                if ( i < len - 1 ) strVal.append(',').append(' ');
            }
            return runtime.newString(strVal);
        }
        return value.asString();
    }

    private static byte[] keyidBytes(ASN1Primitive keyid) throws IOException {
        if ( keyid instanceof ASN1TaggedObject ) {
            keyid = ((ASN1TaggedObject) keyid).getObject();
        }
        if ( keyid instanceof ASN1OctetString ) {
            return ((ASN1OctetString) keyid).getOctets();
        }
        return keyid.getEncoded(ASN1Encoding.DER);
    }

    @SuppressWarnings("unchecked")
    private static boolean formatGeneralName(final GeneralName name, final ByteList out, final boolean slashed) {
        final ASN1Encodable obj = name.getName();
        String val; boolean tagged = false;
        switch ( name.getTagNo() ) {
        case GeneralName.rfc822Name:
            if ( ! tagged ) out.append('e').append('m').append('a').append('i').append('l').
                append(':');
            tagged = true;
        case GeneralName.dNSName:
            if ( ! tagged ) out.append('D').append('N').append('S').
                append(':');
            tagged = true;
        case GeneralName.uniformResourceIdentifier:
            if ( ! tagged ) out.append('U').append('R').append('I').
                append(':');
            val = DERIA5String.getInstance(obj).getString();
            out.append( ByteList.plain(val) );
            break;
        case GeneralName.directoryName:
            out.append('D').append('i').append('r').append('N').append('a').append('m').append('e').
                append(':');
            final X500Name dirName = X500Name.getInstance(obj);
            if ( slashed ) {
                final RDN[] rdns = dirName.getRDNs();
                final Hashtable defaultSymbols = getDefaultSymbols();
                for (int i = 0; i < rdns.length; i++) {
                    appendRDN(out.append('/'), rdns[i], defaultSymbols);
                }
            }
            else {
                out.append( ByteList.plain(dirName.toString()) );
            }
            break;
        case GeneralName.iPAddress:
            out.append('I').append('P').
                append(':');
            final byte[] ip = ((ASN1OctetString) name.getName()).getOctets();
            int len = ip.length; boolean ip4 = len == 4;
            if ( ip4 ) {
                for ( int i = 0; i < ip.length; i++ ) {
                    out.append( ConvertBytes.intToCharBytes( ((int) ip[i]) & 0xff ) );
                    if ( i != len - 1 ) out.append('.');
                }
            }
            else {
                for ( int i = 0; i < ip.length; i += 2 ) {
                    out.append( ConvertBytes.intToHexBytes( ((ip[i] & 0xff) << 8 | (ip[i+1] & 0xff)) ) );
                    if ( i != len - 2 ) out.append(':');
                }
            }
            break;
        case GeneralName.otherName:
            out.append('o').append('t').append('h').append('e').append('r').append('N').append('a').append('m').append('e').
                append(':');
            out.append( ByteList.plain( obj.toString() ) );
            return true;
            //tagged = true;
        case GeneralName.registeredID:
            out.append('R').append('I').append('D').
                append(':');
            //tagged = true;
        default:
            out.append( ByteList.plain( obj.toString() ) );
        }
        return false;
    }

    // re-invented IETFUtils.appendRDN related pieces :

    public static ByteList appendRDN(final ByteList out,
        final RDN rdn,
        final Map<ASN1ObjectIdentifier, String> oidSymbols) {

        if ( rdn.isMultiValued() ) {
            AttributeTypeAndValue[] atv = rdn.getTypesAndValues();

            boolean firstAtv = true;
            for ( int j = 0; j != atv.length; j++ ) {
                if (firstAtv) firstAtv = false;
                else out.append('+');

                appendTypeAndValue(out, atv[j], oidSymbols);
            }
            return out;
        }
        return appendTypeAndValue(out, rdn.getFirst(), oidSymbols);
    }

    private static ByteList appendTypeAndValue(final ByteList out,
        final AttributeTypeAndValue typeAndValue,
        final Map<ASN1ObjectIdentifier, String> oidSymbols) {
        ASN1ObjectIdentifier type = typeAndValue.getType();
        final String sym = oidSymbols.get(type);

        if (sym != null) {
            out.append( ByteList.plain(sym) );
        }
        else {
            out.append( ByteList.plain(type.getId()) );
        }

        out.append('=');
        valueToString(typeAndValue.getValue(), out);
        return out;
    }

    private static void valueToString(final ASN1Encodable value, final ByteList out) {
        final int size = out.getRealSize();

        if ( value instanceof ASN1String && !(value instanceof DERUniversalString) ) {
            final String str = ((ASN1String) value).getString();
            if ( str.length() > 0 && str.charAt(0) == '#' ) {
                out.append('\\');
            }
            out.append( ByteList.plain(str) );
        }
        else {
            try {
                byte[] val = value.toASN1Primitive().getEncoded(ASN1Encoding.DER);
                out.append('#').append( Hex.encode(val) );
            }
            catch (IOException e) {
                throw new IllegalArgumentException("Other value has no encoded form", e);
            }
        }

        int index = size; // 0
        int end = out.getRealSize() - size;

        if (end >= 2 && out.charAt(index) == '\\' && out.charAt(index + 1) == '#') {
            index += 2;
        }

        while ( index <= end ) {
            final char c = out.charAt(index);
            if ( c == ',' || c == '"' || c == '\\' || c == '+' ||
                 c == '=' || c == '<' || c == '>'  || c == ';' ) {
                out.insert(index, '\\');
                index++; end++;
            }
            index++;
        }

        if ( out.getRealSize() - size > 0 ) {
            index = size; // 0
            while ( out.charAt(index) == ' ' ) {
                out.insert(index, '\\'); index += 2;
            }
        }

        index = out.getRealSize() - 1; // length - 1
        while ( index >= size && out.charAt(index) == ' ' ) {
            out.insert(index, '\\'); index--;
        }
    }

    private static Hashtable getDefaultSymbols() {
        try {
            Field field = BCStyle.class.getDeclaredField("DefaultSymbols");
            field.setAccessible(true);
            return (Hashtable) field.get(null);
        }
        catch (NoSuchFieldException ex) {
            debug("getDefaultSymbols", ex);
        }
        catch (SecurityException ex) {
            debug("getDefaultSymbols", ex);
        }
        catch (IllegalAccessException ex) {
            debug("getDefaultSymbols", ex);
        }
        return new Hashtable();
    }

    @JRubyMethod(name = "value=")
    public IRubyObject set_value(final ThreadContext context, IRubyObject arg) {
        if ( arg instanceof RubyString ) {
            this.value = arg; return arg;
        }
        throw context.runtime.newTypeError(arg, context.runtime.getString());
    }

    @JRubyMethod(name = "critical?")
    public IRubyObject critical_p(final ThreadContext context) {
        return context.runtime.newBoolean(isRealCritical());
    }

    @JRubyMethod(name = "critical=")
    public IRubyObject set_critical(final ThreadContext context, IRubyObject arg) {
        setRealCritical(arg.isTrue());
        return arg;
    }

    @JRubyMethod
    public IRubyObject to_der() {
        try {
            return StringHelper.newString(getRuntime(), toDER());
        }
        catch (IOException e) {
            throw newExtensionError(getRuntime(), e);
        }
    }

    final byte[] toDER() throws IOException {
        return toASN1Sequence().getEncoded(ASN1Encoding.DER);
    }

    ASN1Sequence toASN1Sequence() throws IOException {
        final ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add( getRealObjectID() );
        if ( critical ) vec.add( ASN1Boolean.TRUE );
        vec.add( new DEROctetString( getRealValueEncoded() ) );
        return new DLSequence(vec);
    }

    @Override
    @JRubyMethod(name = "==")
    public IRubyObject op_equal(ThreadContext context, IRubyObject obj) {
        return equalImpl(context.runtime, obj);
    }

    private IRubyObject equalImpl(final Ruby runtime, IRubyObject obj) {
        if (this == obj) return runtime.getTrue();
        if (obj instanceof X509Extension) {
            boolean equal;
            try {
                equal = Arrays.equals(toDER(), ((X509Extension) obj).toDER());
            }
            catch (IOException e) {
                throw newExtensionError(getRuntime(), e);
            }
            return runtime.newBoolean(equal);
        }
        return runtime.getFalse();
    }

    @Override
    public IRubyObject eql_p(IRubyObject obj) {
        return equalImpl(getRuntime(), obj);
    }

    // [ self.oid, self.value, self.critical? ]
    @JRubyMethod
    public RubyArray to_a(final ThreadContext context) {
        RubyArray array = RubyArray.newArray(context.runtime, 3);
        array.append(oid(context));
        array.append(value(context));
        array.append(critical_p(context));
        return array;
    }

    // {"oid"=>self.oid,"value"=>self.value,"critical"=>self.critical?
    @JRubyMethod
    public RubyHash to_h(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        RubyHash hash = RubyHash.newHash(runtime);
        hash.op_aset(context, newStringFrozen(runtime, "oid"), oid(context));
        hash.op_aset(context, newStringFrozen(runtime, "value"), value(context));
        hash.op_aset(context, newStringFrozen(runtime, "critical"), critical_p(context));
        return hash;
    }

    // "oid = critical, value"
    @JRubyMethod
    public RubyString to_s(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        final RubyString str = RubyString.newString(runtime, oidSym(runtime));
        str.getByteList().append(' ').append('=').append(' ');
        if ( isRealCritical() ) str.getByteList().append(critical__);
        // self.value.gsub(/\n/, ", ")
        final RubyString value = value(context);
        value.callMethod(context, "gsub!", new IRubyObject[] {
            RubyString.newStringShared(runtime, StringHelper.NEW_LINE),
            RubyString.newStringShared(runtime, StringHelper.COMMA_SPACE)
        });
        str.getByteList().append(value.getByteList());
        return str;
    }

    @Override
    public X509Extension clone() {
        try {
            return (X509Extension) super.clone();
        }
        catch (CloneNotSupportedException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    @SuppressWarnings(value = "unchecked")
    @JRubyMethod
    public IRubyObject inspect() {
        return ObjectSupport.inspect(this);
    }

    static RaiseException newExtensionError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _X509(runtime).getClass("ExtensionError"), e);
    }

    static RaiseException newExtensionError(Ruby runtime, String message) {
        return Utils.newError(runtime, _X509(runtime).getClass("ExtensionError"), message);
    }

    // our custom "internal" HEX helpers :

    private static boolean isHex(final char c) {
        return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f');
    }

    static boolean isHex(final String str) {
        for ( int i = 0; i < str.length(); i++ ) {
            if ( ! isHex(str.charAt(i)) ) return false;
        }
        return true;
    }

    static int upHex(final char c) {
        switch (c) {
            case '0' : return '0';
            case '1' : return '1';
            case '2' : return '2';
            case '3' : return '3';
            case '4' : return '4';
            case '5' : return '5';
            case '6' : return '6';
            case '7' : return '7';
            case '8' : return '8';
            case '9' : return '9';
            case 'A' :
            case 'a' : return 'A';
            case 'B' :
            case 'b' : return 'B';
            case 'C' :
            case 'c' : return 'C';
            case 'D' :
            case 'd' : return 'D';
            case 'E' :
            case 'e' : return 'E';
            case 'F' :
            case 'f' : return 'F';
        }
        return -1;
    }

    private static ByteList hexBytes(final byte[] data, final int off) {
        final int len = data.length - off;
        return hexBytes(data, off, len, new ByteList( len * 3 ));
    }

    private static ByteList hexBytes(final byte[] data, final ByteList out) {
        return hexBytes(data, 0, data.length, out);
    }

    //@SuppressWarnings("deprecation")
    //private static ByteList hexBytes(final ByteList data, final ByteList out) {
    //    return hexBytes(data.bytes, data.begin, data.realSize, out);
    //}

    private static ByteList hexBytes(final byte[] data, final int off, final int len, final ByteList out) {
        boolean notFist = false;
        out.ensure( len * 3 - 1 );
        for ( int i = off; i < (off + len); i++ ) {
            if ( notFist ) out.append(':');
            final byte b = data[i];
            out.append( HEX[ (b >> 4) & 0xF ] );
            out.append( HEX[ b & 0xF ] );
            notFist = true;
        }
        return out;
    }

    private static final char[] HEX = {
        '0' , '1' , '2' , '3' , '4' , '5' , '6' , '7' ,
        '8' , '9' , 'A' , 'B' , 'C' , 'D' , 'E' , 'F'
    };

}
