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
import java.math.BigInteger;

import java.security.GeneralSecurityException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.GeneralName;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.impl.ASN1Registry;
import static org.jruby.ext.openssl.OpenSSL.debug;
import static org.jruby.ext.openssl.X509Extension.*;

/**
 * OpenSSL::X509::ExtensionFactory
 * @author kares
 */
public class X509ExtensionFactory extends RubyObject {
    private static final long serialVersionUID = 3180447029639456500L;

    private static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new X509ExtensionFactory(runtime, klass);
        }
    };

    static void createX509ExtensionFactory(final Ruby runtime, final RubyModule _X509) { // OpenSSL::X509
        final RubyClass _ExtensionFactory = _X509.defineClassUnder("ExtensionFactory",
                runtime.getObject(), X509ExtensionFactory.ALLOCATOR);
        _ExtensionFactory.defineAnnotatedMethods(X509ExtensionFactory.class);
    }

    public X509ExtensionFactory(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    @JRubyMethod(rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final IRubyObject[] args, final Block unusedBlock) {
        Arity.checkArgumentCount(getRuntime(), args, 0, 4);
        if (args.length > 0 && !args[0].isNil()) {
            set_issuer_cert(args[0]);
        }
        if (args.length > 1 && !args[1].isNil()) {
            set_subject_cert(args[1]);
        }
        if (args.length > 2 && !args[2].isNil()) {
            set_subject_req(args[2]);
        }
        if (args.length > 3 && !args[3].isNil()) {
            set_crl(args[3]);
        }
        return this;
    }

    @JRubyMethod(name = "issuer_certificate")
    public IRubyObject issuer_cert() {
        return getInstanceVariable("@issuer_certificate");
    }

    @JRubyMethod(name = "issuer_certificate=")
    public IRubyObject set_issuer_cert(IRubyObject arg) {
        setInstanceVariable("@issuer_certificate", arg);
        return arg;
    }

    @JRubyMethod(name = "subject_certificate")
    public IRubyObject subject_cert() {
        return getInstanceVariable("@subject_certificate");
    }

    @JRubyMethod(name = "subject_certificate=")
    public IRubyObject set_subject_cert(IRubyObject arg) {
        setInstanceVariable("@subject_certificate", arg);
        return arg;
    }

    @JRubyMethod(name = "subject_request")
    public IRubyObject subject_req() {
        return getInstanceVariable("@subject_request");
    }

    @JRubyMethod(name = "subject_request=")
    public IRubyObject set_subject_req(IRubyObject arg) {
        setInstanceVariable("@subject_request", arg);
        return arg;
    }

    @JRubyMethod(name = "crl")
    public IRubyObject crl() {
        return getInstanceVariable("@crl");
    }

    @JRubyMethod(name = "crl=")
    public IRubyObject set_crl(IRubyObject arg) {
        setInstanceVariable("@crl", arg);
        return arg;
    }

    @JRubyMethod(name = "config")
    public IRubyObject config() {
        return getInstanceVariable("@config");
    }

    @JRubyMethod(name = "config=")
    public IRubyObject set_config(IRubyObject arg) {
        setInstanceVariable("@config", arg);
        return arg;
    }

    @JRubyMethod(rest = true)
    public IRubyObject create_ext(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        IRubyObject critical;
        if (Arity.checkArgumentCount(runtime, args, 2, 3) == 3 && !args[2].isNil()) {
            critical = args[2];
        } else {
            critical = runtime.getFalse();
        }
        final String oid = args[0].toString();
        String valuex = args[1].toString();
        final ASN1ObjectIdentifier objectId;
        try {
            objectId = ASN1.getObjectID(runtime, oid);
        } catch (IllegalArgumentException e) {
            debug(runtime, "ASN1.getObjectIdentifier() at ExtensionFactory.create_ext", e);
            throw newExtensionError(runtime, "unknown OID `" + oid + "'");
        }
        final String critical_ = "critical,";
        if ( valuex.startsWith(critical_) ) {
            critical = runtime.getTrue();
            valuex = valuex.substring(critical_.length()).trim();
        }
        final ASN1Encodable value;
        try {
            final String id = objectId.getId();
            if (id.equals("2.5.29.14")) { //subjectKeyIdentifier
                value = new DEROctetString(parseSubjectKeyIdentifier(context, oid, valuex));
            }
            else if (id.equals("2.5.29.35")) { //authorityKeyIdentifier
                value = parseAuthorityKeyIdentifier(context, valuex);
            }
            else if (id.equals("2.5.29.17")) { //subjectAltName
                value = parseSubjectAltName(valuex);
            }
            else if (id.equals("2.5.29.18")) { //issuerAltName
                value = parseIssuerAltName(context, valuex);
            }
            else if (id.equals("2.5.29.19")) { //basicConstraints
                value = parseBasicConstrains(valuex);
            }
            else if (id.equals("2.5.29.15")) { //keyUsage
                value = parseKeyUsage(oid, valuex);
            }
            else if (id.equals("2.16.840.1.113730.1.1")) { //nsCertType
                value = parseNsCertType(oid, valuex);
            }
            else if (id.equals("2.5.29.37")) { //extendedKeyUsage
                value = parseExtendedKeyUsage(valuex);
            }
            else {
                value = new DEROctetString(new DEROctetString(ByteList.plain(valuex)).getEncoded(ASN1Encoding.DER));
            }
        }
        catch (IOException e) {
            throw newExtensionError(runtime, "Unable to create extension: " + e.getMessage());
        }
        return newExtension(runtime, objectId, value, critical.isNil() ? null : critical.isTrue());
    }

    @JRubyMethod(rest = true)
    public IRubyObject create_extension(final ThreadContext context, final IRubyObject[] args) {
        if (args.length > 1) {
            return create_ext(context, args);
        }
        final IRubyObject arg = args[0];
        if (arg instanceof RubyArray) {
            return create_ext_from_array(context, arg);
        }
        if (arg instanceof RubyHash) {
            return create_ext_from_hash(context, arg);
        }
        if (arg instanceof RubyString) {
            return create_ext_from_string(context, arg);
        }
        throw context.runtime.newArgumentError("unexpected argument: " + arg.inspect());
    }

    @JRubyMethod
    public IRubyObject create_ext_from_array(final ThreadContext context, final IRubyObject arg) {
        final RubyArray ary = (RubyArray) arg;
        if ( ary.size() > 3 ) throw newExtensionError(context.runtime, "unexpected array form");
        return create_ext(context, ary.toJavaArrayUnsafe());
    }

    @JRubyMethod
    public IRubyObject create_ext_from_hash(final ThreadContext context, final IRubyObject arg) {
        final RubyHash hash = (RubyHash) arg;
        final Ruby runtime = context.runtime;
        final IRubyObject oid = hash.op_aref(context, StringHelper.newStringFrozen(runtime, "oid"));
        final IRubyObject value = hash.op_aref(context, StringHelper.newStringFrozen(runtime, "value"));
        final IRubyObject critical = hash.op_aref(context, StringHelper.newStringFrozen(runtime, "critical"));
        return create_ext(context, new IRubyObject[]{oid, value, critical});
    }

    // "oid = critical, value"
    @JRubyMethod
    public IRubyObject create_ext_from_string(final ThreadContext context, final IRubyObject arg) {
        final RubyString str = (RubyString) arg;
        final Ruby runtime = context.runtime;
        RubyInteger i = str.index19(context, StringHelper.newString(runtime, new byte[]{'='})).convertToInteger("to_i");
        final int ind = (int) i.getLongValue();
        RubyString oid = (RubyString) str.substr19(runtime, 0, ind);
        oid.strip_bang19(context);
        final int len = (int) str.length19().getLongValue() - ind;
        RubyString value = (RubyString) str.substr19(runtime, ind + 1, len);
        value.lstrip_bang19(context);
        IRubyObject critical = context.nil;
        if (value.start_with_p(context, StringHelper.newString(runtime, critical__)).isTrue()) {
            critical = runtime.newBoolean(true); // value[ 0, 'critical, '.length ] = ''
            value.op_aset19(context, runtime.newFixnum(0), runtime.newFixnum(critical__.length), RubyString.newEmptyString(runtime));
        }
        value.strip_bang19(context);
        return create_ext(context, new IRubyObject[]{oid, value, critical});
    }

    private DERBitString parseKeyUsage(final String oid, final String valuex) {
        byte[] inp;
        try {
            final String[] val = valuex.split(":");
            inp = new byte[val.length];
            for (int i = 0; i < val.length; i++) {
                inp[i] = (byte) Integer.parseInt(val[i], 16);
            }
        } catch (NumberFormatException e) {
            inp = null;
        }
        if (inp == null && valuex.length() < 3) {
            inp = ByteList.plain(valuex);
        }
        if (inp == null) {
            byte v1 = 0;
            byte v2 = 0;
            final String[] val = valuex.split(",");
            for (int i = 0; i < val.length; i++) {
                final String value = val[i].trim();
                if ("decipherOnly".equals(value) || "Decipher Only".equals(value)) {
                    v2 |= (byte) 128;
                } else if ("digitalSignature".equals(value) || "Digital Signature".equals(value)) {
                    v1 |= (byte) 128;
                } else if ("nonRepudiation".equals(value) || "Non Repudiation".equals(value)) {
                    v1 |= (byte) 64;
                } else if ("keyEncipherment".equals(value) || "Key Encipherment".equals(value)) {
                    v1 |= (byte) 32;
                } else if ("dataEncipherment".equals(value) || "Data Encipherment".equals(value)) {
                    v1 |= (byte) 16;
                } else if ("keyAgreement".equals(value) || "Key Agreement".equals(value)) {
                    v1 |= (byte) 8;
                } else if ("keyCertSign".equals(value) || "Key Cert Sign".equals(value)) {
                    v1 |= (byte) 4;
                } else if ("cRLSign".equals(value)) {
                    v1 |= (byte) 2;
                } else if ("encipherOnly".equals(value) || "Encipher Only".equals(value)) {
                    v1 |= (byte) 1;
                } else {
                    throw newExtensionError(getRuntime(), oid + " = " + valuex + ": unknown bit string argument");
                }
            }
            inp = (v2 == 0) ? new byte[]{v1} : new byte[]{v1, v2};
        }
        int unused = 0;
        for (int i = inp.length - 1; i > -1; i--) {
            if (inp[i] == 0) {
                unused += 8;
            } else {
                byte a2 = inp[i];
                int x = 8;
                while (a2 != 0) {
                    a2 <<= 1;
                    x--;
                }
                unused += x;
                break;
            }
        }
        return new DERBitString(inp, unused);
    }

    private DERBitString parseNsCertType(String oid, String valuex) {
        byte v = 0;
        if (valuex.length() < 3) {
            byte[] inp = ByteList.plain(valuex);
            v = inp[0];
        } else {
            final String[] val = valuex.split(",");
            for (int i = 0; i < val.length; i++) {
                final String value = val[i].trim();
                if ("SSL Client".equals(value) || "client".equals(value)) {
                    v |= (byte) 128;
                } else if ("SSL Server".equals(value) || "server".equals(value)) {
                    v |= (byte) 64;
                } else if ("S/MIME".equals(value) || "email".equals(value)) {
                    v |= (byte) 32;
                } else if ("Object Signing".equals(value) || "objsign".equals(value)) {
                    v |= (byte) 16;
                } else if ("Unused".equals(value) || "reserved".equals(value)) {
                    v |= (byte) 8;
                } else if ("SSL CA".equals(value) || "sslCA".equals(value)) {
                    v |= (byte) 4;
                } else if ("S/MIME CA".equals(value) || "emailCA".equals(value)) {
                    v |= (byte) 2;
                } else if ("Object Signing CA".equals(value) || "objCA".equals(value)) {
                    v |= (byte) 1;
                } else {
                    throw newExtensionError(getRuntime(), oid + " = " + valuex + ": unknown bit string argument");
                }
            }
        }
        int unused = 0;
        if (v == 0) {
            unused += 8;
        } else {
            byte a2 = v;
            int x = 8;
            while (a2 != 0) {
                a2 <<= 1;
                x--;
            }
            unused += x;
        }
        return new DERBitString(new byte[]{v}, unused);
    }

    private static DLSequence parseBasicConstrains(final String valuex) {
        final String[] val = valuex.split(",");
        final ASN1EncodableVector vec = new ASN1EncodableVector();
        for (int i = 0; i < val.length; i++) {
            final String value = val[i] = val[i].trim();
            if (value.length() > 3 && value.substring(0, 3).equalsIgnoreCase("CA:")) {
                boolean isTrue = "true".equalsIgnoreCase(value.substring(3).trim());
                vec.add(ASN1Boolean.getInstance(isTrue));
            }
        }
        for (int i = 0; i < val.length; i++) {
            final String value = val[i];
            if (value.length() > 8 && value.substring(0, 8).equalsIgnoreCase("pathlen:")) {
                int pathlen = Integer.parseInt(value.substring(8).trim());
                vec.add(new ASN1Integer(BigInteger.valueOf(pathlen)));
            }
        }
        return new DLSequence(vec);
    }

    private DLSequence parseAuthorityKeyIdentifier(final ThreadContext context, final String valuex) {
        final ASN1EncodableVector vec = new ASN1EncodableVector();
        if ( valuex.startsWith("keyid:always") ) {
            vec.add(new DEROctetString(derDigest(context)));
        } else if ( valuex.startsWith("keyid") ) {
            vec.add(new DEROctetString(derDigest(context)));
        }
        return new DLSequence(vec);
    }

    private byte[] derDigest(final ThreadContext context) {
        final Ruby runtime = context.runtime;
        IRubyObject pkey = getInstanceVariable("@issuer_certificate").callMethod(context, "public_key");
        IRubyObject der;
        if (pkey instanceof PKeyRSA) {
            der = pkey.callMethod(context, "to_der");
        } else {
            der = ASN1.decode(context, ASN1._ASN1(runtime), pkey.callMethod(context, "to_der"));
            der = der.callMethod(context, "value").callMethod(context, "[]", runtime.newFixnum(1)).callMethod(context, "value");
        }
        return getSHA1Digest(runtime, der.asString().getBytes());
    }

    private static byte[] getSHA1Digest(Ruby runtime, byte[] bytes) {
        try {
            return SecurityHelper.getMessageDigest("SHA-1").digest(bytes);
        }
        catch (GeneralSecurityException e) {
            throw newExtensionError(runtime, e.getMessage());
        }
    }

    private ASN1Encodable parseIssuerAltName(final ThreadContext context, final String valuex)
        throws IOException {
        if ( valuex.startsWith("issuer:copy") ) {
            RubyArray exts = (RubyArray) getInstanceVariable("@issuer_certificate").callMethod(context, "extensions");
            for ( int i = 0; i < exts.size(); i++ ) {
                X509Extension ext = (X509Extension) exts.entry(i);
                final String oid = ext.getRealObjectID().getId();
                if ( "2.5.29.17".equals(oid) ) return ext.getRealValue();
            }
        }
        throw new IOException("Malformed IssuerAltName: " + valuex);
    }

    private static final String DNS_ = "DNS:";
    private static final String DNS_Name_ = "DNS Name:";
    private static final String URI_ = "URI:";
    private static final String RID_ = "RID:";
    private static final String email_ = "email:";
    private static final String dirName_ = "dirName:";
    private static final String otherName_ = "otherName:";

    private static ASN1Encodable parseSubjectAltName(final String valuex) throws IOException {
        if ( valuex.startsWith(DNS_) ) {
            final String dns = valuex.substring(DNS_.length());
            return new GeneralName(GeneralName.dNSName, dns);
        }
        if ( valuex.startsWith(DNS_Name_) ) {
            final String dns = valuex.substring(DNS_Name_.length());
            return new GeneralName(GeneralName.dNSName, dns);
        }
        if ( valuex.startsWith(URI_) ) {
            final String uri = valuex.substring(URI_.length());
            return new GeneralName(GeneralName.uniformResourceIdentifier, uri);
        }
        if ( valuex.startsWith(RID_) ) {
            final String rid = valuex.substring(RID_.length());
            return new GeneralName(GeneralName.registeredID, rid);
        }
        if ( valuex.startsWith(email_) ) {
            final String mail = valuex.substring(email_.length());
            return new GeneralName(GeneralName.rfc822Name, mail);
        }
        if ( valuex.startsWith("IP:") || valuex.startsWith("IP Address:") ) {
            final int idx = valuex.charAt(2) == ':' ? 3 : 11;
            String[] vals = valuex.substring(idx).split("\\.|::");
            final byte[] ip = new byte[vals.length];
            for ( int i = 0; i < vals.length; i++ ) {
                ip[i] = (byte) (Integer.parseInt(vals[i]) & 0xff);
            }
            return new GeneralName(GeneralName.iPAddress, new DEROctetString(ip));
        }
        if ( valuex.startsWith("other") ) { // otherName || othername
            final String other = valuex.substring(otherName_.length());
            return new GeneralName(GeneralName.otherName, other);
        }
        if ( valuex.startsWith("dir") ) { // dirName || dirname
            final String dir = valuex.substring(dirName_.length());
            return new GeneralName(GeneralName.directoryName, dir);
        }

        throw new IOException("could not parse SubjectAltName: " + valuex);

    }

    private DEROctetString parseSubjectKeyIdentifier(final ThreadContext context, final String oid, final String valuex) {
        if ( "hash".equalsIgnoreCase(valuex) ) {
            return new DEROctetString(derDigest(context));
        }
        if ( valuex.length() == 20 || ! isHex(valuex) ) {
            return new DEROctetString(ByteList.plain(valuex));
        }

        final int len = valuex.length();
        final ByteList hex = new ByteList(len / 2 + 1);
        for (int i = 0; i < len; i += 2) {
            if (i + 1 >= len) {
                throw newExtensionError(context.runtime, oid + " = " + valuex + ": odd number of digits");
            }
            final int c1 = upHex( valuex.charAt(i) );
            final int c2 = upHex( valuex.charAt(i + 1) );
            if (c1 != -1 && c2 != -1) {
                hex.append(((c1 << 4) & 0xF0) | (c2 & 0xF));
            } else {
                throw newExtensionError(context.runtime, oid + " = " + valuex + ": illegal hex digit");
            }
            while ((i + 2) < len && valuex.charAt(i + 2) == ':') {
                i++;
            }
        }
        final byte[] hexBytes = new byte[hex.length()];
        System.arraycopy(hex.getUnsafeBytes(), hex.getBegin(), hexBytes, 0, hexBytes.length);
        return new DEROctetString(hexBytes);
    }

    private static DLSequence parseExtendedKeyUsage(final String valuex) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (String name : valuex.split(", ?")) {
            vector.add(ASN1Registry.sym2oid(name));
        }
        return new DLSequence(vector);
    }

}
