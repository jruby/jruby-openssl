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
import java.io.StringWriter;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyFile;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyClass;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.ext.openssl.impl.BIO;
import org.jruby.ext.openssl.impl.CipherSpec;
import org.jruby.ext.openssl.impl.MemBIO;
import org.jruby.ext.openssl.impl.Mime;
import org.jruby.ext.openssl.impl.NotVerifiedPKCS7Exception;
import org.jruby.ext.openssl.impl.PKCS7Exception;
import org.jruby.ext.openssl.impl.RecipInfo;
import org.jruby.ext.openssl.impl.SMIME;
import org.jruby.ext.openssl.impl.SignerInfoWithPkey;
import org.jruby.ext.openssl.x509store.PEMInputOutput;
import org.jruby.ext.openssl.x509store.Store;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;

import static org.jruby.ext.openssl.OpenSSL.*;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newString;
import static org.jruby.ext.openssl.util.RubySupport.newUTF8String;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
@JRubyClass(name = "OpenSSL::PKCS7")
public class PKCS7 extends RubyObject {
    private static final long serialVersionUID = -3925104500966826973L;
    private static final Logger LOG = Logger.getLogger(PKCS7.class);

    private static ObjectAllocator PKCS7_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new PKCS7(runtime, klass);
        }
    };

    public static void createPKCS7(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        RubyClass _PKCS7 = OpenSSL.defineClassUnder("PKCS7", runtime.getObject(), PKCS7_ALLOCATOR);
        _PKCS7.defineClassUnder("PKCS7Error", OpenSSLError, OpenSSLError.getAllocator());
        _PKCS7.addReadWriteAttribute(runtime.getCurrentContext(), "data");
        _PKCS7.addReadWriteAttribute(runtime.getCurrentContext(), "error_string");
        _PKCS7.defineAnnotatedMethods(PKCS7.class);

        SignerInfo.createSignerInfo(runtime, _PKCS7);
        RecipientInfo.createRecipientInfo(runtime, _PKCS7);

        _PKCS7.setConstant("TEXT", runtime.newFixnum(1));
        _PKCS7.setConstant("NOCERTS", runtime.newFixnum(2));
        _PKCS7.setConstant("NOSIGS", runtime.newFixnum(4));
        _PKCS7.setConstant("NOCHAIN", runtime.newFixnum(8));
        _PKCS7.setConstant("NOINTERN", runtime.newFixnum(16));
        _PKCS7.setConstant("NOVERIFY", runtime.newFixnum(32));
        _PKCS7.setConstant("DETACHED", runtime.newFixnum(64));
        _PKCS7.setConstant("BINARY", runtime.newFixnum(128));
        _PKCS7.setConstant("NOATTR", runtime.newFixnum(256));
        _PKCS7.setConstant("NOSMIMECAP", runtime.newFixnum(512));
    }

    // ossl_obj2bio
    public static BIO obj2bio(ThreadContext context, IRubyObject obj) {
        if (obj instanceof RubyFile) {
            obj = obj.callMethod(context, "read");
        }
        final ByteList str = obj.asString().getByteList();
        return BIO.memBuf(str.getUnsafeBytes(), str.getBegin(), str.getRealSize());
    }

    private static PKCS7 wrap(final Ruby runtime, org.jruby.ext.openssl.impl.PKCS7 p7) {
        PKCS7 wrapped = new PKCS7(runtime, _PKCS7(runtime));
        wrapped.p7 = p7;
        return wrapped;
    }

    static RubyString membio2str(Ruby runtime, BIO bio, boolean mem) {
        final ByteList bytes;
        if (mem) {
            bytes = new ByteList(((MemBIO) bio).getBuffer(), 0, ((MemBIO) bio).length(), false);
        }
        else {
            bytes = new ByteList(bio.toBytes(), false);
        }
        return runtime.newString(bytes);
    }

    private static List<X509AuxCertificate> getAuxCerts(final IRubyObject arg) {
        final RubyArray arr = (RubyArray) arg;
        List<X509AuxCertificate> certs = new ArrayList<X509AuxCertificate>(arr.size());
        for ( int i = 0; i<arr.size(); i++ ) {
            certs.add( ((X509Cert) arr.eltInternal(i)).getAuxCert() );
        }
        return certs;
    }

    @JRubyMethod(meta = true)
    public static IRubyObject read_smime(ThreadContext context, IRubyObject self, IRubyObject arg) {
        final Ruby runtime = context.runtime;
        final BIO in = obj2bio(context, arg);
        final BIO[] out = new BIO[] { null };
        org.jruby.ext.openssl.impl.PKCS7 pkcs7Impl;
        try {
            pkcs7Impl = new SMIME(Mime.DEFAULT).readPKCS7(in, out);
        }
        catch (IOException ioe) {
            throw newPKCS7Error(runtime, ioe.getMessage());
        }
        catch (PKCS7Exception pkcs7e) {
            throw newPKCS7Error(runtime, pkcs7e);
        }
        if ( pkcs7Impl == null ) {
            throw newPKCS7Error(runtime, (String) null);
        }
        IRubyObject data = out[0] != null ? membio2str(runtime, out[0], false) : runtime.getNil();
        final PKCS7 pkcs7 = wrap(runtime, pkcs7Impl);
        pkcs7.setData(data);
        return pkcs7;
    }

    @JRubyMethod(meta = true, rest = true)
    public static IRubyObject write_smime(IRubyObject self, IRubyObject[] args) {
        final Ruby runtime = self.getRuntime();

        final PKCS7 pkcs7;
        IRubyObject data = runtime.getNil();
        IRubyObject flags = runtime.getNil();

        switch ( Arity.checkArgumentCount(runtime, args, 1, 3) ) {
            case 3: flags = args[2];
            case 2: data = args[1];
            default: pkcs7 = (PKCS7) args[0];
        }

        if (data.isNil()) data = pkcs7.getData();

        final int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);

        String smime;
        try {
            smime = new SMIME().writePKCS7(pkcs7.p7, data.asJavaString(), flg);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(runtime, e);
        }
        catch (IOException e) {
            throw newPKCS7Error(runtime, e.getMessage());
        }

        return RubyString.newString(runtime, smime);
    }

    @JRubyMethod(meta = true, rest = true)
    public static IRubyObject sign(ThreadContext context, IRubyObject self, IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        final X509Cert cert; final PKey key; final IRubyObject data;
        IRubyObject certs = runtime.getNil();
        IRubyObject flags = runtime.getNil();

        switch ( Arity.checkArgumentCount(runtime, args, 3, 5) ) {
            case 5: flags = args[4];
            case 4: certs = args[3];
            default:
                cert = (X509Cert) args[0];
                key = (PKey) args[1];
                data = args[2];
        }

        X509AuxCertificate auxCert = cert.getAuxCert();
        PrivateKey privKey = key.getPrivateKey();
        final int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);
        final BIO dataBIO = obj2bio(context, data);
        List<X509AuxCertificate> auxCerts = certs.isNil() ? null : getAuxCerts(certs);

        org.jruby.ext.openssl.impl.PKCS7 pkcs7Impl;
        try {
            pkcs7Impl = org.jruby.ext.openssl.impl.PKCS7.sign(auxCert, privKey, auxCerts, dataBIO, flg);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(runtime, e);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(runtime, ex);
        }
        final PKCS7 pkcs7 = wrap(runtime, pkcs7Impl);
        pkcs7.setData(data);
        return pkcs7;
    }

    /** ossl_pkcs7_s_encrypt
     *
     */
    @JRubyMethod(meta = true, rest = true)
    public static IRubyObject encrypt(IRubyObject self, IRubyObject[] args) {
        final Ruby runtime = self.getRuntime();

        IRubyObject certs, data, cipher = runtime.getNil(), flags = runtime.getNil();

        switch ( Arity.checkArgumentCount(self.getRuntime(), args, 2, 4) ) {
            case 4: flags = args[3];
            case 3: cipher = args[2];
        }
        data = args[1]; certs = args[0];

        CipherSpec cipherSpec;
        if ( cipher.isNil() ) {
            try {
                javax.crypto.Cipher c = SecurityHelper.getCipher("RC2/CBC/PKCS5Padding");
                cipherSpec = new CipherSpec(c, Cipher.Algorithm.javaToOssl("RC2/CBC/PKCS5Padding", 40), 40);
            }
            catch (GeneralSecurityException e) { throw newPKCS7Error(runtime, e); }
        }
        else {
            final Cipher c = (Cipher) cipher;
            cipherSpec = new CipherSpec(c.getCipherInstance(), c.getName(), c.getGenerateKeyLength() * 8);
        }
        final int flg = flags.isNil() ? 0 : RubyNumeric.fix2int(flags);
        final List<X509AuxCertificate> auxCerts = getAuxCerts(certs);
        final byte[] dataBytes = data.asString().getBytes();

        org.jruby.ext.openssl.impl.PKCS7 pkcs7Impl;
        try {
            pkcs7Impl = org.jruby.ext.openssl.impl.PKCS7.encrypt(auxCerts, dataBytes, cipherSpec, flg);
        }
        catch (PKCS7Exception pkcs7e) {
            throw newPKCS7Error(self.getRuntime(), pkcs7e);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(runtime, ex);
        }
        final PKCS7 pkcs7 = wrap(runtime, pkcs7Impl);
        pkcs7.setData(data);
        return pkcs7;
    }

    public PKCS7(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private org.jruby.ext.openssl.impl.PKCS7 p7;

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject[] args) {
        if ( Arity.checkArgumentCount(context.runtime, args, 0, 1) == 0 ) {
            p7 = new org.jruby.ext.openssl.impl.PKCS7();
            try {
                p7.setType(ASN1Registry.NID_undef);
            }
            catch (PKCS7Exception e) {
                throw newPKCS7Error(context.runtime, e);
            }
            return this;
        }

        IRubyObject arg = to_der_if_possible(context, args[0]);
        BIO input = obj2bio(context, arg);
        try {
            p7 = org.jruby.ext.openssl.impl.PKCS7.readPEM(input);
            if (p7 == null) {
                input.reset();
                p7 = org.jruby.ext.openssl.impl.PKCS7.fromASN1(input);
            }
        }
        catch (IllegalArgumentException e) {
            throw context.runtime.newArgumentError(e.getMessage());
        }
        catch (IOException e) {
            throw newPKCS7Error(context.runtime, e.getMessage());
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(context.runtime, e);
        }
        setData(context.nil);
        return this;
    }

    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        // checkFrozen();
        if (this == obj) return this;

        final PKCS7 that = (PKCS7) obj;
        try {
            this.p7 = org.jruby.ext.openssl.impl.PKCS7.fromASN1(that.p7.asASN1());
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(getRuntime(), e);
        }

        setData(that.getData());
        // getInstanceVariable returns Java null when unset; setInstanceVariable asserts non-null
        final IRubyObject errorString = that.getInstanceVariable("@error_string");
        if (errorString != null) setInstanceVariable("@error_string", errorString);
        return this;
    }

    @JRubyMethod(name = "type=")
    public IRubyObject set_type(IRubyObject type) {
        final String typeStr = type.asString().toString();

        int typeId = ASN1Registry.NID_undef;
        if ("signed".equals(typeStr)) {
            typeId = ASN1Registry.NID_pkcs7_signed;
        } else if ("data".equals(typeStr)) {
            typeId = ASN1Registry.NID_pkcs7_data;
        } else if ("signedAndEnveloped".equals(typeStr)) {
            typeId = ASN1Registry.NID_pkcs7_signedAndEnveloped;
        } else if ("enveloped".equals(typeStr)) {
            typeId = ASN1Registry.NID_pkcs7_enveloped;
        } else if ("encrypted".equals(typeStr)) {
            typeId = ASN1Registry.NID_pkcs7_encrypted;
        } else if ("digest".equals(typeStr)) {
            typeId = ASN1Registry.NID_pkcs7_digest;
        }

        try {
            p7.setType(typeId);
        }
        catch (PKCS7Exception pkcs7e) {
            throw newPKCS7Error(getRuntime(), pkcs7e);
        }
        return type;
    }

    @JRubyMethod(name = "type")
    public IRubyObject get_type() {
        if (p7.isSigned()) return getRuntime().newSymbol("signed");
        if (p7.isEncrypted()) return getRuntime().newSymbol("encrypted");
        if (p7.isEnveloped()) return getRuntime().newSymbol("enveloped");
        if (p7.isSignedAndEnveloped()) return getRuntime().newSymbol("signedAndEnveloped");
        if (p7.isData()) return getRuntime().newSymbol("data");
        return getRuntime().getNil();
    }

    @JRubyMethod(name = "detached")
    public IRubyObject detached(ThreadContext context) {
        try {
            if (!p7.isSigned()) return context.runtime.getFalse();
            return context.runtime.newBoolean(p7.getDetached() != 0);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(context.runtime, e);
        }
    }

    @JRubyMethod(name = "detached=")
    public IRubyObject set_detached(ThreadContext context, IRubyObject obj) {
        final Ruby runtime = context.runtime;
        if (obj != runtime.getTrue() && obj != runtime.getFalse()) {
            throw newPKCS7Error(runtime, "must specify a boolean");
        }

        try {
            p7.setDetached(obj.isTrue() ? 1 : 0);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(runtime, e);
        }
        return obj;
    }

    @JRubyMethod(name = "detached?")
    public IRubyObject detached_p(ThreadContext context) {
        try {
            return context.runtime.newBoolean(p7.isDetached());
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(context.runtime, e);
        }
    }

    @JRubyMethod(name = "cipher=")
    public IRubyObject set_cipher(IRubyObject obj) {
        final CipherSpec spec = PKey.cipherSpec(obj);
        if (spec == null) throw newPKCS7Error(getRuntime(), "PKCS7_set_cipher");

        try {
            p7.setCipher(spec);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(getRuntime(), e);
        }
        return obj;
    }

    @JRubyMethod
    public IRubyObject add_signer(IRubyObject obj) {
        SignerInfoWithPkey signedInfo = ((SignerInfo) obj).getSignerInfo().dup();

        try {
            p7.addSigner(signedInfo);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(getRuntime(), e);
        }
        // TODO: Handle exception here

        if ( p7.isSigned() ) {
            ASN1Encodable objectId = org.jruby.ext.openssl.impl.PKCS7.OID_pkcs7_data;
            signedInfo.addSignedAttribute(ASN1Registry.NID_pkcs9_contentType, objectId);
        }

        return this;
    }

    /** ossl_pkcs7_get_signer
     *
     * This seems to return a list of SignerInfo objects.
     *
     */
    @JRubyMethod
    public IRubyObject signers() {
        Collection<SignerInfoWithPkey> signerInfos = p7.getSignerInfo();
        if (signerInfos == null) return getRuntime().newEmptyArray();
        RubyArray ary = getRuntime().newArray(signerInfos.size());
        for ( SignerInfoWithPkey signerInfo : signerInfos ) {
            ary.append( SignerInfo.create(getRuntime(), signerInfo) );
        }
        return ary;
    }

    @JRubyMethod
    public IRubyObject add_recipient(IRubyObject obj) {
        final RecipientInfo recipient = (RecipientInfo) obj;
        final RecipInfo copy = new RecipInfo();
        copy.setVersion(recipient.info.getVersion());
        copy.setIssuerAndSerial(recipient.info.getIssuerAndSerial());
        copy.setKeyEncAlgor(recipient.info.getKeyEncAlgor());
        copy.setEncKey(recipient.info.getEncKey());
        copy.setCert(recipient.info.getCert());
        try {
            p7.addRecipientInfo(copy);
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(getRuntime(), e);
        }
        return RecipientInfo.create(getRuntime(), copy);
    }

    @JRubyMethod
    public IRubyObject recipients() {
        Collection<RecipInfo> sk;

        if (p7.isEnveloped()) {
            sk = p7.getEnveloped().getRecipientInfo();
        } else if (p7.isSignedAndEnveloped()) {
            sk = p7.getSignedAndEnveloped().getRecipientInfo();
        } else {
            sk = null;
        }

        final Ruby runtime = getRuntime();
        if (sk == null) return runtime.newEmptyArray();

        RubyArray ary = runtime.newArray(sk.size());
        for (RecipInfo ri : sk) {
            ary.append(RecipientInfo.create(runtime, ri));
        }
        return ary;
    }

    @JRubyMethod
    public IRubyObject add_certificate(IRubyObject obj) {
        try {
            p7.addCertificate(((X509Cert)obj).getAuxCert());
        } catch (PKCS7Exception pkcse) {
            throw newPKCS7Error(getRuntime(), pkcse);
        }
        return this;
    }

    @JRubyMethod(name="certificates=")
    public IRubyObject set_certificates(IRubyObject obj) {
        final Collection<X509AuxCertificate> certs = getCertificates();
        if (certs != null) certs.clear();

        final RubyArray arr = obj.convertToArray();
        for (int i = 0; i < arr.size(); i++) {
            add_certificate(arr.eltInternal(i));
        }
        return obj;
    }

    private Collection<X509AuxCertificate> getCertificates() {
        int type = p7.getType();
        switch (type) {
            case ASN1Registry.NID_pkcs7_signed:
                return p7.getSign().getCert();
            case ASN1Registry.NID_pkcs7_signedAndEnveloped:
                return p7.getSignedAndEnveloped().getCert();
            default:
                return null;
        }
    }

    private RubyArray certsToArray(Ruby runtime, Collection<X509AuxCertificate> certs) throws CertificateEncodingException {
        RubyArray ary = runtime.newArray(certs.size());
        for (X509AuxCertificate x509 : certs) {
            ary.append(X509Cert.wrap(runtime, x509));
        }
        return ary;
    }

    @JRubyMethod
    public IRubyObject certificates(ThreadContext context) {
        try {
            final Collection<X509AuxCertificate> certs = getCertificates();
            if (certs == null) return context.nil;
            return certsToArray(context.runtime, certs);
        } catch (CertificateEncodingException ex) {
            throw newPKCS7Error(context.runtime, ex.getMessage());
        }
    }

    @JRubyMethod
    public IRubyObject add_crl(IRubyObject obj) {
        try {
            p7.addCRL(((X509CRL) obj).getCRL());
        }
        catch (PKCS7Exception e) {
            throw newPKCS7Error(getRuntime(), e);
        }
        return this;
    }

    @JRubyMethod(name="crls=")
    public IRubyObject set_crls(IRubyObject obj) {
        final RubyArray arr = obj.convertToArray();

        final Collection<java.security.cert.X509CRL> crls = getCRLs();
        if (crls != null) crls.clear();

        for (int i = 0; i < arr.size(); i++) add_crl(arr.eltInternal(i));
        return obj;
    }

    @JRubyMethod
    public IRubyObject crls(ThreadContext context) {
        final Collection<java.security.cert.X509CRL> crls = getCRLs();
        if (crls == null) return context.nil;

        final Ruby runtime = context.runtime;
        final RubyArray ary = runtime.newArray(crls.size());
        for (java.security.cert.X509CRL crl : crls) {
            try {
                RubyString encoded = newString(runtime, crl.getEncoded());
                ary.append(X509CRL._CRL(runtime).newInstance(context, encoded, Block.NULL_BLOCK));
            }
            catch (CRLException e) {
                throw X509CRL.newCRLError(runtime, e);
            }
        }
        return ary;
    }

    private Collection<java.security.cert.X509CRL> getCRLs() {
        int type = p7.getType();
        switch (type) {
            case ASN1Registry.NID_pkcs7_signed:
                return p7.getSign().getCrl();
            case ASN1Registry.NID_pkcs7_signedAndEnveloped:
                return p7.getSignedAndEnveloped().getCrl();
            default:
                return null;
        }
    }

    @JRubyMethod(name = { "add_data", "data=" })
    public IRubyObject add_data(ThreadContext context, IRubyObject obj) {
        if (p7.isData()) {
            p7.setData(new DEROctetString(obj.asString().getBytes()));
            setData(obj);
            return obj;
        }

        if (p7.isSigned()) {
            try {
                p7.contentNew(ASN1Registry.NID_pkcs7_data);
            } catch (PKCS7Exception e) {
                throw newPKCS7Error(context.runtime, e);
            }
        }

        BIO in = obj2bio(context, obj);
        BIO out;
        try {
            out = p7.dataInit(null);
        } catch (PKCS7Exception e) {
            throw newPKCS7Error(context.runtime, e);
        }
        byte[] buf = new byte[4096];
        for(;;) {
            try {
                int i = in.read(buf, 0, buf.length);
                if(i <= 0) {
                    break;
                }
                if(out != null) {
                    out.write(buf, 0, i);
                }
            } catch(IOException e) {
                throw context.runtime.newIOErrorFromException(e);
            }
        }

        try {
            p7.dataFinal(out);
        } catch (PKCS7Exception e) {
            throw newPKCS7Error(context.runtime, e);
        }
        setData(context.nil);

        return obj;
    }

    @JRubyMethod(rest = true)
    public IRubyObject verify(ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;

        IRubyObject certs; X509Store store;
        IRubyObject indata = runtime.getNil();
        IRubyObject vflags = runtime.getNil();

        switch ( Arity.checkArgumentCount(runtime, args, 2, 4) ) {
            case 4: vflags = args[3];
            case 3: indata = args[2];
            default: store = (X509Store) args[1]; certs = args[0];
        }
        final int flg = vflags.isNil() ? 0 : RubyNumeric.fix2int(vflags);

        if ( indata.isNil() ) indata = getData();

        final BIO in = indata.isNil() ? null : obj2bio(context, indata);

        List<X509AuxCertificate> x509s = certs.isNil() ? null : getAuxCerts(certs);

        final Store storeStr = store.getStore();
        final BIO out = BIO.mem();

        boolean result = false;
        try {
            p7.verify(x509s, storeStr, in, out, flg);
            result = true;
        }
        catch (NotVerifiedPKCS7Exception e) {
            // result = false;
        }
        catch (PKCS7Exception ex) {
            LOG.debugStack(runtime, null, ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(runtime, ex);
        }

        IRubyObject data = membio2str(runtime, out, true);
        setData(data);

        return result ? runtime.getTrue() : runtime.getFalse();
    }

    @JRubyMethod(rest=true)
    public IRubyObject decrypt(ThreadContext context, IRubyObject... args) {
        IRubyObject dflags;
        if ( Arity.checkArgumentCount(context.runtime, args, 1, 3) == 3 ) {
            dflags = args[2];
        }
        else {
            dflags = context.nil;
        }
        PKey pkey = (PKey) args[0];

        final PrivateKey privKey = pkey.getPrivateKey();
        final X509AuxCertificate auxCert = args.length > 1 ? ((X509Cert) args[1]).getAuxCert() : null;
        final int flg = dflags == context.nil ? 0 : RubyNumeric.fix2int(dflags);

        final BIO out = BIO.mem();
        try {
            p7.decrypt(privKey, auxCert, out, flg);
        }
        catch (PKCS7Exception ex) {
            LOG.debugStack(context.runtime, null, ex);
            throw newPKCS7Error(context.runtime, ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(context.runtime, ex);
        }
        return membio2str(context.runtime, out, true);
    }

    @JRubyMethod(name = {"to_pem", "to_s"})
    public IRubyObject to_pem() {
        StringWriter writer = new StringWriter();
        try {
            PEMInputOutput.writePKCS7(writer, p7.toASN1());
        }
        catch (IllegalStateException e) {
            throw newPKCS7Error(getRuntime(), e.getMessage());
        }
        catch (IOException ex) {
            LOG.debugStack(getRuntime(), null, ex);
            throw getRuntime().newIOErrorFromException(ex);
        }
        return newUTF8String(getRuntime(), writer.getBuffer());
    }

    @JRubyMethod
    public IRubyObject to_der() {
        try {
            return newString(getRuntime(), p7.toASN1());
        }
        catch (IllegalStateException|IOException e) {
            throw newPKCS7Error(getRuntime(), e);
        }
    }

    public void setData(IRubyObject object) {
        setInstanceVariable("@data", object);
    }

    public IRubyObject getData() {
        return getInstanceVariable("@data");
    }

    @JRubyClass(name = "OpenSSL::PKCS7::SignerInfo")
    public static class SignerInfo extends RubyObject {

        private static final long serialVersionUID = -3799397032272738848L;

        private static ObjectAllocator SIGNERINFO_ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new SignerInfo(runtime, klass);
            }
        };

        public static void createSignerInfo(final Ruby runtime, final RubyModule _PKCS7) {
            RubyClass _SignerInfo = _PKCS7.defineClassUnder("SignerInfo", runtime.getObject(), SIGNERINFO_ALLOCATOR);
            _PKCS7.defineConstant("Signer",_SignerInfo);
            _SignerInfo.defineAnnotatedMethods(SignerInfo.class);
        }

        private static RubyClass _SignerInfo(final Ruby runtime) {
            return _PKCS7(runtime).getClass("SignerInfo");
        }

        public static SignerInfo create(Ruby runtime, SignerInfoWithPkey info) {
            SignerInfo instance = new SignerInfo(runtime, _SignerInfo(runtime));
            instance.info = info;
            return instance;
        }

        public SignerInfo(Ruby runtime, RubyClass type) {
            super(runtime,type);
        }

        private SignerInfoWithPkey info;

        SignerInfoWithPkey getSignerInfo() {
            return info;
        }

        @JRubyMethod(visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context,
            IRubyObject arg1, IRubyObject arg2, IRubyObject arg3) {
            this.info = new SignerInfoWithPkey();
            final X509AuxCertificate cert = ((X509Cert) arg1).getAuxCert();
            final PrivateKey pkey = ((PKey) arg2).getPrivateKey();
            final java.security.MessageDigest digest = Digest.getDigest(context, arg3).getDigestImpl();

            try {
                info.set(cert, pkey, digest);
            }
            catch (PKCS7Exception e) {
                throw newPKCS7Error(context.runtime, e);
            }
            return this;
        }


        @JRubyMethod(name={"issuer","name"})
        public IRubyObject issuer() {
            return X509Name.newName(getRuntime(), info.getIssuerAndSerialNumber().getName());
        }

        @JRubyMethod
        public IRubyObject serial() {
            return RubyBignum.bignorm(getRuntime(), info.getIssuerAndSerialNumber().getCertificateSerialNumber().getValue());
        }

        @JRubyMethod
        public IRubyObject signed_time(final ThreadContext context) {
            ASN1Encodable asn1obj = info.getSignedAttribute(ASN1Registry.NID_pkcs9_signingTime);
            if (asn1obj == null) {
                throw newPKCS7Error(context.runtime, "no signing time attribute");
            }
            if (asn1obj instanceof ASN1UTCTime) {
                final Date adjusted;
                try {
                    adjusted = ((ASN1UTCTime) asn1obj).getAdjustedDate();
                } catch (ParseException ex) {
                    throw newPKCS7Error(context.runtime, ex);
                }
                return RubyTime.newTime(context.runtime, adjusted.getTime());
            }
            return context.nil;
        }
    }

    @JRubyClass(name = "OpenSSL::PKCS7::RecipientInfo")
    public static class RecipientInfo extends RubyObject {

        private static final long serialVersionUID = 6977793206950149902L;

        private static ObjectAllocator RECIPIENTINFO_ALLOCATOR = new ObjectAllocator() {
            public IRubyObject allocate(Ruby runtime, RubyClass klass) {
                return new RecipientInfo(runtime, klass);
            }
        };

        public static void createRecipientInfo(final Ruby runtime, final RubyModule _PKCS7) {
            RubyClass _Recipient = _PKCS7.defineClassUnder("RecipientInfo", runtime.getObject(), RECIPIENTINFO_ALLOCATOR);
            _Recipient.defineAnnotatedMethods(RecipientInfo.class);
        }

        private static RubyClass _RecipientInfo(final Ruby runtime) {
            return _PKCS7(runtime).getClass("RecipientInfo");
        }

        public RecipientInfo(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }

        public static RecipientInfo create(Ruby runtime, RecipInfo info) {
            RecipientInfo instance = new RecipientInfo(runtime, _RecipientInfo(runtime));
            instance.info = info;
            return instance;
        }

        private RecipInfo info;

        @JRubyMethod(visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, IRubyObject arg) {
            this.info = new RecipInfo();
            try {
                info.set(((X509Cert) arg).getAuxCert());
            }
            catch (PKCS7Exception e) {
                throw newPKCS7Error(context.runtime, e.getErrorData());
            }
            return this;
        }

        @JRubyMethod
        public IRubyObject issuer() {
            return X509Name.newName(getRuntime(), info.getIssuerAndSerial().getName());
        }

        @JRubyMethod
        public IRubyObject serial() {
            return RubyBignum.bignorm(getRuntime(), info.getIssuerAndSerial().getCertificateSerialNumber().getValue());
        }

        @JRubyMethod
        public IRubyObject enc_key(final ThreadContext context) {
            return newString(context.runtime, info.getEncKey().getOctets());
        }
    }

    private static RaiseException newPKCS7Error(Ruby runtime, Exception e) {
        return newError(runtime, _PKCS7(runtime).getClass("PKCS7Error"), e);
    }

    private static RaiseException newPKCS7Error(Ruby runtime, String message) {
        return newError(runtime, _PKCS7(runtime).getClass("PKCS7Error"), message);
    }

    static RubyClass _PKCS7(final Ruby runtime) {
        return (RubyClass) runtime.getModule("OpenSSL").getConstant("PKCS7");
    }

}// PKCS7
