/*
* The contents of this file are subject to the Common Public License Version 1.0
* (the "License"); you may not use this file except in compliance with the License.
* You may obtain a copy of the License at http://www.eclipse.org/legal/cpl-v10.html
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR APARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
* DEALINGS IN THE SOFTWARE.
*
*  Copyright (C) 2017 Donovan Lampa <donovan.lampa@gmail.com>
*  Copyright (C) 2009-2017 The JRuby Team
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
*
*
* JRuby-OpenSSL includes software by The Legion of the Bouncy Castle Inc.
* Please, visit (http://bouncycastle.org/license.html) for licensing details.
*/
package org.jruby.ext.openssl;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.jruby.Ruby;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.Digest._Digest;
import static org.jruby.ext.openssl.OCSP.*;

/**
 * An OpenSSL::OCSP::CertificateId identifies a certificate to the
 * CA so that a status check can be performed.
 * 
 * @author lampad
 */
public class OCSPCertificateId extends RubyObject {
    private static final long serialVersionUID = 6324454052172773918L;

    private static ObjectAllocator CERTIFICATEID_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPCertificateId(runtime, klass);
        }
    };
        
    public static void createCertificateId(final Ruby runtime, final RubyModule _OCSP) {
        RubyClass _certificateId = _OCSP.defineClassUnder("CertificateId", runtime.getObject(), CERTIFICATEID_ALLOCATOR);
        _certificateId.defineAnnotatedMethods(OCSPCertificateId.class);
    }
    
    private CertID bcCertId;
    private X509Cert originalIssuer;

    public OCSPCertificateId(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }
    
    public OCSPCertificateId(Ruby runtime) {
        this(runtime, (RubyClass) _OCSP(runtime).getConstantAt("CertificateId"));
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject subject, IRubyObject issuer, IRubyObject digest) {           
        if (digest == null || digest.isNil()) {
            return initialize(context, subject, issuer);
        }
        
        X509Cert subjectCert = (X509Cert) subject;
        originalIssuer = (X509Cert) issuer;
        BigInteger serial = subjectCert.getSerial();        
        
        return initializeImpl(context.runtime, serial, originalIssuer, digest);
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject subject, IRubyObject issuer) {
        final Ruby runtime = context.runtime;
        
        X509Cert subjectCert = (X509Cert) subject;
        originalIssuer = (X509Cert) issuer;
        BigInteger serial = subjectCert.getSerial();

        Digest digest = new Digest(runtime, _Digest(runtime));
        digest.initializeImpl(runtime, RubyString.newString(runtime, "SHA1"), runtime.getNil());
        
        return initializeImpl(runtime, serial, originalIssuer, digest);
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject der) {
        RubyString derStr = StringHelper.readPossibleDERInput(context, der);
        try {
            return initializeImpl(derStr.getBytes());
        }
        catch (Exception e) {
            throw newOCSPError(context.runtime, e);
        }
    }
    
    private IRubyObject initializeImpl(final Ruby runtime, BigInteger serial, X509Cert issuerCert, IRubyObject digest) {
        
        Digest rubyDigest = (Digest) digest;
        ASN1ObjectIdentifier oid = ASN1.sym2Oid(runtime, rubyDigest.getName().toLowerCase());
        AlgorithmIdentifier bcAlgId = new AlgorithmIdentifier(oid);
        BcDigestCalculatorProvider calculatorProvider = new BcDigestCalculatorProvider();
        DigestCalculator calc;
        try {
            calc = calculatorProvider.get(bcAlgId);
        }
        catch (OperatorCreationException e) {
            throw newOCSPError(runtime, e);
        }

        try {
            this.bcCertId = new CertificateID(calc, new X509CertificateHolder(issuerCert.getAuxCert().getEncoded()), serial).toASN1Primitive();
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    private IRubyObject initializeImpl(byte[] derByteStream) {
        this.bcCertId = CertID.getInstance(derByteStream);
        
        return this;
    }
    
    @JRubyMethod(name = "serial")
    public IRubyObject serial() {
        return RubyBignum.newBignum(getRuntime(), bcCertId.getSerialNumber().getValue());
    }
    
    @JRubyMethod(name = "issuer_name_hash")
    public IRubyObject issuer_name_hash(ThreadContext context) {
        Ruby runtime = context.runtime;
        String oidSym = ASN1.oid2Sym(runtime, getBCCertificateID().getHashAlgOID());
        RubyString digestName = RubyString.newString(runtime, oidSym);

        // For whatever reason, the MRI Ruby tests appear to suggest that they compute the hexdigest hash
        // of the issuer name over the original name instead of the hash computed in the created CertID.
        // I'm not sure how it's supposed to work with a passed in DER string since presumably the hash
        // is already computed and can't be reversed to get to the original name and thus we just compute
        // a hash of a hash if we don't have the original issuer around.
        if (originalIssuer == null) {
            try {
                return Digest.hexdigest(context, this, digestName,
                        RubyString.newString(runtime, bcCertId.getIssuerNameHash().getEncoded("DER")));
            }
            catch (IOException e) {
                throw newOCSPError(runtime, e);
            }
        }
        return Digest.hexdigest(context, this, digestName, originalIssuer.getSubject().to_der(context));
    }
    
    // For whatever reason, the MRI Ruby tests appear to suggest that they compute the hexdigest hash 
    // of the issuer key over the original key instead of the hash computed in the created CertID.
    // I'm not sure how it's supposed to work with a passed in DER string since presumably the hash
    // is already computed and can't be reversed to get to the original key, so we just compute 
    // a hash of a hash if we don't have the original issuer around.
    @JRubyMethod(name = "issuer_key_hash")
    public IRubyObject issuer_key_hash(ThreadContext context) {
        Ruby runtime = context.runtime;
        String oidSym = ASN1.oid2Sym(runtime, getBCCertificateID().getHashAlgOID());
        RubyString digestName = RubyString.newString(runtime, oidSym);

        try {
            if (originalIssuer == null) {
                return Digest.hexdigest(context, this, digestName,
                        RubyString.newString(runtime, bcCertId.getIssuerKeyHash().getEncoded("DER")));
            }
            PKey key = (PKey) originalIssuer.public_key(context);
            byte[] key_der = key.toASN1PublicInfo().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            return Digest.hexdigest(context, this, digestName, RubyString.newStringNoCopy(runtime, key_der));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    @JRubyMethod(name = "hash_algorithm")
    public IRubyObject hash_algorithm() {
        Ruby runtime = getRuntime();
        ASN1ObjectIdentifier oid = bcCertId.getHashAlgorithm().getAlgorithm();
        return RubyString.newString(runtime, ASN1.o2a(runtime, oid));
    }
    
    @JRubyMethod(name = "cmp")
    public IRubyObject cmp(IRubyObject other) {  
        Ruby runtime = getRuntime();
        RubyFixnum ret = (RubyFixnum) this.cmp_issuer(other);
        if (!ret.eql(RubyFixnum.zero(runtime))) return ret;
        OCSPCertificateId that = (OCSPCertificateId) other;
        return RubyFixnum.newFixnum(
                runtime, 
                this.getCertID().getSerialNumber().getValue().compareTo(
                        that.getCertID().getSerialNumber().getValue()
                        )
                );
    }
    
    @JRubyMethod(name = "cmp_issuer")
    public IRubyObject cmp_issuer(IRubyObject other) {
        Ruby runtime = getRuntime();
        if ( equals(other) ) {
            return RubyFixnum.zero(runtime);
        }
        if (other instanceof OCSPCertificateId) {
            OCSPCertificateId that = (OCSPCertificateId) other;
            CertID thisCert = this.getCertID();
            CertID thatCert = that.getCertID();
            int ret = thisCert.getHashAlgorithm().getAlgorithm().toString().compareTo(
                    thatCert.getHashAlgorithm().getAlgorithm().toString());
            if (ret != 0) return RubyFixnum.newFixnum(runtime, ret);
            ret = thisCert.getIssuerNameHash().toString().compareTo(
                    thatCert.getIssuerNameHash().toString());
            if (ret != 0) return RubyFixnum.newFixnum(runtime, ret);
            return RubyFixnum.newFixnum(runtime,
                    thisCert.getIssuerKeyHash().toString().compareTo(
                            thatCert.getIssuerKeyHash().toString()));
        }
        else {
            return runtime.getCurrentContext().nil;
        }
    }
    
    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        Ruby runtime = getRuntime();
        try {
            return StringHelper.newString(runtime, bcCertId.getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();
        this.bcCertId = ((OCSPCertificateId)obj).getCertID();
        return this;
    }
    
    @Override
    public boolean equals(Object other) {
        if ( this == other ) return true;
        if ( other instanceof OCSPCertificateId ) {
            OCSPCertificateId that = (OCSPCertificateId) other;
            return this.getCertID().equals(that.getCertID());
        }
        else {
            return false;
        }
    }
    
    public CertID getCertID() {
        return bcCertId;
    }
    
    public CertificateID getBCCertificateID() {
        if (bcCertId == null) return null;
        return new CertificateID(bcCertId);
    }

}
