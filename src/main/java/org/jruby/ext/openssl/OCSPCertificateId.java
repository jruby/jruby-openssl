package org.jruby.ext.openssl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
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
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.OCSP._OCSP;
import static org.jruby.ext.openssl.Digest._Digest;

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
        
        return initializeImpl(context, serial, originalIssuer, digest);
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject subject, IRubyObject issuer) {
        Ruby runtime = context.getRuntime();
        
        X509Cert subjectCert = (X509Cert) subject;
        originalIssuer = (X509Cert) issuer;
        BigInteger serial = subjectCert.getSerial();

        Digest digestInstance = new Digest(runtime, _Digest(runtime));
        IRubyObject digest = digestInstance.initialize(context, new IRubyObject[] { RubyString.newString(runtime, "SHA1") });
        
        return initializeImpl(context, serial, originalIssuer, digest);
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject der) {
        Ruby runtime = context.getRuntime();
        
        RubyString derStr = StringHelper.readPossibleDERInput(context, der);
        try {            
            return initializeImpl(derStr.getBytes());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    private IRubyObject initializeImpl(final ThreadContext context, BigInteger serial,
            IRubyObject issuerCert, IRubyObject digest) {
        Ruby runtime = context.getRuntime();
        
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

        X509Cert rubyCert = (X509Cert) issuerCert;
        
        try {
            this.bcCertId = new CertificateID(calc, new X509CertificateHolder(rubyCert.getAuxCert().getEncoded()), serial).toASN1Primitive();
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    private IRubyObject initializeImpl(byte[] derByteStream) throws IOException {
        this.bcCertId = CertID.getInstance(derByteStream);
        
        return this;
    }
    
    @JRubyMethod(name = "serial")
    public IRubyObject serial() {
        return RubyBignum.newBignum(getRuntime(), bcCertId.getSerialNumber().getValue());
    }
    
    @JRubyMethod(name = "issuer_name_hash")
    public IRubyObject issuer_name_hash() {
        Ruby runtime = getRuntime();
        String oidSym = ASN1.oid2Sym(runtime, getBCCertificateID().getHashAlgOID());
        RubyString digestName = RubyString.newString(runtime, oidSym);

        // For whatever reason, the MRI Ruby tests appear to suggest that they compute the hexdigest hash
        // of the issuer name over the original name instead of the hash computed in the created CertID.
        // I'm not sure how it's supposed to work with a passed in DER string since presumably the hash
        // is already computed and can't be reversed to get to the original name and thus we just compute
        // a hash of a hash if we don't have the original issuer around.
        if (originalIssuer == null) {
            try {
                return Digest.hexdigest(runtime.getCurrentContext(), this, digestName,
                        RubyString.newString(runtime, bcCertId.getIssuerNameHash().getEncoded("DER")));
            }
            catch (IOException e) {
                throw newOCSPError(runtime, e);
            }
        }
        else {
            return Digest.hexdigest(runtime.getCurrentContext(), this, digestName,
                    originalIssuer.getSubject().to_der(runtime.getCurrentContext()));
        }
    }
    
    // For whatever reason, the MRI Ruby tests appear to suggest that they compute the hexdigest hash 
    // of the issuer key over the original key instead of the hash computed in the created CertID.
    // I'm not sure how it's supposed to work with a passed in DER string since presumably the hash
    // is already computed and can't be reversed to get to the original key, so we just compute 
    // a hash of a hash if we don't have the original issuer around.
    @JRubyMethod(name = "issuer_key_hash")
    public IRubyObject issuer_key_hash() {
        Ruby runtime = getRuntime();
        String oidSym = ASN1.oid2Sym(runtime, getBCCertificateID().getHashAlgOID());
        RubyString digestName = RubyString.newString(runtime, oidSym);

        if (originalIssuer == null) {
            try {
                return Digest.hexdigest(runtime.getCurrentContext(), this, RubyString.newString(runtime, oidSym),
                        RubyString.newString(runtime, bcCertId.getIssuerKeyHash().getEncoded("DER")));
            }
            catch (IOException e) {
                throw newOCSPError(runtime, e);
            }
        }
        else {
            PKey key = (PKey)originalIssuer.public_key(runtime.getCurrentContext());
            return Digest.hexdigest(runtime.getCurrentContext(), this, digestName, key.to_der()); 
        }
    }
    
    @JRubyMethod(name = "hash_algorithm")
    public IRubyObject hash_algorithm() {
        Ruby runtime = getRuntime();
        ASN1ObjectIdentifier oid = bcCertId.getHashAlgorithm().getAlgorithm();
        Integer nid = ASN1.oid2nid(runtime, oid);
        String ln = ASN1.nid2ln(runtime, nid);
        
        return RubyString.newString(runtime, ln);
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

    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }

}
