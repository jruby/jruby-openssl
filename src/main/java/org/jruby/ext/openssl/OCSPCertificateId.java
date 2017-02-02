package org.jruby.ext.openssl;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
        X509Cert issuerCert = (X509Cert) issuer;
        BigInteger serial = subjectCert.getSerial();        
        
        return initializeImpl(context, serial, issuerCert.getSubject(), issuerCert.public_key(context), digest);
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject subject, IRubyObject issuer) {
        Ruby runtime = context.getRuntime();
        
        X509Cert subjectCert = (X509Cert) subject;
        X509Cert issuerCert = (X509Cert) issuer;
        BigInteger serial = subjectCert.getSerial();

        Digest digestInstance = new Digest(runtime, _Digest(runtime));
        IRubyObject digest = digestInstance.initialize(context, new IRubyObject[] { RubyString.newString(runtime, "SHA1") });
        
        return initializeImpl(context, serial, issuerCert.getSubject(), issuerCert.public_key(context), digest);
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
            IRubyObject issuerName, IRubyObject issuerKey, IRubyObject digest) {
        Ruby runtime = context.getRuntime();
        
        ASN1Integer bcSerial = new ASN1Integer(serial);
        
        Digest rubyDigest = (Digest) digest;
        ASN1ObjectIdentifier oid = ASN1.sym2Oid(runtime, rubyDigest.getName().toLowerCase());
        AlgorithmIdentifier bcAlgId = new AlgorithmIdentifier(oid);

        X509Name rubyIName = (X509Name) issuerName;
        RubyString iNameHash = Digest.hexdigest(context, this, rubyDigest.name(), rubyIName.to_der(context));
        DEROctetString bcINameHash = new DEROctetString(iNameHash.decodeString().getBytes());
        
        PKey iKey = (PKey) issuerKey;
        RubyString iKeyHash = Digest.hexdigest(context, this, rubyDigest.name(), iKey.to_der());
        DEROctetString bcIKeyHash = new DEROctetString(iKeyHash.decodeString().getBytes());
        
        bcCertId = new CertID(bcAlgId, bcINameHash, bcIKeyHash, bcSerial);
        
        return this;
    }
    
    private IRubyObject initializeImpl(byte[] derByteStream) throws IOException {
        bcCertId = CertID.getInstance(DERTaggedObject.fromByteArray(derByteStream));
        
        return this;
    }
    
    @JRubyMethod(name = "serial")
    public IRubyObject serial() {
        return RubyBignum.newBignum(getRuntime(), bcCertId.getSerialNumber().getValue());
    }
    
    @JRubyMethod(name = "issuer_name_hash")
    public IRubyObject issuer_name_hash() {
        Ruby runtime = getRuntime();
        ASN1OctetString iNameHash = bcCertId.getIssuerNameHash();
        
        try {
            return RubyString.newString(runtime, iNameHash.getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    @JRubyMethod(name = "issuer_key_hash")
    public IRubyObject issuer_key_hash() {
        Ruby runtime = getRuntime();
        ASN1OctetString iKeyHash = bcCertId.getIssuerKeyHash();

        try {
            return RubyString.newString(runtime, iKeyHash.getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
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
            return RubyString.newString(runtime, getCertID().getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
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

    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }

}
