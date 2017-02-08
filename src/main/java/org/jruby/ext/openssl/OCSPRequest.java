package org.jruby.ext.openssl;

import static org.jruby.ext.openssl.Digest._Digest;
import static org.jruby.ext.openssl.OCSP._OCSP;
import static org.jruby.ext.openssl.X509._X509;


import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

public class OCSPRequest extends RubyObject {
    private static final long serialVersionUID = -4020616730425816999L;

    private static ObjectAllocator REQUEST_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPRequest(runtime, klass);
        }
    };
    
    public OCSPRequest(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }
    
    public static void createRequest(final Ruby runtime, final RubyModule _OCSP) {
        RubyClass _request = _OCSP.defineClassUnder("Request", runtime.getObject(), REQUEST_ALLOCATOR);
        _request.defineAnnotatedMethods(OCSPRequest.class);
    }
    
    private final static String OCSP_NOCERTS = "NOCERTS";
    private final static String OCSP_NOSIGS = "NOSIGS";
    private final static String OCSP_NOINTERN = "NOINTERN";
    private final static String OCSP_NOVERIFY = "NOVERIFY";
    private final static String OCSP_TRUSTOTHER = "TRUSTOTHER";
    private final static String OCSP_NOCHAIN = "NOCHAIN";
    private org.bouncycastle.asn1.ocsp.OCSPRequest asn1bcReq = null;
    private byte[] nonce;
    
    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;
        
        RubyString derString = StringHelper.readPossibleDERInput(context, args[0]);
        try {
            asn1bcReq = org.bouncycastle.asn1.ocsp.OCSPRequest.getInstance(DERTaggedObject.fromByteArray(derString.getBytes()));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    @JRubyMethod(name = "add_certid")
    public IRubyObject add_certid(IRubyObject certId) {
        OCSPCertificateId rubyCertId = (OCSPCertificateId) certId;
        List<org.bouncycastle.asn1.ocsp.Request> currentRequestList = new ArrayList<org.bouncycastle.asn1.ocsp.Request>();
        Signature currentSig = null;
        TBSRequest tbsReq = null;
        GeneralName currentName = new GeneralName(4, "Placeholder");
        Extensions currentExtensions = new Extensions(new Extension[] {});
        
        if (asn1bcReq != null && asn1bcReq.getTbsRequest() != null) {
            currentSig = asn1bcReq.getOptionalSignature();
            tbsReq = asn1bcReq.getTbsRequest();
            currentRequestList = asn1ToRequestList(tbsReq.getRequestList());
            currentName = tbsReq.getRequestorName();
            currentExtensions = tbsReq.getRequestExtensions();
        }
        
        CertID bcCertId = rubyCertId.getCertID();
        org.bouncycastle.asn1.ocsp.Request bcReq = new org.bouncycastle.asn1.ocsp.Request(bcCertId, new Extensions(new Extension[] {}));
        currentRequestList.add(bcReq);
        
        ASN1Sequence newReqSeq = listToAsn1(currentRequestList);
        tbsReq = new TBSRequest(currentName, newReqSeq, currentExtensions);
        asn1bcReq = new org.bouncycastle.asn1.ocsp.OCSPRequest(tbsReq, currentSig);
        
        return this;
    }

    @JRubyMethod(name = "add_nonce", rest = true)
    public IRubyObject add_nonce(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) {
            nonce = generateNonce();
        }
        else {
            RubyString input = (RubyString)args[0];
            nonce = generateNonce(input.getBytes());
        }
        return this;
    }
    
    @JRubyMethod(name = "certid")
    public IRubyObject certid() {
        Ruby runtime = getRuntime();
        ThreadContext context = runtime.getCurrentContext();
        
        if (asn1bcReq == null) {
            return RubyArray.newEmptyArray(runtime);
        }
        
        ASN1Sequence requests = asn1bcReq.getTbsRequest().getRequestList();
        List<Request> javaReqs = asn1ToRequestList(requests);
        RubyArray ret = RubyArray.newEmptyArray(runtime);
        
        try {
            for (Request req : javaReqs) {
                OCSPCertificateId certId = new OCSPCertificateId(runtime);
                RubyString der = RubyString.newString(runtime, req.getReqCert().getEncoded(ASN1Encoding.DER));
                certId.initialize(context, der);
                ret.add(certId);
            }
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return ret;
    }
    
    @JRubyMethod(name = "check_nonce")
    public IRubyObject check_nonce(IRubyObject response) {
        Ruby runtime = getRuntime();
        if (response instanceof OCSPBasicResponse) {
            OCSPBasicResponse rubyBasicRes = (OCSPBasicResponse) response;
            return checkNonceImpl(runtime, this.nonce, rubyBasicRes.getNonce());
        }
        else if (response instanceof OCSPResponse) {
            OCSPResponse rubyResp = (OCSPResponse) response;
            return checkNonceImpl(runtime, this.nonce, rubyResp.getBasicResponse().getNonce());
        }
        else {
            return checkNonceImpl(runtime, this.nonce, null);
        }
    }
    
    @JRubyMethod(name = "sign", rest = true)
    public IRubyObject sign(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        ThreadContext context = runtime.getCurrentContext();
        
        if (asn1bcReq == null || asn1bcReq.getTbsRequest() == null) {
            throw newOCSPError(runtime, new NullPointerException("Need at least one certid."));
        }
        
        int flag = 0;
        IRubyObject additionalCerts = context.nil;
        IRubyObject flags = context.nil;
        IRubyObject digest = context.nil;
        Digest digestInstance = new Digest(runtime, _Digest(runtime));
        IRubyObject nocerts = (RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCERTS);
        
        switch (Arity.checkArgumentCount(runtime, args, 2, 5)) {
            case 1 :
                additionalCerts = args[0];
            case 2 :
                additionalCerts = args[0];
                flags = args[1];
            default:
                additionalCerts = args[0];
                flags = args[1];
                digest = args[2];
        }
        
        java.security.Signature sig = null;
        
        if (digest.isNil()) digest = digestInstance.initialize(context, new IRubyObject[] { RubyString.newString(runtime, "SHA1") });
        if (additionalCerts.isNil()) flag |= RubyFixnum.fix2int(nocerts);
        if (!flags.isNil()) flag = RubyFixnum.fix2int(flags);
                
        X509Cert signer = (X509Cert) args[0];
        PKey signerKey = (PKey) args[1];
        TBSRequest tbsReq = asn1bcReq.getTbsRequest();
        TBSRequest newTbsReq = new TBSRequest(new GeneralName(signer.getSubject().getX500Name()), tbsReq.getRequestList(), tbsReq.getRequestExtensions());
        DERBitString sigBytes = null;
        try {
            sig = java.security.Signature.getInstance(((Digest)digest).getRealName());
            sig.initSign(signerKey.getPrivateKey());
            sig.update(newTbsReq.getEncoded(ASN1Encoding.DER));
            sigBytes = new DERBitString(sig.sign());
            
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        ASN1Sequence sigCerts = null;
        ASN1EncodableVector vector = new ASN1EncodableVector();
        
        if (!(flag == RubyFixnum.fix2int(nocerts))) {
            try {
                vector.add(ASN1Primitive.fromByteArray(((RubyString)signer.to_der()).getBytes()));
            
                if (!additionalCerts.isNil()) {
                    @SuppressWarnings("unchecked")
                    Iterator<X509Cert> it = ((RubyArray) additionalCerts).iterator();
                    while (it.hasNext()) {
                        X509Cert addlCert = it.next();
                        vector.add(ASN1Primitive.fromByteArray(((RubyString)addlCert.to_der()).getBytes()));
                    }
                }
            }
            catch (IOException e) {
                throw newOCSPError(runtime, e);
            }
            sigCerts = new DERSequence(vector);
        }
        
        Signature asn1Sig = null;
        if (sigCerts == null) {
            asn1Sig = new Signature(new AlgorithmIdentifier(ASN1.sym2Oid(runtime, ((Digest)digest).getName())), sigBytes);
        }
        else {
            asn1Sig = new Signature(new AlgorithmIdentifier(ASN1.sym2Oid(runtime, ((Digest)digest).getName())), sigBytes, sigCerts);
        }
        
        asn1bcReq = new org.bouncycastle.asn1.ocsp.OCSPRequest(tbsReq, asn1Sig);
                
        return this;
    }
    
    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        Ruby runtime = getRuntime();
        try {
            return RubyString.newString(runtime, asn1bcReq.getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    @JRubyMethod(name = "verify")
    public IRubyObject verify(IRubyObject certificates, IRubyObject store, IRubyObject flags) {
        Ruby runtime = getRuntime();
        ThreadContext context = runtime.getCurrentContext();
        
        if (asn1bcReq == null) {
            throw newOCSPError(runtime, new NullPointerException("No certificate IDs added"));
        }
        
        if (asn1bcReq.getOptionalSignature() == null) {
            throw newOCSPError(runtime, Utils.newRuntimeError(runtime, "Request not signed"));
        }
        
        if (flags == null || flags.isNil()) {
            flags = RubyFixnum.zero(runtime);
        }
      
        GeneralName genName = asn1bcReq.getTbsRequest().getRequestorName();
        if (genName.getTagNo() != 4) {
            throw newOCSPError(runtime, Utils.newRuntimeError(runtime, "Unsupported Requestor Name Type"));
        }
        
        X500Name genX500Name = X500Name.getInstance(genName.getName());
        X509Cert signer = null;
        X509StoreContext storeContext = null;
        
        try {
           Map.Entry<Integer, IRubyObject> resAndCert = findCertByName(genX500Name, certificates, flags).entrySet().iterator().next();
           
           if (resAndCert.getKey() == 0) throw newOCSPError(runtime, Utils.newRuntimeError(runtime, "Signer certificate not found."));
           signer = (X509Cert)resAndCert.getValue();
           if (resAndCert.getKey() == 2 && ((RubyFixnum.fix2int(flags) & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_TRUSTOTHER))) == 1))
               flags = RubyFixnum.newFixnum(runtime, (RubyFixnum.fix2int(flags) | RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOVERIFY))));
           if ((RubyFixnum.fix2int(flags) & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOSIGS))) == 0) {
               PKey signerPubKey = (PKey)signer.public_key(context);
               boolean verified = verifyImpl(runtime, asn1bcReq, signerPubKey);
               if (!verified) {
                   return (RubyBoolean.newBoolean(runtime, false));
               }
           }
           if ((RubyFixnum.fix2int(flags) & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOVERIFY))) == 0) {
               if ((RubyFixnum.fix2int(flags) & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOCHAIN))) == 1) {
                   storeContext = X509StoreContext.newStoreContext(context, (X509Store)store, signer, context.nil); 
               }
               else {
                   Iterator<ASN1Encodable> it = asn1bcReq.getOptionalSignature().getCerts().iterator();
                   RubyArray certs = RubyArray.newEmptyArray(runtime);
                   while (it.hasNext()) {
                       Certificate cert = Certificate.getInstance(it.next());
                       certs.add(X509Cert.wrap(runtime, new X509AuxCertificate(cert)));
                   }

                   storeContext = X509StoreContext.newStoreContext(context, (X509Store)store, signer, certs); 
               }
               
               storeContext.set_purpose(context, _X509(runtime).getConstant("PURPOSE_OCSP_HELPER"));
               storeContext.set_trust(context, _X509(runtime).getConstant("TRUST_OCSP_REQUEST"));
               RubyBoolean verified = (RubyBoolean)storeContext.verify(context);
               if (verified.isFalse()) return RubyBoolean.newBoolean(runtime, false);
           }
        }
        catch ( Exception e ) {
            throw newOCSPError(runtime, e);
        }
        
        return RubyBoolean.newBoolean(getRuntime(), true);
    }
    
    private boolean verifyImpl(Ruby runtime, org.bouncycastle.asn1.ocsp.OCSPRequest req, PKey signerPubKey) throws 
    NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Signature bcSig = req.getOptionalSignature();
        java.security.Signature sig = java.security.Signature.getInstance(ASN1.oid2Sym(runtime, bcSig.getSignatureAlgorithm().getAlgorithm()));
        sig.initVerify(signerPubKey.getPublicKey());
        sig.update(req.getTbsRequest().getEncoded(ASN1Encoding.DER));
        
        return sig.verify(bcSig.getSignature().getEncoded(ASN1Encoding.DER));
    }

    private Map<Integer, IRubyObject> findCertByName(ASN1Encodable genX500Name, IRubyObject certificates, IRubyObject flags) throws CertificateException, IOException {
        Ruby runtime = getRuntime();
        Map<Integer, IRubyObject> ret = new HashMap<Integer, IRubyObject>();
        ThreadContext context = runtime.getCurrentContext();
        if ((RubyFixnum.fix2int(flags) & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOINTERN))) != 1) {
            Iterator<ASN1Encodable> it = asn1bcReq.getOptionalSignature().getCerts().iterator();
            while (it.hasNext()) {
                Certificate cert = Certificate.getInstance(it.next());
                if (genX500Name.equals(cert.getSubject())) {
                    ret.put(1, X509Cert.wrap(context, new X509AuxCertificate(cert)));
                    return ret;
                }
            }
        }
        
        @SuppressWarnings("unchecked")
        Iterator<X509Cert> it = ((RubyArray) certificates).iterator();
        while (it.hasNext()) {
            X509Cert cert = it.next();
            if (genX500Name.equals(cert.getSubject().getX500Name())) {
                ret.put(2, cert);
                return ret;
            }
        }
        
        ret.put(0, null);
        return ret;
    }

    public byte[] getNonce() {
        return this.nonce;
    }
    
    private IRubyObject checkNonceImpl(Ruby runtime, byte[] reqNonce, byte[] respNonce) {
        if (reqNonce != null && respNonce != null) {
            if (Arrays.equals(reqNonce, respNonce)) {
                return RubyFixnum.one(runtime);
            }
            else {
                return RubyFixnum.zero(runtime);
            }
        }
        else if (reqNonce == null && respNonce == null) {
            return RubyFixnum.two(runtime);
        }
        else if (reqNonce != null && respNonce == null) {
            return RubyFixnum.newFixnum(runtime, -1);
        }
        else {
            return RubyFixnum.three(runtime);
        }
    }

    private byte[] generateNonce() {
        // OSSL currently generates 16 byte nonce by default
        return generateNonce(new byte[16]);
    }
    
    private byte[] generateNonce(byte[] bytes) {
        OpenSSL.getSecureRandom(getRuntime()).nextBytes(bytes);
        return bytes;
    }
    
    private List<Request> asn1ToRequestList(ASN1Sequence requestList) {
        List<Request> ret = new ArrayList<Request>();
        Iterator<ASN1Encodable> it = requestList.iterator();
        
        while (it.hasNext()) {
            ASN1Encodable req = it.next();
            ret.add(Request.getInstance(req));
        }
        
        return ret;
    }
    
    private ASN1Sequence listToAsn1(List<Request> currentRequestList) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for(Request req : currentRequestList) {
            vector.add(req);
        }
        
        return DERSequence.getInstance(vector);
    }


    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }

}
