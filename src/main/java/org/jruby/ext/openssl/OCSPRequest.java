package org.jruby.ext.openssl;

import static org.jruby.ext.openssl.Digest._Digest;
import static org.jruby.ext.openssl.OCSP._OCSP;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.OCSPReq;
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
    
    private final static String OP_NOCERTS = "NOCERTS"; 
    private org.bouncycastle.asn1.ocsp.OCSPRequest asn1bcReq = null;
    private byte[] nonce = null;
    private SecureRandom random = new SecureRandom();
    
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

    @JRubyMethod(name = "add_nonce")
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
    public IRubyObject sign(IRubyObject cert, IRubyObject key, IRubyObject[] args) {
        Ruby runtime = getRuntime();
        ThreadContext context = runtime.getCurrentContext();
        
        int flag = 0;
        IRubyObject additionalCerts = context.nil;
        IRubyObject flags = context.nil;
        IRubyObject digest = context.nil;
        Digest digestInstance = new Digest(runtime, _Digest(runtime));
        IRubyObject nocerts = (RubyFixnum)_OCSP(runtime).getConstant(OP_NOCERTS);
        
        switch (Arity.checkArgumentCount(runtime, args, 0, 3)) {
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
                
        X509Cert signer = (X509Cert) cert;
        PKey signerKey = (PKey) key;
        
        try {
            sig = java.security.Signature.getInstance(((Digest)digest).getRealName());
            sig.initSign(signerKey.getPrivateKey());
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        //TODO implement
        return RubyString.newEmptyString(getRuntime());
    }
    
    @JRubyMethod(name = "verify")
    public IRubyObject verify(IRubyObject certificates, IRubyObject store, IRubyObject flags) {
        //TODO implement
        
        return RubyBoolean.newBoolean(getRuntime(), true);
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
        random.nextBytes(bytes);
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
