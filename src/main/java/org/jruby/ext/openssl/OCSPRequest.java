package org.jruby.ext.openssl;

import static org.jruby.ext.openssl.OCSP._OCSP;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1TaggedObject;
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
    
    private org.bouncycastle.asn1.ocsp.OCSPRequest bcReq;
    private List<OCSPCertificateId> certificateIds;
    private byte[] nonce;
    private SecureRandom random = new SecureRandom();
    
    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;
        
        RubyString derString = (RubyString) args[0];
        try {
            bcReq = org.bouncycastle.asn1.ocsp.OCSPRequest.getInstance(ASN1TaggedObject.fromByteArray(derString.getBytes()));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    @JRubyMethod(name = "add_certid")
    public IRubyObject add_certid(IRubyObject certId) {
        OCSPCertificateId rubyCertId = (OCSPCertificateId) certId;
        certificateIds.add(rubyCertId);
        
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
        return RubyArray.newArray(getRuntime(), certificateIds);
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
        //TODO finish
        X509Cert rubyCert = (X509Cert) cert;
        
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

    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }

}
