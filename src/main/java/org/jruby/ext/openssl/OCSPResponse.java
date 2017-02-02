package org.jruby.ext.openssl;

import static org.jruby.ext.openssl.OCSP._OCSP;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.jruby.Ruby;
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

public class OCSPResponse extends RubyObject {
    private static final long serialVersionUID = 5763247988029815198L;
    private static final String BASIC_RESPONSE_OID = "1.3.6.1.5.5.7.48.1.1";

    private static ObjectAllocator RESPONSE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPResponse(runtime, klass);
        }
    };
    
    public OCSPResponse(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }
    
    public OCSPResponse(Ruby runtime) {
        this(runtime, (RubyClass) _OCSP(runtime).getConstantAt("Response"));
    }
    
    public static void createResponse(final Ruby runtime, final RubyModule _OCSP) {
        RubyClass _request = _OCSP.defineClassUnder("Response", runtime.getObject(), RESPONSE_ALLOCATOR);
        _request.defineAnnotatedMethods(OCSPResponse.class);
    }
    
    private org.bouncycastle.asn1.ocsp.OCSPResponse bcResp;
    private Integer status; //one of the OCSP Response Statuses
    private OCSPBasicResponse basicResponse;
    
    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject args[]) {
        Ruby runtime = context.getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;
        
        RubyString derString = (RubyString) args[0];
        try {
            bcResp = org.bouncycastle.asn1.ocsp.OCSPResponse.getInstance(ASN1TaggedObject.fromByteArray(derString.getBytes()));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    @JRubyMethod(name = "create", meta = true)
    public static IRubyObject create(final ThreadContext context, IRubyObject status) {
        Ruby runtime = context.getRuntime();
        OCSPResponse ret = new OCSPResponse(runtime);
        ret.initialize(context, new IRubyObject[] {});
        RubyFixnum rubyStatus = (RubyFixnum) status;
        ret.setStatus((int)rubyStatus.getLongValue());        
        
        return ret;
    }
    
    @JRubyMethod(name = "create", meta = true)
    public static IRubyObject create(final ThreadContext context, IRubyObject status, IRubyObject basicResponse) {
        if (basicResponse == null || basicResponse.isNil()) {
            return create(context, status);
        } 
        else {
            OCSPResponse ret = (OCSPResponse) create(context, status);
            OCSPBasicResponse rubyBasicResp = (OCSPBasicResponse) basicResponse;
            ret.setBasicResponse(rubyBasicResp);
            
            return ret;
        }
    }
    
    @JRubyMethod(name = "basic")
    public IRubyObject basic() {
        return getBasicResponse();
    }
    
    @JRubyMethod(name = "status")
    public IRubyObject status() {
        return RubyFixnum.newFixnum(getRuntime(), this.status);
    }
    
    @JRubyMethod(name = "status_string")
    public IRubyObject status_string() {
        String statusStr = OCSP.getResponseStringForValue(status());
        return RubyString.newString(getRuntime(), statusStr);
    }
    
    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        Ruby runtime = getRuntime();
        try {
            if (bcResp == null) {
                OCSPResponseStatus bcStatus = new OCSPResponseStatus(this.status);
                ASN1ObjectIdentifier basicRespOid = new ASN1ObjectIdentifier(BASIC_RESPONSE_OID);
                DEROctetString basicRespStr = new DEROctetString(basicResponse.getBCOCSPResp().getEncoded());
                ResponseBytes bcRespBytes = new ResponseBytes(basicRespOid, basicRespStr);
                bcResp = new org.bouncycastle.asn1.ocsp.OCSPResponse(bcStatus, bcRespBytes);
            }

            return RubyString.newString(runtime, bcResp.getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    public void setStatus(Integer status) {
        this.status = status;
    }
    
    public void setBasicResponse(IRubyObject basicResponse) {
        OCSPBasicResponse resp = (OCSPBasicResponse) basicResponse;
        this.basicResponse = resp;
    }
    
    public OCSPBasicResponse getBasicResponse() {
        return this.basicResponse;
    }
    
    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }

}
