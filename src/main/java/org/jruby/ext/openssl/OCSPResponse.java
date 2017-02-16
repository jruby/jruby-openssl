package org.jruby.ext.openssl;

import static org.jruby.ext.openssl.OCSP._OCSP;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
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
    public static IRubyObject create(final ThreadContext context, final IRubyObject self, IRubyObject status) {
        Ruby runtime = context.runtime;
        OCSPRespBuilder builder = new OCSPRespBuilder();
        OCSPResp tmpResp;
        OCSPResponse ret = new OCSPResponse(runtime);
        try {
            tmpResp = builder.build(RubyFixnum.fix2int((RubyFixnum)status), null);
            ret.initialize(context, new IRubyObject[] { RubyString.newString(runtime, tmpResp.getEncoded())});
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        return ret;
    }
    
    @JRubyMethod(name = "create", meta = true)
    public static IRubyObject create(final ThreadContext context, final IRubyObject self, IRubyObject status, IRubyObject basicResponse) {
        Ruby runtime = context.runtime;
        if (basicResponse == null || basicResponse.isNil()) {
            return create(context, self, status);
        } 
        else {
            OCSPResponse ret = new OCSPResponse(runtime);
            OCSPBasicResponse rubyBasicResp = (OCSPBasicResponse) basicResponse;
            OCSPRespBuilder builder = new OCSPRespBuilder();
            try {
                OCSPResp tmpResp = builder.build(RubyFixnum.fix2int((RubyFixnum)status), new BasicOCSPResp(rubyBasicResp.getASN1BCOCSPResp()));
                ret.initialize(context, new IRubyObject[] { RubyString.newString(runtime, tmpResp.getEncoded())});
            }
            catch (Exception e) {
                throw newOCSPError(runtime, e);
            }
            
            return ret;
        }
    }
    
    @Override
    @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();
        this.bcResp = ((OCSPResponse)obj).getBCResp();
        return this;
    }
    
    @JRubyMethod(name = "basic")
    public IRubyObject basic() {
        Ruby runtime = getRuntime();
        ThreadContext context = runtime.getCurrentContext();
        if (bcResp == null || bcResp.getResponseBytes() == null || bcResp.getResponseBytes().getResponse() == null) {
            return getRuntime().getCurrentContext().nil;
        }
        else {
            OCSPBasicResponse ret = new OCSPBasicResponse(runtime);
            return ret.initialize(context, RubyString.newString(runtime, bcResp.getResponseBytes().getResponse().getOctets()));
        }
    }
    
    @JRubyMethod(name = "status")
    public IRubyObject status() {
        return RubyFixnum.newFixnum(getRuntime(), bcResp.getResponseStatus().getValue().longValue());
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
            return RubyString.newString(runtime, bcResp.getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    public org.bouncycastle.asn1.ocsp.OCSPResponse getBCResp() {
        return bcResp;
    }
            
    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }

}
