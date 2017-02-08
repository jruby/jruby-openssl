package org.jruby.ext.openssl;

import static org.jruby.ext.openssl.OCSP._OCSP;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

public class OCSPSingleResponse extends RubyObject {
    private static final long serialVersionUID = 7947277768033100227L;

    private static ObjectAllocator SINGLERESPONSE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPSingleResponse(runtime, klass);
        }
    };
        
    public static void createSingleResponse(final Ruby runtime, final RubyModule _OCSP) {
        RubyClass _request = _OCSP.defineClassUnder("SingleResponse", runtime.getObject(), SINGLERESPONSE_ALLOCATOR);
        _request.defineAnnotatedMethods(OCSPSingleResponse.class);
    }

    public OCSPSingleResponse(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }
    
    public OCSPSingleResponse(Ruby runtime) {
        this(runtime, (RubyClass) _OCSP(runtime).getConstantAt("SingleResponse"));
    }
    
    private SingleResponse bcSingleResponse;
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject derStr) {
        Ruby runtime = context.getRuntime();
        RubyString rubyDerStr = (RubyString) derStr;
        try {
            bcSingleResponse = SingleResponse.getInstance(DERTaggedObject.fromByteArray(rubyDerStr.getBytes()));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    @JRubyMethod(name = "cert_status")
    public IRubyObject cert_status() {
        return RubyFixnum.newFixnum(getRuntime(), bcSingleResponse.getCertStatus().getTagNo());
    }
    
    @JRubyMethod(name = "certid")
    public IRubyObject certid() {
        Ruby runtime = getRuntime();
        ThreadContext context = runtime.getCurrentContext();
        CertID bcCertId = bcSingleResponse.getCertID();
        OCSPCertificateId rubyCertId = new OCSPCertificateId(runtime); 
        try {
            rubyCertId.initialize(context, RubyString.newString(runtime, bcCertId.getEncoded()));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return rubyCertId;
    }
    
    @JRubyMethod(name = "check_validity", rest = true)
    public IRubyObject check_validity(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        int nsec, maxsec;
        Date thisUpdate, nextUpdate;
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 2) == 0 ) {
            nsec = 0;
            maxsec = -1;
        }
        else if ( Arity.checkArgumentCount(runtime, args, 0, 2) == 0 ) {
            RubyFixnum rNsec = (RubyFixnum) args[0];
            nsec = (int)rNsec.getLongValue();
            maxsec = -1;
        }
        else {
            RubyFixnum rNsec = (RubyFixnum) args[0];
            RubyFixnum rMaxsec = (RubyFixnum) args[1];
            nsec = (int)rNsec.getLongValue();
            maxsec = (int)rMaxsec.getLongValue();
        }

        try {
            thisUpdate = bcSingleResponse.getThisUpdate().getDate();
            nextUpdate = bcSingleResponse.getNextUpdate().getDate();
        }
        catch (ParseException e) {
            throw newOCSPError(runtime, e);
        }
        
        return RubyBoolean.newBoolean(runtime, checkValidityImpl(thisUpdate, nextUpdate, nsec, maxsec));
    }
    
    @JRubyMethod(name = "extensions")
    public IRubyObject extensions() {
        Ruby runtime = getRuntime();
        List<X509Extension> retExts = new ArrayList<X509Extension>();
        Extensions exts = bcSingleResponse.getSingleExtensions();
        List<ASN1ObjectIdentifier> extOids = Arrays.asList(exts.getExtensionOIDs());
        for (ASN1ObjectIdentifier extOid : extOids) {
            Extension ext = exts.getExtension(extOid);
            ASN1Encodable extAsn1 = ext.getParsedValue();
            X509Extension retExt = X509Extension.newExtension(runtime, extOid, extAsn1, ext.isCritical());
            retExts.add(retExt);
        }
        
        return RubyArray.newArray(runtime, retExts);
    }
    
    @JRubyMethod(name = "next_update")
    public IRubyObject next_update() {
        Ruby runtime = getRuntime();
        Date nextUpdate;
        try {
            nextUpdate = bcSingleResponse.getNextUpdate().getDate();
        }
        catch (ParseException e) {
            throw newOCSPError(runtime, e);
        }
        
        if (nextUpdate == null) {
            return runtime.getCurrentContext().nil;
        }
        
        return RubyTime.newTime(runtime, nextUpdate.getTime());
    }
    
    @JRubyMethod(name = "this_update")
    public IRubyObject this_update() {
        Ruby runtime = getRuntime();
        Date thisUpdate;
        try {
            thisUpdate = bcSingleResponse.getThisUpdate().getDate();
        }
        catch (ParseException e) {
            throw newOCSPError(runtime, e);
        }
        
        return RubyTime.newTime(runtime, thisUpdate.getTime());
    }
    
    @JRubyMethod(name = "revocation_reason")
    public IRubyObject revocation_reason() {
        Ruby runtime = getRuntime();
        RubyFixnum revoked = (RubyFixnum) _OCSP(runtime).getConstant("V_CERTSTATUS_REVOKED");
        if (bcSingleResponse.getCertStatus().getTagNo() == (int)revoked.getLongValue()) {
            try {
                RevokedInfo revokedInfo = RevokedInfo.getInstance(
                        DERTaggedObject.fromByteArray(bcSingleResponse.getCertStatus().getStatus().toASN1Primitive().getEncoded())
                        );
                return RubyFixnum.newFixnum(runtime, revokedInfo.getRevocationReason().getValue().intValue());
            }
            catch (IOException e) {
                throw newOCSPError(runtime, e);
            }
        }
        return runtime.getCurrentContext().nil;
    }
    
    @JRubyMethod(name = "revocation_time")
    public IRubyObject revocation_time() {
        Ruby runtime = getRuntime();
        RubyFixnum revoked = (RubyFixnum) _OCSP(runtime).getConstant("V_CERTSTATUS_REVOKED");
        if (bcSingleResponse.getCertStatus().getTagNo() == (int)revoked.getLongValue()) {
            try {
                RevokedInfo revokedInfo = RevokedInfo.getInstance(
                        DERTaggedObject.fromByteArray(bcSingleResponse.getCertStatus().getStatus().toASN1Primitive().getEncoded())
                        );
                return RubyTime.newTime(runtime, revokedInfo.getRevocationTime().getDate().getTime());
            }
            catch (Exception e) {
                throw newOCSPError(runtime, e);
            }
        }
        return runtime.getCurrentContext().nil;
    }
    
    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        Ruby runtime = getRuntime();
        try {
            return RubyString.newString(runtime, bcSingleResponse.getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    // see OCSP_check_validity in ocsp_cl.c
    private boolean checkValidityImpl(Date thisUpdate, Date nextUpdate, int nsec, int maxsec) {
        boolean ret = true;
        Date currentTime = new Date();
        Date tempTime = new Date();
        
        tempTime.setTime(currentTime.getTime() + (nsec*1000));
        if (thisUpdate.compareTo(tempTime) > 0) {
            ret = false;
        }
        
        if (maxsec >= 0) {
            tempTime.setTime(currentTime.getTime() - (maxsec*1000));
            if (thisUpdate.compareTo(tempTime) < 0) {
                ret = false;
            }
        }
        
        if (nextUpdate == null) {
            return ret;
        }
        
        tempTime.setTime(currentTime.getTime() - (nsec*1000));
        if (nextUpdate.compareTo(tempTime) < 0) {
            ret = false;
        }
        
        if (nextUpdate.compareTo(thisUpdate) < 0) {
            ret = false;
        }
        
        return ret;
    }
    
    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }
}
