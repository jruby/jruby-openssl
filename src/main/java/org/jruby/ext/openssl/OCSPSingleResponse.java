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
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
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
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.OCSP.*;

/*
 * An OpenSSL::OCSP::SingleResponse represents an OCSP SingleResponse structure, 
 * which contains the basic information of the status of the certificate.
 * 
 * @author lampad
 */
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
    public IRubyObject certid(ThreadContext context) {
        Ruby runtime = context.runtime;
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
        else if ( Arity.checkArgumentCount(runtime, args, 0, 2) == 1 ) {
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
            ASN1GeneralizedTime bcThisUpdate = bcSingleResponse.getThisUpdate();
            if (bcThisUpdate == null) {
                thisUpdate = null;
            }
            else {
                thisUpdate = bcThisUpdate.getDate();
            }
            ASN1GeneralizedTime bcNextUpdate = bcSingleResponse.getNextUpdate();
            if (bcNextUpdate == null) {
                nextUpdate = null;
            }
            else {
                nextUpdate = bcNextUpdate.getDate();
            }
        }
        catch (ParseException e) {
            throw newOCSPError(runtime, e);
        }
        
        return RubyBoolean.newBoolean(runtime, checkValidityImpl(thisUpdate, nextUpdate, nsec, maxsec));
    }
    
    @JRubyMethod(name = "extensions")
    public IRubyObject extensions() {
        Ruby runtime = getRuntime();
        Extensions exts = bcSingleResponse.getSingleExtensions();
        if (exts == null) return RubyArray.newEmptyArray(runtime);
        ASN1ObjectIdentifier[] extOIDs = exts.getExtensionOIDs();
        RubyArray retExts = runtime.newArray(extOIDs.length);
        for (ASN1ObjectIdentifier extOID : extOIDs) {
            Extension ext = exts.getExtension(extOID);
            ASN1Encodable extAsn1 = ext.getParsedValue();
            X509Extension retExt = X509Extension.newExtension(runtime, extOID, extAsn1, ext.isCritical());
            retExts.append(retExt);
        }
        return retExts;
    }
    
    @JRubyMethod(name = "next_update")
    public IRubyObject next_update() {
        Ruby runtime = getRuntime();
        if (bcSingleResponse.getNextUpdate() == null) return runtime.getNil();
        Date nextUpdate;
        try {
            nextUpdate = bcSingleResponse.getNextUpdate().getDate();
        }
        catch (ParseException e) {
            throw newOCSPError(runtime, e);
        }
        
        if (nextUpdate == null) {
            return runtime.getNil();
        }
        
        return RubyTime.newTime(runtime, nextUpdate.getTime());
    }
    
    @JRubyMethod(name = "this_update")
    public IRubyObject this_update() {
        Ruby runtime = getRuntime();
        if (bcSingleResponse.getThisUpdate() == null) return runtime.getNil();
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
        if (bcSingleResponse.getCertStatus().getTagNo() == (int) revoked.getLongValue()) {
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
        return runtime.getNil();
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
        return runtime.getNil();
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
    
    public SingleResponse getBCSingleResp() {
        return bcSingleResponse;
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

}
