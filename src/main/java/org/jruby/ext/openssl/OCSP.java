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

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * OCSP
 *
 * @author lampad
 */
public class OCSP {
    
    //Response has valid confirmations
    private static final String _RESPONSE_STATUS_SUCCESSFUL_STR = "RESPONSE_STATUS_SUCCESSFUL";
    private static final int _RESPONSE_STATUS_SUCCESSFUL = 0;
    //Illegal confirmation request
    private static final String _RESPONSE_STATUS_MALFORMEDREQUEST_STR = "RESPONSE_STATUS_MALFORMEDREQUEST";
    private static final int _RESPONSE_STATUS_MALFORMEDREQUEST = 1;
    //Internal error in issuer
    private static final String _RESPONSE_STATUS_INTERNALERROR_STR = "RESPONSE_STATUS_INTERNALERROR";
    private static final int _RESPONSE_STATUS_INTERNALERROR = 2;
    //Try again later
    private static final String _RESPONSE_STATUS_TRYLATER_STR = "RESPONSE_STATUS_TRYLATER";
    private static final int _RESPONSE_STATUS_TRYLATER = 3;
    //You must sign the request and resubmit
    private static final String _RESPONSE_STATUS_SIGREQUIRED_STR = "RESPONSE_STATUS_SIGREQUIRED";
    private static final int _RESPONSE_STATUS_SIGREQUIRED = 5;
    //Your request is unauthorized.
    private static final String _RESPONSE_STATUS_UNAUTHORIZED_STR = "RESPONSE_STATUS_UNAUTHORIZED";
    private static final int _RESPONSE_STATUS_UNAUTHORIZED = 6;
    
    private static final Map<Integer, String> responseMap;
    
    //The certificate was revoked for an unknown reason
    private static final int _REVOKED_STATUS_NOSTATUS = -1;
    //The certificate was revoked for an unspecified reason
    private static final int _REVOKED_STATUS_UNSPECIFIED = 0;
    //The certificate was revoked due to a key compromise
    private static final int _REVOKED_STATUS_KEYCOMPROMISE = 1;
    //This CA certificate was revoked due to a key compromise
    private static final int _REVOKED_STATUS_CACOMPROMISE = 2;
    //The certificate subject's name or other information changed
    private static final int _REVOKED_STATUS_AFFILIATIONCHANGED = 3;
    //The certificate was superseded by a new certificate
    private static final int _REVOKED_STATUS_SUPERSEDED = 4;
    //The certificate is no longer needed
    private static final int _REVOKED_STATUS_CESSATIONOFOPERATION = 5;
    //The certificate is on hold
    private static final int _REVOKED_STATUS_CERTIFICATEHOLD = 6;
    //The certificate was previously on hold and should now be removed from the CRL
    private static final int _REVOKED_STATUS_REMOVEFROMCRL = 8;
    
    //Do not include certificates in the response 
    private static final int _NOCERTS = 0x1;
    //Do not search certificates contained in the response for a signer 
    private static final int _NOINTERN = 0x2;
    //Do not check the signature on the response 
    private static final int _NOSIGS = 0x4;
    //Do not verify the certificate chain on the response
    private static final int _NOCHAIN = 0x8;
    //Do not verify the response at all
    private static final int _NOVERIFY = 0x10;
    //Do not check trust
    private static final int _NOEXPLICIT = 0x20;
    //(This flag is not used by OpenSSL 1.0.1g) 
    private static final int _NOCASIGN = 0x40;
    //(This flag is not used by OpenSSL 1.0.1g)
    private static final int _NODELEGATED = 0x80;
    //Do not make additional signing certificate checks
    private static final int _NOCHECKS = 0x100;
    //Do not verify additional certificates
    private static final int _TRUSTOTHER = 0x200;
    //Identify the response by signing the certificate key ID
    private static final int _RESPID_KEY = 0x400;
    //Do not include producedAt time in response 
    private static final int _NOTIME = 0x800;
    
    /*
     * Indicates the certificate is not revoked but does not necessarily mean
     * the certificate was issued or that this response is within the
     * certificate's validity interval 
     */
    private static final int _V_CERTSTATUS_GOOD = 0;
    /* Indicates the certificate has been revoked either permanently or
     * temporarily (on hold). 
     */
    private static final int _V_CERTSTATUS_REVOKED = 1;
    /* Indicates the responder does not know about the certificate being
     * requested. 
     */
    private static final int _V_CERTSTATUS_UNKNOWN = 2;
    
    //The responder ID is based on the key name.
    private static final int _V_RESPID_NAME = 0;
    //The responder ID is based on the public key.
    private static final int _V_RESPID_KEY =1;
    
    static {
        Map<Integer, String> resMap = new HashMap<>(8, 1);
        resMap.put(_RESPONSE_STATUS_SUCCESSFUL, _RESPONSE_STATUS_SUCCESSFUL_STR);
        resMap.put(_RESPONSE_STATUS_MALFORMEDREQUEST, _RESPONSE_STATUS_MALFORMEDREQUEST_STR);
        resMap.put(_RESPONSE_STATUS_INTERNALERROR, _RESPONSE_STATUS_INTERNALERROR_STR);
        resMap.put(_RESPONSE_STATUS_TRYLATER, _RESPONSE_STATUS_TRYLATER_STR);
        resMap.put(_RESPONSE_STATUS_SIGREQUIRED, _RESPONSE_STATUS_SIGREQUIRED_STR);
        resMap.put(_RESPONSE_STATUS_UNAUTHORIZED, _RESPONSE_STATUS_UNAUTHORIZED_STR);
        responseMap = resMap;
    }
    
    static void createOCSP(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule OCSP = OpenSSL.defineModuleUnder("OCSP");
        OCSP.defineClassUnder("OCSPError", OpenSSLError, OpenSSLError.getAllocator());
        
        OCSPBasicResponse.createBasicResponse(runtime, OCSP);
        OCSPCertificateId.createCertificateId(runtime, OCSP);
        OCSPRequest.createRequest(runtime, OCSP);
        OCSPResponse.createResponse(runtime, OCSP);
        OCSPSingleResponse.createSingleResponse(runtime, OCSP);
        
        //ResponseStatuses
        OCSP.setConstant(_RESPONSE_STATUS_SUCCESSFUL_STR, runtime.newFixnum(_RESPONSE_STATUS_SUCCESSFUL));
        OCSP.setConstant(_RESPONSE_STATUS_MALFORMEDREQUEST_STR, runtime.newFixnum(_RESPONSE_STATUS_MALFORMEDREQUEST));
        OCSP.setConstant(_RESPONSE_STATUS_INTERNALERROR_STR, runtime.newFixnum(_RESPONSE_STATUS_INTERNALERROR));
        OCSP.setConstant(_RESPONSE_STATUS_TRYLATER_STR, runtime.newFixnum(_RESPONSE_STATUS_TRYLATER));
        OCSP.setConstant(_RESPONSE_STATUS_SIGREQUIRED_STR, runtime.newFixnum(_RESPONSE_STATUS_SIGREQUIRED));
        OCSP.setConstant(_RESPONSE_STATUS_UNAUTHORIZED_STR, runtime.newFixnum(_RESPONSE_STATUS_UNAUTHORIZED));

        //RevocationReasons
        OCSP.setConstant("REVOKED_STATUS_NOSTATUS", runtime.newFixnum(_REVOKED_STATUS_NOSTATUS));
        OCSP.setConstant("REVOKED_STATUS_UNSPECIFIED", runtime.newFixnum(_REVOKED_STATUS_UNSPECIFIED));
        OCSP.setConstant("REVOKED_STATUS_KEYCOMPROMISE", runtime.newFixnum(_REVOKED_STATUS_KEYCOMPROMISE));
        OCSP.setConstant("REVOKED_STATUS_CACOMPROMISE", runtime.newFixnum(_REVOKED_STATUS_CACOMPROMISE));
        OCSP.setConstant("REVOKED_STATUS_AFFILIATIONCHANGED", runtime.newFixnum(_REVOKED_STATUS_AFFILIATIONCHANGED));
        OCSP.setConstant("REVOKED_STATUS_SUPERSEDED", runtime.newFixnum(_REVOKED_STATUS_SUPERSEDED));
        OCSP.setConstant("REVOKED_STATUS_CESSATIONOFOPERATION", runtime.newFixnum(_REVOKED_STATUS_CESSATIONOFOPERATION));
        OCSP.setConstant("REVOKED_STATUS_CERTIFICATEHOLD", runtime.newFixnum(_REVOKED_STATUS_CERTIFICATEHOLD));
        OCSP.setConstant("REVOKED_STATUS_REMOVEFROMCRL", runtime.newFixnum(_REVOKED_STATUS_REMOVEFROMCRL));

        OCSP.setConstant("NOCERTS", runtime.newFixnum(_NOCERTS));
        OCSP.setConstant("NOINTERN", runtime.newFixnum(_NOINTERN));
        OCSP.setConstant("NOSIGS", runtime.newFixnum(_NOSIGS));
        OCSP.setConstant("NOCHAIN", runtime.newFixnum(_NOCHAIN));
        OCSP.setConstant("NOVERIFY", runtime.newFixnum(_NOVERIFY));
        OCSP.setConstant("NOEXPLICIT", runtime.newFixnum(_NOEXPLICIT));
        OCSP.setConstant("NOCASIGN", runtime.newFixnum(_NOCASIGN));
        OCSP.setConstant("NODELEGATED", runtime.newFixnum(_NODELEGATED));
        OCSP.setConstant("NOCHECKS", runtime.newFixnum(_NOCHECKS));
        OCSP.setConstant("TRUSTOTHER", runtime.newFixnum(_TRUSTOTHER));
        OCSP.setConstant("RESPID_KEY", runtime.newFixnum(_RESPID_KEY));
        OCSP.setConstant("NOTIME", runtime.newFixnum(_NOTIME));
        
        OCSP.setConstant("V_CERTSTATUS_GOOD", runtime.newFixnum(_V_CERTSTATUS_GOOD));
        OCSP.setConstant("V_CERTSTATUS_REVOKED", runtime.newFixnum(_V_CERTSTATUS_REVOKED));
        OCSP.setConstant("V_CERTSTATUS_UNKNOWN", runtime.newFixnum(_V_CERTSTATUS_UNKNOWN));

        OCSP.setConstant("V_RESPID_NAME", runtime.newFixnum(_V_RESPID_NAME));
        OCSP.setConstant("V_RESPID_KEY", runtime.newFixnum(_V_RESPID_KEY));
    }
    
    public static String getResponseStringForValue(IRubyObject fixnum) {
        RubyFixnum rubyFixnum = (RubyFixnum) fixnum;
        return responseMap.get((int)rubyFixnum.getLongValue());
    }
    
    static RaiseException newOCSPError(Ruby runtime, Exception ex) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), ex);
    }
    
    static RubyModule _OCSP(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstant("OCSP");
    }

    static byte[] generateNonce(final Ruby runtime) {
        // OSSL currently generates 16 byte nonce by default
        return generateNonce(runtime, new byte[16]);
    }

    static byte[] generateNonce(final Ruby runtime, byte[] bytes) {
        OpenSSL.getSecureRandom(runtime).nextBytes(bytes);
        return bytes;
    }

    static JcaContentSignerBuilder newJcaContentSignerBuilder(String alg) {
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(alg);
        if (SecurityHelper.isProviderAvailable("BC")) builder.setProvider("BC");
        else builder.setProvider( SecurityHelper.getSecurityProvider() );
        return builder;
    }

    static JcaContentVerifierProviderBuilder newJcaContentVerifierProviderBuilder() {
        JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder();
        if (SecurityHelper.isProviderAvailable("BC")) builder.setProvider("BC");
        else builder.setProvider( SecurityHelper.getSecurityProvider() );
        return builder;
    }

    static JcaDigestCalculatorProviderBuilder newJcaDigestCalculatorProviderBuilder() {
        JcaDigestCalculatorProviderBuilder builder = new JcaDigestCalculatorProviderBuilder();
        if (SecurityHelper.isProviderAvailable("BC")) builder.setProvider("BC");
        else builder.setProvider( SecurityHelper.getSecurityProvider() );
        return builder;
    }

}
