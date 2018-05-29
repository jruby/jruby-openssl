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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.OCSP.*;

/*
 * An OpenSSL::OCSP::Response contains the status of a certificate check which 
 * is created from an OpenSSL::OCSP::Request.
 * 
 * @author lampad
 */
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
    
    public static void createResponse(final Ruby runtime, final RubyModule OCSP) {
        RubyClass Response = OCSP.defineClassUnder("Response", runtime.getObject(), RESPONSE_ALLOCATOR);
        Response.defineAnnotatedMethods(OCSPResponse.class);
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
        this.bcResp = ((OCSPResponse)obj).bcResp;
        return this;
    }
    
    @JRubyMethod(name = "basic")
    public IRubyObject basic(ThreadContext context) {
        Ruby runtime = context.runtime;
        if (bcResp == null || bcResp.getResponseBytes() == null || bcResp.getResponseBytes().getResponse() == null) {
            return context.nil;
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

}
