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
*  Copyright (C) 2007-2009 Ola Bini <ola.bini@gmail.com>
*  Copyright (C) 2009-2016 The JRuby Team
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

import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
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

import static org.jruby.ext.openssl.OCSP._OCSP;

/*
 * An OpenSSL::OCSP::BasicResponse contains the status of a certificate
 * check which is created from an OpenSSL::OCSP::Request. 
 * A BasicResponse is more detailed than a Response.
 * 
 * @author lampad
 */
public class OCSPBasicResponse extends RubyObject {
    private static final long serialVersionUID = 8755480816625884227L;
    
    private static ObjectAllocator BASICRESPONSE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPBasicResponse(runtime, klass);
        }
    };
    
    public static void createBasicResponse(final Ruby runtime, final RubyModule _OCSP) {
        RubyClass _BasicResponse = _OCSP.defineClassUnder("BasicResponse", runtime.getObject(), BASICRESPONSE_ALLOCATOR);
        _BasicResponse.defineAnnotatedMethods(OCSPBasicResponse.class);
    }
    
    private RubyString der;
    private byte[] nonce;
    private BasicOCSPResponse bcBasicOCSPResponse;

    public OCSPBasicResponse(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject der) {        
        if (der == null || der.isNil()) return this;
        
        this.der = StringHelper.readPossibleDERInput(context, der);
        
        return this;
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context) {
        return this;
    }
    
    @JRubyMethod(name = "add_nonce", rest = true)
    public OCSPBasicResponse add_nonce(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) {
            nonce = generateNonce();
        }
        else if (args[0] == null || args[0].isNil()) {
            nonce = generateNonce();
        }
        else {
            RubyString input = (RubyString)args[0];
            nonce = generateNonce(input.getBytes());
        }
        
        return this;
    }
    
    @JRubyMethod(name = "add_status")
    public OCSPBasicResponse add_status(final ThreadContext context) {
        //TODO: Implement
        return this;
    }
    
    @JRubyMethod(name = "copy_nonce")
    public RubyFixnum copy_nonce(final ThreadContext context, OCSPRequest request) {
        //TODO: Implement
        return RubyFixnum.zero(context.getRuntime());
    }
    
    public BasicOCSPResponse getBCOCSPResp() {
        return this.bcBasicOCSPResponse;
    }
    
    public byte[] getNonce() {
        return this.nonce;
    }
        
    private byte[] generateNonce() {
        // OSSL currently generates 16 byte nonce by default
        return generateNonce(new byte[16]);
    }
    
    private byte[] generateNonce(byte[] bytes) {
        OpenSSL.getSecureRandom(getRuntime()).nextBytes(bytes);
        return bytes;
    }
    
    private static RaiseException newOCSPError(Ruby runtime, Exception e) {
        return Utils.newError(runtime, _OCSP(runtime).getClass("OCSPError"), e);
    }


}
