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

import static org.jruby.ext.openssl.Digest._Digest;
import static org.jruby.ext.openssl.OCSP._OCSP;
import static org.jruby.ext.openssl.OCSP.newOCSPError;
import static org.jruby.ext.openssl.OpenSSL.debugStackTrace;
import static org.jruby.ext.openssl.X509._X509;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.OCSP.*;

/*
 * An OpenSSL::OCSP::Request contains the certificate information for determining 
 * if a certificate has been revoked or not. A Request can be created for a 
 * certificate or from a DER-encoded request created elsewhere.
 * 
 * @author lampad
 */
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
    private org.bouncycastle.asn1.ocsp.OCSPRequest asn1bcReq;
    private List<OCSPCertificateId> certificateIds = new ArrayList<OCSPCertificateId>();
    private byte[] nonce;
    
    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) return this;
        
        RubyString derString = StringHelper.readPossibleDERInput(context, args[0]);
        asn1bcReq = org.bouncycastle.asn1.ocsp.OCSPRequest.getInstance(derString.getBytes());
        
        return this;
    }
    
    @JRubyMethod(name = "add_certid")
    public IRubyObject add_certid(IRubyObject certId) {
        Ruby runtime = getRuntime();
        OCSPCertificateId rubyCertId = (OCSPCertificateId) certId;
        certificateIds.add(rubyCertId);
        
        OCSPReqBuilder builder = new OCSPReqBuilder();
        for (OCSPCertificateId certificateId : certificateIds) {
            builder.addRequest(new CertificateID(certificateId.getCertID()));
        }
        
        try {
            asn1bcReq = org.bouncycastle.asn1.ocsp.OCSPRequest.getInstance(builder.build().getEncoded());
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        if (nonce != null) {
            addNonceImpl();
        }
        return this;
    }

    @JRubyMethod(name = "add_nonce", rest = true)
    public IRubyObject add_nonce(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) {
            nonce = generateNonce(runtime);
        }
        else {
            RubyString input = (RubyString) args[0];
            nonce = input.getBytes();
        }
        
        addNonceImpl();
        return this;
    }
    
    // BC doesn't have support for nonces... gotta do things manually
    private void addNonceImpl() {
        GeneralName requestorName = null;
        ASN1Sequence requestList = new DERSequence();
        Extensions extensions;
        Signature sig = null;
        List<Extension> tmpExtensions = new ArrayList<Extension>();
        
        if (asn1bcReq != null) {
            TBSRequest currentTbsReq = asn1bcReq.getTbsRequest();
            extensions = currentTbsReq.getRequestExtensions();
            sig = asn1bcReq.getOptionalSignature();        
            Enumeration<ASN1ObjectIdentifier> oids = extensions.oids();
            while (oids.hasMoreElements()) {
                tmpExtensions.add(extensions.getExtension(oids.nextElement()));
            }
        }
        
        tmpExtensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce));
        Extension[] exts = new Extension[tmpExtensions.size()];
        Extensions newExtensions = new Extensions(tmpExtensions.toArray(exts));
        TBSRequest newTbsReq = new TBSRequest(requestorName, requestList, newExtensions);

        asn1bcReq = new org.bouncycastle.asn1.ocsp.OCSPRequest(newTbsReq, sig);
    }
    
    @JRubyMethod(name = "certid")
    public IRubyObject certid() {
        Ruby runtime = getRuntime();
        return RubyArray.newArray(runtime, certificateIds);
    }
    
    @JRubyMethod(name = "check_nonce")
    public IRubyObject check_nonce(ThreadContext context, IRubyObject response) {
        final Ruby runtime = context.runtime;
        if (response instanceof OCSPBasicResponse) {
            OCSPBasicResponse rubyBasicRes = (OCSPBasicResponse) response;
            return checkNonceImpl(runtime, this.nonce, rubyBasicRes.getNonce());
        }
        else if (response instanceof OCSPResponse) {
            OCSPResponse rubyResp = (OCSPResponse) response;
            return checkNonceImpl(runtime, this.nonce, ((OCSPBasicResponse)rubyResp.basic(context)).getNonce());
        }
        else {
            return checkNonceImpl(runtime, this.nonce, null);
        }
    }
    
    @JRubyMethod(name = "sign", rest = true)
    public IRubyObject sign(final ThreadContext context, IRubyObject[] args) {
        final Ruby runtime = context.runtime;
                
        int flag = 0;
        IRubyObject additionalCerts = context.nil;
        IRubyObject flags = context.nil;
        IRubyObject digest = context.nil;
        Digest digestInstance = new Digest(runtime, _Digest(runtime));
        IRubyObject nocerts = (RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCERTS);
        
        switch (Arity.checkArgumentCount(runtime, args, 2, 5)) {
            case 3 :
                additionalCerts = args[2];
                break;
            case 4 :
                additionalCerts = args[2];
                flags = args[3];
                break;
            case 5 :
                additionalCerts = args[2];
                flags = args[3];
                digest = args[4];
                break;
            default :
                break;
                    
        }
                
        if (digest.isNil()) digest = digestInstance.initialize(context, new IRubyObject[] { RubyString.newString(runtime, "SHA1") });
        if (additionalCerts.isNil()) flag |= RubyFixnum.fix2int(nocerts);
        if (!flags.isNil()) flag = RubyFixnum.fix2int(flags);
                
        X509Cert signer = (X509Cert) args[0];
        PKey signerKey = (PKey) args[1];
        
        String keyAlg = signerKey.getAlgorithm();
        String digAlg = ((Digest) digest).getShortAlgorithm();
        
        JcaContentSignerBuilder signerBuilder = newJcaContentSignerBuilder(digAlg + "with" + keyAlg);
        ContentSigner contentSigner;
        try {
            contentSigner = signerBuilder.build(signerKey.getPrivateKey());
        }
        catch (OperatorCreationException e) {
            throw newOCSPError(runtime, e);
        }

        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.setRequestorName(signer.getSubject().getX500Name());
        for (OCSPCertificateId certId : certificateIds) {
            builder.addRequest(new CertificateID(certId.getCertID()));
        }
        
        List<X509CertificateHolder> certChain = new ArrayList<X509CertificateHolder>();
        if (flag != RubyFixnum.fix2int(nocerts)) {
            try {
                certChain.add(new X509CertificateHolder(signer.getAuxCert().getEncoded()));
                if (!additionalCerts.isNil()) {
                    Iterator<java.security.cert.Certificate> certIt = ((RubyArray)additionalCerts).iterator();
                    while (certIt.hasNext()) {
                        certChain.add(new X509CertificateHolder(certIt.next().getEncoded()));
                    }
                }
            }
            catch (Exception e) {
                throw newOCSPError(runtime, e);
            }
        }
        
        X509CertificateHolder[] chain = new X509CertificateHolder[certChain.size()];
        certChain.toArray(chain);
        
        try {
            asn1bcReq = org.bouncycastle.asn1.ocsp.OCSPRequest.getInstance(builder.build(contentSigner, chain).getEncoded());
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }

        if (nonce != null) {
            addNonceImpl();
        }
                
        return this;
    }
        
    @JRubyMethod(name = "verify", rest = true)
    public IRubyObject verify(ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.runtime;
        int flags = 0;
        boolean ret = false;
        
        if (Arity.checkArgumentCount(runtime, args, 2, 3) == 3) {
            flags = RubyFixnum.fix2int((RubyFixnum)args[2]);
        }
        
        IRubyObject certificates = args[0];
        IRubyObject store = args[1];
        
        OCSPReq bcOCSPReq = getBCOCSPReq();  
        if (bcOCSPReq == null) {
            throw newOCSPError(runtime, new NullPointerException("Missing BC asn1bcReq. Missing certIDs or signature?"));
        }
        
        if (!bcOCSPReq.isSigned()) {
            return RubyBoolean.newBoolean(runtime, ret);
        }
              
        GeneralName genName = bcOCSPReq.getRequestorName();
        if (genName.getTagNo() != 4) {
            return RubyBoolean.newBoolean(runtime, ret);
        }
        
        X500Name genX500Name = X500Name.getInstance(genName.getName());
        X509StoreContext storeContext;
        
        try {
           java.security.cert.Certificate signer = findCertByName(genX500Name, certificates, flags);
           
           if (signer == null) return RubyBoolean.newBoolean(runtime, ret);
           if ((flags & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOINTERN))) > 0 &&
                   ((flags & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_TRUSTOTHER))) > 0))
               flags |= RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOVERIFY));
           if ((flags & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOSIGS))) == 0) {
               PublicKey signerPubKey = signer.getPublicKey();
               ContentVerifierProvider cvp = newJcaContentVerifierProviderBuilder().build(signerPubKey);
               ret = bcOCSPReq.isSignatureValid(cvp);
               if (!ret) {
                   return RubyBoolean.newBoolean(runtime, ret);
               }
           }
           if ((flags & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOVERIFY))) == 0) {
               if ((flags & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOCHAIN))) > 0) {
                   storeContext = X509StoreContext.newStoreContext(context, (X509Store)store, X509Cert.wrap(runtime, signer), context.nil); 
               }
               else {
                   RubyArray certs = RubyArray.newEmptyArray(runtime);

                   ASN1Sequence bcCerts = asn1bcReq.getOptionalSignature().getCerts();
                   if (bcCerts != null) {
                       Iterator<ASN1Encodable> it = bcCerts.iterator();
                       while (it.hasNext()) {
                           Certificate cert = Certificate.getInstance(it.next());
                           certs.add(X509Cert.wrap(runtime, new X509AuxCertificate(cert)));
                       }
                   }
                   storeContext = X509StoreContext.newStoreContext(context, (X509Store)store, X509Cert.wrap(runtime, signer), certs); 
               }
               
               storeContext.set_purpose(context, _X509(runtime).getConstant("PURPOSE_OCSP_HELPER"));
               storeContext.set_trust(context, _X509(runtime).getConstant("TRUST_OCSP_REQUEST"));
               ret = storeContext.verify(context).isTrue();
               if (!ret) return RubyBoolean.newBoolean(runtime, false);
           }
        }
        catch (Exception e) {
            debugStackTrace(e);
            throw newOCSPError(runtime, e);
        }
        
        return RubyBoolean.newBoolean(getRuntime(), ret);
    }

    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        Ruby runtime = getRuntime();
        try {
            return RubyString.newString(runtime, this.asn1bcReq.getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
    }
    
    @Override
    @JRubyMethod(visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();
        this.asn1bcReq = ((OCSPRequest)obj).asn1bcReq;
        return this;
    }
    
    private java.security.cert.Certificate findCertByName(ASN1Encodable genX500Name, IRubyObject certificates, int flags) throws CertificateException, IOException {
        Ruby runtime = getRuntime();
        if ((flags & RubyFixnum.fix2int(_OCSP(runtime).getConstant(OCSP_NOINTERN))) == 0) {
            ASN1Sequence certs = asn1bcReq.getOptionalSignature().getCerts();
            if (certs != null) {
                Iterator<ASN1Encodable> it = certs.iterator();
                while (it.hasNext()) {
                    Certificate cert = Certificate.getInstance(it.next());
                    if (genX500Name.equals(cert.getSubject())) return new X509AuxCertificate(cert);
                }
            }
        }
        
        @SuppressWarnings("unchecked")
        List<X509Certificate> certList = (RubyArray)certificates;
        for (X509Certificate cert : certList) {
            if (genX500Name.equals(X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()))) return new X509AuxCertificate(cert);
        }
        
        return null;
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
    
    private OCSPReq getBCOCSPReq() {
        if (asn1bcReq == null) return null;
        return new OCSPReq(asn1bcReq);
    }

}
