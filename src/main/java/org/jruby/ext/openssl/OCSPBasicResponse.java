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
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.openssl.impl.ASN1Registry;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.X509Utils;
import org.jruby.runtime.Arity;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.Digest._Digest;
import static org.jruby.ext.openssl.OCSP.*;
import static org.jruby.ext.openssl.X509._X509;

/*
 * An OpenSSL::OCSP::BasicResponse contains the status of a certificate
 * check which is created from an OpenSSL::OCSP::Request. 
 * A BasicResponse is more detailed than a Response.
 * 
 * @author lampad
 */
public class OCSPBasicResponse extends RubyObject {
    private static final long serialVersionUID = 8755480816625884227L;

    private static final String OCSP_NOCERTS = "NOCERTS";
    private static final String OCSP_NOCHAIN = "NOCHAIN";
    private static final String OCSP_NOCHECKS = "NOCHECKS";
    private static final String OCSP_NOTIME = "NOTIME";
    private static final String OCSP_NOSIGS = "NOSIGS";
    private static final String OCSP_NOVERIFY = "NOVERIFY";
    private static final String OCSP_NOINTERN = "NOINTERN";
    private static final String OCSP_RESPID_KEY = "RESPID_KEY";
    private static final String OCSP_TRUSTOTHER = "TRUSTOTHER";
    
    private static ObjectAllocator BASICRESPONSE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPBasicResponse(runtime, klass);
        }
    };
    
    public static void createBasicResponse(final Ruby runtime, final RubyModule OCSP) {
        RubyClass BasicResponse = OCSP.defineClassUnder("BasicResponse", runtime.getObject(), BASICRESPONSE_ALLOCATOR);
        BasicResponse.defineAnnotatedMethods(OCSPBasicResponse.class);
    }
    
    private byte[] nonce;
    private List<OCSPSingleResponse> singleResponses = new ArrayList<OCSPSingleResponse>();
    private BasicOCSPResponse asn1BCBasicOCSPResp;
    private List<Extension> extensions = new ArrayList<Extension>();

    public OCSPBasicResponse(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }
    
    public OCSPBasicResponse(Ruby runtime) {
        this(runtime, (RubyClass) _OCSP(runtime).getConstantAt("BasicResponse"));
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, IRubyObject der) {        
        if (der == null || der.isNil()) return this;
        
        asn1BCBasicOCSPResp = BasicOCSPResponse.getInstance(StringHelper.readPossibleDERInput(context, der).getBytes());
        
        return this;
    }
    
    @JRubyMethod(name = "initialize", visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context) {
        return this;
    }
    
    @Override
    @JRubyMethod(name = "initialize_copy", visibility = Visibility.PRIVATE)
    public IRubyObject initialize_copy(IRubyObject obj) {
        if ( this == obj ) return this;

        checkFrozen();
        this.asn1BCBasicOCSPResp = ((OCSPBasicResponse)obj).getASN1BCOCSPResp();
        return this;
    }
    
    @JRubyMethod(name = "add_nonce", rest = true)
    public OCSPBasicResponse add_nonce(IRubyObject[] args) {
        Ruby runtime = getRuntime();
                
        byte[] tmpNonce;
        if ( Arity.checkArgumentCount(runtime, args, 0, 1) == 0 ) {
            tmpNonce = generateNonce(runtime);
        }
        else {
            RubyString input = (RubyString) args[0];
            tmpNonce = input.getBytes();
        }
                
        extensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, tmpNonce));
        nonce = tmpNonce;
        
        return this;
    }
    
    @JRubyMethod(name = "add_status", rest = true)
    public OCSPBasicResponse add_status(final ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.getRuntime();
        Arity.checkArgumentCount(runtime, args, 7, 7);
                
        IRubyObject certificateId = args[0];
        IRubyObject status = args[1];
        IRubyObject reason = args[2];
        IRubyObject revocation_time = args[3];
        IRubyObject this_update = args[4];
        IRubyObject next_update = args[5];
        IRubyObject extensions = args[6];
        
        CertStatus certStatus = null;
        switch (RubyFixnum.fix2int((RubyFixnum)status)) {
            case 0 : 
                certStatus = new CertStatus();
                break;
            case 1 :
                ASN1GeneralizedTime revTime = rubyIntOrTimeToGenTime(revocation_time);
                RevokedInfo revokedInfo = new RevokedInfo(revTime,
                        CRLReason.lookup(RubyFixnum.fix2int((RubyFixnum)reason)));
                certStatus = new CertStatus(revokedInfo);
                break;
            case 2 :
                certStatus = new CertStatus(2, DERNull.INSTANCE);
                break;
            default :
                break;
        }
        
        ASN1GeneralizedTime thisUpdate = rubyIntOrTimeToGenTime(this_update);
        ASN1GeneralizedTime nextUpdate = rubyIntOrTimeToGenTime(next_update);
        Extensions singleExtensions = convertRubyExtensions(extensions);
        CertID certID = ((OCSPCertificateId)certificateId).getCertID();
        
        SingleResponse ocspSingleResp = new SingleResponse(certID, certStatus, thisUpdate, nextUpdate, singleExtensions);
        OCSPSingleResponse rubySingleResp = new OCSPSingleResponse(runtime);
        try {
            rubySingleResp.initialize(context, RubyString.newString(runtime, ocspSingleResp.getEncoded()));
            singleResponses.add(rubySingleResp);
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return this;
    }
    
    @JRubyMethod(name = "copy_nonce")
    public IRubyObject copy_nonce(final ThreadContext context, IRubyObject request) {
        add_nonce(new IRubyObject[] {RubyString.newString(getRuntime(), ((OCSPRequest)request).getNonce())});
        return RubyFixnum.one(context.getRuntime());
    }
    
    @JRubyMethod(name = "find_response")
    public IRubyObject find_response(final ThreadContext context, IRubyObject certId) {
        if (certId.isNil()) return context.nil;
        OCSPCertificateId rubyCertId = (OCSPCertificateId)certId;
        IRubyObject retResp = context.nil;
        for (OCSPSingleResponse singleResp : singleResponses) {
            CertID thisId = rubyCertId.getCertID();
            CertID thatId = singleResp.getBCSingleResp().getCertID();
            if (thisId.equals(thatId)) {
                retResp = singleResp;
                break;
            }
        }
        
        return retResp;
    }
    
    @JRubyMethod(name = "responses")
    public IRubyObject responses() {
        return RubyArray.newArray(getRuntime(), singleResponses);
    }
    
    @JRubyMethod(name = "sign", rest = true)
    public IRubyObject sign(final ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.getRuntime();
        
        int flag = 0;
        IRubyObject additionalCerts = context.nil;
        IRubyObject flags = context.nil;
        IRubyObject digest = context.nil;
        Digest digestInstance = new Digest(runtime, _Digest(runtime));
        List<X509CertificateHolder> addlCerts = new ArrayList<>();
        
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
                        
        if (digest.isNil()) digest = digestInstance.initialize(context, RubyString.newString(runtime, "SHA1"));
        if (!flags.isNil()) flag = RubyFixnum.fix2int(flags);
        if (additionalCerts.isNil()) flag |= RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCERTS));
                        
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
        
        final BasicOCSPRespBuilder respBuilder;
        try {
            if ((flag & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_RESPID_KEY))) != 0) {
                DigestCalculatorProvider dcp = newJcaDigestCalculatorProviderBuilder().build();
                DigestCalculator calculator = dcp.get(contentSigner.getAlgorithmIdentifier());
                respBuilder = new BasicOCSPRespBuilder(SubjectPublicKeyInfo.getInstance(signerKey.getPublicKey().getEncoded()), calculator);
            }
            else {
                respBuilder = new BasicOCSPRespBuilder(new RespID(signer.getSubject().getX500Name()));
            }
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        X509CertificateHolder[] chain = null;
        try {
            if ((flag & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCERTS))) == 0) {
                addlCerts.add(new X509CertificateHolder(signer.getAuxCert().getEncoded()));
                if (!additionalCerts.isNil()) {
                    Iterator<java.security.cert.Certificate> rubyAddlCerts = ((RubyArray)additionalCerts).iterator();
                    while (rubyAddlCerts.hasNext()) {
                        java.security.cert.Certificate cert = rubyAddlCerts.next();
                        addlCerts.add(new X509CertificateHolder(cert.getEncoded()));
                    }
                }
                
                chain = addlCerts.toArray(new X509CertificateHolder[addlCerts.size()]);
            }
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        
        Date producedAt = null;
        if ((flag & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOTIME))) == 0) {
            producedAt = new Date();
        }
        
        for (OCSPSingleResponse resp : singleResponses) {
            SingleResp singleResp = new SingleResp(resp.getBCSingleResp());
            respBuilder.addResponse(singleResp.getCertID(), 
                    singleResp.getCertStatus(), 
                    singleResp.getThisUpdate(), 
                    singleResp.getNextUpdate(), 
                    resp.getBCSingleResp().getSingleExtensions());
        }
        
        try {
            Extension[] respExtAry = new Extension[extensions.size()];
            Extensions respExtensions = new Extensions(extensions.toArray(respExtAry));
            BasicOCSPResp bcBasicOCSPResp = respBuilder.setResponseExtensions(respExtensions).build(contentSigner, chain, producedAt);
            asn1BCBasicOCSPResp = BasicOCSPResponse.getInstance(bcBasicOCSPResp.getEncoded());
        }
        catch (Exception e) {
            throw newOCSPError(runtime, e);
        }
        return this;
    }
    
    @JRubyMethod(name = "verify", rest = true)
    public IRubyObject verify(final ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.runtime;
        int flags = 0;
        IRubyObject certificates = args[0];
        IRubyObject store = args[1];
        boolean ret = false;
        
        if (Arity.checkArgumentCount(runtime, args, 2, 3) == 3) {
            flags = RubyFixnum.fix2int(args[2]);
        }
        
        JcaContentVerifierProviderBuilder jcacvpb = newJcaContentVerifierProviderBuilder();
        BasicOCSPResp basicOCSPResp = getBasicOCSPResp();
        
        java.security.cert.Certificate signer = findSignerCert(context, asn1BCBasicOCSPResp, convertRubyCerts(certificates), flags);
        if ( signer == null ) return RubyBoolean.newBoolean(runtime, false);
        if ( (flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOINTERN))) == 0 && 
                (flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_TRUSTOTHER))) != 0 ) {
            flags |= RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOVERIFY));
        }
        if ( (flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOSIGS))) == 0 ) {
            PublicKey sPKey = signer.getPublicKey();
            if ( sPKey == null ) return RubyBoolean.newBoolean(runtime, false);
            try {
                ContentVerifierProvider cvp = jcacvpb.build(sPKey);
                ret = basicOCSPResp.isSignatureValid(cvp);
            }
            catch (Exception e) {
                throw newOCSPError(runtime, e);
            }
        }
        if ((flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOVERIFY))) == 0) {
            List<X509Cert> untrustedCerts;
            if ((flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCHAIN))) != 0) {
                untrustedCerts = Collections.EMPTY_LIST;
            }
            else if (basicOCSPResp.getCerts() != null && (certificates != null && !((RubyArray)certificates).isEmpty())) {
                untrustedCerts = getCertsFromResp(context);
                
                Iterator<java.security.cert.Certificate> certIt = ((RubyArray)certificates).iterator();
                while (certIt.hasNext()) {
                    try {
                        untrustedCerts.add(X509Cert.wrap(context, certIt.next().getEncoded()));
                    }
                    catch (CertificateEncodingException e) {
                        throw newOCSPError(runtime, e);
                    }
                }
            }
            else {
                untrustedCerts = getCertsFromResp(context);
            }
            
            RubyArray rUntrustedCerts = RubyArray.newArray(runtime, untrustedCerts);
            X509StoreContext ctx;
            try {
                ctx = X509StoreContext.newStoreContext(context, (X509Store)store, X509Cert.wrap(runtime, signer), rUntrustedCerts);
            }
            catch (CertificateEncodingException e) {
                throw newOCSPError(runtime, e);
            }
            
            ctx.set_purpose(context, _X509(runtime).getConstant("PURPOSE_OCSP_HELPER"));
            ret = ctx.verify(context).isTrue();
            IRubyObject chain = ctx.chain(context);
            
            if ((flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCHECKS))) > 0) {
                ret = true;
            }
            
            try {
                if (checkIssuer(getBasicOCSPResp(), chain)) return RubyBoolean.newBoolean(runtime, true);
            }
            catch (IOException e) {
                throw newOCSPError(runtime, e);
            }
            
            if ((flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOCHAIN))) != 0) {
                return RubyBoolean.newBoolean(runtime, ret);
            }
            else {
                X509Cert rootCA = (X509Cert)((RubyArray)chain).last();
                PublicKey rootKey = rootCA.getAuxCert().getPublicKey();
                try {
                    // check if self-signed and valid (trusts itself)
                    rootCA.getAuxCert().verify(rootKey);
                    ret = true;
                }
                catch (Exception e) {
                    ret = false;
                }
            }
        }
        
        return RubyBoolean.newBoolean(runtime, ret);
    }
    
    @JRubyMethod(name = "status")
    public IRubyObject status(ThreadContext context) {
        final Ruby runtime = context.runtime;
        RubyArray ret = RubyArray.newArray(runtime, singleResponses.size());
        
        for (OCSPSingleResponse resp : singleResponses) {
            RubyArray respAry = RubyArray.newArray(runtime, 7);
            
            respAry.append(resp.certid(context));
            respAry.append(resp.cert_status());
            respAry.append(resp.revocation_reason());
            respAry.append(resp.revocation_time());
            respAry.append(resp.this_update());
            respAry.append(resp.next_update());
            respAry.append(resp.extensions());

            ret.add(respAry);
        }
        
        return ret;
    }
    
    @JRubyMethod(name = "to_der")
    public IRubyObject to_der() {
        Ruby runtime = getRuntime();
        IRubyObject ret;
        try {
           ret = RubyString.newString(runtime, asn1BCBasicOCSPResp.getEncoded());
        }
        catch (IOException e) {
            throw newOCSPError(runtime, e);
        }
        
        return ret;
    }
    
    private boolean checkIssuer(BasicOCSPResp basicOCSPResp, IRubyObject chain) throws IOException {
        boolean ret = false;
        if ( ((RubyArray)chain).size() <= 0 ) return false;
        List<SingleResp> singleResponses = Arrays.asList(basicOCSPResp.getResponses());
        CertificateID certId = checkCertIds(singleResponses);
        
        X509Cert signer = (X509Cert)((RubyArray)chain).first();
        if (((RubyArray)chain).size() > 1) {
            X509Cert signerCA = (X509Cert)((RubyArray)chain).entry(1);
            if(matchIssuerId(signerCA, certId, singleResponses)) {
                return checkDelegated(signerCA);
            }
        }
        else {
            ret = matchIssuerId(signer, certId, singleResponses);
        }
        
        return ret;
    }

    private boolean checkDelegated(X509Cert signerCA) {
        try {
            return (signerCA.getAuxCert().getExFlags() & X509Utils.EXFLAG_XKUSAGE) != 0 &&
                    (signerCA.getAuxCert().getExtendedKeyUsage().contains(ASN1Registry.OBJ_OCSP_sign));
        }
        catch (CertificateParsingException e) {
            throw newOCSPError(getRuntime(), e);
        }
    }

    private boolean matchIssuerId(X509Cert signerCA, CertificateID certId, List<SingleResp> singleResponses) throws IOException {
        Ruby runtime = getRuntime();
        if (certId == null) {
            //gotta check em all
            for(SingleResp resp : singleResponses) {
                CertificateID tempId = resp.getCertID();
                if(!matchIssuerId(signerCA, tempId, null)) return false;
            }
            return true;
        }
        else {
            // we have a matching cid
            ASN1ObjectIdentifier alg = certId.getHashAlgOID();
            String sym = ASN1.oid2Sym(runtime, alg);
            MessageDigest md = Digest.getDigest(runtime, sym);
            byte[] issuerNameDigest = md.digest(signerCA.getIssuer().getX500Name().getEncoded());
            byte[] issuerKeyDigest = md.digest(signerCA.getAuxCert().getPublicKey().getEncoded());
            if(!issuerNameDigest.equals(certId.getIssuerNameHash())) return false;
            if(!issuerKeyDigest.equals(certId.getIssuerKeyHash())) return false;
            return true;
        }
    }

    private CertificateID checkCertIds(List<SingleResp> singleResponses) {
        ArrayList<SingleResp> ary = new ArrayList<>(singleResponses);
        CertificateID cid = ary.remove(0).getCertID();
        
        for (SingleResp singleResp : ary) {
            if (!cid.equals(singleResp.getCertID())) return null;
        }
        
        return cid;
    }

    public BasicOCSPResponse getASN1BCOCSPResp() {
        return this.asn1BCBasicOCSPResp;
    }
    
    public byte[] getNonce() {
        return this.nonce;
    }
    
    private ASN1GeneralizedTime rubyIntOrTimeToGenTime(IRubyObject intOrTime) {
        if (intOrTime.isNil()) return null;
        Date retTime;
        if (intOrTime instanceof RubyInteger) {
            retTime = new Date(System.currentTimeMillis() + RubyFixnum.fix2int(intOrTime)*1000);
        }
        else if (intOrTime instanceof RubyTime) {
            retTime = ((RubyTime) intOrTime).getJavaDate();
        }
        else {
            throw getRuntime().newArgumentError("Unknown Revocation Time class: " + intOrTime.getMetaClass());
        }
        
        return new ASN1GeneralizedTime(retTime);
    }
    
    private Extensions convertRubyExtensions(IRubyObject extensions) {
        if (extensions.isNil()) return null;
        List<Extension> retExtensions = new ArrayList<Extension>();
        Iterator<IRubyObject> rubyExtensions = ((RubyArray)extensions).iterator();
        while (rubyExtensions.hasNext()) {
            X509Extension rubyExt = (X509Extension)rubyExtensions.next();
            Extension ext = Extension.getInstance(((RubyString)rubyExt.to_der()).getBytes());
            retExtensions.add(ext);
        }
        Extension[] exts = new Extension[retExtensions.size()];
        retExtensions.toArray(exts);
        return new Extensions(exts);
    }
    
    private List<java.security.cert.Certificate> convertRubyCerts(IRubyObject certificates) {
        Iterator<java.security.cert.Certificate> it = ((RubyArray)certificates).iterator();
        List<java.security.cert.Certificate> ret = new ArrayList<java.security.cert.Certificate>();
        while (it.hasNext()) {
            ret.add(it.next());
        }
        
        return ret;
    }
    
    private java.security.cert.Certificate findSignerCert(final ThreadContext context,
        BasicOCSPResponse basicResp, List<java.security.cert.Certificate> certificates, int flags) {
        final Ruby runtime = context.runtime;
        ResponderID respID = basicResp.getTbsResponseData().getResponderID();
        java.security.cert.Certificate ret;
        ret = findSignerByRespId(context, certificates, respID);
        
        if (ret == null && (flags & RubyFixnum.fix2int((RubyFixnum)_OCSP(runtime).getConstant(OCSP_NOINTERN))) == 0) {
            List<X509AuxCertificate> javaCerts = new ArrayList<X509AuxCertificate>();
            for (X509CertificateHolder cert : getBasicOCSPResp().getCerts()) {
                try {
                    javaCerts.add(X509Cert.wrap(context, cert.getEncoded()).getAuxCert());
                }
                catch (IOException e) {
                    throw newOCSPError(runtime, e);
                }
            }
            ret = findSignerByRespId(context, javaCerts, respID);
        }
        
        return ret;
    }
    
    private java.security.cert.Certificate findSignerByRespId(final ThreadContext context, List<? extends java.security.cert.Certificate> certificates, ResponderID respID) {
        if (respID.getName() != null) {
            for (java.security.cert.Certificate cert : certificates) {
                try {
                    X509Cert rubyCert = X509Cert.wrap(context, cert);
                    if (rubyCert.getSubject().getX500Name().equals(respID.getName())) return cert;
                }
                catch (CertificateEncodingException e) {
                    throw newOCSPError(context.runtime, e);
                }
            }
        }
        else {
            // Ignore anything that's not SHA1 (weirdly) SHA_DIGEST_LENGTH == 20
            if (respID.getKeyHash().length != 20) return null;
            for (java.security.cert.Certificate cert : certificates) {
                byte[] pubKeyDigest = Digest.digest(
                        context,
                        this,
                        RubyString.newString(context.runtime, "SHA1"),
                        RubyString.newString(context.runtime, cert.getPublicKey().getEncoded())
                        ).getBytes();
                if (respID.getKeyHash().equals(pubKeyDigest)) return cert;
            }
        }
        return null;
    }

    private List<X509Cert> getCertsFromResp(ThreadContext context) {
        X509CertificateHolder[] certs = getBasicOCSPResp().getCerts();
        List<X509Cert> retCerts = new ArrayList<>(certs.length);
        for (X509CertificateHolder cert : certs) {
            try {
                retCerts.add(X509Cert.wrap(context, cert.getEncoded()));
            }
            catch (IOException e) {
                throw newOCSPError(context.runtime, e);
            }                    
        }
        return retCerts;
    }

    
    private BasicOCSPResp getBasicOCSPResp() {
        return new BasicOCSPResp(asn1BCBasicOCSPResp);
    }

}
