/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2013 Matt Hauck <matthauck@gmail.com>
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
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl.impl;

import java.util.List;
import java.io.OutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCSException;
import org.jruby.ext.openssl.SecurityHelper;

public class PKCS10Request {

    private X500Name subject;
    private SubjectPublicKeyInfo publicKeyInfo;
    private List<Attribute> attributes;

    private transient PKCS10CertificationRequest signedRequest;

    public PKCS10Request(X500Name subject,
        SubjectPublicKeyInfo publicKeyInfo, List<Attribute> attrs) {
        this.subject = subject;
        this.publicKeyInfo = publicKeyInfo;
        this.attributes = attrs;
    }

    public PKCS10Request(X500Name subject,
        PublicKey publicKey, List<Attribute> attrs) {
        this.subject = subject;
        this.publicKeyInfo = makePublicKeyInfo(publicKey);
        this.attributes = attrs;
    }

    // For reading existing requests

    public PKCS10Request(final CertificationRequest req) {
        subject       = req.getCertificationRequestInfo().getSubject();
        publicKeyInfo = req.getCertificationRequestInfo().getSubjectPublicKeyInfo();
        setAttributes( req.getCertificationRequestInfo().getAttributes() );
        signedRequest = new PKCS10CertificationRequest(req); // valid = true;
    }

    public PKCS10Request(byte[] bytes) {
        this(CertificationRequest.getInstance(bytes));
    }

    public PKCS10Request(ASN1Sequence sequence) {
        this(CertificationRequest.getInstance(sequence));
    }

    private void resetSignedRequest() {
        if ( signedRequest == null ) return;

        CertificationRequest req = signedRequest.toASN1Structure();
        CertificationRequestInfo reqInfo = new CertificationRequestInfo(subject, publicKeyInfo, req.getCertificationRequestInfo().getAttributes());
        ASN1Sequence seq = (ASN1Sequence) req.toASN1Primitive();
        req = new CertificationRequest(reqInfo, (AlgorithmIdentifier) seq.getObjectAt(1), (DERBitString) seq.getObjectAt(2));
        signedRequest = new PKCS10CertificationRequest(req); // valid = true;
    }

    // sign

    public PKCS10CertificationRequest sign(final PrivateKey privateKey,
        final AlgorithmIdentifier signatureAlg)
        throws NoSuchAlgorithmException, InvalidKeyException {
        final ContentSigner signer = new PKCS10Signer(privateKey, signatureAlg);
        signedRequest = newBuilder().build(signer); // valid = true;
        return signedRequest;
    }

    public PKCS10CertificationRequest sign(final PrivateKey privateKey,
        final String digestAlg)
        throws NoSuchAlgorithmException, InvalidKeyException {
        String sigAlg = digestAlg + "WITH" + getPublicKeyAlgorithm();
        return sign( privateKey,
            new DefaultSignatureAlgorithmIdentifierFinder().find( sigAlg )
        );
    }

    // verify

    public boolean verify(final PublicKey publicKey) throws InvalidKeyException {
        if ( signedRequest == null ) {
            if ( true ) throw new IllegalStateException("no signed request");
            return false;
        }

        try {
            ContentVerifierProvider verifier = new PKCS10VerifierProvider( publicKey );
            return signedRequest.isSignatureValid( verifier );
        }
        catch (PKCSException e) {
            throw new InvalidKeyException(e);
        }
    }

    // privates

    private PKCS10CertificationRequestBuilder newBuilder() {
        final PKCS10CertificationRequestBuilder builder =
                new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);
        if ( attributes != null ) {
            for ( Attribute attribute : attributes ) {
                builder.addAttribute(attribute.getAttrType(), attribute.getAttributeValues());
            }
        }
        return builder;
    }

    private static SubjectPublicKeyInfo makePublicKeyInfo(PublicKey publicKey) {
        if ( publicKey == null ) return null;
        return SubjectPublicKeyInfo.getInstance( publicKey.getEncoded() );
    }

    // conversion

    public ASN1Sequence toASN1Structure() {
        if ( signedRequest == null ) {
            // return an empty Sequence
            return new DLSequence();
        }
        return ASN1Sequence.getInstance( signedRequest.toASN1Structure() );
    }

    // getters and setters

    public void setSubject(final X500Name subject) {
        this.subject = subject;
        resetSignedRequest();
    }

    public X500Name getSubject() {
        return subject;
    }

    //private transient String publicKeyAlgorithm;

    public void setPublicKey(final PublicKey publicKey) {
        this.publicKeyInfo = makePublicKeyInfo(publicKey);
        //if ( publicKey == null ) publicKeyAlgorithm = null;
        //else publicKeyAlgorithm = publicKey.getAlgorithm();
        resetSignedRequest();
    }

    private String getPublicKeyAlgorithm() {
        //if ( publicKeyAlgorithm == null ) {
        //    throw new IllegalStateException("no public key info");
        //}
        //return publicKeyAlgorithm;
        if ( publicKeyInfo == null ) {
            throw new IllegalStateException("no public key info");
        }
        AlgorithmIdentifier algId = publicKeyInfo.getAlgorithm();
        return ASN1Registry.oid2sym( algId.getAlgorithm() );
    }

    public PublicKey generatePublicKey() throws NoSuchAlgorithmException,
        InvalidKeySpecException, IOException {

        AsymmetricKeyParameter keyParams = PublicKeyFactory.createKey(publicKeyInfo);

        final KeySpec keySpec; final KeyFactory keyFactory;

        if ( keyParams instanceof RSAKeyParameters ) {
            RSAKeyParameters rsa = (RSAKeyParameters) keyParams;
            keySpec = new RSAPublicKeySpec(
                rsa.getModulus(), rsa.getExponent()
            );
            keyFactory = SecurityHelper.getKeyFactory("RSA");
            return keyFactory.generatePublic(keySpec);

        }
        else if ( keyParams instanceof DSAPublicKeyParameters ) {
            DSAPublicKeyParameters dsa = (DSAPublicKeyParameters) keyParams;
            DSAParameters params = dsa.getParameters();
            keySpec = new DSAPublicKeySpec(
                dsa.getY(), params.getP(), params.getQ(), params.getG()
            );
            keyFactory = SecurityHelper.getKeyFactory("DSA");
            return keyFactory.generatePublic(keySpec);
        }
        else if ( keyParams instanceof ECPublicKeyParameters ) {
            ECPublicKeyParameters ec = (ECPublicKeyParameters) keyParams;
            ECDomainParameters ecParams = ec.getParameters();
            ECParameterSpec params = new ECParameterSpec(
                    ecParams.getCurve(),
                    ecParams.getG(), ecParams.getN(), ecParams.getH(),
                    ecParams.getSeed()
            );
            // NOTE: likely to fail if non BC factory picked up :
            keySpec = new ECPublicKeySpec(ec.getQ(), params);
            keyFactory = SecurityHelper.getKeyFactory("EC");
            return keyFactory.generatePublic(keySpec);
        }
        else {
            throw new IllegalStateException("could not generate public key for request, params type: " + keyParams);
        }
    }

    public Attribute[] getAttributes() {
        return signedRequest != null ? signedRequest.getAttributes() :
                    attributes.toArray(new Attribute[ attributes.size() ]);
    }

    public void setAttributes(final List<Attribute> attrs) {
        this.attributes = attrs;
    }

    private void setAttributes(final ASN1Set attrs) {
        this.attributes = new ArrayList<Attribute>();
        final Enumeration e = attrs.getObjects();
        while ( e.hasMoreElements() ) {
            addAttribute( Attribute.getInstance( e.nextElement() ) );
        }
    }

    public void addAttribute(final Attribute attribute) {
        this.attributes.add( attribute );
    }

    public BigInteger getVersion() {
        if ( signedRequest == null ) return null;
        return signedRequest.toASN1Structure().
                getCertificationRequestInfo().
                    getVersion().getValue();
    }


    private static class PKCS10Signer implements ContentSigner {

        final AlgorithmIdentifier signatureAlg;
        final Signature signature;
        private final SignatureOutputStream out;

        PKCS10Signer(PrivateKey privateKey, AlgorithmIdentifier signatureAlg)
            throws NoSuchAlgorithmException, InvalidKeyException {
            this.signatureAlg = signatureAlg;
            signature = SecurityHelper.getSignature( signatureAlg.getAlgorithm().getId() );
            signature.initSign( privateKey );
            out = new SignatureOutputStream(signature);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() { return signatureAlg; }

        public OutputStream getOutputStream() { return out; }

        public byte[] getSignature() {
            try {
                return signature.sign();
            }
            catch (SignatureException e) {
                throw new RuntimeException("Could not read signature: " + e);
            }
        }
    }

    private static class PKCS10VerifierProvider implements ContentVerifierProvider {

        final PublicKey publicKey;

        PKCS10VerifierProvider(PublicKey key) {
            publicKey = key;
        }

        public ContentVerifier get(AlgorithmIdentifier sigAlg) {
            try {
                return new PKCS10Verifier(publicKey, sigAlg);
            }
            catch (Exception e) {
                throw new RuntimeException("Could not create content verifier: " + e);
            }
        }

        public boolean hasAssociatedCertificate() {
            return false;
        }

        public org.bouncycastle.cert.X509CertificateHolder getAssociatedCertificate() {
            return null;
        }
    }

    private static class PKCS10Verifier implements ContentVerifier {

        final AlgorithmIdentifier signatureAlg;
        final Signature signature;
        private final SignatureOutputStream out;

        public PKCS10Verifier(PublicKey publicKey, AlgorithmIdentifier signatureAlg)
            throws NoSuchAlgorithmException, InvalidKeyException {
            this.signatureAlg = signatureAlg;
            signature = SecurityHelper.getSignature( signatureAlg.getAlgorithm().getId() );
            signature.initVerify( publicKey );
            out = new SignatureOutputStream(signature);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() { return signatureAlg; }

        public OutputStream getOutputStream() { return out; }

        public boolean verify(byte[] expected) {
            try {
                return signature.verify( expected );
            }
            catch (SignatureException e) {
                throw new RuntimeException("Could not verify signature: " + e);
            }
        }
    }

    private static class SignatureOutputStream extends OutputStream {

        private final Signature signature;

        SignatureOutputStream(Signature signature) {
            this.signature = signature;
        }

        @Override
        public void write(byte[] bytes, int off, int len) throws IOException {
            try {
                signature.update(bytes, off, len);
            }
            catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(byte[] bytes) throws IOException {
            try {
                signature.update(bytes);
            }
            catch (SignatureException e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(int b) throws IOException {
            try {
                signature.update((byte) b);
            }
            catch (SignatureException e) {
                throw new IOException(e);
            }
        }

    }
}

