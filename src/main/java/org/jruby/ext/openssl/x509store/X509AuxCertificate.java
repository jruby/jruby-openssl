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
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
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
package org.jruby.ext.openssl.x509store;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import java.util.Date;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import java.security.Principal;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

import org.jruby.ext.openssl.SecurityHelper;

/**
 * Since regular X509Certificate doesn't represent the Aux part of a
 * certification, this class uses composition and extension to contain
 * both pieces of information.
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class X509AuxCertificate extends X509Certificate implements Cloneable {
    private static final long serialVersionUID = -909543379295427515L;

    final X509Certificate cert;

    final X509Aux aux;

    private boolean valid = false;
    private int ex_flags = 0;

    public X509AuxCertificate(Certificate wrap) throws IOException, CertificateException {
        super();
        CertificateFactory factory = SecurityHelper.getCertificateFactory("X.509");
        ByteArrayInputStream bis = new ByteArrayInputStream(wrap.getEncoded());
        this.cert = (X509Certificate) factory.generateCertificate(bis);
        this.aux = null;
    }

    public X509AuxCertificate(X509Certificate wrap) {
        this(wrap, null);
    }

    X509AuxCertificate(X509Certificate wrap, X509Aux aux) {
        super();
        this.cert = wrap;
        this.aux = aux;
    }

    public final X509AuxCertificate clone() {
        try {
            return (X509AuxCertificate) super.clone();
        }
        catch (CloneNotSupportedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    final X509AuxCertificate cloneForCache() {
        final X509AuxCertificate clone = clone();
        clone.valid = false;
        clone.ex_flags = 0;
        return clone;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean v) {
        this.valid = v;
    }

    public int getExFlags() {
        return ex_flags;
    }

    public void setExFlags(int ex_flags) {
        this.ex_flags = ex_flags;
    }

    // DELEGATES :

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        cert.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        cert.checkValidity(date);
    }

    @Override
    public int getBasicConstraints()  {
        return cert.getBasicConstraints();
    }

    @Override
    public List<String> getExtendedKeyUsage() throws CertificateParsingException {
        return cert.getExtendedKeyUsage();
    }

    @Override
    public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
        return cert.getIssuerAlternativeNames();
    }

    @Override
    public Principal getIssuerDN() {
        return cert.getIssuerDN();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return cert.getIssuerUniqueID();
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        return cert.getIssuerX500Principal();
    }

    @Override
    public boolean[] getKeyUsage() { return cert.getKeyUsage(); }

    @Override
    public Date getNotAfter() { return cert.getNotAfter(); }

    @Override
    public Date getNotBefore() { return cert.getNotBefore(); }

    @Override
    public BigInteger getSerialNumber() { return cert.getSerialNumber(); }

    @Override
    public String getSigAlgName() { return cert.getSigAlgName(); }

    @Override
    public String getSigAlgOID() { return cert.getSigAlgOID(); }

    @Override
    public byte[] getSigAlgParams() { return cert.getSigAlgParams(); }

    @Override
    public byte[] getSignature() { return cert.getSignature(); }

    @Override
    public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
        return cert.getSubjectAlternativeNames();
    }

    @Override
    public Principal getSubjectDN() { return cert.getSubjectDN(); }

    @Override
    public boolean[] getSubjectUniqueID() { return cert.getSubjectUniqueID(); }

    @Override
    public X500Principal getSubjectX500Principal() { return cert.getSubjectX500Principal(); }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return cert.getTBSCertificate();
    }

    @Override
    public int getVersion() { return cert.getVersion(); }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return cert.getEncoded();
    }

    @Override
    public PublicKey getPublicKey() { return cert.getPublicKey(); }

    @Override
    public String toString() { return cert.toString(); }

    @Override
    public boolean equals(Object other) {
        if ( this == other ) return true;
        if ( other instanceof X509AuxCertificate ) {
            X509AuxCertificate o = (X509AuxCertificate) other;
            return this.cert.equals(o.cert) && ((this.aux == null) ? o.aux == null : this.aux.equals(o.aux));
        }
        return false;
    }

    @Override
    public int hashCode() {
        int ret = cert.hashCode();
        ret += 3 * (aux == null ? 1 : aux.hashCode());
        return ret;
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException,
        InvalidKeyException, NoSuchProviderException, SignatureException {
        cert.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException,
        NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
        SignatureException {
        cert.verify(key,sigProvider);
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return cert.getCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return cert.getExtensionValue(oid);
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return cert.getNonCriticalExtensionOIDs();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return cert.hasUnsupportedCriticalExtension();
    }

    public Integer getNsCertType() throws CertificateException {
        final String NS_CERT_TYPE_OID = "2.16.840.1.113730.1.1";
        final byte[] bytes = getExtensionValue(NS_CERT_TYPE_OID);
        if ( bytes == null ) return null;

        try {
            Object o = new ASN1InputStream(bytes).readObject();
            if ( o instanceof DERBitString ) {
                return ((DERBitString) o).intValue();
            }
            if ( o instanceof DEROctetString ) {
                // just reads initial object for nsCertType definition and ignores trailing objects.
                ASN1InputStream in = new ASN1InputStream(((DEROctetString) o).getOctets());
                o = in.readObject();
                return ((DERBitString) o).intValue();
            }
            else {
                throw new CertificateException("unknown type from ASN1InputStream.readObject: " + o);
            }
        }
        catch (IOException ioe) {
            throw new CertificateEncodingException(ioe.getMessage(), ioe);
        }
    }

    static boolean equalSubjects(final X509AuxCertificate cert1, final X509AuxCertificate cert2) {
        if ( cert1.cert == cert2.cert ) return true;

        if ( cert1.cert instanceof X509CertificateObject && cert2.cert instanceof X509CertificateObject ) {
            return cert1.cert.getSubjectDN().equals( cert2.cert.getSubjectDN() ); // less expensive on mem
        }
        // otherwise need to take the 'expensive' path :
        return cert1.getSubjectX500Principal().equals( cert2.getSubjectX500Principal() );
    }

}// X509AuxCertificate
