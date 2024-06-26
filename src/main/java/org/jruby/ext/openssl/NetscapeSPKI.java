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
 * Copyright (C) 2006, 2007 Ola Bini <ola@ologix.com>
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
package org.jruby.ext.openssl;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.impl.Base64;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.util.ByteList;

// org.bouncycastle.jce.netscape.NetscapeCertRequest emulator:
import org.jruby.ext.openssl.impl.NetscapeCertRequest;

import static org.jruby.ext.openssl.OpenSSL.*;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class NetscapeSPKI extends RubyObject {
    private static final long serialVersionUID = 3211242351810109432L;

    static void createNetscapeSPKI(Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        RubyModule Netscape = OpenSSL.defineModuleUnder("Netscape");
        RubyClass SPKI = Netscape.defineClassUnder("SPKI", runtime.getObject(), (r, klass) -> new NetscapeSPKI(r, klass));
        Netscape.defineClassUnder("SPKIError", OpenSSLError, OpenSSLError.getAllocator());
        SPKI.defineAnnotatedMethods(NetscapeSPKI.class);
    }

    private static RubyModule _Netscape(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstant("Netscape");
    }

    public NetscapeSPKI(Ruby runtime, RubyClass type) {
        super(runtime,type);
    }

    private IRubyObject public_key;
    private IRubyObject challenge;

    private Object cert;

    @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
        final Ruby runtime = context.runtime;
        if ( args.length > 0 ) {
            byte[] request = args[0].convertToString().getBytes();
            request = tryBase64Decode(request);

            final NetscapeCertRequest cert;
            try {
                this.cert = cert = new NetscapeCertRequest(request);
                challenge = runtime.newString( cert.getChallenge() );
            }
            catch (GeneralSecurityException e) { throw newSPKIError(e); }
            catch (IllegalArgumentException e) { throw newSPKIError(e); }

            this.public_key = PKey.newInstance(runtime, cert.getPublicKey());
        }
        return this;
    }

    // just try to decode for the time when the given bytes are base64 encoded.
    private static byte[] tryBase64Decode(byte[] b) {
        try {
            b = Base64.decode(b, 0, b.length, Base64.NO_OPTIONS);
        }
        catch (IOException ignored) { }
        catch (IllegalArgumentException ignored) { }
        return b;
    }

    @JRubyMethod
    public IRubyObject to_der() {
        try {
            final byte[] derBytes = toDER();
            return getRuntime().newString(new ByteList(derBytes, false));
        }
        catch (IOException ioe) { throw newSPKIError(ioe); }
    }

    @JRubyMethod(name = { "to_pem", "to_s" })
    public IRubyObject to_pem() {
        try {
            byte[] source = toDER();
            // no Base64.DO_BREAK_LINES option needed for NSPKI :
            source = Base64.encodeBytesToBytes(source, 0, source.length, Base64.NO_OPTIONS);
            return getRuntime().newString(new ByteList(source, false));
        }
        catch (IOException ioe) { throw newSPKIError(ioe); }
    }

    private byte[] toDER() throws IOException {
        ASN1Sequence b = (ASN1Sequence) ((NetscapeCertRequest) cert).toASN1Primitive();
        ASN1ObjectIdentifier encType = (ASN1ObjectIdentifier)((ASN1Sequence)((ASN1Sequence)((ASN1Sequence)b.getObjectAt(0)).getObjectAt(0)).getObjectAt(0)).getObjectAt(0);
        ASN1ObjectIdentifier sigAlg = ((AlgorithmIdentifier)b.getObjectAt(1)).getAlgorithm();
        DERBitString sig = (DERBitString) b.getObjectAt(2);

        DERBitString publicKey = new DERBitString(((PKey) public_key).to_der().convertToString().getBytes());
        DERIA5String encodedChallenge = new DERIA5String(this.challenge.toString());

        ASN1EncodableVector v1 = new ASN1EncodableVector();
        ASN1EncodableVector v1_2 = new ASN1EncodableVector();
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        ASN1EncodableVector v3 = new ASN1EncodableVector();
        ASN1EncodableVector v4 = new ASN1EncodableVector();
        v4.add(encType);
        v4.add(DERNull.INSTANCE);
        v3.add(new DLSequence(v4));
        v3.add(publicKey);
        v2.add(new DLSequence(v3));
        v2.add(encodedChallenge);
        v1.add(new DLSequence(v2));
        v1_2.add(sigAlg);
        v1_2.add(DERNull.INSTANCE);
        v1.add(new DLSequence(v1_2));
        v1.add(sig);
        return new DLSequence(v1).getEncoded();
    }

    @JRubyMethod
    public IRubyObject to_text() {
        warn(getRuntime().getCurrentContext(), "WARNING: unimplemented method called: Netscape::SPKI#to_text");
        return getRuntime().getNil();
    }

    @JRubyMethod
    public IRubyObject public_key() {
        return this.public_key;
    }

    @JRubyMethod(name="public_key=")
    public IRubyObject set_public_key(final IRubyObject public_key) {
        return this.public_key = public_key;
    }

    @JRubyMethod
    public IRubyObject sign(final IRubyObject key, final IRubyObject digest) {
        final String keyAlg = ((PKey) key).getAlgorithm();
        final String digAlg = ((Digest) digest).getShortAlgorithm();
        final String symKey = keyAlg.toLowerCase() + '-' + digAlg.toLowerCase();
        try {
            final ASN1ObjectIdentifier alg = ASN1.sym2Oid( getRuntime(), symKey );
            final PublicKey publicKey = ( (PKey) this.public_key ).getPublicKey();
            final String challengeStr = challenge.toString();
            final NetscapeCertRequest cert;
            this.cert = cert = new NetscapeCertRequest(challengeStr, new AlgorithmIdentifier(alg), publicKey);
            cert.sign( ((PKey) key).getPrivateKey() );
        }
        catch (NoSuchAlgorithmException e) {
            debugStackTrace(getRuntime(), e);
            throw newSPKIError(e);
        }
        catch (GeneralSecurityException e) {
            throw newSPKIError(e);
        }
        return this;
    }

    @JRubyMethod
    public IRubyObject verify(final IRubyObject pkey) {
        final NetscapeCertRequest cert = (NetscapeCertRequest) this.cert;
        cert.setPublicKey( ((PKey) pkey).getPublicKey() );
        try {
            boolean result = cert.verify(challenge.toString());
            return getRuntime().newBoolean(result);
        }
        catch (NoSuchAlgorithmException e) {
            debugStackTrace(getRuntime(), e);
            throw newSPKIError(e);
        }
        catch (GeneralSecurityException e) {
            throw newSPKIError(e);
        }
    }

    @JRubyMethod
    public IRubyObject challenge() {
        return this.challenge;
    }

    @JRubyMethod(name="challenge=")
    public IRubyObject set_challenge(final IRubyObject challenge) {
        return this.challenge = challenge;
    }

    private RaiseException newSPKIError(final Exception e) {
        return newSPKIError(getRuntime(), e.getMessage());
    }

    private static RaiseException newSPKIError(Ruby runtime, String message) {
        return Utils.newError(runtime, _Netscape(runtime).getClass("SPKIError"), message);
    }

}// NetscapeSPKI
