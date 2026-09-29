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
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.impl.Base64;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;

import org.jruby.ext.openssl.impl.NetscapeCertRequest;

import static org.jruby.ext.openssl.OpenSSL.handlePotentialOperationError;
import static org.jruby.ext.openssl.util.RubySupport.newError;
import static org.jruby.ext.openssl.util.RubySupport.newString;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class NetscapeSPKI extends RubyObject {
    private static final long serialVersionUID = 3211242351810109432L;

    private static final Logger LOG = Logger.getLogger(NetscapeSPKI.class);

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
            catch (GeneralSecurityException|IllegalArgumentException e) {
                throw newSPKIError(e);
            }

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
            return newString(getRuntime(), toDER());
        } catch (Exception ex) {
            throw newSPKIError(ex);
        }
    }

    @JRubyMethod(name = { "to_pem", "to_s" })
    public IRubyObject to_pem() {
        try {
            byte[] derBytes = toDER(); // no Base64.DO_BREAK_LINES option needed for NSPKI
            return newString(getRuntime(), Base64.encodeBytesToBytes(derBytes));
        } catch (Exception ex) {
            throw newSPKIError(ex);
        }
    }

    private byte[] toDER() throws IOException {
        return ((NetscapeCertRequest) cert).toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    @JRubyMethod
    public IRubyObject to_text(ThreadContext context) {
        final Ruby runtime = context.runtime;

        final StringBuilder text = new StringBuilder(256);
        text.append("Netscape SPKI:\n");

        final NetscapeCertRequest cert = (NetscapeCertRequest) this.cert;
        if (cert == null) return newString(runtime, text);

        // public key algorithm
        final AlgorithmIdentifier keyAlg = cert.getKeyAlgorithm();
        final String keyAlgName = resolveAlgorithmName(runtime, keyAlg);
        text.append("  Public Key Algorithm: ").append(keyAlgName).append('\n');

        if (public_key instanceof PKey) {
            try {
                final RubyString keyText = ((PKey) public_key).to_text();
                for (CharSequence line : StringHelper.split(keyText, '\n')) {
                    text.append("    ").append(line).append('\n');
                }
            } catch (Exception ex) {
                LOG.debug(runtime, "to_text unable to load public key", ex);
                text.append("    Unable to load public key\n");
            }
        }

        final String challenge = cert.getChallenge();
        if (challenge != null && !challenge.isEmpty()) {
            text.append("  Challenge String: ").append(challenge).append('\n');
        }

        final AlgorithmIdentifier sigAlg = cert.getSigningAlgorithm();
        final String sigAlgName = resolveAlgorithmName(runtime, sigAlg);
        text.append("  Signature Algorithm: ").append(sigAlgName);

        // signature bytes as hex with : separators, 18 bytes per line
        final byte[] sig = cert.getSignatureBits();
        if (sig != null) {
            for (int i = 0; i < sig.length; i++) {
                if (i % 18 == 0) text.append("\n      ");
                text.append(String.format("%02x", sig[i] & 0xFF));
                if (i + 1 < sig.length) text.append(':');
            }
        }
        text.append('\n');

        return newString(runtime, text);
    }

    private static String resolveAlgorithmName(final Ruby runtime, final AlgorithmIdentifier algId) {
        if (algId == null) return null;
        try {
            final String name = ASN1.oid2name(runtime, algId.getAlgorithm(), true);
            if (name != null) return name;
        } catch (Exception ex) {
            LOG.debug(runtime, "Failed to resolve algorithm name: " + algId, ex);
        }
        return algId.getAlgorithm().getId();
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
            final ASN1ObjectIdentifier alg = ASN1.getObjectID( getRuntime(), symKey );
            final PublicKey publicKey = ( (PKey) this.public_key ).getPublicKey();
            final String challengeStr = challenge.toString();
            final NetscapeCertRequest cert;
            this.cert = cert = new NetscapeCertRequest(challengeStr, new AlgorithmIdentifier(alg), publicKey);
            cert.sign( ((PKey) key).getPrivateKey() );
        }
        catch (GeneralSecurityException ex) {
            LOG.debugStack(getRuntime(), "sign", ex);
            throw newSPKIError(ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(getRuntime(), ex);
        }
        return this;
    }

    @JRubyMethod
    public IRubyObject verify(final IRubyObject pkey) {
        final NetscapeCertRequest cert = (NetscapeCertRequest) this.cert;
        try {
            final PublicKey publicKey = ((PKey) pkey).getPublicKey();
            boolean result = cert.verify(publicKey);
            return getRuntime().newBoolean(result);
        }
        catch (GeneralSecurityException ex) {
            LOG.debugStack(getRuntime(), "verify", ex);
            throw newSPKIError(ex);
        }
        catch (Throwable ex) {
            return handlePotentialOperationError(getRuntime(), ex);
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

    private RaiseException newSPKIError(final Exception ex) {
        final Ruby runtime = getRuntime();
        return newError(runtime, _Netscape(runtime).getClass("SPKIError"), ex);
    }

}// NetscapeSPKI
