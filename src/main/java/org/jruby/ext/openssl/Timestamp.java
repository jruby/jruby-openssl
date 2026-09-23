/*
 * The MIT License
 *
 * Copyright (C) 2026 Karol Bucek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.openssl.log.Logger;
import org.jruby.ext.openssl.util.RubySupport;
import org.jruby.ext.openssl.x509store.X509AuxCertificate;
import org.jruby.ext.openssl.x509store.Purpose;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

import static org.jruby.ext.openssl.ASN1.newASN1Error;
import static org.jruby.ext.openssl.PKCS7._PKCS7;
import static org.jruby.ext.openssl.X509._X509;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_PURPOSE_TIMESTAMP_SIGN;
import static org.jruby.ext.openssl.util.RubySupport.newError;

public final class Timestamp {
    private static final Logger LOG = Logger.getLogger(Timestamp.class);

    private Timestamp() { }

    static void createTimestamp(final Ruby runtime, final RubyModule OpenSSL, final RubyClass OpenSSLError) {
        final RubyModule timestamp = OpenSSL.defineModuleUnder("Timestamp");
        timestamp.defineClassUnder("TimestampError", OpenSSLError, OpenSSLError.getAllocator());

        final RubyClass request = timestamp.defineClassUnder("Request", runtime.getObject(), Request::new);
        request.defineAnnotatedMethods(Request.class);

        final RubyClass response = timestamp.defineClassUnder("Response", runtime.getObject(), Response::new);
        response.defineAnnotatedMethods(Response.class);

        response.setConstant("GRANTED", runtime.newFixnum(0));
        response.setConstant("GRANTED_WITH_MODS", runtime.newFixnum(1));
        response.setConstant("REJECTION", runtime.newFixnum(2));
        response.setConstant("WAITING", runtime.newFixnum(3));
        response.setConstant("REVOCATION_WARNING", runtime.newFixnum(4));
        response.setConstant("REVOCATION_NOTIFICATION", runtime.newFixnum(5));

        final RubyClass tokenInfo = timestamp.defineClassUnder("TokenInfo", runtime.getObject(), TokenInfo::new);
        tokenInfo.defineAnnotatedMethods(TokenInfo.class);

        final RubyClass factory = timestamp.defineClassUnder("Factory", runtime.getObject(), Factory::new);
        factory.defineAnnotatedMethods(Factory.class);
    }

    static RubyModule _Timestamp(final Ruby runtime) {
        return (RubyModule) runtime.getModule("OpenSSL").getConstantAt("Timestamp");
    }

    static RubyClass _TimestampError(final Ruby runtime) {
        return _Timestamp(runtime).getClass("TimestampError");
    }

    static RaiseException newTimestampError(final Ruby runtime, final Throwable cause) {
        return newError(runtime, _TimestampError(runtime), cause);
    }

    static RaiseException newTimestampError(final Ruby runtime, final String message) {
        return newError(runtime, _TimestampError(runtime), message);
    }

    static ASN1ObjectIdentifier oid(final Ruby runtime, final IRubyObject value) {
        try {
            return ASN1.getObjectID(runtime, value.convertToString().asJavaString());
        } catch (IllegalArgumentException e) {
            throw newASN1Error(runtime, e);
        }
    }

    public static final class Request extends RubyObject {

        private TimeStampReq timeStampReq;
        private int version = 1;
        private ASN1ObjectIdentifier algorithm;
        private byte[] messageImprint;
        private ASN1ObjectIdentifier policyId;
        private BigInteger nonce;
        private boolean certRequested = true;
        private Extensions extensions;

        Request(final Ruby runtime, final RubyClass type) { super(runtime, type); }

        @JRubyMethod(name = "initialize", rest = true, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject[] args) {
            if (Arity.checkArgumentCount(context.runtime, args, 0, 1) == 0) return this;

            final RubyString input = StringHelper.readPossibleDERInput(context, args[0]);
            try {
                timeStampReq = TimeStampReq.getInstance(ASN1Primitive.fromByteArray(input.getBytes()));
                version = timeStampReq.getVersion().intValueExact();
                final MessageImprint imprint = timeStampReq.getMessageImprint();
                algorithm = imprint.getHashAlgorithm().getAlgorithm();
                messageImprint = imprint.getHashedMessage();
                policyId = timeStampReq.getReqPolicy();
                nonce = timeStampReq.getNonce() == null ? null : timeStampReq.getNonce().getValue();
                certRequested = timeStampReq.getCertReq() != null && timeStampReq.getCertReq().isTrue();
                extensions = timeStampReq.getExtensions();
                return this;
            } catch (IOException e) {
                LOG.debug(context.runtime, "timestamp request decode failed", e);
                throw newTimestampError(context.runtime, "Error when decoding the timestamp request: " + e.getMessage());
            } catch (RuntimeException e) {
                LOG.debug(context.runtime, "timestamp request decode failed", e);
                throw newTimestampError(context.runtime, e);
            }
        }

        TimeStampReq timeStampReq() {
            if (timeStampReq != null) return timeStampReq;

            if (algorithm == null) {
                throw newTimestampError(getRuntime(), "Message imprint missing algorithm");
            }
            if (messageImprint == null || messageImprint.length == 0) {
                throw newTimestampError(getRuntime(), "Message imprint missing hashed message");
            }

            final MessageImprint imprint = new MessageImprint(new AlgorithmIdentifier(algorithm), messageImprint);
            final TimeStampReq result;
            if (version == 1) {
                result = new TimeStampReq(imprint, policyId,
                        nonce == null ? null : new ASN1Integer(nonce),
                        certRequested ? ASN1Boolean.TRUE : null, extensions
                );
            }
            else {
                final ASN1EncodableVector values = new ASN1EncodableVector();
                values.add(new ASN1Integer(BigInteger.valueOf(version)));
                values.add(imprint);
                if (policyId != null) values.add(policyId);
                if (nonce != null) values.add(new ASN1Integer(nonce));
                if (certRequested) values.add(ASN1Boolean.TRUE);
                if (extensions != null) values.add(new DERTaggedObject(false, 0, extensions));
                result = TimeStampReq.getInstance(new DERSequence(values));
            }
            timeStampReq = result;
            return result;
        }

        TimeStampRequest asn1RequestObject() throws IOException {
            return new TimeStampRequest(timeStampReq().getEncoded());
        }

        private void markChanged() { timeStampReq = null; }

        @JRubyMethod
        public IRubyObject algorithm(ThreadContext context) {
            if (algorithm == null) return context.runtime.newString("NULL");
            return context.runtime.newString(ASN1.shortName(context.runtime, algorithm));
        }

        @JRubyMethod(name = "algorithm=")
        public IRubyObject set_algorithm(final IRubyObject value) {
            algorithm = oid(getRuntime(), value);
            markChanged();
            return value;
        }

        @JRubyMethod(name = "cert_requested?")
        public IRubyObject cert_requested_p() {
            return getRuntime().newBoolean(certRequested);
        }

        @JRubyMethod(name = "cert_requested=")
        public IRubyObject set_cert_requested(final IRubyObject value) {
            certRequested = value.isTrue();
            markChanged();
            return value;
        }

        @JRubyMethod
        public IRubyObject message_imprint(ThreadContext context) {
            if (messageImprint == null) return context.runtime.newString("");
            return RubyString.newString(context.runtime, messageImprint);
        }

        @JRubyMethod(name = "message_imprint=")
        public IRubyObject set_message_imprint(final IRubyObject value) {
            messageImprint = value.convertToString().getBytes();
            markChanged();
            return value;
        }

        @JRubyMethod
        public IRubyObject nonce(ThreadContext context) {
            if (nonce == null) return context.nil;
            return BN.newBN(context.runtime, nonce);
        }

        @JRubyMethod(name = "nonce=")
        public IRubyObject set_nonce(final IRubyObject value) {
            if (value.isNil()) throw getRuntime().newTypeError("can't convert nil into Integer");
            nonce = BN.asBigInteger(value);
            markChanged();
            return value;
        }

        @JRubyMethod
        public IRubyObject policy_id(ThreadContext context) {
            final Ruby runtime = context.runtime;
            return policyId == null ? context.nil : runtime.newString(ASN1.shortName(runtime, policyId));
        }

        @JRubyMethod(name = "policy_id=")
        public IRubyObject set_policy_id(final IRubyObject value) {
            if (value.isNil()) throw getRuntime().newTypeError(value, "String");
            policyId = oid(getRuntime(), value);
            markChanged();
            return value;
        }

        @JRubyMethod
        public IRubyObject to_der(ThreadContext context) {
            try {
                return RubySupport.newString(context.runtime, timeStampReq().getEncoded());
            } catch (Exception e) {
                throw newTimestampError(getRuntime(), e);
            }
        }

        @JRubyMethod(name = "to_text")
        public IRubyObject to_text() {
            final StringBuilder text = new StringBuilder();
            text.append("Version: ").append(version).append('\n');
            text.append("Hash Algorithm: ").append(algorithm == null ? "(none)" : ASN1.shortName(getRuntime(), algorithm)).append('\n');
            if (policyId != null) text.append("Policy OID: ").append(policyId.getId()).append('\n');
            if (nonce != null) text.append("Nonce: ").append(nonce).append('\n');
            text.append("Certificate required: ").append(certRequested).append('\n');
            return getRuntime().newString(text.toString());
        }

        @JRubyMethod
        public IRubyObject version() { return getRuntime().newFixnum(version); }

        @JRubyMethod(name = "version=")
        public IRubyObject set_version(final IRubyObject value) {
            final int v = RubyNumeric.num2int(value);
            if (v < 0) throw newTimestampError(getRuntime(), "version must be >= 0!");
            version = v;
            markChanged();
            return value;
        }
    }

    public static final class Response extends RubyObject {

        private TimeStampResponse response;

        Response(final Ruby runtime, final RubyClass type) { super(runtime, type); }

        Response(final Ruby runtime, TimeStampResponse response) {
            this(runtime, (RubyClass) _Timestamp(runtime).getConstantAt("Response"));
            this.response = response;
        }

        @JRubyMethod(name = "initialize", required = 1, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject value) {
            final RubyString input = StringHelper.readPossibleDERInput(context, value);
            try {
                response = new TimeStampResponse(TimeStampResp.getInstance(ASN1Primitive.fromByteArray(input.getBytes())));
                return this;
            } catch (Exception e) {
                LOG.debug(context.runtime, "response decoding failed", e);
                throw newTimestampError(context.runtime, "Error when decoding the timestamp response: " + e.getMessage());
            }
        }

        @JRubyMethod
        public IRubyObject failure_info() {
            if (response.getFailInfo() == null) return getRuntime().getNil();
            final int bits = response.getFailInfo().intValue();
            if ((bits & PKIFailureInfo.badAlg) != 0) return getRuntime().newSymbol("BAD_ALG");
            if ((bits & PKIFailureInfo.badRequest) != 0) return getRuntime().newSymbol("BAD_REQUEST");
            if ((bits & PKIFailureInfo.badDataFormat) != 0) return getRuntime().newSymbol("BAD_DATA_FORMAT");
            if ((bits & PKIFailureInfo.timeNotAvailable) != 0) return getRuntime().newSymbol("TIME_NOT_AVAILABLE");
            if ((bits & PKIFailureInfo.unacceptedPolicy) != 0) return getRuntime().newSymbol("UNACCEPTED_POLICY");
            if ((bits & PKIFailureInfo.unacceptedExtension) != 0) return getRuntime().newSymbol("UNACCEPTED_EXTENSION");
            if ((bits & PKIFailureInfo.addInfoNotAvailable) != 0) return getRuntime().newSymbol("ADD_INFO_NOT_AVAILABLE");
            if ((bits & PKIFailureInfo.systemFailure) != 0) return getRuntime().newSymbol("SYSTEM_FAILURE");
            throw newTimestampError(getRuntime(), "Unrecognized failure info");
        }

        @JRubyMethod
        public IRubyObject status(ThreadContext context) {
            return BN.newBN(context.runtime, BigInteger.valueOf(response.getStatus()));
        }

        @JRubyMethod
        public IRubyObject status_text(ThreadContext context) {
            final Ruby runtime = context.runtime;
            try {
                final TimeStampResp encoded = TimeStampResp.getInstance(ASN1Primitive.fromByteArray(response.getEncoded()));
                final RubyArray result = runtime.newArray();
                if (encoded.getStatus().getStatusString() != null) {
                    final ASN1Sequence strings = (ASN1Sequence) encoded.getStatus().getStatusString().toASN1Primitive();
                    for (int i = 0; i < strings.size(); i++) {
                        result.append(runtime.newString(((ASN1String) strings.getObjectAt(i)).getString()));
                    }
                }
                return result;
            } catch (IOException e) {
                throw newTimestampError(runtime, e);
            }
        }

        @JRubyMethod
        public IRubyObject to_der(ThreadContext context) {
            try {
                return RubySupport.newString(context.runtime, response.getEncoded());
            } catch (Exception e) {
                throw newTimestampError(context.runtime, e);
            }
        }

        @JRubyMethod(name = "to_text")
        public IRubyObject to_text() {
            final StringBuilder text = new StringBuilder();
            text.append("Status: ").append(response.getStatus()).append('\n');
            if (response.getStatusString() != null) text.append(response.getStatusString()).append('\n');
            final TimeStampToken token = response.getTimeStampToken();
            if (token != null) {
                final TokenInfo info = new TokenInfo(getRuntime(), (RubyClass) _Timestamp(getRuntime()).getConstantAt("TokenInfo"));
                info.info = token.getTimeStampInfo().toASN1Structure();
                text.append(info.text());
            }
            return RubyString.newString(getRuntime(), text);
        }

        @JRubyMethod
        public IRubyObject token(ThreadContext context) {
            final TimeStampToken token = response.getTimeStampToken();
            if (token == null) return context.nil;
            try {
                final byte[] tokenData = token.toCMSSignedData().getEncoded();
                return _PKCS7(context.runtime).newInstance(context, // OpenSSL::PKCS7.new
                        RubySupport.newString(context.runtime, tokenData),
                        Block.NULL_BLOCK
                );
            }
            catch (Exception e) { throw newTimestampError(context.runtime, e); }
        }

        @JRubyMethod
        public IRubyObject token_info(ThreadContext context) {
            final TimeStampToken token = response.getTimeStampToken();
            if (token == null) return context.nil;
            final Ruby runtime = context.runtime;
            try {
                final TokenInfo result = new TokenInfo(runtime, (RubyClass) _Timestamp(runtime).getConstantAt("TokenInfo"));
                result.info = token.getTimeStampInfo().toASN1Structure();
                return result;
            }
            catch (Exception e) { throw newTimestampError(runtime, e); }
        }

        @JRubyMethod
        public IRubyObject tsa_certificate(final ThreadContext context) {
            final X509CertificateHolder holder = signerCertificate();
            if (holder == null) return context.nil;
            try { return X509Cert.wrap(context, holder.getEncoded()); }
            catch (Exception e) { throw newTimestampError(context.runtime, e); }
        }

        private X509CertificateHolder signerCertificate() {
            final TimeStampToken token = response.getTimeStampToken();
            if (token == null) return null;
            final Collection<?> matches = token.getCertificates().getMatches(token.getSID());
            return matches.isEmpty() ? null : (X509CertificateHolder) matches.iterator().next();
        }

        @JRubyMethod(name = "verify", required = 2, optional = 1)
        public IRubyObject verify(final ThreadContext context, final IRubyObject[] args) {
            if (!(args[0] instanceof Request)) throw context.runtime.newTypeError(args[0], "OpenSSL::Timestamp::Request");
            if (!(args[1] instanceof X509Store)) throw context.runtime.newTypeError(args[1], "OpenSSL::X509::Store");
            final Request request = (Request) args[0];
            final X509Store store = (X509Store) args[1];
            final IRubyObject intermediates = args.length == 3 ? args[2] : context.nil;

            final RubyArray chain = context.runtime.newArray();
            if (!intermediates.isNil()) {
                if (!(intermediates instanceof RubyArray)) throw context.runtime.newTypeError(intermediates, "Array");
                final RubyArray certs = (RubyArray) intermediates;
                for (int i = 0; i < certs.size(); i++) {
                    final IRubyObject cert = certs.eltInternal(i);
                    if (!(cert instanceof X509Cert)) throw context.runtime.newTypeError(cert, "OpenSSL::X509::Certificate");
                    chain.append(cert);
                }
            }
            try {
                final TimeStampToken token = response.getTimeStampToken();
                if (token == null) throw newTimestampError(context.runtime, "timestamp response contains no token");
                response.validate(request.asn1RequestObject());
                if (token.getTimeStampInfo().toASN1Structure().getVersion().intValueExact() != 1) {
                    throw newTimestampError(context.runtime, "unsupported timestamp token version");
                }

                for (Object entry : token.getCertificates().getMatches(null)) {
                    chain.append(X509Cert.wrap(context, ((X509CertificateHolder) entry).getEncoded()));
                }
                X509Cert tsa = null;
                X509CertificateHolder signer = null;
                for (int i = 0; i < chain.size(); i++) {
                    final X509Cert candidate = (X509Cert) chain.eltInternal(i);
                    final X509CertificateHolder holder = new X509CertificateHolder(candidate.getCert().getEncoded());
                    if (token.getSID().match(holder)) {
                        tsa = candidate;
                        signer = holder;
                        break;
                    }
                }
                if (signer == null) throw newTimestampError(context.runtime, "timestamp response contains no signer certificate");
                if (!matchesTsaName(token, signer)) {
                    throw newTimestampError(context.runtime, "timestamp authority name does not match signer certificate");
                }
                final Provider provider = SecurityHelper.getSecurityProvider();
                final JcaSimpleSignerInfoVerifierBuilder verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
                if (provider != null) verifierBuilder.setProvider(provider);
                final SignerInformationVerifier verifier = verifierBuilder.build(signer);
                token.validate(verifier);

                final X509StoreContext storeContext = X509StoreContext.newStoreContext(context, store, tsa, chain);
                storeContext.set_purpose(context, context.runtime.newFixnum(X509_PURPOSE_TIMESTAMP_SIGN));
                if (!storeContext.verify(context).isTrue()) {
                    throw newTimestampError(context.runtime, "timestamp certificate chain validation failed: " +
                            storeContext.error_string(context).asJavaString());
                }
                return this;
            }
            catch (RaiseException e) { throw e; }
            catch (Exception e) {
                LOG.debug(context.runtime, "response verification failed", e);
                throw newTimestampError(context.runtime, e);
            }
        }

        private boolean matchesTsaName(final TimeStampToken token, final X509CertificateHolder signer) {
            final GeneralName tsa = token.getTimeStampInfo().toASN1Structure().getTsa();
            if (tsa == null) return true;
            if (tsa.getTagNo() == GeneralName.directoryName) {
                return X500Name.getInstance(tsa.getName()).equals(signer.getSubject());
            }

            final Extension subjectAltName = signer.getExtension(Extension.subjectAlternativeName);
            if (subjectAltName == null) return false;
            for (GeneralName name : GeneralNames.getInstance(subjectAltName.getParsedValue()).getNames()) {
                if (tsa.equals(name)) return true;
            }
            return false;
        }

    }

    public static final class TokenInfo extends RubyObject {

        private TSTInfo info;

        TokenInfo(final Ruby runtime, final RubyClass type) { super(runtime, type); }

        @JRubyMethod(name = "initialize", required = 1, visibility = Visibility.PRIVATE)
        public IRubyObject initialize(final ThreadContext context, final IRubyObject value) {
            final RubyString input = StringHelper.readPossibleDERInput(context, value);
            try {
                info = TSTInfo.getInstance(ASN1Primitive.fromByteArray(input.getBytes()));
                if (info == null) throw new IOException("empty timestamp token info");
                return this;
            } catch (Exception e) {
                LOG.debug(context.runtime, "token info decode failed", e);
                throw newTimestampError(context.runtime, "Error when decoding the timestamp token info: " + e.getMessage());
            }
        }

        @JRubyMethod
        public IRubyObject algorithm() {
            AlgorithmIdentifier algId = info.getMessageImprint().getHashAlgorithm();
            return getRuntime().newString(ASN1.shortName(getRuntime(), algId.getAlgorithm()));
        }

        @JRubyMethod
        public IRubyObject gen_time(ThreadContext context) {
            try {
                final Date genTime = info.getGenTime().getDate();
                return genTime == null ? context.nil : RubyTime.newTime(context.runtime, genTime.getTime()).gmtime();
            } catch (Exception e) { // ParseException
                throw newTimestampError(context.runtime, e);
            }
        }

        @JRubyMethod(name = "message_imprint", alias = "msg_imprint")
        public IRubyObject message_imprint() { return RubyString.newString(getRuntime(), info.getMessageImprint().getHashedMessage()); }

        @JRubyMethod
        public IRubyObject nonce(ThreadContext context) {
            if (info.getNonce() == null) return context.nil;
            return BN.newBN(context.runtime, info.getNonce().getValue());
        }

        @JRubyMethod
        public IRubyObject ordering() {
            return getRuntime().newBoolean(info.getOrdering() != null && info.getOrdering().isTrue());
        }

        @JRubyMethod
        public IRubyObject policy_id() {
            return getRuntime().newString(ASN1.shortName(getRuntime(), info.getPolicy()));
        }

        @JRubyMethod
        public IRubyObject serial_number() {
            return BN.newBN(getRuntime(), info.getSerialNumber().getValue());
        }

        @JRubyMethod
        public IRubyObject to_der(ThreadContext context) {
            try {
                return RubySupport.newString(context.runtime, info.getEncoded());
            } catch (IOException e) {
                throw newTimestampError(context.runtime, e);
            }
        }

        @JRubyMethod(name = "to_text")
        public RubyString to_text() {
            return getRuntime().newString(text());
        }

        private String text() {
            final StringBuilder text = new StringBuilder();
            text.append("Version: ").append(info.getVersion().getValue()).append('\n');
            text.append("Policy OID: ").append(info.getPolicy().getId()).append('\n');
            text.append("Hash Algorithm: ").append(ASN1.shortName(getRuntime(), info.getMessageImprint().getHashAlgorithm().getAlgorithm())).append('\n');
            text.append("Message data: ").append(Hex.toHexString(info.getMessageImprint().getHashedMessage())).append('\n');
            text.append("Serial number: ").append(info.getSerialNumber().getValue()).append('\n');
            text.append("Time stamp: ").append(info.getGenTime().getTimeString()).append('\n');
            return text.toString();
        }

        @JRubyMethod
        public IRubyObject version() {
            return getRuntime().newFixnum(info.getVersion().intValueExact());
        }
    }

    public static final class Factory extends RubyObject {
        Factory(final Ruby runtime, final RubyClass type) {
            super(runtime, type);
        }

        @JRubyMethod(visibility = Visibility.PRIVATE)
        public IRubyObject initialize() { return this; }

        @JRubyMethod
        public IRubyObject default_policy_id() {
            return attribute("@default_policy_id");
        }

        @JRubyMethod(name = "default_policy_id=")
        public IRubyObject set_default_policy_id(final IRubyObject value) {
            setInstanceVariable("@default_policy_id", value);
            return value;
        }

        @JRubyMethod
        public IRubyObject serial_number() {
            return attribute("@serial_number");
        }

        @JRubyMethod(name = "serial_number=")
        public IRubyObject set_serial_number(final IRubyObject value) {
            setInstanceVariable("@serial_number", value);
            return value;
        }

        @JRubyMethod
        public IRubyObject gen_time() {
            return attribute("@gen_time");
        }

        @JRubyMethod(name = "gen_time=")
        public IRubyObject set_gen_time(final IRubyObject value) {
            setInstanceVariable("@gen_time", value);
            return value;
        }

        @JRubyMethod
        public IRubyObject additional_certs() {
            return attribute("@additional_certs");
        }

        @JRubyMethod(name = "additional_certs=")
        public IRubyObject set_additional_certs(final IRubyObject value) {
            setInstanceVariable("@additional_certs", value);
            return value;
        }

        @JRubyMethod
        public IRubyObject allowed_digests() {
            return attribute("@allowed_digests");
        }

        @JRubyMethod(name = "allowed_digests=")
        public IRubyObject set_allowed_digests(final IRubyObject value) {
            setInstanceVariable("@allowed_digests", value);
            return value;
        }

        private IRubyObject attribute(final String name) {
            final IRubyObject value = getInstanceVariable(name);
            return value == null ? getRuntime().getNil() : value;
        }

        @JRubyMethod
        public IRubyObject create_timestamp(final ThreadContext context, final IRubyObject key,
                                            final IRubyObject certificate, final IRubyObject request) {
            final Ruby runtime = context.runtime;
            if (!(key instanceof PKey) || !(certificate instanceof X509Cert) || !(request instanceof Request)) {
                throw runtime.newTypeError("expected OpenSSL::PKey, OpenSSL::X509::Certificate, OpenSSL::Timestamp::Request");
            }

            final PKey pkey = (PKey) key;
            final X509Cert cert = (X509Cert) certificate;
            final Request req = (Request) request;
            final IRubyObject serialNumber = serial_number();
            final IRubyObject genTime = gen_time();
            final IRubyObject defaultPolicy = default_policy_id();
            final IRubyObject additionalCerts = additional_certs();
            final IRubyObject allowedDigests = allowed_digests();

            final X509AuxCertificate auxCert = cert.getAuxCert();
            if (!isTimestampingCertificate(auxCert)) {
                throw newTimestampError(runtime, "Certificate does not contain the timestamping extension");
            }
            if (serialNumber == null || serialNumber.isNil()) throw newTimestampError(runtime, "@serial_number must be set");
            if (genTime == null || genTime.isNil()) throw newTimestampError(runtime, "@gen_time must be set");

            if (req.policyId == null && (defaultPolicy == null || defaultPolicy.isNil())) {
                throw newTimestampError(runtime, "No policy id in the request and no default policy set");
            }

            try {
                final Provider provider = SecurityHelper.getSecurityProvider();
                if (pkey.getPrivateKey() == null) throw newTimestampError(runtime, "private key is required");

                final String signatureAlgorithm = signatureAlgorithm("SHA256", pkey.getAlgorithm());
                final JcaSimpleSignerInfoGeneratorBuilder signerBuilder = new JcaSimpleSignerInfoGeneratorBuilder();
                if (provider != null) signerBuilder.setProvider(provider);
                final X509CertificateHolder certHolder = new X509CertificateHolder(auxCert.getEncoded());
                final SignerInfoGenerator signer = signerBuilder.build(signatureAlgorithm, pkey.getPrivateKey(), certHolder);

                final JcaDigestCalculatorProviderBuilder digestBuilder = new JcaDigestCalculatorProviderBuilder();
                if (provider != null) digestBuilder.setProvider(provider);
                final DigestCalculatorProvider digestProvider = digestBuilder.build();
                final DigestCalculator digestCalculator = digestProvider.get(new AlgorithmIdentifier(TSPAlgorithms.SHA256));
                final ASN1ObjectIdentifier policy = req.policyId != null ? req.policyId : oid(runtime, defaultPolicy);
                final TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(signer, digestCalculator, policy);
                if (req.certRequested) {
                    tokenGenerator.addCertificates(new JcaCertStore(Collections.singletonList(auxCert)));
                    addAdditionalCertificates(runtime, tokenGenerator, additionalCerts);
                }

                final TimeStampRequest timestampRequest = req.asn1RequestObject();
                final BigInteger serial = BN.asBigInteger(serialNumber);
                final Date timeValue = RubySupport.timeToJavaDate(context, genTime);
                final Date time = new Date(Math.floorDiv(timeValue.getTime(), 1000L) * 1000L);
                final TimeStampResponseGenerator generator = new TimeStampResponseGenerator(
                        tokenGenerator,
                        acceptedAlgorithms(runtime, allowedDigests),
                        null,
                        Collections.emptySet()
                );

                TimeStampResponse response;
                try {
                    if (timestampRequest.getVersion() != 1) {
                        throw new TSPValidationException("unsupported request version", PKIFailureInfo.badRequest);
                    }
                    if (!cert.check_private_key(key).isTrue()) {
                        response = generator.generateFailResponse(2, 0, "Error during signature generation.");
                    } else {
                        response = generator.generateGrantedResponse(timestampRequest, serial, time);
                    }
                } catch (TSPValidationException e) {
                    response = generator.generateRejectedResponse(e);
                }

                return new Response(runtime, response);
            } catch (RaiseException e) {
                throw e;
            } catch (Exception e) {
                LOG.debugStack(runtime, "timestamp creation failed", e);
                throw newTimestampError(runtime, e);
            }
        }

        private void addAdditionalCertificates(final Ruby runtime,
                                               final TimeStampTokenGenerator generator,
                                               final IRubyObject additionalCerts) throws CertificateEncodingException {
            if (!(additionalCerts instanceof RubyArray)) return;

            final RubyArray certs = additionalCerts.convertToArray();
            final List<X509Certificate> values = new ArrayList<>(certs.size());
            for (int i = 0; i < certs.size(); i++) {
                if (!(certs.eltInternal(i) instanceof X509Cert)) {
                    throw runtime.newTypeError(certs.eltInternal(i), _X509(runtime).getClass("Certificate"));
                }
                values.add(((X509Cert) certs.eltInternal(i)).getAuxCert());
            }
            generator.addCertificates(new JcaCertStore(values));
        }

        private boolean isTimestampingCertificate(final X509AuxCertificate certificate) {
            try {
                return Purpose.checkPurpose(certificate, X509_PURPOSE_TIMESTAMP_SIGN, 0) == 1;
            } catch (CertificateException e) {
                LOG.debug(getRuntime(), "timestamp certificate purpose check failed", e);
                throw newTimestampError(getRuntime(), e);
            }
        }

        private Set<ASN1ObjectIdentifier> acceptedAlgorithms(final Ruby runtime, final IRubyObject allowedDigests) {
            final Set<ASN1ObjectIdentifier> result = new HashSet<>();
            if (!(allowedDigests instanceof RubyArray)) return result;
            final RubyArray values = (RubyArray) allowedDigests;
            for (int i = 0; i < values.size(); i++) {
                final IRubyObject value = values.eltInternal(i);
                final String name = value instanceof Digest ? ((Digest) value).getShortAlgorithm() : value.convertToString().asJavaString();
                result.add(oid(runtime, runtime.newString(name)));
            }
            return result;
        }

        private static String signatureAlgorithm(final String digest, final String keyAlgorithm) {
            final String key = "EC".equalsIgnoreCase(keyAlgorithm) ? "ECDSA" : keyAlgorithm;
            return digest + "WITH" + key;
        }
    }
}
