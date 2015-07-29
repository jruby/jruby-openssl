package org.jruby.ext.openssl;

import java.security.*;

/**
 * Created by cmeier on 7/29/15.
 */
class SignatureSpiFake extends Signature {

    SignatureSpiFake() {
        super("fake");
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {

    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {

    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
