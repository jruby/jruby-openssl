/*
 * Copyright (c) 2016 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl.impl;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * a trick to keep the curve name around
 * (since {@link java.security.KeyPair} is final).
 *
 * @author kares
 */
public final class ECPrivateKeyWithName implements ECPrivateKey {

    private final ECPrivateKey realKey;
    // private final String curveNameId;
    private final ASN1ObjectIdentifier curveNameOID;

    public static ECPrivateKeyWithName wrap(ECPrivateKey realKey, ASN1ObjectIdentifier nameOID) {
        return new ECPrivateKeyWithName(realKey, nameOID);
    }

    private ECPrivateKeyWithName(ECPrivateKey realKey, ASN1ObjectIdentifier nameOID) {
        this.realKey = realKey; this.curveNameOID = nameOID;
    }

    //private ECPrivateKeyWithName(ECPrivateKey realKey, String curveNameId) {
    //    this.realKey = realKey;
    //    this.curveNameId = curveNameId;
    //}

    //public String getCurveNameId() {
    //    return curveNameId;
    //}

    public ASN1ObjectIdentifier getCurveNameOID() {
        return curveNameOID;
    }

    public ECPrivateKey unwrap() {
        return realKey;
    }

    public BigInteger getS() {
        return realKey.getS();
    }

    public String getAlgorithm() {
        return realKey.getAlgorithm();
    }

    public String getFormat() {
        return realKey.getFormat();
    }

    public byte[] getEncoded() {
        return realKey.getEncoded();
    }

    public ECParameterSpec getParams() {
        return realKey.getParams();
    }

    @Override
    public String toString() {
        return realKey.toString();
    }

}
