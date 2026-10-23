/*
 * Copyright (c) 2026 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Lets provider key managers handle TLS algorithms, issuers and security constraints,
 * while preserving opaque and (FIPS) key objects without encoding or reconstructing.
 * @author kares
 */
final class SSLKeyStore extends KeyStore {

    SSLKeyStore(Map<String, PrivateKeyEntry> entries) throws GeneralSecurityException, IOException {
        super(new Store(entries), null, "JOSSL");
        load(null, null); // marks the store initialized through spi.engineLoad
    }

    private static final class Store extends KeyStoreSpi {
        private final Map<String, PrivateKeyEntry> entries;

        Store(Map<String, PrivateKeyEntry> entries) {
            this.entries = entries;
        }

        @Override
        public Key engineGetKey(String alias, char[] password) {
            PrivateKeyEntry entry = entries.get(alias);
            return entry == null ? null : entry.getPrivateKey();
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            PrivateKeyEntry entry = entries.get(alias);
            return entry == null ? null : entry.getCertificateChain();
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            PrivateKeyEntry entry = entries.get(alias);
            return entry == null ? null : entry.getCertificate();
        }

        @Override
        public Date engineGetCreationDate(String alias) {
            return entries.containsKey(alias) ? new Date(0) : null;
        }

        @Override
        public Enumeration<String> engineAliases() {
            return Collections.enumeration(entries.keySet());
        }

        @Override
        public boolean engineContainsAlias(String alias) {
            return entries.containsKey(alias);
        }

        @Override
        public int engineSize() {
            return entries.size();
        }

        @Override
        public boolean engineIsKeyEntry(String alias) {
            return entries.containsKey(alias);
        }

        @Override
        public boolean engineIsCertificateEntry(String alias) {
            return false;
        }

        @Override
        public String engineGetCertificateAlias(Certificate cert) {
            for (Map.Entry<String, PrivateKeyEntry> entry : entries.entrySet()) {
                if (entry.getValue().getCertificate().equals(cert)) return entry.getKey();
            }
            return null;
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
            throw new KeyStoreException("read-only TLS credentials");
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
            throw new KeyStoreException("read-only TLS credentials");
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
            throw new KeyStoreException("read-only TLS credentials");
        }

        @Override
        public void engineDeleteEntry(String alias) throws KeyStoreException {
            throw new KeyStoreException("read-only TLS credentials");
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) {
            throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) {
            if (stream != null) throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineLoad(final LoadStoreParameter param) {
            engineLoad((InputStream) null, (char[]) null);
        }
    }
}
