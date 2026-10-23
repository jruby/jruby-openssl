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
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;

/**
 * Lets provider key managers handle TLS algorithms, issuers and security constraints,
 * while preserving opaque and (FIPS) key objects without encoding or reconstructing.
 * @author kares
 */
final class SSLKeyStore extends KeyStore {

    static final class Entry {
        private final PrivateKey key;
        private final X509Certificate[] chain;

        Entry(PrivateKey key, X509Certificate[] chain) {
            this.key = key;
            this.chain = chain;
        }
    }

    SSLKeyStore(Map<String, Entry> entries) throws GeneralSecurityException, IOException {
        super(new Store(entries), null, "JOSSL");
        load(null, null); // so that the store is initialized (doe spi.engineLoad)
    }

    private static final class Store extends KeyStoreSpi {
        private final Map<String, Entry> entries; // we're using a LinkedHashMap

        Store(Map<String, Entry> entries) {
            this.entries = entries;
        }

        @Override
        public Key engineGetKey(String alias, char[] password) {
            Entry entry = entries.get(alias);
            return entry == null ? null : entry.key;
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            Entry entry = entries.get(alias);
            return entry == null ? null : entry.chain.clone();
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            Entry entry = entries.get(alias);
            return entry == null ? null : entry.chain[0];
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
            for (Map.Entry<String, Entry> entry : entries.entrySet()) {
                if (entry.getValue().chain[0].equals(cert)) return entry.getKey();
            }
            return null;
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
            throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
            throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) {
            throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineDeleteEntry(String alias) {
            throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) {
            throw new UnsupportedOperationException("read-only TLS credentials");
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) throws IOException {
            if (stream != null) throw new IOException("read-only TLS credentials");
        }

        @Override
        public void engineLoad(final LoadStoreParameter param) throws IOException {
            engineLoad((InputStream) null, (char[]) null);
        }
    }
}
