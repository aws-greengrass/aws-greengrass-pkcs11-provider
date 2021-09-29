/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;

import sun.security.jca.GetInstance;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

/**
 * The single key keystore which masks off the other keys in the underneath keystore.
 * e.g. KeyStore abstraction on TPM could incorporate multiple keys which are supposed to be used in different
 * use cases. Exposing the entire KeyStore could lead the use case picking up the key other than the desired
 * one (e.g. JSSE SSL negotiation would enumerate the keys and certs matching the filters, use the first one works),
 * this will cause customer losing insights of which key is actually used for the use case. Masking off the keys
 * other than the desired one would eliminate this ambiguity.
 */
@SuppressWarnings("PMD.DontImportSun")
class SingleKeyStore extends KeyStore {

    private SingleKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
    }

    @SuppressWarnings("PMD.SingletonClassReturningNewInstance")
    static KeyStore getInstance(Provider provider, String type, String keyLabel) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("Provider can't be null");
        }
        GetInstance.Instance instance = GetInstance.getInstance("KeyStore", KeyStoreSpi.class, type, provider);
        KeyStoreSpi keyStoreSpi = new SingleKeyStoreDecorator((KeyStoreSpi) instance.impl, keyLabel);
        return new SingleKeyStore(keyStoreSpi, instance.provider, type);
    }

    /**
     * Wrap around key store to at most have one specific key,
     * mask off the other keys existed in the underneath keystore.
     */
    static class SingleKeyStoreDecorator extends KeyStoreSpi {

        private final String keyLabel;
        private final KeyStoreSpi keyStoreSpi;

        SingleKeyStoreDecorator(KeyStoreSpi keyStoreSpi, String keyLabel) {
            super();
            this.keyStoreSpi = keyStoreSpi;
            this.keyLabel = keyLabel;
        }

        @Override
        public Key engineGetKey(String alias, char[] password)
                throws NoSuchAlgorithmException, UnrecoverableKeyException {
            if (!keyLabel.equals(alias)) {
                return null;
            }
            return keyStoreSpi.engineGetKey(alias, password);
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            if (!keyLabel.equals(alias)) {
                return new Certificate[0];
            }
            return keyStoreSpi.engineGetCertificateChain(alias);
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            return null;
        }

        @Override
        public Date engineGetCreationDate(String alias) {
            if (!keyLabel.equals(alias)) {
                return null;
            }
            return keyStoreSpi.engineGetCreationDate(alias);
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
                throws KeyStoreException {
            if (keyLabel.equals(alias)) {
                keyStoreSpi.engineSetKeyEntry(alias, key, password, chain);
            }
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
            if (keyLabel.equals(alias)) {
                keyStoreSpi.engineSetKeyEntry(alias, key, chain);
            }
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        }

        @Override
        public void engineDeleteEntry(String alias) throws KeyStoreException {
            if (keyLabel.equals(alias)) {
                keyStoreSpi.engineDeleteEntry(alias);
            }
        }

        @Override
        public Enumeration<String> engineAliases() {
            return engineContainsAlias(keyLabel) ? Collections.enumeration(Collections.singleton(keyLabel))
                    : Collections.emptyEnumeration();
        }


        @Override
        public boolean engineContainsAlias(String alias) {
            if (!keyLabel.equals(alias)) {
                return false;
            }
            return keyStoreSpi.engineContainsAlias(keyLabel);
        }

        @Override
        public int engineSize() {
            return engineContainsAlias(keyLabel) ? 1 : 0;
        }

        @Override
        public boolean engineIsKeyEntry(String alias) {
            if (!keyLabel.equals(alias)) {
                return false;
            }
            return keyStoreSpi.engineIsKeyEntry(alias);
        }

        @Override
        public boolean engineIsCertificateEntry(String alias) {
            return false;
        }

        @Override
        public String engineGetCertificateAlias(Certificate cert) {
            return null;
        }

        @Override
        public void engineStore(OutputStream stream, char[] password)
                throws IOException, NoSuchAlgorithmException, CertificateException {
            keyStoreSpi.engineStore(stream, password);
        }

        @Override
        public void engineStore(KeyStore.LoadStoreParameter param)
                throws IOException, NoSuchAlgorithmException, CertificateException {
            keyStoreSpi.engineStore(param);
        }

        @Override
        public void engineLoad(InputStream stream, char[] password)
                throws IOException, NoSuchAlgorithmException, CertificateException {
            keyStoreSpi.engineLoad(stream, password);
        }

        @Override
        public void engineLoad(KeyStore.LoadStoreParameter param)
                throws IOException, NoSuchAlgorithmException, CertificateException {
            keyStoreSpi.engineLoad(param);
        }
    }

}
