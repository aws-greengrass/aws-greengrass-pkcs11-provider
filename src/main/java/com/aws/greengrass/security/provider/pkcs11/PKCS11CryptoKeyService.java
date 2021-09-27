/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;

import com.aws.greengrass.config.Topic;
import com.aws.greengrass.config.Topics;
import com.aws.greengrass.config.WhatHappened;
import com.aws.greengrass.dependency.ImplementsService;
import com.aws.greengrass.dependency.State;
import com.aws.greengrass.lifecyclemanager.PluginService;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.ServiceProviderConflictException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.EncryptionUtils;
import com.aws.greengrass.util.Utils;
import sun.security.pkcs11.SunPKCS11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;

@ImplementsService(name = PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, autostart = true)
public class PKCS11CryptoKeyService extends PluginService implements CryptoKeySpi {
    private static final Logger logger = LogManager.getLogger(PKCS11CryptoKeyService.class);
    public static final String PKCS11_SERVICE_NAME = "aws.greengrass.pkcs11.provider";
    public static final String NAME_TOPIC = "name";
    public static final String LIBRARY_TOPIC = "library";
    public static final String SLOT_ID_TOPIC = "slot";
    public static final String USER_PIN_TOPIC = "userPin";

    private static final String PKCS11_TYPE = "PKCS11";
    private static final String PRIVATE_KEY_URI = "privateKeyUri";
    private static final String CERT_URI = "certificateUri";
    private static final String FILE_SCHEME = "file";
    private static final String PKCS11_TYPE_PRIVATE = "private";
    private static final String PKCS11_TYPE_CERT = "cert";

    private final SecurityService securityService;

    private Provider pkcs11Provider;

    // PKCS11 configuration
    private String name;
    private String libraryPath;
    private int slotId;
    // It's read and written on different threads
    private final AtomicReference<char[]> userPin = new AtomicReference<>();

    protected synchronized Provider getPkcs11Provider() {
        return pkcs11Provider;
    }

    @Inject
    public PKCS11CryptoKeyService(Topics topics, SecurityService securityService) {
        super(topics);
        this.securityService = securityService;
    }

    @Override
    protected void install() throws InterruptedException {
        super.install();
        this.config.lookup(CONFIGURATION_CONFIG_KEY, NAME_TOPIC).subscribe(this::updateName);
        this.config.lookup(CONFIGURATION_CONFIG_KEY, LIBRARY_TOPIC).subscribe(this::updateLibrary);
        this.config.lookup(CONFIGURATION_CONFIG_KEY, SLOT_ID_TOPIC).subscribe(this::updateSlotId);
        this.config.lookup(CONFIGURATION_CONFIG_KEY, USER_PIN_TOPIC).subscribe(this::updateUserPin);
        initializePkcs11Provider();
    }

    @Override
    protected void startup() throws InterruptedException {
        try {
            securityService.registerCryptoKeyProvider(this);
        } catch (ServiceProviderConflictException e) {
            logger.atError().setCause(e).log("Can't register pkcs11 crypto key service");
            serviceErrored(e);
            return;
        }

        super.startup();
    }


    private void updateName(WhatHappened what, Topic topic) {
        if (topic != null) {
            this.name = Coerce.toString(topic);
            if (what != WhatHappened.initialized) {
                initializePkcs11Provider();
            }
        }
    }

    private void updateLibrary(WhatHappened what, Topic topic) {
        if (topic != null) {
            this.libraryPath = Coerce.toString(topic);
            if (what != WhatHappened.initialized) {
                initializePkcs11Provider();
            }
        }
    }

    private void updateSlotId(WhatHappened what, Topic topic) {
        if (topic != null) {
            this.slotId = Coerce.toInt(topic);
            if (what != WhatHappened.initialized) {
                initializePkcs11Provider();
            }
        }
    }

    @SuppressWarnings("PMD.UnusedFormalParameter")
    private void updateUserPin(WhatHappened what, Topic topic) {
        if (topic != null) {
            String userPinStr = Coerce.toString(topic);
            this.userPin.set(userPinStr == null ? null : userPinStr.toCharArray());
        }
    }

    private synchronized void initializePkcs11Provider() {
        Provider newProvider = createNewProvider();
        if (newProvider != null && removeProviderFromJCA()) {
            if (addProviderToJCA(newProvider)) {
                this.pkcs11Provider = newProvider;
            } else {
                serviceErrored("Can't add pkcs11 provider to JCA");
            }
        }
    }

    private Provider createNewProvider() {
        String configuration = buildConfiguration();
        logger.atInfo().kv("configuration", configuration).log("Initialize pkcs11 provider with configuration");
        try (InputStream configStream = new ByteArrayInputStream(configuration.getBytes())) {
            return new SunPKCS11(configStream);
        } catch (ProviderException | IOException e) {
            logger.atError().setCause(e).kv("configuration", configuration).log("Failed to initialize pkcs11 provider");
            serviceErrored(e);
            return null;
        }
    }

    private boolean removeProviderFromJCA() {
        if (pkcs11Provider != null) {
            try {
                Security.removeProvider(pkcs11Provider.getName());
            } catch (SecurityException e) {
                logger.atError().setCause(e).kv("providerName", pkcs11Provider.getName())
                        .log("Can't remove JCA provider");
                serviceErrored("Can't remove provider from JCA");
                return false;
            }
        }
        return true;
    }

    private boolean addProviderToJCA(Provider provider) {
        try {
            if (Security.addProvider(provider) == -1) {
                logger.atError().log("Pkcs11 provider is not added to JCA provider list");
                return false;
            }
        } catch (SecurityException e) {
            logger.atError().setCause(e).kv("providerName", provider.getName()).log("Can't add PKCS11 JCA provider");
            return false;
        }
        return true;
    }

    private String buildConfiguration() {
        return new StringBuilder().append(NAME_TOPIC + "=" + name).append(System.lineSeparator())
                .append(LIBRARY_TOPIC + "=" + libraryPath).append(System.lineSeparator())
                .append(SLOT_ID_TOPIC + "=" + slotId).toString();
    }

    @Override
    protected void shutdown() throws InterruptedException {
        super.shutdown();
        securityService.deregisterCryptoKeyProvider(this);
        if (pkcs11Provider != null) {
            Security.removeProvider(pkcs11Provider.getName());
        }
    }

    @Override
    public KeyManager[] getKeyManagers(String privateKeyUri, String certificateUri)
            throws ServiceUnavailableException, KeyLoadingException, URISyntaxException {
        checkServiceAvailability();

        Pkcs11URI keyUri = validatePrivateKeyUri(privateKeyUri);
        URI certUri = new URI(certificateUri);
        if (isUriTypeOf(certUri, Pkcs11URI.PKCS11_SCHEME)) {
            validateCertificateUri(new Pkcs11URI(certUri), keyUri);
        } else {
            if (!isUriTypeOf(certUri, FILE_SCHEME)) {
                logger.atError().kv(CERT_URI, certificateUri)
                        .log(String.format("Cert URI is neither %s nor %s", Pkcs11URI.PKCS11_SCHEME, FILE_SCHEME));
                throw new KeyLoadingException("Cert URI not supported");
            }
        }

        String keyLabel = keyUri.getLabel();
        char[] password = userPin.get();
        try {
            KeyStore ks = SingleKeyStore.getInstance(getPkcs11Provider(), PKCS11_TYPE, keyLabel);
            ks.load(null, password);
            if (!ks.containsAlias(keyLabel)) {
                logger.atError().kv("keyLabel", keyLabel).log("No specific key in key store");
                throw new KeyLoadingException("Key not existed");
            }
            if (isUriTypeOf(certUri, FILE_SCHEME)) {
                List<X509Certificate> certChain = EncryptionUtils.loadX509Certificates(Paths.get(certificateUri));
                ks.setKeyEntry(keyLabel, ks.getKey(keyLabel, password), password,
                        certChain.toArray(new Certificate[0]));
            }

            KeyManagerFactory keyManagerFactory =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(ks, null);
            return keyManagerFactory.getKeyManagers();
        } catch (GeneralSecurityException | IOException e) {
            logger.atError().setCause(e).kv(PRIVATE_KEY_URI, privateKeyUri).kv(CERT_URI, certificateUri)
                    .log("Exception caught during getting key manager");
            throw new KeyLoadingException("Failed to get key manager", e);
        }
    }

    private Pkcs11URI validatePrivateKeyUri(String privateKeyUri) throws KeyLoadingException, URISyntaxException {
        Pkcs11URI keyUri;
        try {
            keyUri = new Pkcs11URI(privateKeyUri);
        } catch (IllegalArgumentException e) {
            logger.atError().setCause(e).kv(PRIVATE_KEY_URI, privateKeyUri).log("Private key URI is not valid");
            throw new KeyLoadingException("Invalid private key URI", e);
        }

        if (Utils.isEmpty(keyUri.getLabel())) {
            logger.atError().kv(PRIVATE_KEY_URI, privateKeyUri).log("Key Label is empty");
            throw new KeyLoadingException("Empty key label");
        }
        if (!PKCS11_TYPE_PRIVATE.equals(keyUri.getType())) {
            logger.atError().kv(PRIVATE_KEY_URI, privateKeyUri).log("Key type is not private");
            throw new KeyLoadingException("Wrong key type");
        }
        return keyUri;
    }

    private void validateCertificateUri(Pkcs11URI certUri, Pkcs11URI keyUri) throws KeyLoadingException {
        if (!PKCS11_TYPE_CERT.equals(certUri.getType())) {
            logger.atError().kv(CERT_URI, certUri).log("The type of cert URI is not cert");
            throw new KeyLoadingException("Wrong cert type");
        }
        if (!keyUri.getLabel().equals(certUri.getLabel())) {
            logger.atError().kv(PRIVATE_KEY_URI, keyUri).kv(CERT_URI, certUri)
                    .log("Cert label is different from private key label");
            throw new KeyLoadingException("Different key and cert labels");
        }
    }

    private void checkServiceAvailability() throws ServiceUnavailableException {
        if (getState() != State.RUNNING) {
            logger.atInfo().kv("serviceState", getState()).log("Pkcs11 crypto key service is not running");
            throw new ServiceUnavailableException("Pkcs11 crypto key service is unavailable");
        }
    }

    private boolean isUriTypeOf(URI uri, String type) {
        return type.equalsIgnoreCase(uri.getScheme());
    }

    @Override
    public String supportedKeyType() {
        return Pkcs11URI.PKCS11_SCHEME;
    }
}
