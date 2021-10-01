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
import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.ServiceProviderConflictException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.EncryptionUtils;
import com.aws.greengrass.util.Utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
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
    public static final String PKCS11_SERVICE_NAME = "aws.greengrass.pkcs11.provider";
    public static final String NAME_TOPIC = "name";
    public static final String LIBRARY_TOPIC = "library";
    public static final String SLOT_ID_TOPIC = "slot";
    public static final String USER_PIN_TOPIC = "userPin";

    private static final String PKCS11_TYPE = "PKCS11";
    private static final String FILE_SCHEME = "file";
    private static final String PKCS11_TYPE_PRIVATE = "private";
    private static final String PKCS11_TYPE_CERT = "cert";
    private static final String CONFIGURE_METHOD_NAME = "configure";
    private static final String GET_PROVIDER_METHOD_NAME = "getProvider";
    private static final String SUNPKCS11_PROVIDER = "SunPKCS11";

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
            serviceErrored(e);
            return;
        }

        super.startup();
    }


    private void updateName(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.name = Coerce.toString(topic);
            if (what != WhatHappened.initialized) {
                initializePkcs11Provider();
            }
        }
    }

    private void updateLibrary(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.libraryPath = Coerce.toString(topic);
            if (what != WhatHappened.initialized) {
                initializePkcs11Provider();
            }
        }
    }

    private void updateSlotId(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.slotId = Coerce.toInt(topic);
            if (what != WhatHappened.initialized) {
                initializePkcs11Provider();
            }
        }
    }

    private void updateUserPin(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
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
        logger.atInfo().kv("configuration", configuration).log("Initializing PKCS11 provider with configuration");
        final Exception exception;

        try (InputStream configStream = new ByteArrayInputStream(configuration.getBytes())) {
            Constructor sunPKCS11Constructor =
                    Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
            return (Provider) sunPKCS11Constructor.newInstance(configStream);
        } catch (NoSuchMethodError | IllegalAccessError | NoSuchMethodException ex) {
            try {
                Method configureMethod = Provider.class.getMethod(CONFIGURE_METHOD_NAME, String.class);
                Method getProviderMethod = Security.class.getMethod(GET_PROVIDER_METHOD_NAME, String.class);
                Provider provider = (Provider) getProviderMethod.invoke(null, SUNPKCS11_PROVIDER);
                return (Provider) configureMethod.invoke(provider, convertConfigToJdk9AndAbove(configuration));
            } catch (InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
                exception = e;
            }
        } catch (ProviderException | IOException | ClassNotFoundException | InstantiationException |
                IllegalAccessException | InvocationTargetException ex) {
            exception = ex;
        }
        serviceErrored(exception);
        return null;
    }

    private String convertConfigToJdk9AndAbove(String configuration) {
        return "--" + configuration;
    }

    private boolean removeProviderFromJCA() {
        if (pkcs11Provider != null) {
            try {
                Security.removeProvider(pkcs11Provider.getName());
            } catch (SecurityException e) {
                serviceErrored("Can't remove provider from JCA");
                return false;
            }
        }
        return true;
    }

    private boolean addProviderToJCA(Provider provider) {
        try {
            if (Security.addProvider(provider) == -1) {
                logger.atError().log("PKCS11 provider was not added to JCA provider list");
                return false;
            }
        } catch (SecurityException e) {
            logger.atError().setCause(e).kv("providerName", provider.getName()).log("Can't add PKCS11 JCA provider");
            return false;
        }
        return true;
    }

    private String buildConfiguration() {
        return NAME_TOPIC + "=" + name + System.lineSeparator() + LIBRARY_TOPIC + "=" + libraryPath + System
                .lineSeparator() + SLOT_ID_TOPIC + "=" + slotId;
    }

    @Override
    protected void shutdown() throws InterruptedException {
        super.shutdown();
        securityService.deregisterCryptoKeyProvider(this);
        removeProviderFromJCA();
    }

    @Override
    public KeyManager[] getKeyManagers(URI privateKeyUri, URI certificateUri)
            throws ServiceUnavailableException, KeyLoadingException {
        checkServiceAvailability();

        try {
            KeyStore ks = getKeyStore(privateKeyUri, certificateUri);

            KeyManagerFactory keyManagerFactory =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(ks, null);
            return keyManagerFactory.getKeyManagers();
        } catch (GeneralSecurityException e) {
            throw new KeyLoadingException(
                    String.format("Failed to get key manager for key %s and certificate %s", privateKeyUri,
                            certificateUri), e);
        }
    }

    private KeyStore getKeyStore(URI privateKeyUri, URI certificateUri) throws KeyLoadingException {
        Pkcs11URI keyUri = validatePrivateKeyUri(privateKeyUri);
        if (isUriTypeOf(certificateUri, Pkcs11URI.PKCS11_SCHEME)) {
            validateCertificateUri(new Pkcs11URI(certificateUri), keyUri);
        } else {
            if (!isUriTypeOf(certificateUri, FILE_SCHEME)) {
                throw new KeyLoadingException(String.format("Unrecognized certificate URI scheme %s for provider %s",
                        certificateUri.getScheme(), PKCS11_SERVICE_NAME));
            }
        }

        String keyLabel = keyUri.getLabel();
        char[] password = userPin.get();
        try {
            KeyStore ks = SingleKeyStore.getInstance(getPkcs11Provider(), PKCS11_TYPE, keyLabel);
            ks.load(null, password);
            if (!ks.containsAlias(keyLabel)) {
                throw new KeyLoadingException(String.format("Key %s does not exist", keyLabel));
            }
            if (isUriTypeOf(certificateUri, FILE_SCHEME)) {
                List<X509Certificate> certChain = EncryptionUtils.loadX509Certificates(Paths.get(certificateUri));
                ks.setKeyEntry(keyLabel, ks.getKey(keyLabel, password), password,
                        certChain.toArray(new Certificate[0]));
            }
            return ks;
        } catch (GeneralSecurityException | IOException e) {
            throw new KeyLoadingException(
                    String.format("Failed to get key store for key %s and certificate %s", privateKeyUri,
                            certificateUri), e);
        }
    }

    @Override
    public KeyPair getKeyPair(URI privateKeyUri, URI certificateUri) throws
            ServiceUnavailableException, KeyLoadingException {
        checkServiceAvailability();

        Pkcs11URI keyUri = validatePrivateKeyUri(privateKeyUri);

        String keyLabel = keyUri.getLabel();
        char[] password = userPin.get();
        try {
            KeyStore ks = getKeyStore(privateKeyUri, certificateUri);
            Key pk = ks.getKey(keyLabel, password);
            if (!(pk instanceof PrivateKey)) {
                throw new KeyLoadingException(String.format("Key %s is not a private key", keyLabel));
            }
            // We cannot easily extract the public key from PKCS11, so instead we will get it from the
            // certificate. The certificate *must* be signed by the private key for this to work correctly.
            Certificate cert = ks.getCertificate(keyLabel);
            if (cert == null) {
                throw new KeyLoadingException(
                        String.format("Unable to load certificate associated with private key %s", keyLabel));
            }

            return new KeyPair(cert.getPublicKey(), (PrivateKey) pk);
        } catch (GeneralSecurityException e) {
            throw new KeyLoadingException(
                    String.format("Failed to get key pair for key %s and certificate %s",
                            privateKeyUri, certificateUri), e);
        }
    }

    private Pkcs11URI validatePrivateKeyUri(URI privateKeyUri) throws KeyLoadingException {
        Pkcs11URI keyUri;
        try {
            keyUri = new Pkcs11URI(privateKeyUri);
        } catch (IllegalArgumentException e) {
            throw new KeyLoadingException(String.format("Invalid private key URI: %s", privateKeyUri), e);
        }

        if (Utils.isEmpty(keyUri.getLabel())) {
            throw new KeyLoadingException("Empty key label in private key URI");
        }
        if (!PKCS11_TYPE_PRIVATE.equals(keyUri.getType())) {
            throw new KeyLoadingException(String.format("Private key must be a PKCS11 %s type, but was %s",
                    PKCS11_TYPE_PRIVATE, keyUri.getType()));
        }
        return keyUri;
    }

    private void validateCertificateUri(Pkcs11URI certUri, Pkcs11URI keyUri) throws KeyLoadingException {
        if (!PKCS11_TYPE_CERT.equals(certUri.getType())) {
            throw new KeyLoadingException(String.format("Certificate must be a PKCS11 %s type, but was %s",
                    PKCS11_TYPE_CERT, certUri.getType()));
        }
        if (!keyUri.getLabel().equals(certUri.getLabel())) {
            throw new KeyLoadingException("Private key and certificate labels must be the same");
        }
    }

    private void checkServiceAvailability() throws ServiceUnavailableException {
        if (getState() != State.RUNNING) {
            throw new ServiceUnavailableException("PKCS11 crypto key service is unavailable");
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
