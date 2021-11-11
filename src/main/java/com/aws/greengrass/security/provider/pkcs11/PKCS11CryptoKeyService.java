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
import com.aws.greengrass.security.MqttConnectionSpi;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.MqttConnectionProviderException;
import com.aws.greengrass.security.exceptions.ServiceProviderConflictException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.security.provider.pkcs11.exceptions.ProviderInstantiationException;
import com.aws.greengrass.util.Coerce;
import com.aws.greengrass.util.Utils;
import software.amazon.awssdk.crt.CrtRuntimeException;
import software.amazon.awssdk.crt.io.Pkcs11Lib;
import software.amazon.awssdk.crt.io.TlsContextPkcs11Options;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;

@SuppressWarnings("PMD.AvoidCatchingGenericException")
@ImplementsService(name = PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, autostart = true)
public class PKCS11CryptoKeyService extends PluginService implements CryptoKeySpi, MqttConnectionSpi {
    public static final String PKCS11_SERVICE_NAME = "aws.greengrass.crypto.Pkcs11Provider";
    public static final String NAME_TOPIC = "name";
    public static final String LIBRARY_TOPIC = "library";
    public static final String SLOT_ID_TOPIC = "slot";
    public static final String USER_PIN_TOPIC = "userPin";

    private static final String PKCS11_TYPE = "PKCS11";
    private static final String PKCS11_TYPE_PRIVATE = "private";
    private static final String PKCS11_TYPE_CERT = "cert";
    private static final String CONFIGURE_METHOD_NAME = "configure";
    private static final String GET_PROVIDER_METHOD_NAME = "getProvider";
    private static final String SUNPKCS11_PROVIDER = "SunPKCS11";
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    private final SecurityService securityService;

    private Provider pkcs11Provider;

    private Pkcs11Lib pkcs11Lib;

    // PKCS11 configuration
    private String name;
    // To ensure variable visibility on read thread
    private volatile String libraryPath;
    private volatile Integer slotId;
    private volatile char[] userPin;

    /**
     * Creates a new SunPKCS11 Provider.
     * @param configuration str String used to configure the provider.
     * @return Provider
     * @throws ProviderInstantiationException if Provider cannot be instantiated.
     */
    public static Provider createNewProvider(String configuration) throws ProviderInstantiationException {
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
        } catch (ProviderException | IOException | ClassNotFoundException | InstantiationException
                | IllegalAccessException | InvocationTargetException ex) {
            exception = ex;
        }
        throw new ProviderInstantiationException(exception);
    }

    private static String convertConfigToJdk9AndAbove(String configuration) {
        return "--" + configuration;
    }

    protected synchronized Provider getPkcs11Provider() {
        return pkcs11Provider;
    }

    protected synchronized Pkcs11Lib getPkcs11Lib() {
        return pkcs11Lib;
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
        if (!initializePkcs11Lib() || !initializePkcs11Provider()) {
            serviceErrored("Can't initialize PKCS11");
        }
    }

    @Override
    protected void startup() throws InterruptedException {
        try {
            securityService.registerCryptoKeyProvider(this);
            securityService.registerMqttConnectionProvider(this);
        } catch (ServiceProviderConflictException e) {
            serviceErrored(e);
            return;
        }
        super.startup();
    }


    private void updateName(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.name = Coerce.toString(topic);
            if (what != WhatHappened.initialized && !initializePkcs11Provider()) {
                serviceErrored("Can't initialize PKCS11 JCA provider when name update");
            }
        }
    }

    private void updateLibrary(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.libraryPath = Coerce.toString(topic);
            if (what != WhatHappened.initialized && (!initializePkcs11Lib() || !initializePkcs11Provider())) {
                serviceErrored("Can't initialize PKCS11 when lib update");
            }
        }
    }

    private void updateSlotId(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            this.slotId = Coerce.toInt(topic);
            if (what != WhatHappened.initialized && !initializePkcs11Provider()) {
                serviceErrored("Can't initialize PKCS11 JCA provider when slot update");
            }
        }
    }

    private void updateUserPin(WhatHappened what, Topic topic) {
        if (topic != null && what != WhatHappened.timestampUpdated) {
            String userPinStr = Coerce.toString(topic);
            this.userPin = userPinStr == null ? null : userPinStr.toCharArray();
        }
    }

    private synchronized boolean initializePkcs11Lib() {
        closePkcs11Lib();
        if (Utils.isEmpty(libraryPath)) {
            throw new IllegalArgumentException("PKCS11 missing required configuration value for library");
        }
        try {
            pkcs11Lib = new Pkcs11Lib(libraryPath);
            return true;
        } catch (CrtRuntimeException e) {
            logger.atError().setCause(e).log(getErrorMessageForRootCause(e, "Cannot initialize the PKCS11 lib."));
            return false;
        }
    }

    private void closePkcs11Lib() {
        if (pkcs11Lib != null) {
            pkcs11Lib.close();
        }
    }

    private synchronized boolean initializePkcs11Provider() {
        Provider newProvider = getNewProvider();
        if (newProvider != null && removeProviderFromJCA() && addProviderToJCA(newProvider)) {
            this.pkcs11Provider = newProvider;
            return true;
        }
        return false;
    }

    private Provider getNewProvider() {
        String configuration = buildConfiguration();
        logger.atInfo().kv("configuration", configuration).log("Initializing PKCS11 provider with configuration");
        try {
            return createNewProvider(configuration);
        } catch (ProviderInstantiationException e) {
            logger.atError().setCause(e).log(getErrorMessageForRootCause(e, "Cannot create new PKCS11 JCA provider."));
            return null;
        }
    }

    private boolean removeProviderFromJCA() {
        if (pkcs11Provider != null) {
            try {
                Security.removeProvider(pkcs11Provider.getName());
            } catch (SecurityException e) {
                logger.atError().setCause(e).log("Can't remove provider from JCA");
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
        if (Utils.isEmpty(libraryPath)) {
            throw new IllegalArgumentException("PKCS11 missing required configuration value for library");
        }
        if (slotId == null) {
            throw new IllegalArgumentException("PKCS11 missing required configuration value for slot id");
        }
        return NAME_TOPIC + "=" + name + System.lineSeparator() + LIBRARY_TOPIC + "=" + libraryPath + System
                .lineSeparator() + SLOT_ID_TOPIC + "=" + slotId;
    }

    @Override
    protected void shutdown() throws InterruptedException {
        super.shutdown();
        securityService.deregisterMqttConnectionProvider(this);
        removeProviderFromJCA();
        securityService.deregisterCryptoKeyProvider(this);
        closePkcs11Lib();
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
            String errorMessage = getErrorMessageForRootCause(e,
                    String.format("Failed to get key manager for key %s and certificate %s",
                            privateKeyUri, certificateUri));
            throw new KeyLoadingException(errorMessage, e);
        }
    }

    private KeyStore getKeyStore(URI privateKeyUri, URI certificateUri) throws KeyLoadingException {
        Pkcs11URI keyUri = validatePrivateKeyUri(privateKeyUri);
        validateCertificateUri(certificateUri, keyUri);

        String keyLabel = keyUri.getLabel();
        char[] password = userPin;
        try {
            KeyStore ks = SingleKeyStore.getInstance(getPkcs11Provider(), PKCS11_TYPE, keyLabel);
            ks.load(null, password);
            if (!ks.containsAlias(keyLabel)) {
                throw new KeyLoadingException(String.format("Private key or certificate with label %s does not exist. "
                        + "Make sure to import both private key and the certificate into PKCS11 device "
                        + "with the same label and id.", keyLabel));
            }
            logger.atDebug().log(String.format("Successfully loaded KeyStore with private key %s", keyLabel));
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
        char[] password = userPin;
        try {
            KeyStore ks = getKeyStore(privateKeyUri, certificateUri);
            Key pk = ks.getKey(keyLabel, password);
            if (!(pk instanceof PrivateKey)) {
                throw new KeyLoadingException(String.format("Key %s is not a private key", keyLabel));
            }
            // We cannot easily extract the public key from PKCS11, so instead we will get it from the
            // certificate. The certificate *must* be signed by the private key for this to work correctly.
            Certificate cert = getCertificateFromKeyStore(ks, keyLabel);

            return new KeyPair(cert.getPublicKey(), (PrivateKey) pk);
        } catch (GeneralSecurityException e) {
            String errorMessage = getErrorMessageForRootCause(e,
                    String.format("Failed to get key pair for key %s and certificate %s",
                            privateKeyUri, certificateUri));
            throw new KeyLoadingException(errorMessage, e);
        }
    }

    @Override
    public AwsIotMqttConnectionBuilder getMqttConnectionBuilder(URI privateKeyUri, URI certificateUri)
            throws ServiceUnavailableException, MqttConnectionProviderException {
        checkServiceAvailability();

        Pkcs11URI keyUri;
        String certificateContent;
        try {
            keyUri = validatePrivateKeyUri(privateKeyUri);
            KeyStore ks = getKeyStore(privateKeyUri, certificateUri);
            X509Certificate certificate = (X509Certificate) getCertificateFromKeyStore(ks, keyUri.getLabel());
            certificateContent = getX509CertificateContentString(certificate);
        } catch (KeyLoadingException | KeyStoreException | CertificateEncodingException e) {
            logger.atError().log(getErrorMessageForRootCause(e));
            throw new MqttConnectionProviderException(e.getMessage(), e);
        }
        try (TlsContextPkcs11Options options = new TlsContextPkcs11Options(getPkcs11Lib())
                .withSlotId(slotId)
                .withUserPin(userPin == null ? null : String.valueOf(userPin))
                .withPrivateKeyObjectLabel(keyUri.getLabel())
                .withCertificateFileContents(certificateContent)) {
            return AwsIotMqttConnectionBuilder.newMtlsPkcs11Builder(options);
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

    private Pkcs11URI validateCertificateUri(URI certUri, Pkcs11URI keyUri) throws KeyLoadingException {
        Pkcs11URI certPkcs11Uri;
        try {
            certPkcs11Uri = new Pkcs11URI(certUri);
        } catch (IllegalArgumentException e) {
            throw new KeyLoadingException(String.format("Invalid certificate URI: %s", certUri), e);
        }
        if (!PKCS11_TYPE_CERT.equals(certPkcs11Uri.getType())) {
            throw new KeyLoadingException(String.format("Certificate must be a PKCS11 %s type, but was %s",
                    PKCS11_TYPE_CERT, certPkcs11Uri.getType()));
        }
        if (!keyUri.getLabel().equals(certPkcs11Uri.getLabel())) {
            throw new KeyLoadingException("Private key and certificate labels must be the same");
        }
        return certPkcs11Uri;
    }

    private void checkServiceAvailability() throws ServiceUnavailableException {
        if (getState() != State.RUNNING) {
            throw new ServiceUnavailableException("PKCS11 crypto key service is unavailable");
        }
    }

    @Override
    public String supportedKeyType() {
        return Pkcs11URI.PKCS11_SCHEME;
    }

    @Override
    public boolean isBootstrapRequired(Map<String, Object> newServiceConfig) {
        if (super.isBootstrapRequired(newServiceConfig)) {
            return true;
        }
        Map<String, Object> newConfiguration = getNewServiceConfiguration(newServiceConfig);
        if (!Objects.equals(libraryPath, newConfiguration.get(LIBRARY_TOPIC))) {
            logger.atTrace().log("PKCS11 library path changes, requires bootstrap");
            return true;
        }
        if (!Integer.valueOf(slotId).equals(Coerce.toInt(newConfiguration.get(SLOT_ID_TOPIC)))) {
            logger.atTrace().log("PKCS11 slot id changes, requires bootstrap");
            return true;
        }
        char[] updatedUserPin = newConfiguration.get(USER_PIN_TOPIC) == null ? null
                : ((String) newConfiguration.get(USER_PIN_TOPIC)).toCharArray();
        if (!Arrays.equals(userPin, updatedUserPin)) {
            logger.atTrace().log("PKCS11 user pin changes, requires bootstrap");
            return true;
        }
        logger.atTrace().log("No configuration change requires bootstrap");
        return false;
    }

    private Map<String, Object> getNewServiceConfiguration(Map<String, Object> serviceDeploymentConfig) {
        if (serviceDeploymentConfig != null) {
            Object configuration = serviceDeploymentConfig.get(CONFIGURATION_CONFIG_KEY);
            if (configuration instanceof Map) {
                return (Map<String, Object>) configuration;
            }
        }
        return Collections.emptyMap();
    }

    private Certificate getCertificateFromKeyStore(KeyStore keyStore, String certLabel)
            throws KeyStoreException, KeyLoadingException {
        Certificate cert = keyStore.getCertificate(certLabel);
        if (cert == null) {
            throw new KeyLoadingException(
                    String.format("Unable to load certificate with the label %s", certLabel));
        }
        return cert;
    }

    private String getX509CertificateContentString(X509Certificate certificate) throws CertificateEncodingException {
        Base64.Encoder encoder = Base64.getEncoder();
        StringBuilder sb = new StringBuilder(BEGIN_CERT)
                .append(System.lineSeparator())
                .append(encoder.encodeToString(certificate.getEncoded()))
                .append(System.lineSeparator())
                .append(END_CERT)
                .append(System.lineSeparator());
        return sb.toString();
    }

    private String getErrorMessageForRootCause(Exception exception) {
        return getErrorMessageForRootCause(exception, "");
    }

    private String getErrorMessageForRootCause(Exception exception, String baseMessage) {
        String rootCause = Utils.getUltimateMessage(exception);
        if (rootCause.contains("AWS_IO_SHARED_LIBRARY_LOAD_FAILURE")) {
            rootCause = String.format("Unable to load PKCS11 shared library: %s", libraryPath);
        }
        if (rootCause.contains("CKR_SLOT_ID_INVALID")) {
            rootCause = String.format("PKCS11 slot: %s is invalid. Please ensure it is a valid slot-id "
                    + "and not the slot-index or slot-label", slotId);
        }
        if (rootCause.contains("CKR_PIN_INCORRECT")) {
            rootCause =  String.format("userPin: %s is incorrect for PKCS11 slot %s", String.valueOf(userPin), slotId);
        }
        return Utils.isEmpty(baseMessage) ? rootCause : String.join(" ", baseMessage, rootCause);
    }
}
