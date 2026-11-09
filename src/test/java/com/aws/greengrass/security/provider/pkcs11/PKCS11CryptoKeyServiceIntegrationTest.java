/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;


import com.aws.greengrass.dependency.State;
import com.aws.greengrass.integrationtests.BaseITCase;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.security.SecurityService;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.MqttConnectionProviderException;
import com.aws.greengrass.security.exceptions.ServiceProviderConflictException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;
import com.aws.greengrass.security.provider.pkcs11.softhsm.HSMToken;
import com.aws.greengrass.security.provider.pkcs11.softhsm.SoftHSM;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
import com.aws.greengrass.util.EncryptionUtilsTest;
import com.aws.greengrass.util.Pair;
import org.hamcrest.core.Is;
import org.hamcrest.core.IsNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.crt.CrtRuntimeException;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;

import static com.aws.greengrass.componentmanager.KernelConfigResolver.CONFIGURATION_CONFIG_KEY;
import static com.aws.greengrass.componentmanager.KernelConfigResolver.VERSION_CONFIG_KEY;
import static com.aws.greengrass.lifecyclemanager.GreengrassService.SERVICES_NAMESPACE_TOPIC;
import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionUltimateCauseOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class PKCS11CryptoKeyServiceIntegrationTest extends BaseITCase {
    private static final long TEST_TIME_OUT_SEC = 30L;
    private static final URI PRIVATE_KEY_URI = URI.create("pkcs11:object=iotkey;type=private");
    private static final URI CERTIFICATE_URI = URI.create("pkcs11:object=iotkey;type=cert");
    // Key and certificate share a CKA_ID but have different labels, like on a YubiKey
    private static final URI SEPARATE_LABEL_KEY_URI = URI.create("pkcs11:object=separate-key;type=private");
    private static final URI SEPARATE_LABEL_CERT_URI = URI.create("pkcs11:object=separate-cert;type=cert");

    private Kernel kernel;

    @Mock
    private SecurityService securityService;

    private static SoftHSM hsm;
    private static HSMToken token;
    private static X509Certificate separateLabelCertificate;

    @BeforeAll
    static void beforeAll(@TempDir Path resourcePath) throws Exception {
        hsm = new SoftHSM();
        token = hsm.initToken(
                HSMToken.builder().name("softhsm-pkcs11").label("greengrass1").slotId(0).userPin("7526").build());
        Pair<Path, KeyPair> cert =
                EncryptionUtilsTest.generateCertificateFile(2048, true, resourcePath.resolve("certificate.pem"),
                        false);
        List<X509Certificate> certificateChain = EncryptionUtils.loadX509Certificates(cert.getLeft());
        hsm.importPrivateKey(cert.getRight().getPrivate(), certificateChain.toArray(new Certificate[0]), "iotkey", token);

        Pair<Path, KeyPair> separateLabelCert =
                EncryptionUtilsTest.generateCertificateFile(2048, true, resourcePath.resolve("separate-cert.pem"),
                        false);
        List<X509Certificate> separateLabelCertChain =
                EncryptionUtils.loadX509Certificates(separateLabelCert.getLeft());
        hsm.importPrivateKey(separateLabelCert.getRight().getPrivate(),
                separateLabelCertChain.toArray(new Certificate[0]), "separate-cert", token);
        hsm.setPrivateKeyLabel("separate-cert", "separate-key", token);
        separateLabelCertificate = separateLabelCertChain.get(0);
    }

    @BeforeEach
    void beforeEach() {
        kernel = new Kernel();
        kernel.getContext().put(SecurityService.class, securityService);
    }

    @AfterEach
    void afterEach() {
        kernel.shutdown();
        // A service that ends up BROKEN never runs shutdown(), so its provider can stay in the JVM-wide JCA list
        Security.removeProvider("SunPKCS11-" + token.getName());
    }

    @AfterAll
    static void afterAll() throws Exception {
        hsm.cleanUpTokens();
        try {
            PKCS11 pkcs11 = PKCS11.getInstance(hsm.getSharedLibraryPath().toString(), null, null, true);
            pkcs11.C_Finalize(PKCS11Constants.NULL_PTR);
        } catch (PKCS11Exception | IOException e) {
            //ignore
        }
    }

    private void startServiceExpectRunning() throws Exception {
        startService(true, State.RUNNING);
    }

    private void startService(boolean validConfig, State expectedState) throws Exception {
        CountDownLatch serviceRunning = new CountDownLatch(1);
        kernel.parseArgs();
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.NAME_TOPIC).withValue(token.getName());
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.LIBRARY_TOPIC).withValue(hsm.getSharedLibraryPath().toString());
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.USER_PIN_TOPIC).withValue(token.getUserPin());
        int slotId = validConfig ? token.getSlotId() : token.getSlotId() + 1;
        kernel.getConfig()
                .lookup(SERVICES_NAMESPACE_TOPIC, PKCS11CryptoKeyService.PKCS11_SERVICE_NAME, CONFIGURATION_CONFIG_KEY,
                        PKCS11CryptoKeyService.SLOT_ID_TOPIC).withValue(slotId);
        kernel.getContext().addGlobalStateChangeListener((service, was, newState) -> {
            if (PKCS11CryptoKeyService.PKCS11_SERVICE_NAME.equals(service.getName()) && service.getState()
                    .equals(expectedState)) {
                serviceRunning.countDown();
            }
        });
        kernel.launch();
        assertThat(serviceRunning.await(TEST_TIME_OUT_SEC, TimeUnit.SECONDS), Is.is(true));
    }

    @Test
    void GIVEN_security_service_register_provider_error_WHEN_install_service_THEN_service_error_state(
            ExtensionContext context) throws Exception {
        ignoreExceptionUltimateCauseOfType(context, ServiceProviderConflictException.class);

        doThrow(ServiceProviderConflictException.class).when(securityService).registerCryptoKeyProvider(any());
        startService(true, State.ERRORED);
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        verify(securityService, atLeastOnce()).registerCryptoKeyProvider(service);
    }

    @Test
    void GIVEN_bad_configuration_WHEN_install_service_THEN_service_error_state_because_cannot_initialize_pkcs11_provider(
            ExtensionContext context) throws Exception {
        ignoreExceptionUltimateCauseOfType(context, PKCS11Exception.class);

        startService(false, State.ERRORED);
        verify(securityService, never()).registerCryptoKeyProvider(any());
    }

    @Test
    void GIVEN_valid_config_WHEN_install_service_THEN_succeed() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        verify(securityService).registerCryptoKeyProvider(service);
        Provider p = service.getPkcs11Provider();
        assertThat(Security.getProvider(p.getName()), Is.is(p));
    }

    @Test
    void GIVEN_service_up_running_WHEN_update_configuration_THEN_provider_updated() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Provider p1 = service.getPkcs11Provider();
        assertThat(Security.getProvider(p1.getName()), Is.is(p1));

        kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME).getConfig()
                .find(CONFIGURATION_CONFIG_KEY, PKCS11CryptoKeyService.NAME_TOPIC).withValue("foo-bar");
        // Block until subscriber has finished updating
        kernel.getContext().waitForPublishQueueToClear();

        Provider p2 = service.getPkcs11Provider();
        assertThat(Security.getProvider(p1.getName()), IsNull.nullValue());
        assertThat(Security.getProvider(p2.getName()), Is.is(p2));
    }

    @Test
    void GIVEN_service_in_error_WHEN_get_key_managers_THEN_throw_unavailable_exception(ExtensionContext context)
            throws Exception {
        ignoreExceptionUltimateCauseOfType(context, PKCS11Exception.class);

        startService(false, State.ERRORED);
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        assertThrows(ServiceUnavailableException.class, () -> service.getKeyManagers(PRIVATE_KEY_URI, CERTIFICATE_URI));
    }

    @Test
    void GIVEN_illegal_key_uri_scheme_WHEN_get_key_managers_THEN_throw_exception(ExtensionContext context)
            throws Exception {
        ignoreExceptionUltimateCauseOfType(context, IllegalArgumentException.class);

        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(new URI("file:///path/to/file"), CERTIFICATE_URI));
        assertThat(e.getMessage(), containsString("Invalid private key URI"));
    }

    @Test
    void GIVEN_key_uri_empty_label_WHEN_get_key_managers_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(new URI("pkcs11:type=private"), CERTIFICATE_URI));
        assertThat(e.getMessage(), containsString("Empty key label"));
    }

    @Test
    void GIVEN_key_uri_empty_type_WHEN_get_key_managers_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(new URI("pkcs11:object=foo-bar"), CERTIFICATE_URI));
        assertThat(e.getMessage(), containsString("Private key must be a PKCS11 private type, but was null"));
    }

    @Test
    void GIVEN_cert_uri_empty_type_WHEN_get_key_managers_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(PRIVATE_KEY_URI, new URI("pkcs11:object=foo-bar")));
        assertThat(e.getMessage(), containsString("Certificate must be a PKCS11 cert type, but was null"));
    }

    @Test
    void GIVEN_cert_uri_empty_label_WHEN_get_key_managers_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(PRIVATE_KEY_URI, new URI("pkcs11:type=cert")));
        assertThat(e.getMessage(), containsString("Empty certificate label"));
    }

    @Test
    void GIVEN_cert_label_not_existed_WHEN_get_key_managers_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(PRIVATE_KEY_URI, new URI("pkcs11:object=foo;type=cert")));
        assertThat(e.getMessage(),
                containsString("Certificate with label foo does not exist, or no private key on the token has the "
                        + "same CKA_ID as it"));
    }

    @Test
    void GIVEN_key_and_cert_with_different_labels_WHEN_get_key_managers_THEN_succeed() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        KeyManager[] keyManagers = service.getKeyManagers(SEPARATE_LABEL_KEY_URI, SEPARATE_LABEL_CERT_URI);
        assertThat(keyManagers.length, Is.is(1));
        // SunPKCS11 names the key entry after the certificate label
        X509KeyManager keyManager = (X509KeyManager) keyManagers[0];
        assertThat(keyManager.getPrivateKey("separate-cert"), IsNull.notNullValue());
        assertThat(keyManager.getCertificateChain("separate-cert")[0], Is.is(separateLabelCertificate));
    }

    @Test
    void GIVEN_key_and_cert_with_different_labels_WHEN_get_key_pair_THEN_return_matching_key_pair()
            throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        KeyPair keyPair = service.getKeyPair(SEPARATE_LABEL_KEY_URI, SEPARATE_LABEL_CERT_URI);
        assertThat(keyPair.getPublic(), Is.is(separateLabelCertificate.getPublicKey()));

        // Sign on the token and verify with the certificate's public key to prove the private key is its pair
        byte[] data = "pkcs11-provider".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(separateLabelCertificate.getPublicKey());
        verifier.update(data);
        assertThat(verifier.verify(signature), Is.is(true));
    }

    @Test
    void GIVEN_cert_uri_invalid_scheme_WHEN_get_key_managers_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class,
                () -> service.getKeyManagers(PRIVATE_KEY_URI, new URI("pkcs:object=foo;type=cert")));
        assertThat(e.getMessage(), containsString("Invalid certificate URI"));
    }

    @Test
    void GIVEN_valid_pkcs11_uri_WHEN_get_key_managers_THEN_succeed() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        KeyManager[] keyManagers = service.getKeyManagers(PRIVATE_KEY_URI, CERTIFICATE_URI);
        assertThat(keyManagers.length, Is.is(1));
        assertThat(((X509KeyManager) keyManagers[0]).getPrivateKey("iotkey"), IsNull.notNullValue());
    }

    @Test
    void GIVEN_not_existed_key_WHEN_get_key_managers_THEN_return_empty_key_manager() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(KeyLoadingException.class, () -> service
                .getKeyManagers(new URI("pkcs11:object=foo-bar;type=private"),
                        new URI("pkcs11:object=foo-bar;type=cert")));
        assertThat(e.getMessage(),
                containsString("Certificate with label foo-bar does not exist, or no private key on the token has the "
                        + "same CKA_ID as it"));
    }

    @Test
    void GIVEN_no_configuration_change_WHEN_bootstrap_required_THEN_return_false() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "0.0.0");
            put(CONFIGURATION_CONFIG_KEY, new HashMap<String, Object>() {{
                put(PKCS11CryptoKeyService.LIBRARY_TOPIC, hsm.getSharedLibraryPath().toString());
                put(PKCS11CryptoKeyService.SLOT_ID_TOPIC, token.getSlotId());
                put(PKCS11CryptoKeyService.USER_PIN_TOPIC, token.getUserPin());
            }});
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(false));
    }

    @Test
    void GIVEN_service_version_change_WHEN_bootstrap_required_THEN_return_true() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "1.0.0");
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(true));
    }

    @Test
    void GIVEN_library_path_change_WHEN_bootstrap_required_THEN_return_true() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "0.0.0");
            put(CONFIGURATION_CONFIG_KEY, new HashMap<String, Object>() {{
                put(PKCS11CryptoKeyService.LIBRARY_TOPIC, "/path/to/new/lib");
                put(PKCS11CryptoKeyService.SLOT_ID_TOPIC, token.getSlotId());
                put(PKCS11CryptoKeyService.USER_PIN_TOPIC, token.getUserPin());
            }});
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(true));
    }

    @Test
    void GIVEN_slot_id_change_WHEN_bootstrap_required_THEN_return_true() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "0.0.0");
            put(CONFIGURATION_CONFIG_KEY, new HashMap<String, Object>() {{
                put(PKCS11CryptoKeyService.LIBRARY_TOPIC, hsm.getSharedLibraryPath().toString());
                put(PKCS11CryptoKeyService.SLOT_ID_TOPIC, token.getSlotId()+1);
                put(PKCS11CryptoKeyService.USER_PIN_TOPIC, token.getUserPin());
            }});
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(true));
    }

    @Test
    void GIVEN_slot_id_change_in_string_WHEN_bootstrap_required_THEN_return_true() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "0.0.0");
            put(CONFIGURATION_CONFIG_KEY, new HashMap<String, Object>() {{
                put(PKCS11CryptoKeyService.LIBRARY_TOPIC, hsm.getSharedLibraryPath().toString());
                put(PKCS11CryptoKeyService.SLOT_ID_TOPIC, String.valueOf(token.getSlotId()+1));
                put(PKCS11CryptoKeyService.USER_PIN_TOPIC, token.getUserPin());
            }});
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(true));
    }

    @Test
    void GIVEN_user_pin_change_WHEN_bootstrap_required_THEN_return_true() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "0.0.0");
            put(CONFIGURATION_CONFIG_KEY, new HashMap<String, Object>() {{
                put(PKCS11CryptoKeyService.LIBRARY_TOPIC, hsm.getSharedLibraryPath().toString());
                put(PKCS11CryptoKeyService.SLOT_ID_TOPIC, token.getSlotId());
                put(PKCS11CryptoKeyService.USER_PIN_TOPIC, token.getUserPin()+"5678");
            }});
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(true));
    }

    @Test
    void GIVEN_user_pin_change_null_WHEN_bootstrap_required_THEN_return_true() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Map<String, Object> newServiceConfig = new HashMap<String, Object>() {{
            put(VERSION_CONFIG_KEY, "0.0.0");
            put(CONFIGURATION_CONFIG_KEY, new HashMap<String, Object>() {{
                put(PKCS11CryptoKeyService.LIBRARY_TOPIC, hsm.getSharedLibraryPath().toString());
                put(PKCS11CryptoKeyService.SLOT_ID_TOPIC, token.getSlotId());
            }});
        }};
        assertThat(service.isBootstrapRequired(newServiceConfig), Is.is(true));
    }

    @Test
    void GIVEN_valid_pkcs11_uri_WHEN_get_mqtt_builder_THEN_succeed() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        try (AwsIotMqttConnectionBuilder builder = service.getMqttConnectionBuilder(PRIVATE_KEY_URI, CERTIFICATE_URI)) {
            assertThat(builder, IsNull.notNullValue());
        }
    }

    @Test
    void GIVEN_key_and_cert_with_different_labels_WHEN_build_mqtt_connection_THEN_succeed() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        try (AwsIotMqttConnectionBuilder builder =
                     service.getMqttConnectionBuilder(SEPARATE_LABEL_KEY_URI, SEPARATE_LABEL_CERT_URI);
             MqttClientConnection connection = buildMqttConnection(builder)) {
            assertThat(connection, IsNull.notNullValue());
        }
    }

    @Test
    void GIVEN_key_label_not_existed_WHEN_build_mqtt_connection_THEN_throw_exception() throws Exception {
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        // The certificate lookup doesn't use the key label, so only CRT can catch a wrong key label
        try (AwsIotMqttConnectionBuilder builder = service.getMqttConnectionBuilder(
                URI.create("pkcs11:object=absent-key;type=private"), SEPARATE_LABEL_CERT_URI)) {
            assertThrows(CrtRuntimeException.class, () -> buildMqttConnection(builder).close());
        }
    }

    // build() creates the TLS context, which is where CRT finds the private key on the token by its label
    private static MqttClientConnection buildMqttConnection(AwsIotMqttConnectionBuilder builder) {
        try (EventLoopGroup eventLoopGroup = new EventLoopGroup(1);
             HostResolver hostResolver = new HostResolver(eventLoopGroup);
             ClientBootstrap clientBootstrap = new ClientBootstrap(eventLoopGroup, hostResolver)) {
            return builder.withBootstrap(clientBootstrap).withEndpoint("localhost").withClientId("test").build();
        }
    }

    @Test
    void GIVEN_cert_uri_invalid_scheme_WHEN_get_mqtt_builder_THEN_throw_exception(ExtensionContext context) throws Exception {
        ignoreExceptionUltimateCauseOfType(context, IllegalArgumentException.class);
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(MqttConnectionProviderException.class,
                () -> service.getMqttConnectionBuilder(PRIVATE_KEY_URI, new URI("file:///path/to/cert")));
        assertThat(e.getMessage(), containsString("Invalid certificate URI"));
    }

    @Test
    void GIVEN_key_absent_WHEN_get_mqtt_builder_THEN_exception_with_useful_message(ExtensionContext context) throws Exception {
        ignoreExceptionUltimateCauseOfType(context, KeyLoadingException.class);
        startServiceExpectRunning();
        PKCS11CryptoKeyService service =
                (PKCS11CryptoKeyService) kernel.locate(PKCS11CryptoKeyService.PKCS11_SERVICE_NAME);
        Exception e = assertThrows(MqttConnectionProviderException.class,
                () -> service.getMqttConnectionBuilder(URI.create("pkcs11:object=absent_key;type=private"),
                        URI.create("pkcs11:object=absent_key;type=cert")));
        assertThat(e.getMessage(),
                containsString("Certificate with label absent_key does not exist, or no private key on the token "
                        + "has the same CKA_ID as it"));
        assertThat(e.getMessage(),
                containsString("Make sure the private key and the certificate are imported with the same id."));
    }
}