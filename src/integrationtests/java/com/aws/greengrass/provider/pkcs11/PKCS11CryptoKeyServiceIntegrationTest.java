/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.provider.pkcs11;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.EncryptionUtils;
import com.aws.greengrass.util.EncryptionUtilsTest;
import org.hamcrest.core.Is;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class PKCS11CryptoKeyServiceIntegrationTest {

    @TempDir
    protected static Path resourcePath;

    private static SoftHSM hsm;
    private static HSMToken token;

    @BeforeAll
    static void beforeAll() throws Exception {
        System.out.println("start prep");
        hsm = new SoftHSM();
        token = hsm.initToken(
                HSMToken.builder().name("softhsm-pkcs11").label("greengrass1").slotId(0).userPin("7526").build());
        Path certPath =
                EncryptionUtilsTest.generateCertificateFile(2048, true, resourcePath.resolve("certificate.pem"));
        Path privateKeyPath =
                EncryptionUtilsTest.generatePkCS8PrivateKeyFile(2048, true, resourcePath.resolve("privateKey.pem"));

        PrivateKey privateKey = EncryptionUtils.loadPrivateKey(privateKeyPath);
        List<X509Certificate> certificateChain = EncryptionUtils.loadX509Certificates(certPath);

        hsm.importPrivateKey(privateKey, certificateChain.toArray(new Certificate[0]), "iotkey", token);
    }

    @AfterAll
    static void afterAll() throws IOException {
        hsm.cleanUpTokens();
        try {
            PKCS11 pkcs11 = PKCS11.getInstance(hsm.getSharedLibraryPath().toString(), null, null, true);
            pkcs11.C_Finalize(PKCS11Constants.NULL_PTR);
        } catch (PKCS11Exception | IOException e) {
            //ignore
        }
    }

    @Test
    void placeholder_test_to_be_replaced() throws Exception {
        assertThat(hsm.containKey("iotkey", token), Is.is(true));
    }

}