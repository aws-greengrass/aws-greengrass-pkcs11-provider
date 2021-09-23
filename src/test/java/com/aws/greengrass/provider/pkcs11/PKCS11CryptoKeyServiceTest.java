/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.provider.pkcs11;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.hamcrest.core.Is;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.hamcrest.MatcherAssert.assertThat;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class PKCS11CryptoKeyServiceTest {

    @Test
    void placeholder_test_to_be_replaced() throws Exception {
        assertThat(new PKCS11CryptoKeyService().getKeyManagers("a", "b").length, Is.is(0));
    }

}