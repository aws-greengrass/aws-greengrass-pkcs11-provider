/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.provider.pkcs11;

import com.aws.greengrass.security.CryptoKeySpi;
import com.aws.greengrass.security.exceptions.KeyLoadingException;
import com.aws.greengrass.security.exceptions.ServiceUnavailableException;

import java.net.URISyntaxException;
import javax.net.ssl.KeyManager;

public class PKCS11CryptoKeyService implements CryptoKeySpi {
    private static final String SUPPORTED_KEY_TYPE = "pkcs11";

    @Override
    public KeyManager[] getKeyManagers(String s, String s1)
            throws ServiceUnavailableException, KeyLoadingException, URISyntaxException {
        return new KeyManager[0];
    }

    @Override
    public String supportedKeyType() {
        return SUPPORTED_KEY_TYPE;
    }
}
