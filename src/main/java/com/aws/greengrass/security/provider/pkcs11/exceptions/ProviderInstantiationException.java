/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11.exceptions;

public class ProviderInstantiationException extends Exception {
    static final long serialVersionUID = -3387516993124229948L;
    static final String MESSAGE = "Failed to instantiate Provider";

    public ProviderInstantiationException(Throwable cause) {
        super(MESSAGE, cause);
    }

    public ProviderInstantiationException(String message, Throwable cause) {
        super(message, cause);
    }
}
