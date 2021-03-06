/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;

import lombok.NonNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * Class to interprete PKCS11 URI.
 */
public class Pkcs11URI {
    public static final String PKCS11_SCHEME = "pkcs11";
    private static final String LABEL_KEY = "object";
    private static final String TYPE_KEY = "type";

    private final URI uri;
    private final Map<String, String> attributeMap = new HashMap<>();

    /**
     * Constructor of PKCS11 URI.
     *
     * @param str String used to parse pkcs11 attributes
     * @throws URISyntaxException if str is not valid URI
     */
    public Pkcs11URI(@NonNull String str) throws URISyntaxException {
        this(new URI(str));
    }

    /**
     * Constructor of PKCS11 URI.
     *
     * @param uri URI used to parse pkcs11 attributes
     */
    public Pkcs11URI(URI uri) {
        this.uri = uri;
        if (!PKCS11_SCHEME.equalsIgnoreCase(this.uri.getScheme())) {
            throw new IllegalArgumentException(String.format("URI scheme is not %s: %s", PKCS11_SCHEME, uri));
        }
        parseAttributes(this.uri.getSchemeSpecificPart());
    }

    private void parseAttributes(String schemeSpecificPart) {
        String[] attributes = schemeSpecificPart.split(";");
        for (String attribute : attributes) {
            int i = attribute.indexOf('=');
            if (i != -1) {
                attributeMap.put(attribute.substring(0, i).trim(), attribute.substring(i + 1).trim());
            }
        }
    }

    public String getLabel() {
        return attributeMap.get(LABEL_KEY);
    }

    public String getType() {
        return attributeMap.get(TYPE_KEY);
    }

    @Override
    public String toString() {
        return this.uri.toString();
    }
}
