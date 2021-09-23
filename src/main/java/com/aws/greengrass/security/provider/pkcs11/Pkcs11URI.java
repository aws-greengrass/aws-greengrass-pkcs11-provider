/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;

import com.aws.greengrass.config.CaseInsensitiveString;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

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
    public Pkcs11URI(String str) throws URISyntaxException {
        this(new URI(str));
    }

    /**
     * Constructor of PKCS11 URI.
     *
     * @param uri URI used to parse pkcs11 attributes
     */
    public Pkcs11URI(URI uri) {
        this.uri = uri;
        if (this.uri.getScheme() == null || !new CaseInsensitiveString(PKCS11_SCHEME)
                .equals(new CaseInsensitiveString(this.uri.getScheme()))) {
            throw new IllegalArgumentException(String.format("URI scheme part is not %s", PKCS11_SCHEME));
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
        return attributeMap.getOrDefault(LABEL_KEY, null);
    }

    public String getType() {
        return attributeMap.getOrDefault(TYPE_KEY, null);
    }

    @Override
    public String toString() {
        return this.uri.toString();
    }
}
