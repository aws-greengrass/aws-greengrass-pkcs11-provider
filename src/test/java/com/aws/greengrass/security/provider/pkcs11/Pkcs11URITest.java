/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.hamcrest.core.Is;
import org.hamcrest.core.IsNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.net.URISyntaxException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(GGExtension.class)
class Pkcs11URITest {

    @Test
    void GIVEN_expected_pkcs11_key_uri_WHEN_create_object_THEN_return_proper_attributes() throws Exception {
        String uriStr = "pkcs11:object=private-key;type=private";
        Pkcs11URI uri = new Pkcs11URI(uriStr);
        assertThat(uri.getLabel(), Is.is("private-key"));
        assertThat(uri.getType(), Is.is("private"));
        assertThat(uri.toString(), Is.is(uriStr));
    }

    @Test
    void GIVEN_pkcs11_key_uri_missing_type_WHEN_create_object_THEN_return_null_type() throws Exception {
        Pkcs11URI uri = new Pkcs11URI("pkcs11:object=private-key");
        assertThat(uri.getLabel(), Is.is("private-key"));
        assertThat(uri.getType(), IsNull.nullValue());
    }

    @Test
    void GIVEN_expected_pkcs11_cert_uri_WHEN_create_object_THEN_return_proper_attributes() throws Exception {
        Pkcs11URI uri = new Pkcs11URI("pkcs11:object=cert-label;type=cert;id=12345;token=/path/to/lib");
        assertThat(uri.getLabel(), Is.is("cert-label"));
        assertThat(uri.getType(), Is.is("cert"));
    }

    @Test
    void GIVEN_file_uri_WHEN_create_object_THEN_throw_exception() {
        assertThrows(IllegalArgumentException.class,  () -> new Pkcs11URI("file:///path/to/file"));
    }

    @Test
    void GIVEN_null_string_WHEN_create_object_THEN_throw_exception() {
        String str = null;
        assertThrows(NullPointerException.class,  () -> new Pkcs11URI(str));
    }

    @Test
    void GIVEN_empty_string_WHEN_create_object_THEN_throw_exception() {
        assertThrows(URISyntaxException.class,  () -> new Pkcs11URI("  "));
    }

    @Test
    void GIVEN_uri_missing_scheme_WHEN_create_object_THEN_throw_exception() {
        assertThrows(IllegalArgumentException.class,  () -> new Pkcs11URI("object=private-key;type=private"));
    }

    @Test
    void GIVEN_uri_missing_separator_WHEN_create_object_THEN_missing_attribute() throws Exception {
        String uriStr = "pkcs11:object=private-keytype=private";
        Pkcs11URI uri = new Pkcs11URI(uriStr);
        assertThat(uri.getLabel(), Is.is("private-keytype=private"));
        assertThat(uri.getType(), IsNull.nullValue());
    }
}