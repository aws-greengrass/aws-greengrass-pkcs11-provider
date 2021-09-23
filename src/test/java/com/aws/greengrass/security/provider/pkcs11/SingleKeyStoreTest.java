/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.security.provider.pkcs11;

import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.hamcrest.core.Is;
import org.hamcrest.core.IsNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyArray;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
class SingleKeyStoreTest {
    private static final String ALIAS = "key";

    private SingleKeyStore.SingleKeyStoreDecorator keyStore;

    @Mock
    private KeyStoreSpi keyStoreSpi;

    @BeforeEach
    void beforeEach() {
        keyStore = new SingleKeyStore.SingleKeyStoreDecorator(keyStoreSpi, ALIAS);
    }

    @Test
    void GIVEN_matched_alias_WHEN_get_key_THEN_delegate() throws Exception {
        char[] password = new char[0];
        Key key = mock(Key.class);
        when(keyStoreSpi.engineGetKey(ALIAS, password)).thenReturn(key);
        assertThat(keyStore.engineGetKey(ALIAS, password), Is.is(key));
    }

    @Test
    void GIVEN_unmatched_alias_WHEN_get_key_THEN_return_null() throws Exception {
        assertThat(keyStore.engineGetKey("foo", null), IsNull.nullValue());
        verify(keyStoreSpi, never()).engineGetKey(anyString(), any());
    }

    @Test
    void GIVEN_matched_alias_WHEN_get_cert_chain_THEN_delegate() {
        Certificate[] chain = new Certificate[0];
        when(keyStoreSpi.engineGetCertificateChain(ALIAS)).thenReturn(chain);
        assertThat(keyStore.engineGetCertificateChain(ALIAS), Is.is(chain));
    }

    @Test
    void GIVEN_unmatched_alias_WHEN_get_cert_chain_THEN_return_null() {
        assertThat(keyStore.engineGetCertificateChain("foo"), emptyArray());
        verify(keyStoreSpi, never()).engineGetCertificateChain(anyString());
    }

    @Test
    void GIVEN_matched_alias_WHEN_set_key_entry_THEN_delegate() throws Exception {
        char[] password = new char[0];
        Key key = mock(Key.class);
        Certificate[] chain = new Certificate[0];
        keyStore.engineSetKeyEntry(ALIAS, key, password, chain);
        verify(keyStoreSpi).engineSetKeyEntry(ALIAS, key, password, chain);
    }

    @Test
    void GIVEN_unmatched_alias_WHEN_set_key_entry_THEN_ignored() throws Exception {
        keyStore.engineSetKeyEntry("foo", null, null, null);
        verify(keyStoreSpi, never()).engineSetKeyEntry(anyString(), any(), any(), any());
    }

    @Test
    void GIVEN_beneath_key_store_contain_alias_WHEN_aliases_THEN_return_single_element() {
        when(keyStoreSpi.engineContainsAlias(ALIAS)).thenReturn(true);
        Enumeration<String> aliases = keyStore.engineAliases();
        List<String> aliasList = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            aliasList.add(aliases.nextElement());
        }
        assertThat(aliasList, IsIterableContainingInOrder.contains(ALIAS));
    }

    @Test
    void GIVEN_beneath_key_store_not_contain_alias_WHEN_aliases_THEN_return_empty() {
        when(keyStoreSpi.engineContainsAlias(ALIAS)).thenReturn(false);
        assertThat(keyStore.engineAliases().hasMoreElements(), Is.is(false));
    }

    @Test
    @SuppressWarnings("PMD.CloseResource")
    void GIVEN_input_stream_and_password_WHEN_load_THEN_delegate() throws Exception {
        InputStream stream = mock(InputStream.class);
        char[] password = new char[0];
        keyStore.engineLoad(stream, password);
        verify(keyStoreSpi).engineLoad(stream, password);
    }

    @Test
    void GIVEN_matched_alias_WHEN_is_key_entry_THEN_delegate() {
        when(keyStoreSpi.engineIsKeyEntry(ALIAS)).thenReturn(true);
        assertThat(keyStore.engineIsKeyEntry(ALIAS), Is.is(true));
    }

    @Test
    void GIVEN_unmatched_alias_WHEN_is_key_entry_THEN_return_false() {
        assertThat(keyStore.engineIsKeyEntry("foo"), Is.is(false));
        verify(keyStoreSpi, never()).engineIsKeyEntry(anyString());
    }
}