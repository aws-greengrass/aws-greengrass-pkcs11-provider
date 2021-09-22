package com.aws.greengrass.provider.pkcs11;


import com.aws.greengrass.testcommons.testutilities.GGExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;


@ExtendWith({MockitoExtension.class, GGExtension.class})
class PKCS11CryptoKeyServiceTest {

    @InjectMocks
    private PKCS11CryptoKeyService service;

    @Test
    void placeholder_test_to_be_replaced() throws Exception {
//        assertThat(service.getKeyManagers("key").length, Is.is(0));
    }
}