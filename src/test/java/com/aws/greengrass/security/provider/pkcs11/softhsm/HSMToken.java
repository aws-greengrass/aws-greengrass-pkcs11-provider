package com.aws.greengrass.security.provider.pkcs11.softhsm;

import lombok.Builder;
import lombok.Value;

@Value
@Builder(toBuilder = true)
public class HSMToken {
    String name;
    String label;
    int slotId;
    String userPin;
}
