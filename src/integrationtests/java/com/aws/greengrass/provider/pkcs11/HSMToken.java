package com.aws.greengrass.provider.pkcs11;

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
