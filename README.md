## AWS Greengrass PKCS11 Provider

This plugin is meant to run with [Greengrass Nucleus](https://github.com/aws-greengrass/aws-greengrass-nucleus) as a PKCS11 provider. The plugin provides the ability to use Trusted Platform Module (TPM) to store the things private key and certificate and use it to connect with AWS IoT and other AWS services.

## Parameters

This plugin takes the following parameters

### Required
* **name:** The name of the configuration.
* **library:** Path to PKCS11 library on the device 
* **slot:** Slot ID of the slot where the key is imported. Not to be confused with slot index.
* **userPin:** User pin used during importing the key to the slot. 

## Start Greengrass with PKCS11 provider plugin
### Setup

* Thing private key and certificate need to be imported to the TPM on the device.
* config.yaml containing the following additional config
```
aws.greengrass.crypto.Pkcs11Provider:
    configuration:
      name: sample_name
      library: /path/to/library
      slot: 0000
      userPin: abc123
```
Command to start Greengrass: 
```
sudo -E java -Droot="<root>" -Dlog.store=FILE \
  -jar ./GreengrassCore/lib/Greengrass.jar \
  --aws-region <region> \
  --initial-config config.yaml \
  --component-default-user ggc_user:ggc_group \
  --setup-system-service true
  --trusted-plugin <path_to_plugin>/aws.greengrass.crypto.Pkcs11Provider.jar
```


## Get PKCS11 provider plugin through deployment
### Setup

* Thing private key and certificate need to be imported to the TPM on the device.  


Create a deployment and merge the parameters as shown
```
{
  "targetArn": "<arn_of_target>",
  "components": {
    "aws.greengrass.crypto.Pkcs11Provider": {
      "componentVersion": "1.0.0",
      "configurationUpdate": {
        "merge": "{\"name\":\"sample_name\",\"library\":\"/path/to/library\",\"slot\":0000,\"userPin\":\"abc123\"}"
      }
    }
  }
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

