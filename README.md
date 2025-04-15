# Project Title

OTA update system for IoT device

## Description

This project contains the source code the OTA update systems for linux-based IoT devices (tested with Raspberry Pi 3B+). The cloud provider is Microsoft Azure, which offers services for device management, provisioning and storage. 

## Getting Started

### Dependencies

* Clone Azure SDK for C : https://github.com/Azure/azure-sdk-for-c

### Installing and set up

* Edit CMakeList according to the requirements
* Run the command below to enable provisioning and relevant settings:

```
cmake -Duse_prov_client:BOOL=ON -Dhsm_type_custom=ON -Dhsm_custom_lib="Path to the custom lib file" .
```

* Build the project using command below. It will create binary files for the SDK that can be used in the project

```
cmake --build .
```

* Then, generate certificate using commands below:

```
curl https :// raw.githubusercontent.com/Azure/azure -iot -sdk -c/master/tools/CACertificates/certGen.sh --output certGen.sh

curl https :// raw.githubusercontent.com/Azure/azure -iot -sdk -c/master/tools/CACertificates/openssl_device_intermediate_ca.cnf --output openssl_device_intermediate_ca.cnf

curl https :// raw.githubusercontent.com/Azure/azure -iot -sdk -c/master/tools/CACertificates/openssl_root_ca.cnf --output openssl_root_ca.cnf

./ certGen.sh create_root_and_intermediate

./ certGen.sh create_device_certificate sensor1000.iottest.soluware.de

openssl rand -base64 32 > key.bin

openssl rsautl -encrypt -inkey "$PUBLIC_KEY" -pubin -in key.bin -out key.bin.enc

openssl enc -aes -256-cbc -salt -in "$FILE" -out "$FILE.enc" -pass file:key.
bin
```

### Executing program

* For detailed explanation for the commands above, refer to documentation.
* Verify the root certificate in the Azure Portal. For detailed description, refer to documentation.
* Place the device certificate in the same folder as the executable file and run the executable file.

## Help

* Any advise for common problems or issues, check existing issues in https://github.com/Azure/azure-sdk-for-c
* If the issue is unique, create a new issue in there. The team will respond in a short amout of time.

## Acknowledgments

* [Azure SDK](https://github.com/Azure/azure-sdk-for-c)
* [Stackoverflow](https://stackoverflow.com/)
* [Microsoft documentation](https://learn.microsoft.com/en-ca/)