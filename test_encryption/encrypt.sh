#!/bin/sh

echo "******** Starting Encryption ****************"

FILE="prov_dev_client"
PUBLIC_KEY="rpi_public.pem"

if [ -f "$FILE" ]; then
    echo "$FILE exists."
    if [ -f "$PUBLIC_KEY" ]; then
        echo "$PUBLIC_KEY exists."
         if [ -f "key.bin" ]; then
            rm -rf key.bin
         fi

         if [ -f "key.bin.enc" ]; then
            rm -rf key.bin.enc
         fi

         if [ -f "$FILE.enc" ]; then
            rm -rf "$FILE.enc"
         fi

        # If both file exists then:
        # create a hash key
        openssl rand -base64 32 > key.bin
        echo "**** Hash key generated ****"

        # Encrypt the hash key using public key
        openssl rsautl -encrypt -inkey "$PUBLIC_KEY" -pubin -in key.bin -out key.bin.enc
        echo "**** Hash key encrypted ****"

        # Encrypt the file using the hash key
        openssl enc -aes-256-cbc -salt -in "$FILE" -out "$FILE.enc" -pass file:key.bin
        echo "**** $FILE encrypted ****"

    else 
        echo "$PUBLIC_KEY does not exist."
    fi
else 
    echo "$FILE does not exist."
fi