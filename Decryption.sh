#!/bin/sh

FILE="/home/pi/Downloads/FirmwareUpdate/prov_dev_client"
HASH_KEY="/home/pi/Downloads/FirmwareUpdate/key.bin"
PRIVATE_KEY="/home/pi/Downloads/FirmwareUpdate/rpi_private.pem"

if [ -f "$FILE.enc" ]; then
    echo "$FILE.enc exists."
    if [ -f "$HASH_KEY.enc" ]; then
        echo "$HASH_KEY.enc exists."
        if [ -f "$PRIVATE_KEY" ]; then
            echo "$PRIVATE_KEY exists."

            openssl rsautl -decrypt -inkey "$PRIVATE_KEY" -in "$HASH_KEY.enc" -out "$HASH_KEY"
            echo "****  Hash Key Decrypted ******"

            openssl enc -d -aes-256-cbc -in "$FILE.enc" -out "$FILE" -pass file:"$HASH_KEY"
            echo "**** File Decrypted *****"


        else 
            echo "$PRIVATE_KEY does not exist."
        fi
    else 
        echo "$HASH_KEY.enc does not exist."
    fi
else 
    echo "$FILE.enc does not exist."
fi