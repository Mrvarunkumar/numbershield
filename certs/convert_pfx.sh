#!/bin/bash
cd '/c/Users/Varun Kumar/OneDrive/Desktop/numbershield'
echo "Extracting private key..."
openssl pkcs12 -in certs/numbershield.pfx -nocerts -nodes -passin pass:numbershield123 -out certs/key.pem
echo "Extracting certificate..."
openssl pkcs12 -in certs/numbershield.pfx -clcerts -nokeys -passin pass:numbershield123 -out certs/cert.pem
echo "Done!"
ls -la certs/

