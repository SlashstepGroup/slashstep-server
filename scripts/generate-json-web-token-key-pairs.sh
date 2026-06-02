#!/bin/bash
script_directory="$(dirname "$0")"
secrets_directory="$script_directory/../secrets"

mkdir -p $secrets_directory

echo "Generating JSON web token key pairs..."
openssl genpkey -algorithm Ed25519 -out $secrets_directory/jwt-private-key.pem
openssl pkey -in $secrets_directory/jwt-private-key.pem -pubout -out $secrets_directory/jwt-public-key.pem