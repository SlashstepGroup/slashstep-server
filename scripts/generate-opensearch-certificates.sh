#!/bin/bash
script_directory="$(dirname "$0")"
secrets_directory="$script_directory/../secrets"

echo "Generating root certificate authority key and certificate..."
mkdir -p $secrets_directory
openssl genrsa -out $secrets_directory/opensearch-root-ca-key.pem 4096
openssl req -new -x509 -sha256 -key $secrets_directory/opensearch-root-ca-key.pem -out $secrets_directory/opensearch-root-ca.pem -days 730 \
  -addext 'basicConstraints = critical, CA:TRUE, pathlen:0' \
  -addext 'keyUsage = critical, keyCertSign, cRLSign' \
  -addext 'authorityKeyIdentifier = keyid'

echo "Generating OpenSearch client key and certificate signed by the root CA..."
openssl genrsa -out $secrets_directory/opensearch-client-key-temp.pem 2048
openssl req -new -ke
# openssl genrsa -out $secrets_directory/opensearch-admin-key-temp.pem 2048
# openssl pkcs8 -inform PEM -outform PEM -in $secrets_directory/opensearch-admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out $secrets_directory/opensearch-admin-key.pem
# openssl req -new -key $secrets_directory/opensearch-admin-key.pem -out $secrets_directory/opensearch-admin.csr
# openssl x509 -req -in $secrets_directory/opensearch-admin.csr -CA $secrets_directory/opensearch-root-ca.pem -CAkey $secrets_directory/opensearch-root-ca-key.pem -CAcreateserial -sha256 -out $secrets_directory/opensearch-admin.pem -days 730

echo "Cleaning up temporary files..."
rm $secrets_directory/opensearch-admin-key-temp.pem
rm $secrets_directory/opensearch-admin.csr