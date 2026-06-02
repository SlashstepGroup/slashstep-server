#!/bin/bash
script_directory="$(dirname "$0")"
secrets_directory="$script_directory/../secrets"

echo "Generating root certificate authority key and certificate..."
mkdir -p $secrets_directory
openssl genrsa -out $secrets_directory/opensearch-root-ca-key.pem 4096
openssl req -new -x509 -sha256 -key $secrets_directory/opensearch-root-ca-key.pem \
  -out $secrets_directory/opensearch-root-ca.pem -days 730 \
  -addext 'basicConstraints = critical, CA:TRUE, pathlen:0' \
  -addext 'keyUsage = critical, keyCertSign, cRLSign' \
  -addext 'authorityKeyIdentifier = keyid' \
  -subj "/CN=slashstep-root-ca"

echo "Generating OpenSearch client key and certificate signed by the root CA..."
openssl genrsa -out $secrets_directory/opensearch-client-key.pem 2048
openssl req -new -key $secrets_directory/opensearch-client-key.pem \
  -out $secrets_directory/opensearch-client.csr \
  -subj "/CN=slashstep-server"
openssl x509 -req -in $secrets_directory/opensearch-client.csr \
  -CA $secrets_directory/opensearch-root-ca.pem \
  -CAkey $secrets_directory/opensearch-root-ca-key.pem \
  -CAcreateserial \
  -out $secrets_directory/opensearch-client.pem \
  -days 365
