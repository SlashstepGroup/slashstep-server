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
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -subj "/CN=localhost"

echo "Generating an admin certificate and key signed by the root CA..."
openssl genrsa -out $secrets_directory/opensearch-admin-key.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in $secrets_directory/opensearch-admin-key.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out $secrets_directory/opensearch-admin-key.pem
openssl req -new -key $secrets_directory/opensearch-admin-key.pem -subj "/CN=admin" -out $secrets_directory/opensearch-admin-certificate.csr
openssl x509 -req -in $secrets_directory/opensearch-admin-certificate.csr -CA $secrets_directory/opensearch-root-ca.pem -CAkey $secrets_directory/opensearch-root-ca-key.pem -CAcreateserial -sha256 -out $secrets_directory/opensearch-admin-certificate.pem -days 730
rm -f $secrets_directory/opensearch-admin-certificate.csr

echo "Generating OpenSearch node key and certificate signed by the root CA..."
openssl genrsa -out $secrets_directory/opensearch-node-key.pem 2048
openssl pkcs8 -inform PEM -outform PEM -in $secrets_directory/opensearch-node-key.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out $secrets_directory/opensearch-node-key.pem
openssl req -new -key $secrets_directory/opensearch-node-key.pem \
  -out $secrets_directory/opensearch-node-certificate.csr \
  -subj "/CN=node1.dns.a-record"

# FIX: Create a temporary extension file for the signing process
echo "subjectAltName=DNS:localhost,IP:127.0.0.1" > $secrets_directory/opensearch-node-certificate.ext

openssl x509 -req -in $secrets_directory/opensearch-node-certificate.csr \
  -CA $secrets_directory/opensearch-root-ca.pem \
  -CAkey $secrets_directory/opensearch-root-ca-key.pem \
  -CAcreateserial -sha256 \
  -out $secrets_directory/opensearch-node-certificate.pem \
  -days 730 \
  -extfile $secrets_directory/opensearch-node-certificate.ext

# Clean up temporary files
rm -f $secrets_directory/opensearch-node-certificate.csr $secrets_directory/opensearch-node-certificate.ext

echo "Generating OpenSearch client key and certificate signed by the root CA..."
openssl genrsa -out $secrets_directory/opensearch-client-key.pem 2048
openssl req -new -key $secrets_directory/opensearch-client-key.pem \
  -out $secrets_directory/opensearch-client-certificate.csr \
  -subj "/CN=slashstep-server.dns.a-record"
echo 'subjectAltName=DNS:slashstep-server.dns.a-record' > $secrets_directory/opensearch-client-certificate.ext
openssl x509 -req -in $secrets_directory/opensearch-client-certificate.csr \
  -CA $secrets_directory/opensearch-root-ca.pem \
  -CAkey $secrets_directory/opensearch-root-ca-key.pem \
  -CAcreateserial \
  -out $secrets_directory/opensearch-client-certificate.pem \
  -days 365
rm -f $secrets_directory/opensearch-client-certificate.csr $secrets_directory/opensearch-client-certificate.ext
