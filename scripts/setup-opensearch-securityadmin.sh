#!/bin/bash -e

# Start OpenSearch in the background
/usr/share/opensearch/opensearch-docker-entrypoint.sh &

# Wait for OpenSearch port 9200 to become responsive
echo "Waiting for OpenSearch to start up..."
until curl -s --cacert /usr/share/opensearch/config/opensearch-root-ca --cert /run/secrets/opensearch-admin-certificate --key /run/secrets/opensearch-admin-key https://localhost:9200 > /dev/null; do
    sleep 2
done

echo "OpenSearch is up. Executing securityadmin.sh..."

# Force JAVA_HOME path to prevent script failures
export JAVA_HOME=/usr/share/opensearch/jdk

# Run the security configuration update
/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/opensearch/config/opensearch-security/ \
  -cacert /usr/share/opensearch/config/opensearch-root-ca \
  -cert /run/secrets/opensearch-admin-certificate \
  -key /run/secrets/opensearch-admin-key \
  -icl -nhnv

echo "Security configuration applied successfully."

# Bring OpenSearch process back to the foreground to keep container running
wait