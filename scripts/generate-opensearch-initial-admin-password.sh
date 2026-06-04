#!/bin/bash -e

script_directory="$(dirname "$0")"
root_directory="$script_directory/.."

echo "OPENSEARCH_INITIAL_ADMIN_PASSWORD=$(openssl rand -base64 24)" > $root_directory/.env
chmod 644 $root_directory/.env