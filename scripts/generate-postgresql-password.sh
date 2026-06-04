#!/bin/bash
script_directory="$(dirname "$0")"
secrets_directory="$script_directory/../secrets"
mkdir -p $secrets_directory
openssl rand -base64 12 | head -c 16 > "$secrets_directory/postgresql-password.txt"