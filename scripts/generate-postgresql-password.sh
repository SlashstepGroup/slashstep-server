#!/bin/bash
script_directory="$(dirname "$0")"
secrets_directory="$script_directory/../secrets"
mkdir -p $secrets_directory
tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16 > "$secrets_directory/postgresql-password.txt"