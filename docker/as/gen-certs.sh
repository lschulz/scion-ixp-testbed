#!/bin/bash

# Generate a TLS certificate in gen-certs.
# 'scion.sh' generates ths certificate when a local topology is created.
# If a gen folder from the coordinator is used the local topology generator is never run and
# therefore no certificate is generated. Since this certificate is still needed to run the AS,
# we use this script to create it. The code is taken from 'scion.sh'.

set -e

if [ ! -e "gen-certs/tls.pem" -o ! -e "gen-certs/tls.key" ]; then
    old=$(umask)
    echo "Generating TLS cert"
    mkdir -p "gen-certs"
    umask 0177
    openssl genrsa -out "gen-certs/tls.key" 2048
    umask "$old"
    openssl req -new -x509 -key "gen-certs/tls.key" -out "gen-certs/tls.pem" -days 3650 -subj /CN=scion_def_srv
fi
