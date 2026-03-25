#!/bin/bash
set -e

CERT_SRC="/certs/mitmproxy-ca-cert.pem"
COMBINED_CA="/tmp/ca-bundle.crt"

if [ -f "$CERT_SRC" ]; then
    # System CA store is read-only; build a combined bundle in tmpfs
    cat /etc/ssl/certs/ca-certificates.crt "$CERT_SRC" > "$COMBINED_CA"
    export SSL_CERT_FILE="$COMBINED_CA"
    export REQUESTS_CA_BUNDLE="$COMBINED_CA"
    export CURL_CA_BUNDLE="$COMBINED_CA"
    export NODE_EXTRA_CA_CERTS="$CERT_SRC"
fi

exec gosu aegis "$@"
