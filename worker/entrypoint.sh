#!/bin/bash
set -e

CERT_SRC="/certs/mitmproxy-ca-cert.pem"

if [ -f "$CERT_SRC" ]; then
    # System CA store is read-only; configure per-runtime CA trust instead
    export NODE_EXTRA_CA_CERTS="$CERT_SRC"
    export SSL_CERT_FILE="$CERT_SRC"
    export REQUESTS_CA_BUNDLE="$CERT_SRC"
fi

exec gosu aegis "$@"
