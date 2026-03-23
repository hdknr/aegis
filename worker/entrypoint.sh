#!/bin/bash
set -e

CERT_SRC="/certs/mitmproxy-ca-cert.pem"
CERT_DST="/usr/local/share/ca-certificates/aegis.crt"

if [ -f "$CERT_SRC" ]; then
    cp "$CERT_SRC" "$CERT_DST"
    update-ca-certificates --fresh > /dev/null 2>&1
    export NODE_EXTRA_CA_CERTS="$CERT_SRC"
fi

exec gosu aegis "$@"
