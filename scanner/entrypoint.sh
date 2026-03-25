#!/bin/bash
set -e

DB_DIR="/var/lib/clamav"
if [ ! -f "$DB_DIR/main.cvd" ] && [ ! -f "$DB_DIR/main.cld" ]; then
    echo "ClamAV DB not found, running freshclam..."
    if ! freshclam --quiet --foreground; then
        echo "ERROR: freshclam failed and no existing DB available"
        exit 1
    fi
else
    INTERVAL="${FRESHCLAM_INTERVAL:-21600}"
    DB_AGE=$(( $(date +%s) - $(stat -c %Y "$DB_DIR/main.cvd" 2>/dev/null || stat -c %Y "$DB_DIR/main.cld" 2>/dev/null || echo 0) ))
    if [ "$DB_AGE" -gt "$INTERVAL" ]; then
        echo "ClamAV DB is stale ($DB_AGE seconds old), updating..."
        freshclam --quiet --foreground || echo "Warning: freshclam failed, using existing DB"
    fi
fi

clamd --config-file=/etc/clamav/clamd.conf &

echo "Waiting for clamd..."
for i in {1..60}; do
    if echo PING | nc -w 1 localhost 3310 2>/dev/null | grep -q PONG; then
        echo "clamd is ready"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: clamd did not become ready in 60 seconds"
        exit 1
    fi
    sleep 1
done

TRIVY_CACHE="${TRIVY_CACHE_DIR:-/root/.cache/trivy}"
if [ ! -d "$TRIVY_CACHE/db" ]; then
    echo "Downloading Trivy DB..."
    trivy --quiet --cache-dir "$TRIVY_CACHE" image --download-db-only 2>/dev/null || echo "Warning: Trivy DB download failed"
fi

exec uvicorn scanner.main:app --host 0.0.0.0 --port 8080 --workers "${AEGIS_WORKERS:-2}"
