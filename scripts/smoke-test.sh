#!/bin/bash
# Smoke test: lightweight post-startup verification for aegis environment.
# Unlike test-e2e.sh, this does NOT build/teardown — it tests the running environment.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Aegis Smoke Test ==="
echo ""

# --- Check all containers are running ---
echo "--- Container status ---"
docker compose ps --format "table {{.Name}}\t{{.Status}}"
echo ""

set +e

# 1. Scanner health
HEALTH=$(docker compose exec -T aegis-worker curl -sf http://aegis-scanner:8080/health 2>/dev/null)
echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['status']=='healthy' else 1)" 2>/dev/null
run_test "Scanner is healthy" $?

# 2. Worker is running (not restarting)
WORKER_STATUS=$(docker inspect --format='{{.State.Status}}' aegis-worker 2>/dev/null)
[ "$WORKER_STATUS" = "running" ]
run_test "Worker is running (status: $WORKER_STATUS)" $?

# 3. Fetch a real URL through the full pipeline (proxy + scanner)
echo ""
echo "--- Live URL fetch test ---"

# Pick a random security-related site to verify the full scan pipeline
SITES=(
    "https://www.cisa.gov/"
    "https://nvd.nist.gov/"
    "https://owasp.org/"
    "https://www.sans.org/"
)
SMOKE_URL="${SITES[$((RANDOM % ${#SITES[@]}))]}"

echo "  Target: $SMOKE_URL"
FETCH_RESULT=$(uv run aegis fetch "$SMOKE_URL" --json 2>/dev/null)
FETCH_STATUS=$(echo "$FETCH_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status_code',0))" 2>/dev/null)
FETCH_VERDICT=$(echo "$FETCH_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('verdict',''))" 2>/dev/null)

[ "$FETCH_STATUS" = "200" ] && [ "$FETCH_VERDICT" = "allow" ]
run_test "Live URL fetch: HTTP $FETCH_STATUS, verdict=$FETCH_VERDICT" $?

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo "SMOKE TEST FAILED"
    exit 1
else
    echo "SMOKE TEST PASSED"
    exit 0
fi
