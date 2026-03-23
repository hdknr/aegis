#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Aegis E2E Test Suite ==="
echo ""

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    docker compose down -v 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Building all services ==="
docker compose build

echo ""
echo "=== Starting environment ==="
docker compose up -d

echo ""
echo "=== Waiting for all services to be healthy ==="
for i in $(seq 1 180); do
    SCANNER_STATUS=$(docker inspect --format='{{.State.Health.Status}}' aegis-scanner 2>/dev/null || echo "starting")
    PROXY_STATUS=$(docker inspect --format='{{.State.Health.Status}}' aegis-proxy 2>/dev/null || echo "starting")

    if [ "$SCANNER_STATUS" = "healthy" ] && [ "$PROXY_STATUS" = "healthy" ]; then
        echo "All services healthy after ${i}s"
        break
    fi

    if [ "$i" -eq 180 ]; then
        echo "FAIL: Services did not become healthy in 180s"
        echo "Scanner: $SCANNER_STATUS, Proxy: $PROXY_STATUS"
        docker compose logs --tail=20
        exit 1
    fi
    sleep 1
done

echo ""
docker compose ps --format "table {{.Name}}\t{{.Status}}"

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

# Disable set -e for test assertions (run_test tracks pass/fail)
set +e

echo ""
echo "=== Test 1: Scanner health endpoint ==="
HEALTH=$(docker compose exec -T aegis-worker curl -sf http://aegis-scanner:8080/health 2>/dev/null)
echo "$HEALTH" | python3 -m json.tool 2>/dev/null || true
echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['status']=='healthy' else 1)" 2>/dev/null
run_test "Scanner health returns healthy" $?

echo ""
echo "=== Test 2: Scanner EICAR detection ==="
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
docker compose exec -T aegis-worker bash -c "echo -n '$EICAR' > /tmp/eicar.txt"
SCAN_RESULT=$(docker compose exec -T aegis-worker curl -sf -X POST http://aegis-scanner:8080/scan \
    -F "file=@/tmp/eicar.txt" \
    -F "content_type=application/octet-stream" \
    -F "source_url=https://test/eicar" \
    -F "request_id=e2e_001" 2>/dev/null)
echo "$SCAN_RESULT" | python3 -m json.tool 2>/dev/null || true
echo "$SCAN_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['verdict']=='block' else 1)" 2>/dev/null
run_test "EICAR test file detected as block" $?

echo ""
echo "=== Test 3: Scanner clean file ==="
docker compose exec -T aegis-worker bash -c "echo 'hello world' > /tmp/clean.txt"
CLEAN_RESULT=$(docker compose exec -T aegis-worker curl -sf -X POST http://aegis-scanner:8080/scan \
    -F "file=@/tmp/clean.txt" \
    -F "content_type=text/plain" \
    -F "source_url=https://test/clean" \
    -F "request_id=e2e_002" 2>/dev/null)
echo "$CLEAN_RESULT" | python3 -m json.tool 2>/dev/null || true
echo "$CLEAN_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['verdict']=='allow' else 1)" 2>/dev/null
run_test "Clean file passes scanner" $?

echo ""
echo "=== Test 4: Worker reaches external site via proxy ==="
HTTP_CODE=$(docker compose exec -T aegis-worker curl -sf -o /dev/null -w '%{http_code}' https://github.com 2>/dev/null || echo "000")
[ "$HTTP_CODE" = "200" ]
run_test "Worker can reach github.com via proxy (HTTP $HTTP_CODE)" $?

echo ""
echo "=== Test 5: Proxy logs show traffic ==="
PROXY_LOGS=$(docker compose logs aegis-proxy 2>/dev/null | grep -c "github.com" || echo "0")
[ "$PROXY_LOGS" -gt 0 ]
run_test "Proxy logs contain github.com traffic ($PROXY_LOGS entries)" $?

echo ""
echo "=== Test 6: Worker has no direct internet (aegis-net only) ==="
NETWORKS=$(docker inspect aegis-worker --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null)
echo "$NETWORKS" | grep -q "aegis-net" && ! echo "$NETWORKS" | grep -q "default"
run_test "Worker connected to aegis-net only (networks: $NETWORKS)" $?

echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "E2E TESTS FAILED"
    exit 1
else
    echo "ALL E2E TESTS PASSED"
    exit 0
fi
