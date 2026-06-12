#!/bin/bash
# tests/integration/test_requests.sh
set -e

BASE_URL="${WAF_URL:-http://127.0.0.1}"
PASS=0
FAIL=0

test_blocked() {
    local desc="$1"
    local url="$2"
    local data="$3"

    if [ -n "$data" ]; then
        code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$data" "$url")
    else
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    fi

    if [ "$code" = "403" ] || [ "$code" = "429" ]; then
        echo "  PASS: $desc (got $code)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (got $code, expected 403)"
        FAIL=$((FAIL + 1))
    fi
}

test_allowed() {
    local desc="$1"
    local url="$2"

    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")

    if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
        echo "  PASS: $desc (got $code)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (got $code, expected 200)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== SQLi Tests ==="
while IFS= read -r payload; do
    test_blocked "SQLi: $payload" "$BASE_URL/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")"
done < tests/integration/payloads/sqli.txt

echo ""
echo "=== XSS Tests ==="
while IFS= read -r payload; do
    test_blocked "XSS: $payload" "$BASE_URL/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")"
done < tests/integration/payloads/xss.txt

echo ""
echo "=== CMDI Tests ==="
while IFS= read -r payload; do
    test_blocked "CMDI: $payload" "$BASE_URL/?cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")"
done < tests/integration/payloads/cmdi.txt

echo ""
echo "=== Legitimate Traffic ==="
test_allowed "Normal GET" "$BASE_URL/"
test_allowed "Normal POST" "$BASE_URL/api/data"
test_allowed "Health check" "$BASE_URL/waf-health"

echo ""
echo "=== Results ==="
echo "PASSED: $PASS"
echo "FAILED: $FAIL"
echo "TOTAL:  $((PASS + FAIL))"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
