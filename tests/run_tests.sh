#!/bin/bash
# Test runner for Moat WAF
# Runs all busted-based unit and integration tests
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Ensure Lua path includes project modules and cjson
export LUA_PATH="./?.lua;./lib/?.lua;./tests/?.lua;;"

# Check if busted is available
if ! command -v busted &> /dev/null; then
    echo "Error: busted is not installed."
    echo "Install with: luarocks install busted"
    exit 1
fi

echo "=== Running Moat WAF Tests ==="
echo ""

# Run unit tests
echo "--- Unit Tests ---"
busted tests/unit/ --verbose
UNIT_RESULT=$?

if [ $UNIT_RESULT -ne 0 ]; then
    echo "Unit tests failed."
    exit 1
fi

echo ""
echo "--- Integration Tests ---"
busted tests/integration/ --verbose
INT_RESULT=$?

if [ $INT_RESULT -ne 0 ]; then
    echo "Integration tests failed."
    exit 1
fi

echo ""
echo "=== All tests passed ==="
