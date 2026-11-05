#!/bin/sh
# Test runner for Moat WAF
# Runs Lua syntax checks, standalone regressions, and busted suites.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [ -x /usr/local/openresty/luajit/bin/luajit ]; then
    LUA_BIN="${LUA_BIN:-/usr/local/openresty/luajit/bin/luajit}"
elif command -v luajit >/dev/null 2>&1; then
    LUA_BIN="${LUA_BIN:-$(command -v luajit)}"
elif command -v lua5.1 >/dev/null 2>&1; then
    LUA_BIN="${LUA_BIN:-$(command -v lua5.1)}"
else
    echo "Error: neither OpenResty LuaJIT, luajit, nor lua5.1 is installed." >&2
    exit 1
fi

BUSTED_BIN="${BUSTED_BIN:-}"
if [ -z "$BUSTED_BIN" ]; then
    for candidate in busted busted-5.1 busted5.1; do
        if command -v "$candidate" >/dev/null 2>&1; then
            BUSTED_BIN="$(command -v "$candidate")"
            break
        fi
    done
fi
if [ -z "$BUSTED_BIN" ]; then
    echo "Error: busted is not installed (expected busted or busted-5.1)." >&2
    exit 1
fi

# Alpine installs busted for Lua 5.1 as a library and a script. Run that
# script with OpenResty's LuaJIT so tests match the production runtime
# (notably bit, cjson, and binary string behavior).
export LUA_PATH="./?.lua;./lib/?.lua;/usr/share/lua/common/?.lua;/usr/share/lua/common/?/init.lua;/usr/share/lua/5.1/?.lua;/usr/share/lua/5.1/?/init.lua;;"
export LUA_CPATH="/usr/lib/lua/5.1/?.so;/usr/local/openresty/lualib/?.so;;"

run_busted() {
    if [ -f /usr/bin/busted-5.1 ]; then
        "$LUA_BIN" /usr/bin/busted-5.1 "$@"
    else
        "$BUSTED_BIN" "$@"
    fi
}

echo "=== Running Moat WAF Tests ==="
echo ""

echo "--- Lua Syntax ---"
find lib -name "*.lua" -type f | sort | while IFS= read -r file; do
    "$LUA_BIN" -e "
        local path = '$file'
        local chunk, err = loadfile(path)
        if not chunk then
            io.stderr:write('SYNTAX ERROR ', path, ': ', err, '\n')
            os.exit(1)
        end
    "
done

echo ""
echo "--- Standalone Unit Regressions ---"
for file in tests/unit/test_*.lua; do
    echo "Running $file"
    if [ "$file" = "tests/unit/test_rule_engine.lua" ] && command -v resty >/dev/null 2>&1; then
        resty --errlog-level emerg "$file"
    else
        "$LUA_BIN" "$file"
    fi
done

echo ""
echo "--- Busted Unit Tests ---"
run_busted tests/unit/*_spec.lua --verbose

echo ""
echo "--- Busted Integration Tests ---"
run_busted tests/integration/waf_spec.lua --verbose

echo ""
echo "=== All tests passed ==="
