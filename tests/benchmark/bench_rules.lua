-- tests/benchmark/bench_rules.lua
-- Benchmark for WAF rule engine pattern matching.
-- Usage: resty tests/benchmark/bench_rules.lua
--
-- Runs outside of an nginx request context, so ngx.var and ngx.req
-- are unavailable. We construct request tables directly and call
-- evaluate() for each payload.

---------------------------------------------------------------------------
-- Resolve project root and set up package path
---------------------------------------------------------------------------
local script_dir = arg and arg[0] and arg[0]:match("^(.-)[^/\\]*$") or ""
-- When run via resty, arg[0] may be nil; fall back to current directory.
package.path = script_dir .. "../../?.lua;" .. package.path

---------------------------------------------------------------------------
-- Mock cjson for plain Lua (resty provides it natively)
---------------------------------------------------------------------------
if not package.loaded["cjson"] then
    package.loaded["cjson"] = {
        encode = function() return "{}" end,
        decode = function() return {} end,
    }
end

-- Provide bit library shim for Lua 5.4+/5.5 (resty/LuaJIT has it natively)
if not bit then
    bit = {}
    function bit.band(a, b) return a & b end
    function bit.bor(a, b) return a | b end
    function bit.bxor(a, b) return a ~ b end
    function bit.lshift(a, n) return a << n end
    function bit.rshift(a, n) return a >> n end
end

---------------------------------------------------------------------------
-- Mock ngx subsystems that are unavailable outside a request
---------------------------------------------------------------------------
_G.ngx = _G.ngx or {}
ngx.var = ngx.var or {}
ngx.req = ngx.req or {}
ngx.log = ngx.log or function() end
ngx.ERR = ngx.ERR or 4
ngx.WARN = ngx.WARN or 5
ngx.INFO = ngx.INFO or 6

-- Provide get_body_data / get_body_file if missing
if not ngx.req.get_body_data then
    ngx.req.get_body_data = function() return nil end
end
if not ngx.req.get_body_file then
    ngx.req.get_body_file = function() return nil end
end
if not ngx.req.get_headers then
    ngx.req.get_headers = function()
        return { ["User-Agent"] = "Mozilla/5.0 (bench)" }
    end
end

-- Provide ngx.var fields used by build_request()
if not ngx.var.uri then
    ngx.var.uri = "/"
end
if not ngx.var.query_string then
    ngx.var.query_string = ""
end
if not ngx.var.http_cookie then
    ngx.var.http_cookie = ""
end

---------------------------------------------------------------------------
-- Load rule engine
---------------------------------------------------------------------------
local rule_engine = require("lib.rule_engine")

-- Pre-load rules so disk I/O doesn't skew the benchmark
rule_engine.init()
local rule_count = rule_engine.rule_count()
print(string.format("Loaded %d rules", rule_count))

---------------------------------------------------------------------------
-- Test payloads: mix of attacks and clean traffic
---------------------------------------------------------------------------
local test_payloads = {
    -- SQL injection
    {
        name  = "SQLi (OR 1=1)",
        req   = { URI = "/search", ARGS = "q=1' OR '1'='1", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "block",
    },
    {
        name  = "SQLi (DROP TABLE)",
        req   = { URI = "/user", ARGS = "id=1; DROP TABLE users--", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "block",
    },
    {
        name  = "SQLi (UNION SELECT)",
        req   = { URI = "/search", ARGS = "q=1 UNION SELECT * FROM users", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "block",
    },
    -- XSS
    {
        name  = "XSS (script tag)",
        req   = { URI = "/comment", ARGS = "text=<script>alert(1)</script>", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "block",
    },
    {
        name  = "XSS (img javascript URI)",
        req   = { URI = "/post", ARGS = '<img src="javascript:alert(1)">', BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "block",
    },
    -- Path traversal
    {
        name  = "Path traversal",
        req   = { URI = "/files/../../../etc/passwd", ARGS = "", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "block",
    },
    -- Clean requests (should pass)
    {
        name  = "Clean API request",
        req   = { URI = "/api/users", ARGS = "page=1&limit=10", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "pass",
    },
    {
        name  = "Static asset",
        req   = { URI = "/static/style.css", ARGS = "", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "pass",
    },
    {
        name  = "Clean data request",
        req   = { URI = "/api/data", ARGS = "name=hello&value=123", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0" }, COOKIE = "" },
        expected = "pass",
    },
    {
        name  = "Homepage",
        req   = { URI = "/", ARGS = "", BODY = "",
                  HEADERS = { ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
                  COOKIE = "" },
        expected = "pass",
    },
}

---------------------------------------------------------------------------
-- Warm-up: run each payload a few hundred times so JIT compiles hot paths
---------------------------------------------------------------------------
local warmup_rounds = 500
io.write("Warming up...")
io.flush()
for _ = 1, warmup_rounds do
    for _, payload in ipairs(test_payloads) do
        rule_engine.evaluate(payload.req)
    end
end
print(" done")

---------------------------------------------------------------------------
-- Correctness check: verify expected outcomes before timing
---------------------------------------------------------------------------
print("\nCorrectness check:")
local all_correct = true
for _, payload in ipairs(test_payloads) do
    local action = rule_engine.evaluate(payload.req)
    local ok = (action == payload.expected)
    local mark = ok and "OK" or "MISMATCH"
    print(string.format("  %-28s expected=%-6s got=%-6s [%s]",
        payload.name, payload.expected, action, mark))
    if not ok then all_correct = false end
end
if not all_correct then
    print("\nERROR: Some payloads did not match expected outcome. Aborting.")
    os.exit(1)
end

---------------------------------------------------------------------------
-- Benchmark
---------------------------------------------------------------------------
local iterations = 10000
local total_checks = iterations * #test_payloads

print(string.format("\nBenchmark: %d iterations x %d payloads = %d checks",
    iterations, #test_payloads, total_checks))

-- Use ngx.now() if available (sub-ms), otherwise os.clock()
local now_fn = (ngx and ngx.now) and ngx.now or os.clock

local start = now_fn()

for _ = 1, iterations do
    for _, payload in ipairs(test_payloads) do
        rule_engine.evaluate(payload.req)
    end
end

local elapsed = now_fn() - start
local avg_us = (elapsed / total_checks) * 1e6
local avg_ms = (elapsed / total_checks) * 1000
local rps = total_checks / elapsed

print(string.format("\nResults:"))
print(string.format("  Total time:     %.3f seconds", elapsed))
print(string.format("  Avg per check:  %.2f us  (%.4f ms)", avg_us, avg_ms))
print(string.format("  Throughput:     %.0f checks/second", rps))
print(string.format("  Rules loaded:   %d", rule_count))
