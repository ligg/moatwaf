-- tests/unit/test_cc_protect.lua
-- Tests for lib/cc_protect.lua functions
--
-- NOTE: This test runs in plain Lua/LuaJIT (not OpenResty), so we mock
-- cjson, ngx, and set up the package path appropriately.

-- Set up package path to find lib/ from project root
-- Detect project root (works on both Linux and Windows)
local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

-- Mock cjson since it's only available in OpenResty
package.loaded["cjson"] = {
    encode = function() return "{}" end,
    decode = function() return {} end,
}

-- Provide bit library shim for Lua 5.4+/5.5 (utils.lua uses LuaJIT's bit.band).
-- The shim body is compiled lazily so LuaJIT (Lua 5.1 syntax) never has to
-- parse the 5.3-style bitwise operators.
if not bit then
    bit = (load([[
        local b = {}
        function b.band(a, c) return a & c end
        function b.bor(a, c) return a | c end
        function b.bxor(a, c) return a ~ c end
        function b.lshift(a, n) return a << n end
        function b.rshift(a, n) return a >> n end
        return b
    ]]))()
end

-- Virtual clock shared by ngx.now() and the mock dicts that opt into it.
-- Tests advance time deterministically instead of sleeping.
local virtual_now = 1000000.0

-- Mock ngx.shared dictionaries for testing.
-- Faithful to OpenResty semantics:
--   * incr(key, v, init, ttl): init/ttl apply ONLY when the key is created;
--     incr never refreshes the TTL of an existing key.
--   * add(key, v, ttl): fails when the key exists (and is not expired).
local function make_mock_dict(clock)
    clock = clock or os.time
    local store = {}
    local ttls = {}
    local mock = {}

    local function alive(key)
        if ttls[key] and ttls[key] <= clock() then
            store[key] = nil
            ttls[key] = nil
            return false
        end
        return store[key] ~= nil
    end

    function mock:get(key)
        if not alive(key) then return nil end
        return store[key]
    end

    function mock:set(key, value, ttl)
        store[key] = value
        if ttl then
            ttls[key] = clock() + ttl
        else
            ttls[key] = nil
        end
        return true
    end

    function mock:add(key, value, ttl)
        if alive(key) then
            return false, "exists"
        end
        store[key] = value
        if ttl then
            ttls[key] = clock() + ttl
        end
        return true
    end

    function mock:incr(key, value, init, ttl)
        if not alive(key) then
            if init == nil then
                return nil, "not found"
            end
            store[key] = init
            if ttl then
                ttls[key] = clock() + ttl
            end
        end
        store[key] = store[key] + value
        return store[key], nil
    end

    function mock:delete(key)
        store[key] = nil
        ttls[key] = nil
        return true
    end

    return mock
end

-- Set up global ngx mock
if not ngx then
    ngx = {}
end
ngx.now = function() return virtual_now end
ngx.shared = {
    rate_limit = make_mock_dict(),
    session_track = make_mock_dict(),
}

-- Test: DEFAULTS table exists with expected fields
local function test_defaults()
    local cc = require("lib.cc_protect")

    assert(cc.DEFAULTS ~= nil, "DEFAULTS table should exist")
    assert(cc.DEFAULTS.ip_qps_limit == 100, "ip_qps_limit should be 100")
    assert(cc.DEFAULTS.ip_conn_limit == 50, "ip_conn_limit should be 50")
    assert(cc.DEFAULTS.global_qps_limit == 5000, "global_qps_limit should be 5000")
    assert(cc.DEFAULTS.window_size == 60, "window_size should be 60")

    print("ALL DEFAULTS tests PASSED")
end

-- Test: make_key generates correct key format
local function test_make_key()
    local cc = require("lib.cc_protect")

    -- Full key with ip, method, uri
    assert(cc.make_key("1.2.3.4", "GET", "/api/users") == "1.2.3.4:GET:/api/users",
        "full key should be ip:method:uri")

    -- IP only (nil method and uri)
    assert(cc.make_key("10.0.0.1") == "10.0.0.1",
        "ip-only key should be just ip")

    -- IP + method, no uri
    assert(cc.make_key("10.0.0.1", "POST") == "10.0.0.1:POST",
        "ip+method key should be ip:method")

    -- Nil IP
    assert(cc.make_key(nil, "GET", "/test") == "unknown:GET:/test",
        "nil ip should use 'unknown'")

    -- All nil
    assert(cc.make_key(nil, nil, nil) == "unknown",
        "all nil should return 'unknown'")

    -- Empty string IP
    assert(cc.make_key("", "GET", "/") == ":GET:/",
        "empty ip should be preserved")

    print("ALL make_key tests PASSED")
end

-- Test: check_rate_limit basic functionality
local function test_check_rate_limit()
    local cc = require("lib.cc_protect")

    -- Reset the dict
    ngx.shared.rate_limit = make_mock_dict()

    -- First request should pass
    local blocked, reason = cc.check_rate_limit("test:GET:/page", 5, 60)
    assert(blocked == false, "first request should pass")
    assert(reason == "pass", "reason should be 'pass'")

    -- Requests up to limit should pass
    for i = 2, 5 do
        blocked, reason = cc.check_rate_limit("test:GET:/page", 5, 60)
        assert(blocked == false, "request " .. i .. " should pass")
    end

    -- 6th request should be blocked (limit is 5)
    blocked, reason = cc.check_rate_limit("test:GET:/page", 5, 60)
    assert(blocked == true, "request exceeding limit should be blocked")
    assert(reason == "rate_exceeded", "reason should be 'rate_exceeded'")

    -- Different key should pass
    blocked, reason = cc.check_rate_limit("other:GET:/page", 5, 60)
    assert(blocked == false, "different key should pass")

    print("ALL check_rate_limit tests PASSED")
end

-- Test: window rotation keeps counting correctly across windows.
-- Regression: cur_key must get its TTL refreshed on rotation, otherwise the
-- counter expires after 2*window of continuous traffic and the limiter loses
-- its history (under-blocking).
local function test_rate_limit_rotation_ttl()
    local cc = require("lib.cc_protect")

    local dict = make_mock_dict(function() return virtual_now end)
    ngx.shared.rate_limit = dict

    local limit = 10
    virtual_now = 1000000.0

    -- Window 1: 3 requests
    for _ = 1, 3 do
        local blocked = cc.check_rate_limit("ip1", limit, 1)
        assert(blocked == false, "window1 request should pass")
    end

    -- Window 2 (t+1.1): rotation happens, 3 more requests stay under limit.
    virtual_now = virtual_now + 1.1
    for _ = 1, 3 do
        local blocked = cc.check_rate_limit("ip1", limit, 1)
        assert(blocked == false, "window2 request should pass")
    end

    -- Window 3 (t+2.2): rotation again. The previous window's 3 requests
    -- must still be remembered (prev_count = 3), so 8 more requests push the
    -- sliding rate to 3 + 8 = 11 > 10 and must be blocked. With the old
    -- TTL bug the counter had expired and prev_count was 0 (8 <= 10, pass).
    virtual_now = virtual_now + 1.1
    local blocked
    for i = 1, 7 do
        blocked = cc.check_rate_limit("ip1", limit, 1)
        assert(blocked == false, "window3 request " .. i .. " should pass")
    end
    blocked = cc.check_rate_limit("ip1", limit, 1)
    assert(blocked == true,
        "8th request in window3 should be blocked (prev window must be remembered)")

    print("ALL rate_limit_rotation_ttl tests PASSED")
end

-- Test: global QPS limit is a PER-SECOND limit.
-- Regression: the old implementation counted requests in a 60s window, so any
-- site above ~83 req/s aggregate blocked ALL users (global_exceeded).
local function test_global_limit_per_second()
    local cc = require("lib.cc_protect")

    local dict = make_mock_dict(function() return virtual_now end)
    ngx.shared.rate_limit = dict
    ngx.shared.session_track = make_mock_dict(function() return virtual_now end)
    virtual_now = 2000000.0

    local limit = cc.DEFAULTS.global_qps_limit

    -- Fill the global budget for this second.
    for _ = 1, limit do
        local blocked, reason = cc.check_global_limit()
        assert(blocked == false, "request within global limit should pass: " .. (reason or ""))
    end

    -- Next request in the same second is blocked.
    local blocked, reason = cc.check_global_limit()
    assert(blocked == true, "request above global limit should be blocked")
    assert(reason == "global_exceeded", "reason should be global_exceeded")

    -- Advance past the 1s window so it rotates. The just-finished second was
    -- full, so the sliding-window weight still rejects the first request
    -- right at the boundary (elapsed ~ 0) - expected smoothing, ignore it.
    virtual_now = virtual_now + 2.0
    cc.check_global_limit()

    -- Half a second into the new window the previous second's contribution
    -- has decayed to ~50%, so traffic under the cap passes again. Under the
    -- old 60s-window bug the counter stayed pegged for a full minute.
    virtual_now = virtual_now + 0.5
    blocked, reason = cc.check_global_limit()
    assert(blocked == false,
        "global limit must reset per second (per-second QPS): " .. (reason or ""))

    print("ALL global_limit_per_second tests PASSED")
end

-- Test: connection tracking
local function test_conn_tracking()
    local cc = require("lib.cc_protect")

    -- Reset the dict
    ngx.shared.rate_limit = make_mock_dict()

    -- Track connection start
    local ok, count = cc.track_conn_start("10.0.0.1")
    assert(ok == true, "track_conn_start should succeed")
    assert(count == 1, "first connection should be count 1")

    -- Track another connection
    ok, count = cc.track_conn_start("10.0.0.1")
    assert(ok == true, "second track_conn_start should succeed")
    assert(count == 2, "second track_conn_start should be count 2")

    -- End a connection
    ok, count = cc.track_conn_end("10.0.0.1")
    assert(ok == true, "track_conn_end should succeed")
    assert(count == 1, "after end, count should be 1")

    -- End last connection
    ok, count = cc.track_conn_end("10.0.0.1")
    assert(ok == true, "ending last connection should succeed")
    assert(count == 0, "count should be 0 after last end")

    -- track_conn_end on already-zero counter should clamp to 0
    ok, count = cc.track_conn_end("10.0.0.1")
    assert(ok == true, "extra track_conn_end should still succeed")
    assert(count == 0, "count should stay 0, not go negative")

    -- Connection limit check should pass when under limit
    local blocked, reason = cc.check_conn_limit("10.0.0.1")
    assert(blocked == false, "should pass when under conn limit")

    -- check_conn_limit with custom limit
    ngx.shared.rate_limit = make_mock_dict()
    cc.track_conn_start("10.0.0.2")
    blocked, reason = cc.check_conn_limit("10.0.0.2", 1)
    assert(blocked == false, "count==1, limit==1: should pass (not exceeded)")

    print("ALL conn_tracking tests PASSED")
end

-- Test: path scan detection
local function test_path_scan()
    local cc = require("lib.cc_protect")

    -- Reset the dict
    ngx.shared.session_track = make_mock_dict()

    -- Record 404s up to threshold
    for i = 1, 20 do
        local ok, count = cc.record_404("192.168.1.1")
        assert(ok == true, "record_404 should succeed")
    end

    -- After 20 404s, path scan should detect it
    local blocked, reason = cc.check_path_scan("192.168.1.1")
    assert(blocked == true, "should detect path scan after 20 404s")
    assert(reason == "path_scan_detected", "reason should be 'path_scan_detected'")

    -- Different IP should not be affected
    blocked, reason = cc.check_path_scan("192.168.1.2")
    assert(blocked == false, "different IP should not be blocked")

    -- check_path_scan with custom limit
    ngx.shared.session_track = make_mock_dict()
    for i = 1, 3 do cc.record_404("10.0.0.5") end
    blocked, reason = cc.check_path_scan("10.0.0.5", 3)
    assert(blocked == true, "custom limit 3: 3 404s should trigger")

    print("ALL path_scan tests PASSED")
end

-- Test: main check function
local function test_check()
    local cc = require("lib.cc_protect")

    -- Reset dicts
    ngx.shared.rate_limit = make_mock_dict()
    ngx.shared.session_track = make_mock_dict()

    -- Normal request should pass
    local action, reason = cc.check("10.0.0.1", "GET", "/index.html")
    assert(action == "pass", "normal request should pass")
    assert(reason == "ok", "reason should be 'ok'")

    print("ALL check tests PASSED")
end

-- Test: runtime CC config overrides stored in session_track are honored.
-- Regression: ip_qps_limit/ip_conn_limit/global_qps_limit/challenge_enabled
-- used to read only the hard-coded DEFAULTS table, so admin config changes
-- had no effect on the actual check.
local function test_cc_config_override()
    local cc = require("lib.cc_protect")

    local function reset_dicts()
        ngx.shared.rate_limit = make_mock_dict(function() return virtual_now end)
        ngx.shared.session_track = make_mock_dict(function() return virtual_now end)
    end

    -- Per-IP QPS override.
    reset_dicts()
    virtual_now = 3000000.0
    ngx.shared.session_track:set("cc_config:ip_qps_limit", 3)
    ngx.shared.session_track:set("cc_config:global_qps_limit", 100000)

    local action, reason
    for i = 1, 3 do
        action, reason = cc.check("10.0.1.1", "GET", "/")
        assert(action == "pass", "request " .. i .. " should pass under override")
    end
    action, reason = cc.check("10.0.1.1", "GET", "/")
    assert(action == "block", "4th request should be blocked by overridden ip_qps_limit")
    assert(reason == "rate_exceeded", "reason should be 'rate_exceeded'")

    -- challenge_enabled override turns block into challenge.
    reset_dicts()
    virtual_now = 3100000.0
    ngx.shared.session_track:set("cc_config:ip_qps_limit", 1)
    ngx.shared.session_track:set("cc_config:global_qps_limit", 100000)
    ngx.shared.session_track:set("cc_config:challenge_enabled", true)

    action, reason = cc.check("10.0.1.2", "GET", "/")
    assert(action == "pass", "first request should pass")
    action, reason = cc.check("10.0.1.2", "GET", "/")
    assert(action == "challenge", "over-limit request should challenge when enabled")
    assert(reason == "rate_exceeded", "reason should still be 'rate_exceeded'")

    -- window_size override applies to path-scan tracking TTL.
    reset_dicts()
    virtual_now = 3200000.0
    ngx.shared.session_track:set("cc_config:window_size", 1)

    local ok = cc.record_404("10.0.1.3")
    assert(ok == true, "record_404 should succeed")
    assert(ngx.shared.session_track:get("scan:10.0.1.3") == 1, "scan key should exist")

    virtual_now = virtual_now + 2
    assert(ngx.shared.session_track:get("scan:10.0.1.3") == nil,
        "scan key should expire after overridden window_size")

    print("ALL cc_config_override tests PASSED")
end

-- Test: TTL expiry in mock incr
local function test_ttl_expiry()
    local mock_dict = make_mock_dict()

    -- Simulate: incr with init=0, TTL=1
    mock_dict:incr("ttl:test", 1, 0, 1)
    local val = mock_dict:get("ttl:test")
    assert(val == 1, "value should be 1 after incr")

    -- Manually expire the key by setting TTL to 0 (expires immediately)
    mock_dict:set("ttl:test", 999, 0)
    -- Wait a tick (os.time resolution is 1 second)
    os.execute("sleep 1")

    -- incr should now treat the key as expired and re-initialize
    mock_dict:incr("ttl:test", 5, 0, 10)
    val = mock_dict:get("ttl:test")
    assert(val == 5, "after expiry, incr should re-initialize to init+value (5)")

    print("ALL ttl_expiry tests PASSED")
end

-- Run all tests
test_defaults()
test_make_key()
test_check_rate_limit()
test_rate_limit_rotation_ttl()
test_global_limit_per_second()
test_conn_tracking()
test_path_scan()
test_check()
test_cc_config_override()
test_ttl_expiry()

print("\n=== ALL CC PROTECT TESTS PASSED ===")
