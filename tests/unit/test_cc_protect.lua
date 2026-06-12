-- tests/unit/test_cc_protect.lua
-- Tests for lib/cc_protect.lua functions
--
-- NOTE: This test runs in plain Lua (not OpenResty), so we mock
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

-- Provide bit library shim for Lua 5.4+/5.5 (utils.lua uses LuaJIT's bit.band)
if not bit then
    bit = {}
    function bit.band(a, b) return a & b end
    function bit.bor(a, b) return a | b end
    function bit.bxor(a, b) return a ~ b end
    function bit.lshift(a, n) return a << n end
    function bit.rshift(a, n) return a >> n end
end

-- Mock ngx.shared dictionaries for testing
local function make_mock_dict()
    local store = {}
    local ttls = {}
    local mock = {}

    function mock:get(key)
        -- Check TTL expiry
        if ttls[key] and ttls[key] < os.time() then
            store[key] = nil
            ttls[key] = nil
            return nil
        end
        return store[key]
    end

    function mock:set(key, value, ttl)
        store[key] = value
        if ttl then
            ttls[key] = os.time() + ttl
        end
        return true
    end

    function mock:incr(key, value, init, ttl)
        -- Check TTL expiry before incrementing
        if ttls[key] and ttls[key] < os.time() then
            store[key] = nil
            ttls[key] = nil
        end

        if store[key] == nil then
            if init then
                store[key] = init
            else
                store[key] = 0
            end
            if ttl then
                ttls[key] = os.time() + ttl
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
    assert(count == 2, "second connection should be count 2")

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
    assert(reason == "path_scan_detected", "reason should be path_scan_detected")

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

-- Test: TTL expiry in mock incr
local function test_ttl_expiry()
    local cc = require("lib.cc_protect")
    local mock_dict = make_mock_dict()

    -- Simulate: incr with init=0, TTL=1
    mock_dict:incr("ttl:test", 1, 0, 1)
    local val = mock_dict:get("ttl:test")
    assert(val == 1, "value should be 1 after incr")

    -- Manually expire the key by setting TTL in the past
    mock_dict:set("ttl:test", 999, 0) -- set TTL to 0 (expires immediately)
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
test_conn_tracking()
test_path_scan()
test_check()
test_ttl_expiry()

print("\n=== ALL CC PROTECT TESTS PASSED ===")
