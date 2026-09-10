-- tests/unit/test_trend.lua
-- Tests for the attack trend chart data in lib/logger.lua
--
-- Regression: the trend chart derived an hourly series by subtracting
-- cumulative counters, but seeded the running baseline with a hard-coded 0.
-- The oldest point on the chart therefore came out as every blocked/passed
-- request since the WAF started, which dwarfed the rest of the series.
--
-- NOTE: This test runs in plain Lua/LuaJIT (not OpenResty), so we mock
-- cjson, ngx, and set up the package path appropriately.

-- Set up package path to find lib/ from project root
local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

local unpack = unpack or table.unpack

-- Use the real cjson when it is available (OpenResty image); otherwise fall
-- back to a stand-in that round-trips flat tables through opaque tokens.
local has_cjson, cjson = pcall(require, "cjson")
if not has_cjson then
    local store, seq = {}, 0
    cjson = {
        empty_array = {},
        encode = function(value)
            seq = seq + 1
            local token = "json:" .. seq
            local copy = {}
            for k, v in pairs(value) do copy[k] = v end
            store[token] = copy
            return token
        end,
        decode = function(str) return store[str] end,
    }
end
package.loaded["cjson"] = cjson

-- Virtual clock so tests can place samples on exact hour boundaries.
local virtual_now = 0

local HOUR = 3600
-- Arbitrary "now" so the hour arithmetic is easy to reason about.
local NOW_HOUR = 100000

local function set_clock(seconds) virtual_now = seconds end
local function at_hour(hour, offset) return hour * HOUR + (offset or 60) end

-- Mock ngx.shared dictionary, faithful to OpenResty semantics.
local function make_mock_dict()
    local store, ttls = {}, {}
    local mock = {}

    local function alive(key)
        if ttls[key] and ttls[key] <= virtual_now then
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
        ttls[key] = ttl and (virtual_now + ttl) or nil
        return true
    end

    function mock:incr(key, value, init, ttl)
        if not alive(key) then
            if init == nil then return nil, "not found" end
            store[key] = init
            if ttl then ttls[key] = virtual_now + ttl end
        end
        store[key] = store[key] + value
        return store[key], nil
    end

    function mock:delete(key)
        store[key] = nil
        ttls[key] = nil
        return true
    end

    mock._store = store
    return mock
end

-- Set up global ngx mock
if not ngx then ngx = {} end
ngx.ERR = 4
ngx.log = function() end
ngx.time = function() return virtual_now end
ngx.now = function() return virtual_now end
ngx.var = { remote_addr = "127.0.0.1" }
ngx.req = { get_headers = function() return {} end }

local stats = make_mock_dict()
ngx.shared = { waf_stats = stats }

-- Fresh logger + empty counters for each test.
local function fresh_logger()
    stats = make_mock_dict()
    ngx.shared.waf_stats = stats
    set_clock(0)
    package.loaded["lib.logger"] = nil
    return require("lib.logger")
end

-- Simulate traffic arriving: counters are cumulative, exactly as waf.lua
-- increments them.
local function add_traffic(blocked, passed)
    if blocked > 0 then stats:incr("blocked_total", blocked, 0) end
    if passed > 0 then stats:incr("passed_total", passed, 0) end
end

-- A long-running instance must not dump its lifetime totals onto the oldest
-- point of the chart.
local function test_first_point_is_hourly_delta()
    local logger = fresh_logger()

    -- WAF has been up for a while: counters are already large.
    add_traffic(10000, 100000)
    set_clock(at_hour(NOW_HOUR - 6))
    logger.record_trend_sample()

    -- Then 120 blocked / 1200 passed every hour.
    for hour = NOW_HOUR - 5, NOW_HOUR do
        add_traffic(120, 1200)
        set_clock(at_hour(hour, 600))
        logger.record_trend_sample()
    end

    local trend = logger.get_trend_data("24h")
    local peak = math.max(unpack(trend.blocked))

    assert(peak == 120,
        "every point should be that hour's delta (120), got peak " .. tostring(peak))

    -- The six hours with traffic are the newest points on the chart.
    for i = #trend.blocked - 5, #trend.blocked do
        assert(trend.blocked[i] == 120,
            "point " .. i .. " should be 120, got " .. tostring(trend.blocked[i]))
    end
    for i = 1, #trend.blocked - 6 do
        assert(trend.blocked[i] == 0,
            "hours without traffic should be 0, got " .. tostring(trend.blocked[i]))
    end

    print("ALL first_point_is_hourly_delta tests PASSED")
end

-- Every hour in the range gets a tick, so the x-axis cannot drift out of
-- alignment when an hour has no traffic at all.
local function test_hourly_axis_alignment()
    local logger = fresh_logger()

    set_clock(at_hour(NOW_HOUR - 4))
    add_traffic(5000, 50000)
    logger.record_trend_sample()

    set_clock(at_hour(NOW_HOUR - 3))
    add_traffic(30, 300)
    logger.record_trend_sample()

    -- NOW_HOUR - 2: no traffic at all, so nothing is ever sampled.

    set_clock(at_hour(NOW_HOUR - 1))
    add_traffic(70, 700)
    logger.record_trend_sample()

    -- "Now" is inside NOW_HOUR, so the chart's last tick is the current hour.
    set_clock(at_hour(NOW_HOUR))

    local trend = logger.get_trend_data("24h")
    assert(#trend.labels == 25, "24h should yield 25 ticks, got " .. #trend.labels)
    assert(#trend.blocked == #trend.labels, "labels and blocked series must line up")
    assert(#trend.passed == #trend.labels, "labels and passed series must line up")

    local n = #trend.blocked
    assert(trend.blocked[n - 3] == 30,
        "quiet hour before a gap: expected 30, got " .. tostring(trend.blocked[n - 3]))
    assert(trend.blocked[n - 2] == 0,
        "hour with no traffic should be 0, got " .. tostring(trend.blocked[n - 2]))
    assert(trend.blocked[n - 1] == 70,
        "hour after a gap: expected 70, got " .. tostring(trend.blocked[n - 1]))
    assert(trend.passed[n - 1] == 700,
        "passed series should track the same hours, got " .. tostring(trend.passed[n - 1]))

    assert(#logger.get_trend_data("7d").labels == 169, "7d should yield 169 ticks")

    print("ALL hourly_axis_alignment tests PASSED")
end

-- A restart zeroes the counters; that must not yield negative values and
-- must not swallow the traffic seen right after the restart.
local function test_counter_reset()
    local logger = fresh_logger()

    set_clock(at_hour(NOW_HOUR - 2))
    add_traffic(9000, 90000)
    logger.record_trend_sample()

    -- Process restart: counters start over from zero.
    stats:set("blocked_total", 0)
    stats:set("passed_total", 0)

    set_clock(at_hour(NOW_HOUR - 1))
    add_traffic(40, 400)
    logger.record_trend_sample()

    set_clock(at_hour(NOW_HOUR))
    add_traffic(25, 250)
    logger.record_trend_sample()

    local trend = logger.get_trend_data("24h")
    local n = #trend.blocked

    for i = 1, n do
        assert(trend.blocked[i] >= 0, "point " .. i .. " must not be negative")
    end
    assert(trend.blocked[n - 1] == 40,
        "hour after restart: expected 40, got " .. tostring(trend.blocked[n - 1]))
    assert(trend.blocked[n] == 25,
        "current hour: expected 25, got " .. tostring(trend.blocked[n]))

    print("ALL counter_reset tests PASSED")
end

-- No samples at all still reports "no data" to the caller.
local function test_no_samples()
    local logger = fresh_logger()

    local trend = logger.get_trend_data("24h")
    -- cjson.empty_array is a sentinel (userdata with the real library), so
    -- compare identity rather than length.
    assert(trend.labels == cjson.empty_array, "no samples should yield no labels")
    assert(trend.blocked == cjson.empty_array, "no samples should yield no blocked series")
    assert(trend.passed == cjson.empty_array, "no samples should yield no passed series")

    print("ALL no_samples tests PASSED")
end

test_first_point_is_hourly_delta()
test_hourly_axis_alignment()
test_counter_reset()
test_no_samples()

print("\n=== ALL TREND TESTS PASSED ===")
