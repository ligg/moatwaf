-- tests/unit/logger_spec.lua
-- Unit tests for lib/logger.lua using busted framework
-- Tests run outside nginx with mocked ngx.* APIs

package.path = "./?.lua;./lib/?.lua;" .. package.path

-- Create a mock shared dict that stores data in a Lua table
local function make_mock_dict()
    local data = {}
    local ttls = {}
    local dict = {}

    function dict:get(key)
        if ttls[key] and os.time() > ttls[key] then
            data[key] = nil
            ttls[key] = nil
            return nil
        end
        return data[key]
    end

    function dict:set(key, value, ttl)
        data[key] = value
        if ttl then
            ttls[key] = os.time() + ttl
        end
        return true
    end

    function dict:incr(key, value, init, ttl)
        if data[key] == nil then
            if init ~= nil then
                data[key] = init + value
            else
                return nil, "not found"
            end
        else
            data[key] = data[key] + value
        end
        if ttl then
            ttls[key] = os.time() + ttl
        end
        return data[key], nil
    end

    function dict:delete(key)
        data[key] = nil
        ttls[key] = nil
        return true
    end

    -- Expose internal data for test assertions
    dict._data = data
    dict._ttls = ttls

    return dict
end

-- Set up global ngx mock before requiring logger module
_G.ngx = _G.ngx or {}
ngx.shared = {
    waf_stats = make_mock_dict()
}
ngx.ERR = 4
ngx.log = function(...) end  -- no-op by default
ngx.var = { remote_addr = "127.0.0.1" }
ngx.req = {
    get_headers = function() return {} end
}

describe("logger", function()
    local logger
    local log_output  -- captured ngx.log output

    setup(function()
        -- Clear cached module to get fresh instance with our mock
        package.loaded["lib.logger"] = nil
        -- Make sure utils is loaded (logger requires it)
        package.loaded["lib.utils"] = nil
        logger = require("lib.logger")
    end)

    before_each(function()
        -- Reset stats dict before each test
        local stats_dict = ngx.shared.waf_stats
        stats_dict._data = {}
        stats_dict._ttls = {}
        -- Re-point the mock dict reference
        ngx.shared.waf_stats = stats_dict

        -- Reset captured log output
        log_output = {}
        ngx.log = function(level, ...)
            local parts = { ... }
            table.insert(log_output, { level = level, msg = table.concat(parts, " ") })
        end
    end)

    describe("stats recording", function()
        it("should record total requests", function()
            logger.record_stats("passed", nil)

            local stats = logger.get_stats()
            assert.equals(1, stats.total_requests)
            assert.equals(1, stats.passed_total)
        end)

        it("should record blocked requests with category", function()
            logger.record_stats("blocked", "sqli")

            local stats = logger.get_stats()
            assert.equals(1, stats.total_requests)
            assert.equals(1, stats.blocked_total)
            assert.equals(1, stats.blocked_sqli)
        end)

        it("should accumulate multiple requests", function()
            logger.record_stats("passed", nil)
            logger.record_stats("passed", nil)
            logger.record_stats("blocked", "xss")
            logger.record_stats("blocked", "cc")

            local stats = logger.get_stats()
            assert.equals(4, stats.total_requests)
            assert.equals(2, stats.passed_total)
            assert.equals(2, stats.blocked_total)
            assert.equals(1, stats.blocked_xss)
            assert.equals(1, stats.blocked_cc)
        end)

        it("should record last_request_time", function()
            logger.record_stats("passed", nil)

            local stats = logger.get_stats()
            assert.is_true(stats.last_request_time > 0)
        end)
    end)

    describe("stats retrieval", function()
        it("should return zero counts when no requests recorded", function()
            local stats = logger.get_stats()
            assert.equals(0, stats.total_requests)
            assert.equals(0, stats.passed_total)
            assert.equals(0, stats.blocked_total)
            assert.equals(0, stats.blocked_sqli)
            assert.equals(0, stats.blocked_xss)
            assert.equals(0, stats.blocked_cmdi)
            assert.equals(0, stats.blocked_cc)
            assert.equals(0, stats.blocked_other)
            assert.equals(0, stats.blocked_ip)
            assert.equals(0, stats.last_request_time)
        end)

        it("should return correct counts after recording", function()
            logger.record_stats("passed", nil)
            logger.record_stats("blocked", "sqli")
            logger.record_stats("blocked", "xss")
            logger.record_stats("blocked", "cmdi")
            logger.record_stats("blocked", "cc")
            logger.record_stats("blocked", "other")
            logger.record_stats("blocked", "ip")

            local stats = logger.get_stats()
            assert.equals(7, stats.total_requests)
            assert.equals(1, stats.passed_total)
            assert.equals(6, stats.blocked_total)
            assert.equals(1, stats.blocked_sqli)
            assert.equals(1, stats.blocked_xss)
            assert.equals(1, stats.blocked_cmdi)
            assert.equals(1, stats.blocked_cc)
            assert.equals(1, stats.blocked_other)
            assert.equals(1, stats.blocked_ip)
        end)

        it("should return empty table when waf_stats dict is nil", function()
            local saved = ngx.shared.waf_stats
            ngx.shared.waf_stats = nil

            -- Need to re-require to pick up nil dict
            package.loaded["lib.logger"] = nil
            local fresh_logger = require("lib.logger")
            local stats = fresh_logger.get_stats()
            assert.same({}, stats)

            -- Restore
            ngx.shared.waf_stats = saved
            package.loaded["lib.logger"] = nil
            logger = require("lib.logger")
        end)
    end)

    describe("log entry format", function()
        it("audit log should contain WAF_AUDIT tag and JSON", function()
            logger.audit({
                source_ip = "192.168.1.100",
                rule_id = "SQLI-001",
                action = "block",
                reason = "SQL injection detected"
            })

            assert.is_true(#log_output > 0)
            local entry = log_output[#log_output]
            assert.equals(ngx.ERR, entry.level)
            assert.is_truthy(entry.msg:find("WAF_AUDIT"))

            -- Verify it's valid JSON
            local json_part = entry.msg:match("WAF_AUDIT (.+)")
            assert.is_not_nil(json_part)
            -- Should contain the fields we passed
            assert.is_truthy(json_part:find("192.168.1.100"))
            assert.is_truthy(json_part:find("SQLI-001"))
        end)

        it("attack log should contain WAF_ATTACK tag", function()
            logger.attack({
                source_ip = "10.0.0.1",
                rule_id = "XSS-001",
                action = "block",
                reason = "XSS attempt"
            })

            assert.is_true(#log_output > 0)
            local entry = log_output[#log_output]
            assert.is_truthy(entry.msg:find("WAF_ATTACK"))
            assert.is_truthy(entry.msg:find("10.0.0.1"))
        end)

        it("log entries should have timestamp and client_ip auto-filled", function()
            logger.audit({ action = "block" })

            local json_part = log_output[#log_output].msg:match("WAF_AUDIT (.+)")
            assert.is_truthy(json_part:find("timestamp"))
            assert.is_truthy(json_part:find("client_ip"))
        end)

        it("security log should contain WAF_SECURITY tag", function()
            logger.security({
                event = "admin_login",
                source_ip = "10.0.0.1"
            })

            assert.is_true(#log_output > 0)
            local entry = log_output[#log_output]
            assert.is_truthy(entry.msg:find("WAF_SECURITY"))
        end)
    end)

    describe("log level filtering", function()
        it("should default to INFO level", function()
            assert.equals("INFO", logger.get_level())
        end)

        it("should allow setting log level", function()
            logger.set_level("ERROR")
            assert.equals("ERROR", logger.get_level())
            -- Reset
            logger.set_level("INFO")
        end)
    end)
end)
