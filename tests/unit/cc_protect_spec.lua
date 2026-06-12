-- tests/unit/cc_protect_spec.lua
-- Unit tests for lib/cc_protect.lua using busted framework
-- Tests run outside nginx with mocked ngx.* APIs

package.path = "./?.lua;./lib/?.lua;" .. package.path

-- Mock shared dict with realistic behavior (TTL, incr with init)
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

    function dict:add(key, value, ttl)
        if data[key] ~= nil then
            return false, "exists"
        end
        data[key] = value
        if ttl then
            ttls[key] = os.time() + ttl
        end
        return true
    end

    dict._data = data
    dict._ttls = ttls
    return dict
end

-- Set up global ngx mock before requiring any modules
_G.ngx = _G.ngx or {}
ngx.shared = {
    rate_limit = make_mock_dict(),
    session_track = make_mock_dict(),
}
ngx.var = { remote_addr = "127.0.0.1" }
ngx.req = { get_headers = function() return {} end }

describe("cc_protect", function()
    local cc_protect

    setup(function()
        package.loaded["lib.cc_protect"] = nil
        cc_protect = require("lib.cc_protect")
    end)

    before_each(function()
        -- Reset all shared dicts between tests
        ngx.shared.rate_limit._data = {}
        ngx.shared.rate_limit._ttls = {}
        ngx.shared.session_track._data = {}
        ngx.shared.session_track._ttls = {}
    end)

    describe("normal request passes", function()
        it("should pass a single normal request", function()
            local action, reason = cc_protect.check("10.0.0.1", "GET", "/index.html")
            assert.equals("pass", action)
            assert.equals("ok", reason)
        end)

        it("should pass multiple requests within limits", function()
            -- Send a few requests, all should pass
            for i = 1, 5 do
                local action = cc_protect.check("10.0.0.1", "GET", "/page")
                assert.equals("pass", action)
            end
        end)
    end)

    describe("ip_qps_limit block", function()
        it("should block IP exceeding per-IP QPS limit", function()
            local limit = cc_protect.DEFAULTS.ip_qps_limit
            -- Send requests up to the limit
            for i = 1, limit do
                cc_protect.check("10.0.0.2", "GET", "/api/data")
            end
            -- Next request should be blocked
            local action, reason = cc_protect.check("10.0.0.2", "GET", "/api/data")
            assert.equals("block", action)
            assert.equals("rate_exceeded", reason)
        end)

        it("should not block different IPs independently", function()
            local limit = cc_protect.DEFAULTS.ip_qps_limit
            -- Fill up IP-A's quota
            for i = 1, limit do
                cc_protect.check("10.0.0.10", "GET", "/page")
            end
            -- IP-B should still pass
            local action = cc_protect.check("10.0.0.11", "GET", "/page")
            assert.equals("pass", action)
        end)
    end)

    describe("ip_conn_limit block", function()
        it("should block IP exceeding connection limit", function()
            local limit = cc_protect.DEFAULTS.ip_conn_limit
            -- Simulate opening many connections
            for i = 1, limit + 1 do
                cc_protect.track_conn_start("10.0.0.3")
            end
            -- Check should now block
            local blocked, reason = cc_protect.check_conn_limit("10.0.0.3")
            assert.is_true(blocked)
            assert.equals("conn_exceeded", reason)
        end)

        it("should pass when connections are within limit", function()
            local limit = cc_protect.DEFAULTS.ip_conn_limit
            -- Open connections up to the limit
            for i = 1, limit do
                cc_protect.track_conn_start("10.0.0.4")
            end
            local blocked = cc_protect.check_conn_limit("10.0.0.4")
            assert.is_false(blocked)
        end)
    end)

    describe("global_qps_limit block", function()
        it("should block when global QPS limit is exceeded", function()
            local limit = cc_protect.DEFAULTS.global_qps_limit
            -- Simulate global traffic by directly setting the counter
            local rl = ngx.shared.rate_limit
            rl:set("global:qps", limit)
            -- Next request should trigger a block
            local action, reason = cc_protect.check("10.0.0.5", "GET", "/")
            assert.equals("block", action)
            assert.equals("global_exceeded", reason)
        end)

        it("should pass when global QPS is within limit", function()
            local limit = cc_protect.DEFAULTS.global_qps_limit
            -- Pre-set counter to just under the limit
            local rl = ngx.shared.rate_limit
            rl:set("global:qps", limit - 1)
            local action = cc_protect.check("10.0.0.6", "GET", "/")
            assert.equals("pass", action)
        end)
    end)

    describe("shared dict config read/write", function()
        it("should read rate limit config from shared dict defaults", function()
            assert.equals(100, cc_protect.DEFAULTS.ip_qps_limit)
            assert.equals(50, cc_protect.DEFAULTS.ip_conn_limit)
            assert.equals(5000, cc_protect.DEFAULTS.global_qps_limit)
            assert.equals(60, cc_protect.DEFAULTS.window_size)
        end)

        it("should write and read rate limit keys in shared dict", function()
            local rl = ngx.shared.rate_limit
            -- Simulate rate limiting by writing to the dict
            rl:incr("test_ip:GET:/api", 1, 0, 60)
            local val = rl:get("test_ip:GET:/api")
            assert.equals(1, val)

            -- Increment again
            rl:incr("test_ip:GET:/api", 1, 0, 60)
            val = rl:get("test_ip:GET:/api")
            assert.equals(2, val)
        end)

        it("should write and read connection tracking keys", function()
            local rl = ngx.shared.rate_limit
            -- Track connections
            cc_protect.track_conn_start("10.0.0.7")
            cc_protect.track_conn_start("10.0.0.7")
            local val = rl:get("conn:10.0.0.7")
            assert.equals(2, val)

            -- End one connection
            cc_protect.track_conn_end("10.0.0.7")
            val = rl:get("conn:10.0.0.7")
            assert.equals(1, val)
        end)

        it("should write and read session tracking keys", function()
            local st = ngx.shared.session_track
            -- Record 404s
            cc_protect.record_404("10.0.0.8")
            cc_protect.record_404("10.0.0.8")
            local val = st:get("scan:10.0.0.8")
            assert.equals(2, val)
        end)

        it("should detect path scan when threshold is reached", function()
            -- Record enough 404s to trigger path scan detection
            for i = 1, 20 do
                cc_protect.record_404("10.0.0.9")
            end
            local blocked, reason = cc_protect.check_path_scan("10.0.0.9")
            assert.is_true(blocked)
            assert.equals("path_scan_detected", reason)
        end)
    end)
end)
