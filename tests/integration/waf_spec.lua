-- tests/integration/waf_spec.lua
-- Integration tests for lib/waf.lua using busted framework
-- Tests run outside nginx with fully mocked ngx.* APIs and sub-modules

package.path = "./?.lua;./lib/?.lua;" .. package.path

---------------------------------------------------------------------------
-- Mock shared dict
---------------------------------------------------------------------------
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

    function dict:get_keys(max)
        local keys = {}
        for k, _ in pairs(data) do
            table.insert(keys, k)
        end
        return keys
    end

    dict._data = data
    dict._ttls = ttls
    return dict
end

---------------------------------------------------------------------------
-- Capture output (ngx.say / ngx.exit)
---------------------------------------------------------------------------
local captured_say = {}
local captured_exit = nil
local captured_status = nil
local captured_headers = {}

---------------------------------------------------------------------------
-- Set up global ngx mock
---------------------------------------------------------------------------
_G.ngx = _G.ngx or {}

local function setup_ngx_mock()
    ngx.shared = {
        rate_limit    = make_mock_dict(),
        ip_blacklist  = make_mock_dict(),
        session_track = make_mock_dict(),
        waf_stats     = make_mock_dict(),
    }
    ngx.ctx = {}
    ngx.var = {
        remote_addr    = "10.0.0.1",
        uri            = "/test",
        http_user_agent = "Mozilla/5.0",
        http_host      = "example.com",
    }
    ngx.req = {
        get_method  = function() return "GET" end,
        get_headers = function() return {} end,
        read_body   = function() end,
        get_body_data = function() return nil end,
        get_body_file = function() return nil end,
    }
    ngx.status = 200
    ngx.header = {}
    ngx.ERR = 4
    ngx.log = function(...) end
    ngx.say = function(msg)
        table.insert(captured_say, msg)
    end
    ngx.exit = function(code)
        captured_exit = code
    end
    ngx.time = function() return os.time() end
    ngx.now = function() return os.time() end
end

setup_ngx_mock()

---------------------------------------------------------------------------
-- Stub out sub-modules that waf.lua loads via lib.init
-- We control their behavior per-test by swapping functions.
---------------------------------------------------------------------------
local mock_ip_control = {
    check = function(ip, lists) return "pass", "ok" end,
    blacklist_ip = function(ip, ttl) end,
    load_lists = function() return { whitelist = {}, blacklist = {}, geo_block = {} } end,
    is_whitelisted = function(ip, lists) return false end,
    is_blacklisted = function(ip, lists) return false end,
}

local mock_cc_protect = {
    check = function(ip, method, uri) return "pass", "ok" end,
    track_conn_start = function(ip) end,
    track_conn_end = function(ip) end,
    record_404 = function(ip) end,
}

local mock_rule_engine = {
    check = function() return "pass" end,
    init = function() end,
    reload_rules = function() end,
}

local mock_upload_check = {
    check = function(filename, content_type, body_prefix, full_body)
        return { allowed = true }
    end,
    read_body_prefix = function(n) return nil end,
    read_full_body = function() return nil end,
}

local mock_utils = {
    get_client_ip = function() return "10.0.0.1" end,
    ip_in_cidr = function(ip, cidr) return false end,
    url_decode = function(s) return s end,
    normalize = function(s) return s end,
    json_response = function(code, data) end,
}

-- Inject mock modules into package.loaded so lib.init.load() returns them
package.loaded["lib.utils"] = mock_utils
package.loaded["lib.ip_control"] = mock_ip_control
package.loaded["lib.cc_protect"] = mock_cc_protect
package.loaded["lib.rule_engine"] = mock_rule_engine
package.loaded["lib.upload_check"] = mock_upload_check

-- Also make init.load() return our mocks
package.loaded["lib.init"] = {
    load = function(name)
        local map = {
            utils       = mock_utils,
            ip_control  = mock_ip_control,
            cc_protect  = mock_cc_protect,
            rule_engine = mock_rule_engine,
            upload_check = mock_upload_check,
        }
        return map[name] or require("lib." .. name)
    end
}

---------------------------------------------------------------------------
-- Load waf module (it will pick up the mocked sub-modules)
---------------------------------------------------------------------------
package.loaded["lib.waf"] = nil
local waf = require("lib.waf")

describe("waf integration", function()

    before_each(function()
        -- Reset captured output
        captured_say = {}
        captured_exit = nil
        captured_status = nil
        captured_headers = {}

        -- Reset ngx state
        ngx.ctx = {}
        ngx.status = 200
        ngx.header = {}
        ngx.var.remote_addr = "10.0.0.1"
        ngx.var.uri = "/test"
        ngx.req.get_method = function() return "GET" end

        -- Reset shared dicts
        for _, dict in pairs(ngx.shared) do
            dict._data = {}
            dict._ttls = {}
        end

        -- Reset mocks to default pass behavior
        mock_ip_control.check = function(ip, lists) return "pass", "ok" end
        mock_ip_control.blacklist_ip = function(ip, ttl) end
        mock_ip_control.load_lists = function()
            return { whitelist = {}, blacklist = {}, geo_block = {} }
        end
        mock_cc_protect.check = function(ip, method, uri) return "pass", "ok" end
        mock_cc_protect.track_conn_start = function(ip) end
        mock_cc_protect.track_conn_end = function(ip) end
        mock_rule_engine.check = function() return "pass" end
        mock_upload_check.check = function() return { allowed = true } end
        mock_utils.get_client_ip = function() return "10.0.0.1" end
    end)

    describe("full pipeline", function()
        it("should pass a clean request through all phases", function()
            -- rewrite_phase: IP check passes
            waf.rewrite_phase()
            assert.equals("pass", ngx.ctx.action)
            assert.is_false(ngx.ctx.blocked)
            assert.equals("10.0.0.1", ngx.ctx.client_ip)

            -- access_phase: CC and rule engine pass
            waf.access_phase()
            assert.equals("pass", ngx.ctx.action)
            assert.is_false(ngx.ctx.blocked)
            assert.is_nil(captured_exit)

            -- log_phase: no block, no log entry
            waf.log_phase()
            assert.is_nil(captured_exit)
        end)

        it("should block request when IP is blacklisted", function()
            mock_ip_control.check = function(ip, lists)
                return "block", "static_blacklisted"
            end

            waf.rewrite_phase()

            assert.equals("block", ngx.ctx.action)
            assert.is_true(ngx.ctx.blocked)
            assert.equals("IP-001", ngx.ctx.rule_id)
            assert.equals("static_blacklisted", ngx.ctx.reason)
            assert.equals(403, captured_exit)
            -- Should have sent JSON response
            assert.is_true(#captured_say > 0)
            local resp = captured_say[#captured_say]
            assert.is_truthy(resp:find("Forbidden"))
        end)

        it("should block request when CC protection triggers", function()
            mock_cc_protect.check = function(ip, method, uri)
                return "block", "rate_exceeded"
            end

            waf.rewrite_phase()
            captured_say = {}
            captured_exit = nil

            waf.access_phase()

            assert.equals("block", ngx.ctx.action)
            assert.is_true(ngx.ctx.blocked)
            assert.equals("CC-001", ngx.ctx.rule_id)
            assert.equals(429, captured_exit)
            -- Should have Retry-After header
            assert.equals("300", ngx.header["Retry-After"])
        end)

        it("should block request when rule engine triggers", function()
            mock_rule_engine.check = function()
                return "block", "SQLI-001", "critical", "SQL injection detected"
            end

            waf.rewrite_phase()
            captured_say = {}
            captured_exit = nil

            waf.access_phase()

            assert.equals("block", ngx.ctx.action)
            assert.is_true(ngx.ctx.blocked)
            assert.equals("SQLI-001", ngx.ctx.rule_id)
            assert.equals(403, captured_exit)
        end)
    end)

    describe("whitelisted IP bypasses CC", function()
        it("should skip CC connection tracking for whitelisted IPs", function()
            local conn_start_called = false
            mock_ip_control.check = function(ip, lists)
                return "pass", "whitelisted"
            end
            mock_cc_protect.track_conn_start = function(ip)
                conn_start_called = true
            end

            waf.rewrite_phase()

            assert.is_false(conn_start_called)
            assert.is_false(ngx.ctx.conn_tracked)
        end)

        it("should track connections for non-whitelisted IPs", function()
            local conn_start_called = false
            mock_ip_control.check = function(ip, lists)
                return "pass", "ok"
            end
            mock_cc_protect.track_conn_start = function(ip)
                conn_start_called = true
            end

            waf.rewrite_phase()

            assert.is_true(conn_start_called)
            assert.is_true(ngx.ctx.conn_tracked)
        end)
    end)

    describe("blocked request returns JSON error", function()
        it("IP block should return 403 JSON with error field", function()
            mock_ip_control.check = function(ip, lists)
                return "block", "static_blacklisted"
            end

            waf.rewrite_phase()

            assert.equals(403, captured_exit)
            local resp = captured_say[#captured_say]
            assert.is_truthy(resp:find('"error"'))
            assert.is_truthy(resp:find('"code"'))
            assert.is_truthy(resp:find("403"))
            assert.equals("application/json; charset=utf-8", ngx.header["Content-Type"])
        end)

        it("CC block should return 429 JSON with Retry-After header", function()
            mock_cc_protect.check = function(ip, method, uri)
                return "block", "rate_exceeded"
            end

            waf.rewrite_phase()
            captured_say = {}
            captured_exit = nil
            ngx.header = {}

            waf.access_phase()

            assert.equals(429, captured_exit)
            local resp = captured_say[#captured_say]
            assert.is_truthy(resp:find('"error"'))
            assert.is_truthy(resp:find("429"))
            assert.equals("300", ngx.header["Retry-After"])
            assert.equals("application/json; charset=utf-8", ngx.header["Content-Type"])
        end)

        it("rule engine block should return 403 JSON without exposing rule_id", function()
            mock_rule_engine.check = function()
                return "block", "SQLI-001", "critical", "SQL injection detected"
            end

            waf.rewrite_phase()
            captured_say = {}
            captured_exit = nil
            ngx.header = {}

            waf.access_phase()

            assert.equals(403, captured_exit)
            local resp = captured_say[#captured_say]
            -- Should NOT expose rule_id to the client
            assert.is_falsy(resp:find("SQLI-001"))
            -- Should contain the description
            assert.is_truthy(resp:find("SQL injection"))
        end)
    end)
end)
