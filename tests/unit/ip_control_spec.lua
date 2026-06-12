-- tests/unit/ip_control_spec.lua
-- Unit tests for lib/ip_control.lua using busted framework
-- Tests run outside nginx with mocked ngx.* APIs

package.path = "./?.lua;./lib/?.lua;" .. package.path

-- Mock shared dict for dynamic blacklist
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

    function dict:delete(key)
        data[key] = nil
        ttls[key] = nil
        return true
    end

    dict._data = data
    dict._ttls = ttls
    return dict
end

-- Set up global ngx mock before requiring any modules
_G.ngx = _G.ngx or {}
ngx.shared = {
    ip_blacklist = make_mock_dict(),
}
ngx.var = { remote_addr = "127.0.0.1" }
ngx.req = { get_headers = function() return {} end }

describe("ip_control", function()
    local ip_control

    setup(function()
        package.loaded["lib.ip_control"] = nil
        ip_control = require("lib.ip_control")
    end)

    before_each(function()
        -- Reset dynamic blacklist between tests
        local bl = ngx.shared.ip_blacklist
        bl._data = {}
        bl._ttls = {}
    end)

    -- Helper: build an IP lists table
    local function make_lists(opts)
        opts = opts or {}
        local lists = {
            whitelist = {},
            blacklist = {},
            geo_block = {}
        }
        if opts.whitelist then
            for _, ip in ipairs(opts.whitelist) do
                lists.whitelist[ip] = true
            end
        end
        if opts.blacklist then
            for _, ip in ipairs(opts.blacklist) do
                lists.blacklist[ip] = true
            end
        end
        return lists
    end

    describe("whitelist pass", function()
        it("should allow whitelisted IP to pass", function()
            local lists = make_lists({ whitelist = { "10.0.0.1" } })
            local action, reason = ip_control.check("10.0.0.1", lists)
            assert.equals("pass", action)
        end)

        it("should allow IP matching CIDR whitelist to pass", function()
            local lists = make_lists({ whitelist = { "192.168.1.0/24" } })
            local action = ip_control.check("192.168.1.50", lists)
            assert.equals("pass", action)
        end)
    end)

    describe("blacklist block", function()
        it("should block blacklisted IP", function()
            local lists = make_lists({ blacklist = { "1.2.3.4" } })
            local action, reason = ip_control.check("1.2.3.4", lists)
            assert.equals("block", action)
        end)

        it("should block IP matching CIDR blacklist", function()
            local lists = make_lists({ blacklist = { "10.0.0.0/8" } })
            local action = ip_control.check("10.99.1.1", lists)
            assert.equals("block", action)
        end)

        it("should block dynamically blacklisted IP", function()
            local lists = make_lists()  -- no static lists
            -- Add to dynamic blacklist
            ip_control.blacklist_ip("5.6.7.8", 300)
            local action, reason = ip_control.check("5.6.7.8", lists)
            assert.equals("block", action)
            assert.equals("dynamic_blacklisted", reason)
        end)
    end)

    describe("neither list pass", function()
        it("should allow IP not in any list", function()
            local lists = make_lists({
                whitelist = { "10.0.0.1" },
                blacklist = { "1.2.3.4" }
            })
            local action, reason = ip_control.check("192.168.5.5", lists)
            assert.equals("pass", action)
            assert.equals("ok", reason)
        end)

        it("should allow any IP when lists are empty", function()
            local lists = make_lists()
            local action, reason = ip_control.check("8.8.8.8", lists)
            assert.equals("pass", action)
            assert.equals("ok", reason)
        end)
    end)

    describe("whitelist correct action and reason", function()
        it("should return action=pass and reason=whitelisted", function()
            local lists = make_lists({ whitelist = { "10.0.0.1" } })
            local action, reason = ip_control.check("10.0.0.1", lists)
            assert.equals("pass", action)
            assert.equals("whitelisted", reason)
        end)

        it("whitelist should take priority over blacklist", function()
            local lists = make_lists({
                whitelist = { "10.0.0.1" },
                blacklist = { "10.0.0.1" }
            })
            local action, reason = ip_control.check("10.0.0.1", lists)
            assert.equals("pass", action)
            assert.equals("whitelisted", reason)
        end)
    end)

    describe("blacklist correct action and reason", function()
        it("should return action=block and reason=static_blacklisted for static list", function()
            local lists = make_lists({ blacklist = { "1.2.3.4" } })
            local action, reason = ip_control.check("1.2.3.4", lists)
            assert.equals("block", action)
            assert.equals("static_blacklisted", reason)
        end)

        it("should return action=block and reason=dynamic_blacklisted for dynamic list", function()
            local lists = make_lists()
            ip_control.blacklist_ip("5.6.7.8")
            local action, reason = ip_control.check("5.6.7.8", lists)
            assert.equals("block", action)
            assert.equals("dynamic_blacklisted", reason)
        end)

        it("static blacklist should be checked before dynamic blacklist", function()
            local lists = make_lists({ blacklist = { "1.2.3.4" } })
            ip_control.blacklist_ip("1.2.3.4")
            local action, reason = ip_control.check("1.2.3.4", lists)
            assert.equals("block", action)
            assert.equals("static_blacklisted", reason)
        end)
    end)
end)
