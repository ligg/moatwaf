-- tests/unit/test_waf_challenge_verify.lua
-- Regression test: challenge verify must be handled in rewrite phase on any
-- protected domain, instead of falling through to the upstream (Kong 404).

local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

local modules = {}
modules["lib.init"] = {
    load = function(name)
        return modules["lib." .. name]
    end,
}
modules["lib.utils"] = {}
modules["lib.ip_control"] = {}
modules["lib.cc_protect"] = {}
modules["lib.rule_engine"] = {}
modules["lib.upload_check"] = {}
modules["lib.logger"] = {}

package.loaded["cjson"] = {
    encode = function() return "{}" end,
    decode = function() return {} end,
}
for name, mod in pairs(modules) do
    package.loaded[name] = mod
end

local handle_verify_called = false
local challenge_generated = false
package.loaded["lib.admin.challenge"] = {
    handle_verify = function()
        handle_verify_called = true
        return true
    end,
    has_valid_challenge = function() return false end,
    generate_challenge = function()
        challenge_generated = true
        return true
    end,
}

local exit_status = nil
_G.ngx = {
    ERR = 4,
    log = function() end,
    time = function() return 1000 end,
    header = {},
    status = 0,
    say = function() end,
    exit = function(status)
        exit_status = status
    end,
    var = {
        http_origin = "https://cloud.gongpinlian.com",
        uri = "/admin/challenge/verify",
        remote_addr = "1.2.3.4",
    },
    req = {
        get_method = function() return "POST" end,
        get_headers = function() return {} end,
        read_body = function() end,
    },
    ctx = {},
    shared = {},
}

local waf = require("lib.waf")

waf.rewrite_phase()

assert(
    handle_verify_called == true,
    "POST /admin/challenge/verify must be handled by WAF rewrite phase"
)

-- OPTIONS preflight should be answered by the WAF with CORS headers.
ngx.req.get_method = function() return "OPTIONS" end
handle_verify_called = false
exit_status = nil
ngx.header = {}
ngx.status = 0

waf.rewrite_phase()

assert(handle_verify_called == false, "OPTIONS must not invoke handle_verify")
assert(exit_status == 204, "OPTIONS challenge verify should return 204")
assert(
    ngx.header["Access-Control-Allow-Origin"] == "https://cloud.gongpinlian.com",
    "OPTIONS challenge verify should include Access-Control-Allow-Origin"
)

-- Non-HTML requests (JS/CSS/API) must NOT receive an HTML challenge page.
modules["lib.cc_protect"].check = function()
    return "challenge", "rate_exceeded"
end
modules["lib.rule_engine"].check = function()
    return "pass"
end

ngx.var.uri = "/api/Yunos/SetConfiguration/SetConfigurationList"
ngx.var.request_uri = "/api/Yunos/SetConfiguration/SetConfigurationList"
ngx.var.http_accept = "application/json"
ngx.req.get_method = function() return "GET" end
ngx.ctx = { client_ip = "1.2.3.4", whitelisted = false }
challenge_generated = false

waf.access_phase()

assert(
    challenge_generated == false,
    "non-HTML requests must not be answered with an HTML challenge page"
)

-- Browser page navigations keep the JS Challenge.
ngx.var.http_accept = "text/html"
challenge_generated = false
waf.access_phase()
assert(
    challenge_generated == true,
    "HTML page navigations should still receive the JS Challenge"
)

print("ALL waf challenge verify regression tests PASSED")
