-- tests/unit/test_waf_cors_errors.lua
-- Regression test: every WAF error response must carry CORS headers so
-- browsers never mask 4xx/5xx as "No Access-Control-Allow-Origin".

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

_G.ngx = {
    ERR = 4,
    log = function() end,
    time = function() return 1000 end,
    header = {},
    status = 403,
    var = {
        http_origin = "https://cloud.gongpinlian.com",
    },
    req = {},
    ctx = {},
    shared = {},
}

local waf = require("lib.waf")

waf.header_filter_phase()

assert(
    ngx.header["Access-Control-Allow-Origin"] == "https://cloud.gongpinlian.com",
    "error response must reflect Access-Control-Allow-Origin"
)
assert(
    ngx.header["Access-Control-Allow-Methods"] ~= nil,
    "error response must include Access-Control-Allow-Methods"
)

-- Successful responses must not be modified by this phase.
ngx.status = 200
ngx.header = {}
waf.header_filter_phase()
assert(
    ngx.header["Access-Control-Allow-Origin"] == nil,
    "200 responses should not be altered by the error CORS phase"
)

print("ALL waf error CORS regression tests PASSED")
