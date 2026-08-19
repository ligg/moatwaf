-- tests/unit/test_challenge_cors.lua
-- Regression test: JS Challenge responses must include CORS headers so
-- cross-origin API calls do not surface as generic CORS errors.

local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

local seen_headers = {}

package.loaded["cjson"] = {
    encode = function(v) return "{}" end,
    decode = function(s) return {} end,
}

package.loaded["lib.utils"] = {
    get_client_ip = function() return "1.2.3.4" end,
}

package.loaded["lib.admin.html"] = {
    CHALLENGE_HTML = [[
<html><body>challenge</body></html>
]],
}

_G.ngx = {
    ERR = 4,
    log = function() end,
    time = function() return 1000 end,
    md5 = function(s) return s end,
    header = seen_headers,
    status = 0,
    say = function() end,
    exit = function() end,
    var = {
        http_origin = "https://cloud.gongpinlian.com",
        remote_addr = "1.2.3.4",
        request_uri = "/api/Yunos/SetConfiguration/SetConfigurationList",
        uri = "/api/Yunos/SetConfiguration/SetConfigurationList",
    },
    req = {
        get_method = function() return "GET" end,
    },
}

local challenge = require("lib.admin.challenge")

challenge.generate_challenge("/api/Yunos/SetConfiguration/SetConfigurationList")

assert(
    seen_headers["Access-Control-Allow-Origin"] == "https://cloud.gongpinlian.com" or
    seen_headers["Access-Control-Allow-Origin"] == "*",
    "challenge HTML response must include Access-Control-Allow-Origin"
)

print("ALL challenge CORS regression tests PASSED")
