-- tests/unit/test_ip_control.lua
-- Tests for lib/utils.lua functions used by ip_control module
-- (ip_in_cidr, url_decode, normalize)
--
-- NOTE: This test runs in plain Lua (not OpenResty), so we mock
-- cjson and set up the package path appropriately.

-- Set up package path to find lib/ from project root
package.path = "D:/test/safeguard/?.lua;" .. package.path

-- Mock cjson since it's only available in OpenResty
package.loaded["cjson"] = {
    encode = function() return "{}" end,
    decode = function() return {} end,
}

-- Provide bit library shim for Lua 5.4+/5.5 (utils.lua uses LuaJIT's bit.band)
-- Lua 5.4+ has native bitwise operators but not the bit.* API
if not bit then
    bit = {}
    function bit.band(a, b) return a & b end
    function bit.bor(a, b) return a | b end
    function bit.bxor(a, b) return a ~ b end
    function bit.lshift(a, n) return a << n end
    function bit.rshift(a, n) return a >> n end
end

local function test_ip_in_cidr()
    local utils = require("lib.utils")

    -- Test exact match
    assert(utils.ip_in_cidr("192.168.1.100", "192.168.1.100") == true,
        "exact match should be true")

    -- Test CIDR match
    assert(utils.ip_in_cidr("192.168.1.100", "192.168.1.0/24") == true,
        "/24 match should be true")
    assert(utils.ip_in_cidr("192.168.2.100", "192.168.1.0/24") == false,
        "different subnet should be false")

    -- Test /16
    assert(utils.ip_in_cidr("10.0.5.1", "10.0.0.0/16") == true,
        "/16 match should be true")
    assert(utils.ip_in_cidr("10.1.0.1", "10.0.0.0/16") == false,
        "/16 no match should be false")

    -- Test /8
    assert(utils.ip_in_cidr("172.16.5.1", "172.0.0.0/8") == true,
        "/8 match should be true")

    print("ALL ip_in_cidr tests PASSED")
end

local function test_url_decode()
    local utils = require("lib.utils")

    assert(utils.url_decode("hello%20world") == "hello world", "basic decode")
    assert(utils.url_decode("a%2Bb") == "a+b", "plus encoding")
    assert(utils.url_decode(nil) == "", "nil input")
    assert(utils.url_decode("") == "", "empty input")

    print("ALL url_decode tests PASSED")
end

local function test_normalize()
    local utils = require("lib.utils")

    -- Single URL decode
    assert(utils.normalize("hello%20world") == "hello world", "single decode")

    -- Double URL encode (WAF bypass attempt)
    assert(utils.normalize("hello%2520world") == "hello world", "double decode")

    -- HTML entity
    assert(utils.normalize("&lt;script&gt;") == "<script>", "html entity")

    print("ALL normalize tests PASSED")
end

test_ip_in_cidr()
test_url_decode()
test_normalize()
