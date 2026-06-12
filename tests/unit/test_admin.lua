-- tests/unit/test_admin.lua
-- Tests for lib/admin.lua Admin REST API module
--
-- NOTE: This test runs in plain Lua (not OpenResty), so we mock
-- cjson, ngx, logger, cc_protect, and rule_engine.

-- Set up package path to find lib/ from project root
local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

-- Provide bit library shim for Lua 5.4+/5.5 (utils.lua uses LuaJIT's bit.band)
if not bit then
    bit = {}
    function bit.band(a, b) return a & b end
    function bit.bor(a, b) return a | b end
    function bit.bxor(a, b) return a ~ b end
    function bit.lshift(a, n) return a << n end
    function bit.rshift(a, n) return a >> n end
end

---------------------------------------------------------------------------
-- Minimal JSON encoder/decoder (no cjson dependency)
---------------------------------------------------------------------------

local json = {}

-- Forward declarations
local decode_value, encode_value

-- Skip whitespace in a string starting at position pos
local function skip_ws(s, pos)
    return s:match("^%s*()", pos)
end

-- Decode a JSON string
local function decode_string(s, pos)
    pos = pos or 1
    pos = skip_ws(s, pos)
    if s:sub(pos, pos) ~= '"' then return nil, pos end
    pos = pos + 1
    local result = {}
    while pos <= #s do
        local c = s:sub(pos, pos)
        if c == '"' then
            return table.concat(result), pos + 1
        elseif c == '\\' then
            pos = pos + 1
            local esc = s:sub(pos, pos)
            if esc == '"' then result[#result+1] = '"'
            elseif esc == '\\' then result[#result+1] = '\\'
            elseif esc == '/' then result[#result+1] = '/'
            elseif esc == 'n' then result[#result+1] = '\n'
            elseif esc == 'r' then result[#result+1] = '\r'
            elseif esc == 't' then result[#result+1] = '\t'
            elseif esc == 'b' then result[#result+1] = '\b'
            elseif esc == 'f' then result[#result+1] = '\f'
            elseif esc == 'u' then
                -- Simple unicode escape (basic BMP only)
                local hex = s:sub(pos+1, pos+4)
                local cp = tonumber(hex, 16)
                if cp and cp < 128 then
                    result[#result+1] = string.char(cp)
                else
                    result[#result+1] = "?"  -- simplified
                end
                pos = pos + 4
            else
                result[#result+1] = esc
            end
        else
            result[#result+1] = c
        end
        pos = pos + 1
    end
    return nil, pos
end

-- Decode a JSON number
local function decode_number(s, pos)
    local num_str = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
    if not num_str then return nil, pos end
    return tonumber(num_str), pos + #num_str
end

-- Decode a JSON object
local function decode_object(s, pos)
    pos = skip_ws(s, pos)
    if s:sub(pos, pos) ~= '{' then return nil, pos end
    pos = pos + 1
    local result = {}
    pos = skip_ws(s, pos)
    if s:sub(pos, pos) == '}' then return result, pos + 1 end
    while true do
        local key
        key, pos = decode_string(s, pos)
        if not key then return nil, pos end
        pos = skip_ws(s, pos)
        if s:sub(pos, pos) ~= ':' then return nil, pos end
        pos = pos + 1
        local value
        value, pos = decode_value(s, pos)
        if value == nil and s:sub(skip_ws(s, pos-1), skip_ws(s, pos-1)) ~= 'n' then
            -- Could be nil from failed decode
        end
        result[key] = value
        pos = skip_ws(s, pos)
        local c = s:sub(pos, pos)
        if c == '}' then return result, pos + 1
        elseif c == ',' then pos = pos + 1
        else return nil, pos end
    end
end

-- Decode a JSON array
local function decode_array(s, pos)
    pos = skip_ws(s, pos)
    if s:sub(pos, pos) ~= '[' then return nil, pos end
    pos = pos + 1
    local result = {}
    pos = skip_ws(s, pos)
    if s:sub(pos, pos) == ']' then return result, pos + 1 end
    while true do
        local value
        value, pos = decode_value(s, pos)
        result[#result+1] = value
        pos = skip_ws(s, pos)
        local c = s:sub(pos, pos)
        if c == ']' then return result, pos + 1
        elseif c == ',' then pos = pos + 1
        else return nil, pos end
    end
end

-- Decode any JSON value
decode_value = function(s, pos)
    pos = skip_ws(s, pos)
    if pos > #s then return nil, pos end
    local c = s:sub(pos, pos)
    if c == '"' then return decode_string(s, pos)
    elseif c == '{' then return decode_object(s, pos)
    elseif c == '[' then return decode_array(s, pos)
    elseif c == 't' and s:sub(pos, pos+3) == 'true' then return true, pos + 4
    elseif c == 'f' and s:sub(pos, pos+4) == 'false' then return false, pos + 5
    elseif c == 'n' and s:sub(pos, pos+3) == 'null' then return nil, pos + 4
    elseif c == '-' or (c >= '0' and c <= '9') then return decode_number(s, pos)
    end
    return nil, pos
end

-- Public decode function (matches cjson.decode signature)
function json.decode(s)
    if type(s) ~= "string" then return nil, "expected string" end
    local result, pos = decode_value(s, 1)
    return result
end

-- JSON encode: handle Lua types
local function is_array(t)
    if type(t) ~= "table" then return false end
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    -- Empty table is treated as object
    if count == 0 then return false end
    -- Check if all keys are consecutive integers starting at 1
    for i = 1, count do
        if t[i] == nil then return false end
    end
    return true
end

local escape_map = {
    ['"'] = '\\"', ['\\'] = '\\\\', ['/'] = '\\/',
    ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t',
    ['\b'] = '\\b', ['\f'] = '\\f',
}

encode_value = function(v)
    local t = type(v)
    if v == nil then return "null"
    elseif t == "boolean" then return v and "true" or "false"
    elseif t == "number" then
        if v ~= v then return "null" end  -- NaN
        if v == math.huge or v == -math.huge then return "null" end
        -- Format integers without decimal point
        if v == math.floor(v) and v >= -1e15 and v <= 1e15 then
            return string.format("%.0f", v)
        end
        return tostring(v)
    elseif t == "string" then
        return '"' .. v:gsub('["\\\n\r\t\b\f/]', escape_map) .. '"'
    elseif t == "table" then
        if is_array(v) then
            local parts = {}
            for i = 1, #v do
                parts[#parts+1] = encode_value(v[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            local parts = {}
            for k, val in pairs(v) do
                if type(k) == "string" then
                    parts[#parts+1] = encode_value(k) .. ":" .. encode_value(val)
                end
            end
            table.sort(parts)
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
    return "null"
end

function json.encode(v)
    return encode_value(v)
end

-- Register as cjson mock
package.loaded["cjson"] = json

---------------------------------------------------------------------------
-- Mock infrastructure
---------------------------------------------------------------------------

-- Track captured output
local captured_status = nil
local captured_headers = {}
local captured_output = {}

-- Mock shared dict with get_keys support
local function make_mock_dict()
    local store = {}
    local ttls = {}
    local mock = {}

    function mock:get(key)
        if ttls[key] and ttls[key] < os.time() then
            store[key] = nil
            ttls[key] = nil
            return nil, 2  -- 2 = expired
        end
        return store[key], 0
    end

    function mock:set(key, value, ttl)
        store[key] = value
        if ttl and ttl > 0 then
            ttls[key] = os.time() + ttl
        else
            ttls[key] = nil  -- no expiry
        end
        return true
    end

    function mock:incr(key, value, init, ttl)
        if ttls[key] and ttls[key] < os.time() then
            store[key] = nil
            ttls[key] = nil
        end
        if store[key] == nil then
            store[key] = init or 0
            if ttl then ttls[key] = os.time() + ttl end
        end
        store[key] = store[key] + value
        return store[key], nil
    end

    function mock:delete(key)
        store[key] = nil
        ttls[key] = nil
        return true
    end

    function mock:get_keys(max_count)
        max_count = max_count or 1000
        local keys = {}
        local count = 0
        for k, _ in pairs(store) do
            -- Skip expired keys
            if not (ttls[k] and ttls[k] < os.time()) then
                if count >= max_count then break end
                table.insert(keys, k)
                count = count + 1
            end
        end
        return keys
    end

    return mock
end

-- Module-level shared dicts (rebuilt per test)
local mock_ip_blacklist
local mock_ip_whitelist
local mock_rate_limit
local mock_session_track
local mock_waf_stats
local mock_waf_logs
local mock_waf_state

-- Captured logger audit entries
local audit_entries = {}

-- Set up global ngx mock (admin.lua captures it at require time)
local function setup_ngx()
    captured_status = nil
    captured_headers = {}
    captured_output = {}
    audit_entries = {}

    mock_ip_blacklist = make_mock_dict()
    mock_ip_whitelist = make_mock_dict()
    mock_rate_limit = make_mock_dict()
    mock_session_track = make_mock_dict()
    mock_waf_stats = make_mock_dict()
    mock_waf_logs = make_mock_dict()
    mock_waf_state = make_mock_dict()

    -- Pre-set admin token in waf_state
    mock_waf_state:set("admin_token_valid", true)
    mock_waf_state:set("waf_admin_token", "test-secret-token")

    ngx = {
        now = function() return 1000 end,
        time = function() return 1000 end,
        say = function(text) table.insert(captured_output, text) end,
        exit = function() end,
        log = function() end,
        ERR = 8,
        WARN = 5,
        var = {
            remote_addr = "127.0.0.1",
            waf_admin_token = "test-secret-token",
            http_authorization = nil,
            uri = "/",
            http_accept = nil,
            http_cookie = nil,
        },
        req = {
            get_method = function() return "GET" end,
            read_body = function() end,
            get_body_data = function() return nil end,
            get_uri_args = function() return {} end,
        },
        header = {},
        shared = {
            ip_blacklist = mock_ip_blacklist,
            ip_whitelist = mock_ip_whitelist,
            rate_limit = mock_rate_limit,
            session_track = mock_session_track,
            waf_stats = mock_waf_stats,
            waf_logs = mock_waf_logs,
            waf_state = mock_waf_state,
        },
        status = 200,
    }

    -- Track status writes: remove status from table so __newindex fires
    -- Lua __newindex only fires for keys that don't already exist in the raw table
    ngx.status = nil  -- remove from raw table
    setmetatable(ngx, {
        __newindex = function(t, k, v)
            if k == "status" then
                captured_status = v
            end
            rawset(t, k, v)
        end,
        __index = function(t, k)
            if k == "status" then
                return captured_status
            end
        end,
    })

    -- Mock logger
    package.loaded["lib.logger"] = {
        audit = function(entry)
            table.insert(audit_entries, entry)
        end,
        get_stats = function()
            local stats = ngx.shared.waf_stats
            if not stats then return {} end
            return {
                total_requests = stats:get("total_requests") or 0,
                passed_total = stats:get("passed_total") or 0,
                blocked_total = stats:get("blocked_total") or 0,
            }
        end,
        get_all_logs = function(filters, page, per_page)
            return { logs = {}, total = 0, page = page or 1, per_page = per_page or 20 }
        end,
        get_log_by_id = function(id)
            return nil
        end,
    }

    -- Mock cc_protect
    package.loaded["lib.cc_protect"] = {
        DEFAULTS = {
            ip_qps_limit = 100,
            ip_conn_limit = 50,
            global_qps_limit = 5000,
            window_size = 60,
        },
    }

    -- Mock rule_engine
    package.loaded["lib.rule_engine"] = {
        reload_rules = function() return {} end,
        list_rule_files = function()
            return {
                { filename = "sql_injection.yaml", count = 10 },
                { filename = "custom.yaml", count = 2 },
            }
        end,
        get_rules_from_file = function(filename)
            return {
                { id = "CUSTOM-01", description = "Test rule", severity = "high", target = "URI", pattern = "^/admin", action = "BLOCK" },
            }
        end,
        validate_rule = function(rule)
            if not rule.id or rule.id == "" then return false, "Missing rule ID" end
            if not rule.description or rule.description == "" then return false, "Missing description" end
            if not rule.pattern or rule.pattern == "" then return false, "Missing pattern" end
            return true
        end,
        add_rule_to_custom = function(rule)
            return true
        end,
        update_rule_in_custom = function(rule_id, rule)
            return true
        end,
        delete_rule_from_custom = function(rule_id)
            return true
        end,
        restore_default = function()
            return true
        end,
    }

    -- Force reload admin module so it picks up new mocks
    package.loaded["lib.admin"] = nil
end

---------------------------------------------------------------------------
-- Test helpers
---------------------------------------------------------------------------

local function get_response()
    if #captured_output == 0 then return nil end
    local ok, data = pcall(json.decode, captured_output[#captured_output])
    if ok then return data end
    return nil
end

local function get_status()
    return captured_status
end

local function run_admin()
    local admin = require("lib.admin")
    admin.handle()
end

---------------------------------------------------------------------------
-- Tests
---------------------------------------------------------------------------

local tests_passed = 0
local tests_failed = 0

local function run_test(name, fn)
    local ok, err = pcall(fn)
    if ok then
        tests_passed = tests_passed + 1
    else
        tests_failed = tests_failed + 1
        print("  " .. name .. " FAILED: " .. tostring(err))
    end
end

-- Test 1: JSON response helpers (verify correct Content-Type and status)
local function test_json_response_helpers()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.var.uri = "/admin/status"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    local resp = get_response()
    assert(resp ~= nil, "Response should not be nil")
    assert(resp.status == "ok", "Status should be 'ok'")
    assert(get_status() == 200, "HTTP status should be 200")
    -- Verify output is valid JSON
    assert(#captured_output == 1, "Should produce exactly one output")
end

-- Test 2: read_json_body with valid body
local function test_read_json_body_valid()
    setup_ngx()

    local body_data = '{"ip":"10.0.0.1","ttl":600}'
    ngx.req.get_body_data = function() return body_data end

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    local resp = get_response()
    assert(resp ~= nil, "Response should not be nil")
    assert(resp.ip == "10.0.0.1", "IP should be 10.0.0.1")
end

-- Test 3: read_json_body with invalid body
local function test_read_json_body_invalid()
    setup_ngx()

    ngx.req.get_body_data = function() return "not json" end

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    local resp = get_response()
    assert(resp ~= nil, "Response should not be nil")
    assert(resp.error == true, "Should return error")
    assert(resp.message == "Invalid or empty JSON body", "Should indicate invalid body")
end

-- Test 4: read_json_body with empty body
local function test_read_json_body_empty()
    setup_ngx()

    ngx.req.get_body_data = function() return "" end

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    local resp = get_response()
    assert(resp ~= nil, "Response should not be nil")
    assert(resp.error == true, "Should return error for empty body")
end

-- Test 5: Auth fails without token
local function test_auth_no_token()
    setup_ngx()

    ngx.var.http_authorization = nil
    ngx.var.uri = "/admin/status"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    assert(get_status() == 401, "Should return 401 without token")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
    assert(resp.message == "Missing Authorization header", "Should indicate missing auth")
end

-- Test 6: Auth fails with wrong token
local function test_auth_wrong_token()
    setup_ngx()

    ngx.var.http_authorization = "Bearer wrong-token"
    ngx.var.uri = "/admin/status"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    assert(get_status() == 401, "Should return 401 with wrong token")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
    assert(resp.message == "Invalid token", "Should indicate invalid token")
end

-- Test 7: Auth succeeds with correct token
local function test_auth_success()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.var.uri = "/admin/status"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    assert(get_status() == 200, "Should return 200 with correct token")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok status")
end

-- Test 8: GET /admin/stats returns stats object
local function test_get_stats()
    setup_ngx()

    mock_waf_stats:set("total_requests", 42)
    mock_waf_stats:set("passed_total", 40)
    mock_waf_stats:set("blocked_total", 2)

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.var.uri = "/admin/stats"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.total_requests == 42, "total_requests should be 42, got " .. tostring(resp.total_requests))
    assert(resp.passed_total == 40, "passed_total should be 40")
    assert(resp.blocked_total == 2, "blocked_total should be 2")
end

-- Test 9: POST /admin/ip/blacklist with valid IP
local function test_blacklist_add_valid()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip":"192.168.1.100","ttl":600}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok")
    assert(resp.ip == "192.168.1.100", "Should return the IP")

    -- Verify IP was actually added to shared dict
    local val = mock_ip_blacklist:get("192.168.1.100")
    assert(val == "admin_added", "IP should be stored in blacklist")
end

-- Test 10: POST /admin/ip/blacklist with invalid IP
local function test_blacklist_add_invalid()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip":"not-an-ip"}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    assert(get_status() == 400, "Should return 400 for invalid IP")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
    assert(resp.message == "Invalid IPv4 address", "Should indicate invalid IP")
end

-- Test 11: POST /admin/ip/blacklist with octet > 255
local function test_blacklist_add_bad_octet()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip":"999.999.999.999"}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    assert(get_status() == 400, "Should return 400 for octet > 255")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
end

-- Test 12: DELETE /admin/ip/blacklist/{ip}
local function test_blacklist_delete()
    setup_ngx()

    mock_ip_blacklist:set("10.0.0.5", "test", 300)
    assert(mock_ip_blacklist:get("10.0.0.5") == "test", "IP should be in dict before delete")

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "DELETE" end
    ngx.var.uri = "/admin/ip/blacklist/10.0.0.5"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.ip == "10.0.0.5", "Should return deleted IP")

    -- Verify IP was removed
    local val = mock_ip_blacklist:get("10.0.0.5")
    assert(val == nil, "IP should be removed from blacklist")
end

-- Test 13: DELETE /admin/ip/blacklist with invalid IP
local function test_blacklist_delete_invalid()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "DELETE" end
    ngx.var.uri = "/admin/ip/blacklist/not-valid"

    run_admin()

    assert(get_status() == 400, "Should return 400 for invalid IP in DELETE")
end

-- Test 14: GET /admin/ip/blacklist returns IP list
local function test_blacklist_get()
    setup_ngx()

    mock_ip_blacklist:set("1.2.3.4", "reason1", 300)
    mock_ip_blacklist:set("5.6.7.8", "reason2", 300)

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.entries ~= nil, "Should have entries table")
    assert(resp.entries["1.2.3.4"] == "reason1", "Should contain 1.2.3.4")
    assert(resp.entries["5.6.7.8"] == "reason2", "Should contain 5.6.7.8")
end

-- Test 15: POST /admin/ip/whitelist with valid IP
local function test_whitelist_add_valid()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip":"172.16.0.1"}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/whitelist"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.ip == "172.16.0.1", "Should return the IP")

    local val = mock_ip_whitelist:get("172.16.0.1")
    assert(val == "admin_added", "IP should be in whitelist")
end

-- Test 16: DELETE /admin/ip/whitelist/{ip}
local function test_whitelist_delete()
    setup_ngx()

    mock_ip_whitelist:set("172.16.0.1", "test")
    assert(mock_ip_whitelist:get("172.16.0.1") == "test", "IP should be in dict")

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "DELETE" end
    ngx.var.uri = "/admin/ip/whitelist/172.16.0.1"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local val = mock_ip_whitelist:get("172.16.0.1")
    assert(val == nil, "IP should be removed from whitelist")
end

-- Test 17: GET /admin/ip/whitelist returns IP list
local function test_whitelist_get()
    setup_ngx()

    mock_ip_whitelist:set("10.0.0.1", "admin")
    mock_ip_whitelist:set("10.0.0.2", "trusted")

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/ip/whitelist"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.entries["10.0.0.1"] == "admin", "Should contain 10.0.0.1")
    assert(resp.entries["10.0.0.2"] == "trusted", "Should contain 10.0.0.2")
end

-- Test 18: POST /admin/cc/config with valid values
local function test_cc_config_valid()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip_qps_limit":200,"ip_conn_limit":80}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/cc/config"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok")
    assert(resp.config.ip_qps_limit == 200, "ip_qps_limit should be 200")
    assert(resp.config.ip_conn_limit == 80, "ip_conn_limit should be 80")
    assert(resp.config.global_qps_limit == 5000, "global_qps_limit should keep default")

    -- Verify stored in shared dict
    local val = mock_session_track:get("cc_config:ip_qps_limit")
    assert(val == 200, "Should be stored in session_track")
end

-- Test 19: POST /admin/cc/config rejects negative values
local function test_cc_config_negative()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip_qps_limit":-10}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/cc/config"

    run_admin()

    assert(get_status() == 400, "Should return 400 for negative value")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
    assert(resp.message:find("positive number"), "Should mention positive number")
end

-- Test 20: POST /admin/cc/config rejects zero
local function test_cc_config_zero()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip_qps_limit":0}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/cc/config"

    run_admin()

    assert(get_status() == 400, "Should return 400 for zero value")
end

-- Test 21: POST /admin/cc/config rejects unknown keys
local function test_cc_config_unknown_key()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"unknown_key":100}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/cc/config"

    run_admin()

    assert(get_status() == 400, "Should return 400 for unknown key")
    local resp = get_response()
    assert(resp.message:find("Unknown config key"), "Should mention unknown key")
end

-- Test 22: GET /admin/cc/config returns current config
local function test_cc_config_get()
    setup_ngx()

    mock_session_track:set("cc_config:ip_qps_limit", 250)

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/cc/config"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.ip_qps_limit == 250, "Should return overridden value (250)")
    assert(resp.ip_conn_limit == 50, "Should return default for non-overridden (50)")
end

-- Test 23: Unknown route returns 404
local function test_unknown_route()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/nonexistent"

    run_admin()

    assert(get_status() == 404, "Should return 404 for unknown route")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
    assert(resp.message == "Not Found", "Should say Not Found")
end

-- Test 24: Unknown POST route returns 404
local function test_unknown_post_route()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/unknown/endpoint"

    run_admin()

    assert(get_status() == 404, "Should return 404 for unknown POST route")
end

-- Test 25: Auth fails with invalid Authorization format
local function test_auth_bad_format()
    setup_ngx()

    ngx.var.http_authorization = "Basic dXNlcjpwYXNz"
    ngx.var.uri = "/admin/status"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    assert(get_status() == 401, "Should return 401 for non-Bearer auth")
    local resp = get_response()
    assert(resp.message == "Invalid Authorization format", "Should indicate invalid format")
end

-- Test 26: POST /admin/rules/reload calls rule_engine.reload_rules
local function test_rules_reload()
    setup_ngx()

    local reload_called = false
    package.loaded["lib.rule_engine"] = {
        reload_rules = function()
            reload_called = true
            return {}
        end,
    }
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/rules/reload"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    assert(reload_called == true, "reload_rules should have been called")
    local resp = get_response()
    assert(resp.message == "Rules reloaded", "Should confirm rules reloaded")
end

-- Test 27: Audit logging on admin actions
local function test_audit_logging()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/status"

    run_admin()

    assert(#audit_entries == 1, "Should log exactly one audit entry")
    assert(audit_entries[1].action == "admin", "Action should be 'admin'")
    assert(audit_entries[1].admin_ip == "127.0.0.1", "Admin IP should be captured")
    assert(audit_entries[1].detail == "GET /admin/status", "Detail should include method and URI")
end

-- Test 28: GET /admin/status returns uptime and modules
local function test_status_endpoint()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/status"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Status should be ok")
    assert(resp.uptime ~= nil, "Should have uptime")
    assert(resp.version == "1.0.0", "Should have version")
    assert(resp.modules.rule_engine == true, "Should list rule_engine module")
    assert(resp.modules.cc_protect == true, "Should list cc_protect module")
    assert(resp.modules.logger == true, "Should list logger module")
end

-- Test 29: POST /admin/ip/blacklist with default TTL
local function test_blacklist_default_ttl()
    setup_ngx()

    ngx.req.get_body_data = function() return '{"ip":"10.0.0.1"}' end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/ip/blacklist"

    run_admin()

    local resp = get_response()
    assert(resp.ttl == 300, "Default TTL should be 300, got " .. tostring(resp.ttl))
end

-- Test 30: Auth with no admin token configured
local function test_auth_no_configured_token()
    setup_ngx()

    ngx.var.waf_admin_token = ""
    ngx.var.http_authorization = "Bearer some-token"
    ngx.var.uri = "/admin/status"
    ngx.req.get_method = function() return "GET" end

    run_admin()

    assert(get_status() == 403, "Should return 403 when admin token not configured")
end

---------------------------------------------------------------------------
-- Log viewing tests
---------------------------------------------------------------------------

-- Test 31: GET /admin/logs returns log list
local function test_logs_get()
    setup_ngx()

    local test_logs = {
        { id = 1, timestamp = 1000, source_ip = "1.2.3.4", method = "GET", uri = "/test", rule_id = "SQLI-001", severity = "critical", action = "block" },
    }
    package.loaded["lib.logger"].get_all_logs = function(filters, page, per_page)
        return { logs = test_logs, total = 1, page = 1, per_page = 20 }
    end
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/logs"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.total == 1, "Total should be 1")
    assert(#resp.logs == 1, "Should have 1 log entry")
    assert(resp.logs[1].id == 1, "Log ID should be 1")
end

-- Test 32: GET /admin/logs with filters
local function test_logs_get_with_filters()
    setup_ngx()

    local captured_filters = nil
    package.loaded["lib.logger"].get_all_logs = function(filters, page, per_page)
        captured_filters = filters
        return { logs = {}, total = 0, page = 1, per_page = 20 }
    end
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/logs"
    ngx.req.get_uri_args = function()
        return { rule_id = "SQLI-001", severity = "critical", source_ip = "1.2.3.4", page = "2", per_page = "10" }
    end

    run_admin()

    assert(get_status() == 200, "Should return 200")
    assert(captured_filters ~= nil, "Filters should be passed")
    assert(captured_filters.rule_id == "SQLI-001", "rule_id filter should be SQLI-001")
    assert(captured_filters.severity == "critical", "severity filter should be critical")
    assert(captured_filters.source_ip == "1.2.3.4", "source_ip filter should be 1.2.3.4")
end

-- Test 33: GET /admin/logs/{id} returns log detail
local function test_log_detail_get()
    setup_ngx()

    local test_log = { id = 42, timestamp = 1000, source_ip = "1.2.3.4", method = "POST", uri = "/api/login", rule_id = "SQLI-003", severity = "critical", action = "block", reason = "SQL injection detected" }
    package.loaded["lib.logger"].get_log_by_id = function(id)
        if id == 42 then return test_log end
        return nil
    end
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/logs/42"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.id == 42, "Log ID should be 42")
    assert(resp.source_ip == "1.2.3.4", "Source IP should be 1.2.3.4")
    assert(resp.reason == "SQL injection detected", "Reason should match")
end

-- Test 34: GET /admin/logs/{id} with invalid ID
local function test_log_detail_invalid_id()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/logs/abc"

    run_admin()

    assert(get_status() == 404, "Should return 404 for non-numeric ID")
end

-- Test 35: GET /admin/logs/{id} not found
local function test_log_detail_not_found()
    setup_ngx()

    package.loaded["lib.logger"].get_log_by_id = function(id) return nil end
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/logs/999"

    run_admin()

    assert(get_status() == 404, "Should return 404 for missing log")
end

---------------------------------------------------------------------------
-- Rule management tests
---------------------------------------------------------------------------

-- Test 36: GET /admin/rules/list returns rule files
local function test_rules_list()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/rules/list"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.files ~= nil, "Should have files table")
    assert(#resp.files == 2, "Should have 2 rule files")
    assert(resp.files[1].filename == "sql_injection.yaml", "First file should be sql_injection.yaml")
end

-- Test 37: GET /admin/rules/custom returns custom rules
local function test_custom_rules_get()
    setup_ngx()

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "GET" end
    ngx.var.uri = "/admin/rules/custom"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.rules ~= nil, "Should have rules table")
    assert(#resp.rules == 1, "Should have 1 custom rule")
    assert(resp.rules[1].id == "CUSTOM-01", "Rule ID should be CUSTOM-01")
end

-- Test 38: POST /admin/rules/custom adds a rule
local function test_custom_rule_post()
    setup_ngx()

    local added_rule = nil
    package.loaded["lib.rule_engine"].add_rule_to_custom = function(rule)
        added_rule = rule
        return true
    end
    package.loaded["lib.admin"] = nil

    ngx.req.get_body_data = function()
        return '{"id":"CUSTOM-02","description":"Test","severity":"high","target":"URI","pattern":"^/test","action":"BLOCK"}'
    end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/rules/custom"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok")
    assert(resp.id == "CUSTOM-02", "Should return rule ID")
    assert(added_rule ~= nil, "Rule should have been passed to add_rule_to_custom")
    assert(added_rule.id == "CUSTOM-02", "Rule ID should match")
end

-- Test 39: POST /admin/rules/custom with missing fields
local function test_custom_rule_post_invalid()
    setup_ngx()

    ngx.req.get_body_data = function()
        return '{"id":"CUSTOM-03"}'
    end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/rules/custom"

    run_admin()

    assert(get_status() == 400, "Should return 400 for missing fields")
    local resp = get_response()
    assert(resp.error == true, "Should return error")
end

-- Test 40: PUT /admin/rules/custom/{id} updates a rule
local function test_custom_rule_put()
    setup_ngx()

    local updated_id = nil
    package.loaded["lib.rule_engine"].update_rule_in_custom = function(rule_id, rule)
        updated_id = rule_id
        return true
    end
    package.loaded["lib.admin"] = nil

    ngx.req.get_body_data = function()
        return '{"id":"CUSTOM-01","description":"Updated","severity":"medium","target":"ARGS","pattern":"updated","action":"LOG"}'
    end
    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "PUT" end
    ngx.var.uri = "/admin/rules/custom/CUSTOM-01"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok")
    assert(resp.id == "CUSTOM-01", "Should return rule ID")
    assert(updated_id == "CUSTOM-01", "Should pass correct rule ID to update")
end

-- Test 41: DELETE /admin/rules/custom/{id} deletes a rule
local function test_custom_rule_delete()
    setup_ngx()

    local deleted_id = nil
    package.loaded["lib.rule_engine"].delete_rule_from_custom = function(rule_id)
        deleted_id = rule_id
        return true
    end
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "DELETE" end
    ngx.var.uri = "/admin/rules/custom/CUSTOM-01"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok")
    assert(deleted_id == "CUSTOM-01", "Should pass correct rule ID to delete")
end

-- Test 42: POST /admin/rules/restore-default restores defaults
local function test_rules_restore_default()
    setup_ngx()

    local restore_called = false
    package.loaded["lib.rule_engine"].restore_default = function()
        restore_called = true
        return true
    end
    package.loaded["lib.admin"] = nil

    ngx.var.http_authorization = "Bearer test-secret-token"
    ngx.req.get_method = function() return "POST" end
    ngx.var.uri = "/admin/rules/restore-default"

    run_admin()

    assert(get_status() == 200, "Should return 200")
    local resp = get_response()
    assert(resp.status == "ok", "Should return ok")
    assert(restore_called == true, "restore_default should have been called")
end

---------------------------------------------------------------------------
-- Run all tests
---------------------------------------------------------------------------

print("Running admin.lua tests...")
print("")

run_test("json_response_helpers", test_json_response_helpers)
run_test("read_json_body_valid", test_read_json_body_valid)
run_test("read_json_body_invalid", test_read_json_body_invalid)
run_test("read_json_body_empty", test_read_json_body_empty)
run_test("auth_no_token", test_auth_no_token)
run_test("auth_wrong_token", test_auth_wrong_token)
run_test("auth_success", test_auth_success)
run_test("get_stats", test_get_stats)
run_test("blacklist_add_valid", test_blacklist_add_valid)
run_test("blacklist_add_invalid", test_blacklist_add_invalid)
run_test("blacklist_add_bad_octet", test_blacklist_add_bad_octet)
run_test("blacklist_delete", test_blacklist_delete)
run_test("blacklist_delete_invalid", test_blacklist_delete_invalid)
run_test("blacklist_get", test_blacklist_get)
run_test("whitelist_add_valid", test_whitelist_add_valid)
run_test("whitelist_delete", test_whitelist_delete)
run_test("whitelist_get", test_whitelist_get)
run_test("cc_config_valid", test_cc_config_valid)
run_test("cc_config_negative", test_cc_config_negative)
run_test("cc_config_zero", test_cc_config_zero)
run_test("cc_config_unknown_key", test_cc_config_unknown_key)
run_test("cc_config_get", test_cc_config_get)
run_test("unknown_route", test_unknown_route)
run_test("unknown_post_route", test_unknown_post_route)
run_test("auth_bad_format", test_auth_bad_format)
run_test("rules_reload", test_rules_reload)
run_test("audit_logging", test_audit_logging)
run_test("status_endpoint", test_status_endpoint)
run_test("blacklist_default_ttl", test_blacklist_default_ttl)
run_test("auth_no_configured_token", test_auth_no_configured_token)
run_test("logs_get", test_logs_get)
run_test("logs_get_with_filters", test_logs_get_with_filters)
run_test("log_detail_get", test_log_detail_get)
run_test("log_detail_invalid_id", test_log_detail_invalid_id)
run_test("log_detail_not_found", test_log_detail_not_found)
run_test("rules_list", test_rules_list)
run_test("custom_rules_get", test_custom_rules_get)
run_test("custom_rule_post", test_custom_rule_post)
run_test("custom_rule_post_invalid", test_custom_rule_post_invalid)
run_test("custom_rule_put", test_custom_rule_put)
run_test("custom_rule_delete", test_custom_rule_delete)
run_test("rules_restore_default", test_rules_restore_default)

print("")
if tests_failed == 0 then
    print("=== ALL ADMIN API TESTS PASSED (" .. tests_passed .. " tests) ===")
else
    print("=== " .. tests_passed .. " PASSED, " .. tests_failed .. " FAILED ===")
    os.exit(1)
end
