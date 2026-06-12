-- lib/utils.lua
local _M = {}

local cjson = require "cjson"

-- URL decode
function _M.url_decode(str)
    if not str then return "" end
    str = str:gsub("+", " ")
    str = str:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return str
end

-- HTML entity decode
function _M.html_decode(str)
    if not str then return "" end
    str = str:gsub("&amp;", "&")
    str = str:gsub("&lt;", "<")
    str = str:gsub("&gt;", ">")
    str = str:gsub("&quot;", '"')
    str = str:gsub("&#(%d+);", function(n)
        local val = tonumber(n)
        if val and val >= 0 and val <= 255 then
            return string.char(val)
        end
        return "&#" .. n .. ";"
    end)
    str = str:gsub("&#x(%x+);", function(h)
        local val = tonumber(h, 16)
        if val and val >= 0 and val <= 255 then
            return string.char(val)
        end
        return "&#x" .. h .. ";"
    end)
    return str
end

-- Unicode decode
function _M.unicode_decode(str)
    if not str then return "" end
    return str:gsub("\\u(%x%x%x%x)", function(h)
        local cp = tonumber(h, 16)
        if cp < 0x80 then
            return string.char(cp)
        elseif cp < 0x800 then
            return string.char(0xC0 + math.floor(cp / 64), 0x80 + (cp % 64))
        else
            return string.char(0xE0 + math.floor(cp / 4096), 0x80 + math.floor((cp % 4096) / 64), 0x80 + (cp % 64))
        end
    end)
end

-- Normalize request: multi-layer decode for WAF bypass detection
function _M.normalize(str)
    if not str then return "" end
    local result = str
    -- Round 1: URL decode
    result = _M.url_decode(result)
    -- Round 2: Unicode decode
    result = _M.unicode_decode(result)
    -- Round 3: HTML entity decode
    result = _M.html_decode(result)
    -- Round 4: URL decode again (double encoding)
    result = _M.url_decode(result)
    return result
end

-- Get client IP (trust X-Forwarded-For from upstream WAF only)
local trusted_proxies = {
    ["127.0.0.1"] = true,
    ["10.0.0.0/8"] = true,
    ["172.16.0.0/12"] = true,
    ["192.168.0.0/16"] = true,
}

-- Validate IPv4 address format (each octet 0-255)
local function is_valid_ipv4(ip)
    if type(ip) ~= "string" then return false end
    local parts = { ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
    if #parts ~= 4 then return false end
    for _, part in ipairs(parts) do
        local n = tonumber(part)
        if not n or n < 0 or n > 255 then return false end
    end
    return true
end

-- Validate IPv6 address format (basic check: hex and colons, ≤8 segments)
local function is_valid_ipv6(ip)
    if type(ip) ~= "string" then return false end
    -- Strip zone ID if present (e.g., fe80::1%eth0)
    ip = ip:match("^([^%%]+)") or ip
    if not ip:find(":") then return false end
    -- Must only contain hex digits, colons, and optional dots (for IPv4-mapped)
    if not ip:match("^[%x:]+$") and not ip:match("^[%x:%.]+$") then return false end
    -- Count segments (expand :: as one segment)
    local expanded = ip:gsub("::", function() return ":!" end)
    local segments = 0
    for seg in expanded:gmatch("[^:]+") do
        segments = segments + 1
        if seg ~= "!" and #seg > 4 then return false end
    end
    return segments <= 8
end

-- Check if string is a valid IP address (IPv4 or IPv6)
local function is_valid_ip(ip)
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)
end

local function is_trusted_ip(ip)
    for proxy, _ in pairs(trusted_proxies) do
        if proxy:find("/") then
            if _M.ip_in_cidr(ip, proxy) then
                return true
            end
        else
            if ip == proxy then
                return true
            end
        end
    end
    return false
end

function _M.get_client_ip()
    local ip = ngx.var.remote_addr
    local trusted = is_trusted_ip(ip)
    if not trusted then
        return ip
    end
    local xff = ngx.req.get_headers()["X-Forwarded-For"]
    if xff then
        local entries = {}
        for entry in xff:gmatch("[^,]+") do
            local trimmed = entry:match("^%s*(.-)%s*$")
            if trimmed and trimmed ~= "" then
                entries[#entries + 1] = trimmed
            end
        end
        for i = #entries, 1, -1 do
            local entry = entries[i]
            if is_valid_ip(entry) and not is_trusted_ip(entry) then
                return entry
            end
        end
        if #entries > 0 and is_valid_ip(entries[1]) then
            return entries[1]
        end
    end
    return ip
end

-- Check if IP is in CIDR range
function _M.ip_in_cidr(ip, cidr)
    local base, mask = cidr:match("^(.+)/(%d+)$")
    if not base then
        return ip == cidr
    end
    mask = tonumber(mask)

    local function ip_to_int(address)
        local o1, o2, o3, o4 = address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not o1 then return nil end
        return tonumber(o1) * 16777216
             + tonumber(o2) * 65536
             + tonumber(o3) * 256
             + tonumber(o4)
    end

    local ip_int = ip_to_int(ip)
    local base_int = ip_to_int(base)
    if not ip_int or not base_int then return false end

    local mask_int = 0
    if mask > 0 then
        mask_int = bit.lshift(0xFFFFFFFF, 32 - mask)
    end

    return bit.band(ip_int, mask_int) == bit.band(base_int, mask_int)
end

-- JSON response helper
function _M.json_response(code, data)
    ngx.status = code
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.say(cjson.encode(data))
    ngx.exit(code)
end

-- Parse YAML simple key-value (no nested structures needed for rules)
function _M.parse_simple_yaml(content)
    local result = {}
    local current_section = nil
    local current_list = nil

    for line in content:gmatch("[^\r\n]+") do
        -- Skip comments and empty lines
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and not trimmed:match("^#") then
            -- Check indentation level
            local indent = #line - #line:match("^%s*")

            if indent == 0 then
                -- Top-level key
                local key, value = trimmed:match("^([%w_]+):%s*(.-)%s*$")
                if key then
                    if value == "" then
                        current_section = key
                        result[key] = {}
                        current_list = result[key]
                    else
                        result[key] = value
                        current_section = nil
                        current_list = nil
                    end
                end
            elseif indent > 0 and current_list then
                -- List item under current section
                local item = trimmed:match("^%- (.+)$")
                if item then
                    table.insert(current_list, item)
                end
            end
        end
    end

    return result
end

-- Detect HTTP Request Smuggling (CL/TE mismatch)
function _M.detect_smuggling()
    local headers = ngx.req.get_headers()
    local cl = headers["Content-Length"]
    local te = headers["Transfer-Encoding"]

    -- Normalize TE to string (ngx may return table for duplicate headers)
    local te_str
    if type(te) == "table" then
        -- Multiple TE headers = classic smuggling indicator
        return true, "te_multiple_headers"
    elseif te then
        te_str = tostring(te)
    end

    if te_str then
        local te_lower = te_str:lower():match("^%s*(.-)%s*$")

        -- Check for obfuscated chunked: mixed case, extra spaces, parameters
        -- Normalize: lowercase, strip spaces around commas
        local te_normalized = te_lower:gsub("%s*,%s*", ","):gsub("%s*;.*$", "")

        -- Detect chunked anywhere in the TE value (including "chunked, identity")
        local has_chunked = te_normalized:find("chunked", 1, true) ~= nil

        -- Multiple comma-separated values with chunked is suspicious
        if has_chunked and te_normalized:find(",", 1, true) then
            return true, "te_multiple_values"
        end

        -- CL + TE combination = classic smuggling
        if cl and has_chunked then
            return true, "cl_te_mismatch"
        end

        -- TE present with obfuscated chunked variant (e.g., x-chunked is NOT chunked,
        -- but "chunked" with leading/trailing junk IS suspicious)
        if has_chunked then
            -- Verify it's a clean "chunked" token (not part of another word)
            -- After normalization, "chunked" should be the entire value or followed by comma
            if te_normalized ~= "chunked" and not te_normalized:match("^chunked,") then
                return true, "te_obfuscated_chunked"
            end
        end
    end

    return false, nil
end

return _M
