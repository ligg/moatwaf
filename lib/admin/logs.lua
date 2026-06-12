-- lib/admin/logs.lua
-- Log viewing and IP management handlers
local _M = {}

local ngx = ngx
local cjson = require("cjson")
local logger = require("lib.logger")

---------------------------------------------------------------------------
-- Response helpers
---------------------------------------------------------------------------

local function json_response(status, data)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.say(cjson.encode(data))
end

local function error_response(status, message)
    json_response(status, { error = true, message = message })
end

local function read_json_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" then return nil end
    local ok, data = pcall(cjson.decode, body)
    if not ok then return nil end
    return data
end

---------------------------------------------------------------------------
-- Helpers
---------------------------------------------------------------------------

local function is_valid_ipv4(ip)
    if type(ip) ~= "string" then return false end
    if not ip:match("^%d+%.%d+%.%d+%.%d+$") then return false end
    for octet in ip:gmatch("(%d+)") do
        local n = tonumber(octet)
        if n < 0 or n > 255 then return false end
    end
    return true
end

local function get_dict_entries(dict, max_count)
    max_count = max_count or 1000
    local entries = {}
    if not dict then return entries end
    local keys = dict:get_keys(max_count)
    if not keys then return entries end
    for _, k in ipairs(keys) do
        local key = (type(k) == "table") and k.key or k
        local value, _ = dict:get(key)
        if value then entries[key] = value end
    end
    return entries
end

local function parse_date_param(date_str)
    if not date_str or date_str == "" then return nil end
    local y, m, d = date_str:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)$")
    if not y then return nil end
    y, m, d = tonumber(y), tonumber(m), tonumber(d)
    if not y or not m or not d then return nil end
    return os.time({ year = y, month = m, day = d, hour = 0, min = 0, sec = 0 })
end

---------------------------------------------------------------------------
-- IP Blacklist handlers
---------------------------------------------------------------------------

local function handle_blacklist_get()
    local dict = ngx.shared.ip_blacklist
    local entries = {}
    if dict then
        local keys = dict:get_keys(1000)
        if keys then
            for _, k in ipairs(keys) do
                local key = (type(k) == "table") and k.key or k
                local value, _ = dict:get(key)
                if value then
                    local ttl = dict:ttl(key)
                    entries[key] = { value = value, ttl = ttl and math.floor(ttl) or 0 }
                end
            end
        end
    end
    json_response(200, { entries = entries })
end

local function handle_blacklist_post()
    local body = read_json_body()
    if not body then error_response(400, "Invalid or empty JSON body"); return end
    local ip = body.ip
    if not ip or not is_valid_ipv4(ip) then error_response(400, "Invalid IPv4 address"); return end
    local ttl = tonumber(body.ttl) or 0
    if ttl < 0 then error_response(400, "TTL must be 0 (permanent) or a positive number"); return end
    local dict = ngx.shared.ip_blacklist
    if not dict then error_response(500, "IP blacklist shared dict not available"); return end
    local value = body.value or "admin_added"
    local ok, err = dict:set(ip, value, ttl)
    if not ok then error_response(500, "Failed to add IP: " .. (err or "unknown")); return end
    json_response(200, { status = "ok", message = "IP added to blacklist", ip = ip, ttl = ttl })
end

local function handle_blacklist_delete(sub_uri)
    local ip = sub_uri:match("^ip/blacklist/(.+)$")
    if not ip or not is_valid_ipv4(ip) then error_response(400, "Invalid IPv4 address"); return end
    local dict = ngx.shared.ip_blacklist
    if not dict then error_response(500, "IP blacklist shared dict not available"); return end
    dict:delete(ip)
    json_response(200, { status = "ok", message = "IP removed from blacklist", ip = ip })
end

---------------------------------------------------------------------------
-- IP Whitelist handlers
---------------------------------------------------------------------------

local function handle_whitelist_get()
    local entries = get_dict_entries(ngx.shared.ip_whitelist)
    json_response(200, { entries = entries })
end

local function handle_whitelist_post()
    local body = read_json_body()
    if not body then error_response(400, "Invalid or empty JSON body"); return end
    local ip = body.ip
    if not ip or not is_valid_ipv4(ip) then error_response(400, "Invalid IPv4 address"); return end
    local dict = ngx.shared.ip_whitelist
    if not dict then error_response(500, "IP whitelist shared dict not available"); return end
    local value = body.value or "admin_added"
    local ok, err = dict:set(ip, value, 0)
    if not ok then error_response(500, "Failed to add IP: " .. (err or "unknown")); return end
    json_response(200, { status = "ok", message = "IP added to whitelist", ip = ip })
end

local function handle_whitelist_delete(sub_uri)
    local ip = sub_uri:match("^ip/whitelist/(.+)$")
    if not ip or not is_valid_ipv4(ip) then error_response(400, "Invalid IPv4 address"); return end
    local dict = ngx.shared.ip_whitelist
    if not dict then error_response(500, "IP whitelist shared dict not available"); return end
    dict:delete(ip)
    json_response(200, { status = "ok", message = "IP removed from whitelist", ip = ip })
end

---------------------------------------------------------------------------
-- Log viewing handlers
---------------------------------------------------------------------------

local function handle_logs_get()
    local args = ngx.req.get_uri_args()
    local page = tonumber(args.page) or 1
    local per_page = tonumber(args.per_page) or 20
    if per_page > 100 then per_page = 100 end

    local filters = {}
    if args.rule_id and args.rule_id ~= "" then filters.rule_id = args.rule_id end
    if args.severity and args.severity ~= "" then filters.severity = args.severity end
    if args.source_ip and args.source_ip ~= "" then filters.source_ip = args.source_ip end
    if args.start_time and args.start_time ~= "" then
        local ts = parse_date_param(args.start_time)
        if ts then filters.start_time = ts end
    end
    if args.end_time and args.end_time ~= "" then
        local ts = parse_date_param(args.end_time)
        if ts then filters.end_time = ts + 86400 end
    end

    local result = logger.get_all_logs(filters, page, per_page)
    json_response(200, result)
end

local function handle_log_detail_get(sub_uri)
    local id = tonumber(sub_uri:match("^logs/(%d+)$"))
    if not id then error_response(400, "Invalid log ID"); return end
    local log = logger.get_log_by_id(id)
    if not log then error_response(404, "Log entry not found"); return end
    json_response(200, log)
end

-- POST /admin/logs/ban-ip — one-click IP ban from log viewer
local function handle_ban_ip()
    local body = read_json_body()
    if not body or not body.ip then error_response(400, "Missing ip"); return end
    if not is_valid_ipv4(body.ip) then error_response(400, "Invalid IPv4"); return end
    local ttl = tonumber(body.ttl) or 0
    local dict = ngx.shared.ip_blacklist
    if not dict then error_response(500, "Blacklist not available"); return end
    local value = body.reason or "log_ban"
    local ok, err = dict:set(body.ip, value, ttl)
    if not ok then error_response(500, "Failed: " .. (err or "")); return end
    json_response(200, { status = "ok", message = "IP banned", ip = body.ip, ttl = ttl })
end

-- GET /admin/logs/stream — Server-Sent Events for real-time logs
local function handle_logs_stream()
    ngx.header["Content-Type"] = "text/event-stream"
    ngx.header["Cache-Control"] = "no-cache"
    ngx.header["X-Accel-Buffering"] = "no"
    ngx.flush(true)

    local last_id = 0
    local logs_dict = ngx.shared.waf_logs

    for _ = 1, 3600 do  -- max 1 hour
        local max_id = logs_dict and logs_dict:get("log_max_id") or 0
        if max_id > last_id then
            for id = last_id + 1, max_id do
                local json = logs_dict:get("log:" .. id)
                if json then
                    ngx.say("data: " .. json .. "\n\n")
                    ngx.flush(true)
                end
            end
            last_id = max_id
        end
        ngx.sleep(1)
    end
end

---------------------------------------------------------------------------
-- Route dispatch
---------------------------------------------------------------------------

function _M.handle(method, sub_uri)
    if method == "GET" then
        if sub_uri == "ip/blacklist" then handle_blacklist_get(); return true
        elseif sub_uri == "ip/whitelist" then handle_whitelist_get(); return true
        elseif sub_uri == "logs" then handle_logs_get(); return true
        elseif sub_uri == "logs/stream" then handle_logs_stream(); return true
        elseif sub_uri:match("^logs/%d+$") then handle_log_detail_get(sub_uri); return true
        end
    elseif method == "POST" then
        if sub_uri == "ip/blacklist" then handle_blacklist_post(); return true
        elseif sub_uri == "ip/whitelist" then handle_whitelist_post(); return true
        elseif sub_uri == "logs/ban-ip" then handle_ban_ip(); return true
        end
    elseif method == "DELETE" then
        if sub_uri:match("^ip/blacklist/") then handle_blacklist_delete(sub_uri); return true
        elseif sub_uri:match("^ip/whitelist/") then handle_whitelist_delete(sub_uri); return true
        end
    end
    return false
end

return _M
