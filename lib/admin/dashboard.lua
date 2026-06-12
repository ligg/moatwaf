-- lib/admin/dashboard.lua
-- Dashboard, stats, mode, and CC config handlers
local _M = {}

local ngx = ngx
local cjson = require("cjson")
local logger = require("lib.logger")
local cc_protect = require("lib.cc_protect")

local VERSION = "1.0.0"

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
-- Handlers
---------------------------------------------------------------------------

-- GET /admin/status
local function handle_status()
    json_response(200, {
        status = "ok",
        version = VERSION,
        uptime = ngx.now(),
        modules = {
            rule_engine = true,
            cc_protect = true,
            logger = true,
        }
    })
end

-- GET /admin/stats
local function handle_stats()
    local stats = logger.get_stats()
    json_response(200, stats)
end

-- GET /admin/mode
local function handle_mode_get()
    local mode = ngx.shared.waf_state:get("waf_mode") or "block"
    json_response(200, { mode = mode })
end

-- POST /admin/mode
local function handle_mode_post()
    local body = read_json_body()
    if not body then
        error_response(400, "Invalid or empty JSON body")
        return
    end

    local mode = body.mode
    if mode ~= "block" and mode ~= "log_only" then
        error_response(400, "mode must be 'block' or 'log_only'")
        return
    end

    local old_mode = ngx.shared.waf_state:get("waf_mode") or "block"
    ngx.shared.waf_state:set("waf_mode", mode)

    ngx.log(ngx.WARN, "[WAF ADMIN] Mode changed from ", old_mode, " to ", mode,
        " by ", ngx.var.remote_addr)

    json_response(200, { ok = true, mode = mode, previous = old_mode })
end

-- GET /admin/cc/config
local function handle_cc_config_get()
    local dict = ngx.shared.session_track
    local config = {}
    for key, default in pairs(cc_protect.DEFAULTS) do
        local val = default
        if dict then
            local stored = dict:get("cc_config:" .. key)
            if stored ~= nil then
                val = stored
            end
        end
        config[key] = val
    end
    json_response(200, config)
end

-- POST /admin/cc/config
local function handle_cc_config_post()
    local body = read_json_body()
    if not body then
        error_response(400, "Invalid or empty JSON body")
        return
    end

    local valid_keys = {}
    for k, _ in pairs(cc_protect.DEFAULTS) do
        valid_keys[k] = true
    end

    local max_values = {
        ip_qps_limit = 10000,
        ip_conn_limit = 1000,
        global_qps_limit = 100000,
        window_size = 3600,
    }

    -- Boolean config keys (no numeric validation)
    local bool_keys = { challenge_enabled = true, use_sliding_window = true }

    for key, value in pairs(body) do
        if not valid_keys[key] then
            error_response(400, "Unknown config key: " .. key)
            return
        end
        if not bool_keys[key] then
            if type(value) ~= "number" or value <= 0 then
                error_response(400, "Config value for '" .. key .. "' must be a positive number")
                return
            end
            local max = max_values[key]
            if max and value > max then
                error_response(400, "Config value for '" .. key .. "' exceeds maximum (" .. max .. ")")
                return
            end
        end
    end

    local dict = ngx.shared.session_track
    if not dict then
        error_response(500, "session_track shared dict not available")
        return
    end

    for key, value in pairs(body) do
        dict:set("cc_config:" .. key, value, 0)
    end

    local config = {}
    for k, default in pairs(cc_protect.DEFAULTS) do
        local stored = dict:get("cc_config:" .. k)
        config[k] = (stored ~= nil) and stored or default
    end

    json_response(200, { status = "ok", message = "CC config updated", config = config })
end

---------------------------------------------------------------------------
-- Route dispatch
---------------------------------------------------------------------------

function _M.handle(method, sub_uri)
    if method == "GET" then
        if sub_uri == "status" then
            handle_status()
            return true
        elseif sub_uri == "stats" then
            handle_stats()
            return true
        elseif sub_uri == "mode" then
            handle_mode_get()
            return true
        elseif sub_uri == "cc/config" then
            handle_cc_config_get()
            return true
        elseif sub_uri == "stats/trend" then
            local args = ngx.req.get_uri_args()
            json_response(200, logger.get_trend_data(args.range or "24h"))
            return true
        elseif sub_uri == "stats/top-ip" then
            local args = ngx.req.get_uri_args()
            json_response(200, { items = logger.get_top_ips(tonumber(args.limit) or 10) })
            return true
        elseif sub_uri == "stats/categories" then
            json_response(200, { categories = logger.get_categories() })
            return true
        end
    elseif method == "POST" then
        if sub_uri == "mode" then
            handle_mode_post()
            return true
        elseif sub_uri == "cc/config" then
            handle_cc_config_post()
            return true
        end
    end
    return false
end

return _M
