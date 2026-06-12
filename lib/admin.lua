-- lib/admin.lua
-- Admin REST API router + authentication + browser page serving
local _M = {}

local ngx = ngx
local cjson = require("cjson")
local logger = require("lib.logger")

-- Sub-modules
local admin_nginx = require("lib.admin.nginx")
local admin_rules = require("lib.admin.rules")
local admin_dashboard = require("lib.admin.dashboard")
local admin_logs = require("lib.admin.logs")
local admin_html = require("lib.admin.html")

-- Configurable admin path prefix (from env var, default /admin/)
local ADMIN_PATH = os.getenv("WAF_ADMIN_PATH") or "/admin/"
if ADMIN_PATH:sub(-1) ~= "/" then ADMIN_PATH = ADMIN_PATH .. "/" end
local PATH_DASHBOARD = ADMIN_PATH .. "dashboard"
local PATH_DASHBOARD_SLASH = ADMIN_PATH .. "dashboard/"

-- HTML templates (loaded from admin/html.lua)
local LOGIN_HTML = admin_html.LOGIN_HTML
local DASHBOARD_HTML = admin_html.DASHBOARD_HTML

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

---------------------------------------------------------------------------
-- Authentication
---------------------------------------------------------------------------

local function constant_time_compare(a, b)
    if #a ~= #b then return false end
    local result = 0
    for i = 1, #a do
        result = bit.bor(result, bit.bxor(a:byte(i), b:byte(i)))
    end
    return result == 0
end

local function authenticate_with_header(auth_header)
    if ngx.shared.waf_state and not ngx.shared.waf_state:get("admin_token_valid") then
        error_response(503, "Admin API disabled: token not configured")
        return false
    end

    local client_ip = ngx.var.remote_addr
    local dict = ngx.shared.session_track
    local AUTH_FAIL_TTL = 60

    if dict then
        local fail_count, _ = dict:get("admin_auth_fail:" .. client_ip)
        if fail_count and fail_count >= 5 then
            ngx.status = 429
            ngx.header["Content-Type"] = "application/json; charset=utf-8"
            ngx.header["Retry-After"] = "60"
            ngx.say(cjson.encode({ error = true, message = "Too many failed attempts" }))
            return false
        end
    end

    local token = ""
    if auth_header then
        token = auth_header:match("^Bearer%s+(.+)$") or ""
    end

    local expected = ""
    if ngx.shared.waf_state then
        expected = ngx.shared.waf_state:get("waf_admin_token") or ""
    end

    if expected == "" or not constant_time_compare(token, expected) then
        if dict then
            dict:incr("admin_auth_fail:" .. client_ip, 1, 0, AUTH_FAIL_TTL)
        end
        error_response(401, "Unauthorized")
        return false
    end

    if dict then
        dict:delete("admin_auth_fail:" .. client_ip)
    end

    return true
end

---------------------------------------------------------------------------
-- Route dispatch
---------------------------------------------------------------------------

function _M.handle()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri
    local accept = ngx.var.http_accept or ""
    local is_browser = method == "GET" and accept:find("text/html", 1, true) ~= nil

    local token_valid = true
    if ngx.shared.waf_state and not ngx.shared.waf_state:get("admin_token_valid") then
        token_valid = false
    end

    -- Browser requests: serve HTML pages
    if is_browser then
        local cookie = ngx.var.http_cookie or ""
        local token_from_cookie = cookie:match("waf_token=([^;]+)")
        local cookie_authed = false
        if token_from_cookie then
            local expected = ngx.shared.waf_state:get("waf_admin_token") or ""
            if expected ~= "" and constant_time_compare(token_from_cookie, expected) then
                cookie_authed = true
            end
        end

        if uri == ADMIN_PATH or uri == ADMIN_PATH:sub(1, -2) then
            if not token_valid then
                ngx.header["Content-Type"] = "text/html; charset=utf-8"
                ngx.status = 503
                ngx.say([=[<!DOCTYPE html><html><head><meta charset="utf-8"><title>Moat WAF</title></head><body style="background:#0f172a;color:#fca5a5;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><h1>WAF 管理面板未配置</h1><p>请设置 WAF_ADMIN_TOKEN 环境变量（至少32字符）</p></div></body></html>]=])
                return ngx.exit(503)
            end
            if cookie_authed then
                ngx.header["Content-Type"] = "text/html; charset=utf-8"
                ngx.say(DASHBOARD_HTML)
                return ngx.exit(ngx.HTTP_OK)
            end
            ngx.header["Content-Type"] = "text/html; charset=utf-8"
            ngx.say(LOGIN_HTML)
            return ngx.exit(ngx.HTTP_OK)
        end

        if uri == PATH_DASHBOARD or uri == PATH_DASHBOARD_SLASH then
            if not cookie_authed then return ngx.redirect(ADMIN_PATH) end
            ngx.header["Content-Type"] = "text/html; charset=utf-8"
            ngx.say(DASHBOARD_HTML)
            return ngx.exit(ngx.HTTP_OK)
        end

        if not cookie_authed then return ngx.redirect(ADMIN_PATH) end
    end

    -- Challenge verify endpoint (no auth required — it IS the auth gate)
    local sub_uri = uri:match("^" .. ADMIN_PATH .. "(.+)$") or uri
    if sub_uri == "challenge/verify" and method == "POST" then
        local challenge = require("lib.admin.challenge")
        return challenge.handle_verify()
    end

    -- API auth
    local auth_header = ngx.var.http_authorization or ""
    if auth_header == "" then
        local cookie = ngx.var.http_cookie or ""
        local token_from_cookie = cookie:match("waf_token=([^;]+)")
        if token_from_cookie then auth_header = "Bearer " .. token_from_cookie end
    end
    if not authenticate_with_header(auth_header) then return end

    -- Audit log
    local safe_uri = uri:gsub("[\r\n]", " "):gsub("[%z\x01-\x1f\x7f]", ""):sub(1, 200)
    logger.audit({ action = "admin", detail = method .. " " .. safe_uri, admin_ip = ngx.var.remote_addr })

    -- Sub-module delegation
    local sub_uri = uri:match("^" .. ADMIN_PATH .. "(.+)$") or uri
    if admin_dashboard.handle(method, sub_uri) then return end
    if admin_logs.handle(method, sub_uri) then return end
    if admin_rules.handle(method, sub_uri) then return end
    if admin_nginx.handle(method, sub_uri) then return end

    -- Unknown route
    error_response(404, "Not Found")
end

return _M
