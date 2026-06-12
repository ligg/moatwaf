-- lib/admin/challenge.lua
-- JS Challenge page for CC protection
local _M = {}
local ngx = ngx
local cjson = require("cjson")

local CHALLENGE_SECRET = os.getenv("WAF_CHALLENGE_SECRET") or "moat-challenge-secret-2026"
local CHALLENGE_TTL = 1800  -- 30 minutes

function _M.generate_challenge(redirect_url)
    local admin_html = require("lib.admin.html")
    local a = math.random(1, 50)
    local b = math.random(1, 50)
    local ip = ngx.var.remote_addr or "unknown"
    local ts = ngx.time()
    local token = ngx.md5(a .. b .. ip .. ts .. CHALLENGE_SECRET)

    local challenge_data = cjson.encode({
        a = a, b = b, token = token, redirect = redirect_url or "/"
    })

    local admin_path = os.getenv("WAF_ADMIN_PATH") or "/admin/"
    if admin_path:sub(-1) ~= "/" then admin_path = admin_path .. "/" end

    local html = admin_html.CHALLENGE_HTML
    html = html:gsub("__CHALLENGE_DATA__", challenge_data)
    html = html:gsub("__SG_ADMIN__", admin_path)

    ngx.status = 200
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(html)
    return ngx.exit(200)
end

function _M.handle_verify()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ ok = false, error = "No body" }))
        return ngx.exit(400)
    end

    local ok, data = pcall(cjson.decode, body)
    if not ok or not data then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ ok = false, error = "Invalid JSON" }))
        return ngx.exit(400)
    end

    local cookie_value = ngx.md5(ngx.var.remote_addr .. ngx.time() .. CHALLENGE_SECRET)
    ngx.header["Set-Cookie"] = "waf_challenge_pass=" .. cookie_value
        .. "; Path=/; Max-Age=" .. CHALLENGE_TTL .. "; HttpOnly; SameSite=Strict"

    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ ok = true, redirect = data.redirect or "/" }))
    return ngx.exit(200)
end

function _M.has_valid_challenge()
    local cookie = ngx.var.http_cookie or ""
    local challenge_pass = cookie:match("waf_challenge_pass=([^;]+)")
    return challenge_pass ~= nil and challenge_pass ~= ""
end

return _M
