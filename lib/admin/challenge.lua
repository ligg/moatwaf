-- lib/admin/challenge.lua
-- JS Challenge page for CC protection
local _M = {}
local ngx = ngx
local cjson = require("cjson")
local utils = require("lib.utils")

local CHALLENGE_SECRET = os.getenv("WAF_CHALLENGE_SECRET") or "moat-challenge-secret-2026"
local CHALLENGE_TTL = 1800  -- 30 minutes
local CHALLENGE_MAX_AGE = 300  -- challenge question expires after 5 minutes

local function set_cors_headers()
    local origin = ngx.var.http_origin
    if origin and origin ~= "" then
        ngx.header["Access-Control-Allow-Origin"] = origin
        ngx.header["Vary"] = "Origin"
    else
        ngx.header["Access-Control-Allow-Origin"] = "*"
    end
    ngx.header["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    ngx.header["Access-Control-Allow-Headers"] = "Content-Type"
end

local function secure_compare(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local diff = 0
    if bit and bit.bxor then
        for i = 1, #a do
            diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
        end
    else
        for i = 1, #a do
            if a:byte(i) ~= b:byte(i) then diff = 1 end
        end
    end
    return diff == 0
end

local function sanitize_redirect(redirect_url)
    local redirect = tostring(redirect_url or "/")
    redirect = redirect:gsub("[\r\n%z]", "")
    if redirect == "" or not redirect:match("^/") then
        redirect = "/"
    end
    return redirect
end

local function make_challenge_cookie(ip, expiry)
    local signature = ngx.md5(ip .. ":" .. expiry .. ":" .. CHALLENGE_SECRET)
    return tostring(expiry) .. "." .. signature
end

function _M.generate_challenge(redirect_url)
    set_cors_headers()

    local admin_html = require("lib.admin.html")
    local a = math.random(1, 50)
    local b = math.random(1, 50)
    local ip = utils.get_client_ip() or ngx.var.remote_addr or "unknown"
    local ts = ngx.time()
    local token = ngx.md5(a .. ":" .. b .. ":" .. ip .. ":" .. ts .. ":" .. CHALLENGE_SECRET)

    local challenge_data = cjson.encode({
        a = a, b = b, ts = ts, token = token, redirect = sanitize_redirect(redirect_url)
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
    set_cors_headers()

    local ok = pcall(ngx.req.read_body)
    local body = nil
    if ok then
        local ok2, v = pcall(ngx.req.get_body_data)
        if ok2 then body = v end
    end
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

    local a = tonumber(data.a)
    local b = tonumber(data.b)
    local ts = tonumber(data.ts)
    local token = data.token
    local answer = tonumber(data.answer)

    if not a or not b or not ts or not token or not answer then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ ok = false, error = "Invalid challenge payload" }))
        return ngx.exit(400)
    end

    if math.abs(ngx.time() - ts) > CHALLENGE_MAX_AGE then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ ok = false, error = "Challenge expired" }))
        return ngx.exit(400)
    end

    if answer ~= a + b then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ ok = false, error = "Incorrect answer" }))
        return ngx.exit(400)
    end

    local client_ip = utils.get_client_ip() or ngx.var.remote_addr or "unknown"
    local expected_token = ngx.md5(a .. ":" .. b .. ":" .. client_ip .. ":" .. ts .. ":" .. CHALLENGE_SECRET)
    if not secure_compare(token, expected_token) then
        ngx.status = 400
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({ ok = false, error = "Invalid challenge token" }))
        return ngx.exit(400)
    end

    local expiry = ngx.time() + CHALLENGE_TTL
    local cookie_value = make_challenge_cookie(client_ip, expiry)
    ngx.header["Set-Cookie"] = "waf_challenge_pass=" .. cookie_value
        .. "; Path=/; Max-Age=" .. CHALLENGE_TTL .. "; HttpOnly; SameSite=Strict"

    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({ ok = true, redirect = sanitize_redirect(data.redirect) }))
    return ngx.exit(200)
end

function _M.has_valid_challenge()
    local cookie = ngx.var.http_cookie or ""
    local challenge_pass = cookie:match("waf_challenge_pass=([^;]+)")
    if not challenge_pass or challenge_pass == "" then
        return false
    end

    local expiry, signature = challenge_pass:match("^(%d+)%.(.+)$")
    if not expiry or not signature then
        return false
    end

    expiry = tonumber(expiry)
    if not expiry or expiry <= ngx.time() then
        return false
    end

    local client_ip = utils.get_client_ip() or ngx.var.remote_addr or "unknown"
    local expected = ngx.md5(client_ip .. ":" .. expiry .. ":" .. CHALLENGE_SECRET)
    return secure_compare(signature, expected)
end

return _M
