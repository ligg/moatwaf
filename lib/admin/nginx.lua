-- lib/admin/nginx.lua
-- Nginx configuration management handlers
local _M = {}

local ngx = ngx
local cjson = require("cjson")

---------------------------------------------------------------------------
-- Constants
---------------------------------------------------------------------------

local NGINX_CONF_PATH = "/opt/moat/conf/nginx.conf"
local NGINX_CONF_BAK = "/opt/moat/conf/nginx.conf.bak"
local NGINX_MAX_SIZE = 512 * 1024  -- 512KB max config size

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
-- Request body parsing
---------------------------------------------------------------------------

local function read_json_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" then return nil end
    local ok, data = pcall(cjson.decode, body)
    if not ok then return nil end
    return data
end

---------------------------------------------------------------------------
-- File helpers
---------------------------------------------------------------------------

local function read_file(path)
    local f, err = io.open(path, "r")
    if not f then return nil, err end
    local content = f:read("*a")
    f:close()
    return content
end

local function write_file(path, content)
    local f, err = io.open(path, "w")
    if not f then return nil, err end
    f:write(content)
    f:close()
    return true
end

---------------------------------------------------------------------------
-- Nginx config test helper
---------------------------------------------------------------------------

local function run_nginx_test()
    local conf = read_file(NGINX_CONF_PATH)
    if not conf then return false, "Cannot read nginx.conf" end

    -- Rewrite to a temp config with safe paths so nginx -t doesn't need write access to logs/
    local test_conf = conf
    test_conf = test_conf:gsub("error_log%s+[^;\n]+;", "error_log /dev/null emerg;")
    test_conf = test_conf:gsub("pid%s+[^;\n]+;", "pid /tmp/nginx-test.pid;")
    test_conf = test_conf:gsub("access_log%s+[^;\n]+;", "access_log off;")
    test_conf = test_conf:gsub("include%s+mime%.types;", "include /opt/moat/conf/mime.types;")

    local ok, err = write_file("/tmp/nginx-test.conf", test_conf)
    if not ok then return false, "Cannot write test config: " .. (err or "") end

    local handle = io.popen("/usr/local/openresty/bin/openresty -t -c /tmp/nginx-test.conf -p /opt/moat/ 2>&1")
    if not handle then
        os.remove("/tmp/nginx-test.conf")
        return false, "Failed to run nginx -t"
    end
    local output = handle:read("*a")
    handle:close()
    os.remove("/tmp/nginx-test.conf")
    return output:find("syntax is ok") ~= nil, output
end

---------------------------------------------------------------------------
-- Handlers
---------------------------------------------------------------------------

-- GET /admin/nginx/config
local function handle_nginx_config_get()
    local content, err = read_file(NGINX_CONF_PATH)
    if not content then
        error_response(500, "Failed to read nginx.conf: " .. (err or "unknown"))
        return
    end
    json_response(200, { content = content })
end

-- PUT /admin/nginx/config
local function handle_nginx_config_put()
    local body = read_json_body()
    if not body or not body.content then
        error_response(400, "Missing 'content' field")
        return
    end

    local content = body.content
    if #content > NGINX_MAX_SIZE then
        error_response(400, "Config too large (max " .. (NGINX_MAX_SIZE / 1024) .. "KB)")
        return
    end
    if #content == 0 then
        error_response(400, "Config content cannot be empty")
        return
    end

    -- Backup current config
    local current = read_file(NGINX_CONF_PATH)
    if current then
        write_file(NGINX_CONF_BAK, current)
    end

    local ok, err = write_file(NGINX_CONF_PATH, content)
    if not ok then
        error_response(500, "Failed to write nginx.conf: " .. (err or "unknown"))
        return
    end

    json_response(200, { status = "ok", message = "Config saved (backup: nginx.conf.bak)" })
end

-- POST /admin/nginx/test
local function handle_nginx_test()
    local ok, output = run_nginx_test()
    json_response(200, { ok = ok, output = output })
end

-- POST /admin/nginx/reload
local function handle_nginx_reload()
    -- Test first
    local test_ok, test_output = run_nginx_test()
    if not test_ok then
        json_response(200, { ok = false, output = "Config test failed:\n" .. test_output })
        return
    end

    -- Write trigger file for entrypoint watcher
    local trigger = "/tmp/.nginx-reload"
    local result_file = "/tmp/.nginx-reload-result"
    local f, err = io.open(trigger, "w")
    if not f then
        error_response(500, "Failed to write reload trigger: " .. (err or "unknown"))
        return
    end
    f:write("reload")
    f:close()

    -- Wait up to 3 seconds for watcher to process
    local ok, output = false, "Reload triggered"
    for _ = 1, 6 do
        ngx.sleep(0.5)
        local rf = io.open(result_file, "r")
        if rf then
            local content = rf:read("*a")
            rf:close()
            os.remove(result_file)
            ok = not content:find("%[emerg%]") and not content:find("%[alert%]")
            output = content ~= "" and content or "Reload signal sent"
            break
        end
        -- If trigger file was removed, reload was picked up
        local tf = io.open(trigger, "r")
        if not tf then
            -- Trigger was consumed, wait a bit more for result
            ngx.sleep(0.5)
            local rf2 = io.open(result_file, "r")
            if rf2 then
                local content = rf2:read("*a")
                rf2:close()
                os.remove(result_file)
                ok = not content:find("%[emerg%]") and not content:find("%[alert%]")
                output = content ~= "" and content or "Reload signal sent"
            else
                ok = true
                output = "Reload signal sent successfully"
            end
            break
        else
            tf:close()
        end
    end

    json_response(200, { ok = ok, output = output })
end

-- POST /admin/nginx/restore-backup
local function handle_nginx_restore_backup()
    local content, err = read_file(NGINX_CONF_BAK)
    if not content then
        error_response(400, "No backup file found")
        return
    end

    local ok, err2 = write_file(NGINX_CONF_PATH, content)
    if not ok then
        error_response(500, "Failed to restore: " .. (err2 or "unknown"))
        return
    end

    json_response(200, { status = "ok", message = "Backup restored to nginx.conf" })
end

---------------------------------------------------------------------------
-- Route dispatch
---------------------------------------------------------------------------

-- handle(method, sub_uri)
--   method  - HTTP method (GET, POST, PUT, DELETE)
--   sub_uri - URI suffix after ADMIN_PATH (e.g. "nginx/config")
-- Returns true if this module handled the request, false otherwise.
function _M.handle(method, sub_uri)
    if method == "GET" then
        if sub_uri == "nginx/config" then
            handle_nginx_config_get()
            return true
        end

    elseif method == "POST" then
        if sub_uri == "nginx/test" then
            handle_nginx_test()
            return true
        elseif sub_uri == "nginx/reload" then
            handle_nginx_reload()
            return true
        elseif sub_uri == "nginx/restore-backup" then
            handle_nginx_restore_backup()
            return true
        end

    elseif method == "PUT" then
        if sub_uri == "nginx/config" then
            handle_nginx_config_put()
            return true
        end
    end

    return false
end

return _M
