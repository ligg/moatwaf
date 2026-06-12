-- lib/admin/rules.lua
-- Rule management handlers
local _M = {}

local ngx = ngx
local cjson = require("cjson")
local rule_engine = require("lib.rule_engine")

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

-- GET /admin/rules/list
local function handle_rules_list()
    local files = rule_engine.list_rule_files()
    json_response(200, { files = files })
end

-- GET /admin/rules/custom
local function handle_custom_rules_get()
    local rules = rule_engine.get_rules_from_file("custom.yaml")
    json_response(200, { rules = rules })
end

-- POST /admin/rules/custom
local function handle_custom_rule_post()
    local body = read_json_body()
    if not body then
        error_response(400, "Invalid or empty JSON body")
        return
    end

    local ok, err = rule_engine.validate_rule(body)
    if not ok then
        error_response(400, err)
        return
    end

    ok, err = rule_engine.add_rule_to_custom(body)
    if not ok then
        error_response(400, err)
        return
    end

    json_response(200, { status = "ok", message = "Rule added", id = body.id })
end

-- PUT /admin/rules/custom/{id}
local function handle_custom_rule_put(sub_uri)
    local rule_id = sub_uri:match("^rules/custom/(.+)$")
    if not rule_id or rule_id == "" then
        error_response(400, "Missing rule ID")
        return
    end

    local body = read_json_body()
    if not body then
        error_response(400, "Invalid or empty JSON body")
        return
    end

    body.id = rule_id
    local ok, err = rule_engine.validate_rule(body)
    if not ok then
        error_response(400, err)
        return
    end

    ok, err = rule_engine.update_rule_in_custom(rule_id, body)
    if not ok then
        error_response(400, err)
        return
    end

    json_response(200, { status = "ok", message = "Rule updated", id = rule_id })
end

-- DELETE /admin/rules/custom/{id}
local function handle_custom_rule_delete(sub_uri)
    local rule_id = sub_uri:match("^rules/custom/(.+)$")
    if not rule_id or rule_id == "" then
        error_response(400, "Missing rule ID")
        return
    end

    local ok, err = rule_engine.delete_rule_from_custom(rule_id)
    if not ok then
        error_response(400, err)
        return
    end

    json_response(200, { status = "ok", message = "Rule deleted", id = rule_id })
end

-- POST /admin/rules/reload
local function handle_rules_reload()
    rule_engine.reload_rules()
    json_response(200, { status = "ok", message = "Rules reloaded" })
end

-- POST /admin/rules/restore-default
local function handle_rules_restore()
    local ok, err = rule_engine.restore_default()
    if not ok then
        error_response(500, err or "Failed to restore default rules")
        return
    end
    json_response(200, { status = "ok", message = "Default rules restored" })
end

---------------------------------------------------------------------------
-- Route dispatch
---------------------------------------------------------------------------

function _M.handle(method, sub_uri)
    if method == "GET" then
        if sub_uri == "rules/list" then
            handle_rules_list()
            return true
        elseif sub_uri == "rules/custom" then
            handle_custom_rules_get()
            return true
        end
    elseif method == "POST" then
        if sub_uri == "rules/reload" then
            handle_rules_reload()
            return true
        elseif sub_uri == "rules/custom" then
            handle_custom_rule_post()
            return true
        elseif sub_uri == "rules/restore-default" then
            handle_rules_restore()
            return true
        end
    elseif method == "PUT" then
        if sub_uri:match("^rules/custom/") then
            handle_custom_rule_put(sub_uri)
            return true
        end
    elseif method == "DELETE" then
        if sub_uri:match("^rules/custom/") then
            handle_custom_rule_delete(sub_uri)
            return true
        end
    end
    return false
end

return _M
