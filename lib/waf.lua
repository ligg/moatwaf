-- lib/waf.lua
local _M = {}

local ngx = ngx
local init = require("lib.init")
local utils = init.load("utils")
local ip_control = init.load("ip_control")
local cc_protect = init.load("cc_protect")
local rule_engine = init.load("rule_engine")
local upload_check = init.load("upload_check")
local logger = init.load("logger")
local cjson = require("cjson")

-- Reject an upload with a 403. Used by access_phase().
-- Deliberately independent of waf_mode: upload limits always apply.
local function block_upload(rule_id, reason, message)
    ngx.ctx.action = "block"
    ngx.ctx.rule_id = rule_id
    ngx.ctx.reason = reason
    ngx.ctx.blocked = true

    local stats = ngx.shared.waf_stats
    if stats then
        stats:incr("blocked_total", 1, 0)
        stats:incr("blocked_upload", 1, 0)
    end

    ngx.status = 403
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.say(cjson.encode({
        error = "Forbidden",
        message = message,
        code = 403
    }))
    return ngx.exit(403)
end

-- Check whether a request host matches the allowed host list.
-- Entries support:
--   * exact name:        "www.example.com"  (matches only that host)
--   * base domain:       "example.com"      (matches example.com and *.example.com)
--   * explicit wildcard: "*.example.com"    (matches subdomains only)
-- Matching is case-insensitive.
local function host_allowed(request_host, allowed_hosts)
    if not request_host or request_host == "" then return false end
    if allowed_hosts[request_host] then return true end
    local lower_host = request_host:lower()
    for entry in pairs(allowed_hosts) do
        local domain = entry:gsub("^%*%.", ""):gsub("^%.", ""):lower()
        if domain ~= "" then
            if lower_host == domain then return true end
            if lower_host:sub(-#domain - 1) == "." .. domain then return true end
        end
    end
    return false
end


-- Per-request state uses ngx.ctx (safe across concurrent requests)

-- CC protection auto-blacklist duration (coupled with Retry-After header)
local BLACKLIST_DURATION = 300  -- 5 minutes

-- IP lists with TTL-based cache refresh.
-- Each nginx worker has its own Lua VM, so ip_lists is per-worker.
-- This is acceptable: IP list files change infrequently, and each worker
-- independently reloads on its own TTL cycle. No cross-worker lock needed.
local ip_lists = nil
local ip_lists_loaded_at = 0
local IP_LISTS_TTL = 60  -- refresh every 60 seconds

local function get_ip_lists()
    local now = ngx.time()
    if ip_lists and (now - ip_lists_loaded_at) <= IP_LISTS_TTL then
        return ip_lists
    end

    ip_lists = ip_control.load_lists()
    ip_lists_loaded_at = now
    return ip_lists
end

-- Rewrite phase: IP control
function _M.rewrite_phase()
    -- Host header validation
    local host = ngx.var.http_host
    if not host or host == "" then
        ngx.status = 400
        ngx.say('{"error":"Bad Request","message":"Missing Host header","code":400}')
        return ngx.exit(400)
    end

    -- Validate Host matches expected domains ($waf_allowed_hosts).
    -- Supports exact names, base domains ("example.com" also matches *.example.com)
    -- and explicit wildcards. The parsed list is cached per worker, keyed by the
    -- configured string so different server blocks can use different allowlists.
    local hosts_str = ngx.var.waf_allowed_hosts or ""
    local cache_key = "hosts:" .. hosts_str
    local cache = _M._allowed_hosts_cache or {}
    local allowed_hosts = cache[cache_key]
    if not allowed_hosts then
        allowed_hosts = {}
        if hosts_str ~= "" then
            for h in hosts_str:gmatch("[^,]+") do
                local e = h:match("^%s*(.-)%s*$")
                if e ~= "" then
                    allowed_hosts[e:lower()] = true
                end
            end
        else
            -- Fallback defaults (configure waf_allowed_hosts in production)
            allowed_hosts = {
                ["your-domain.com"] = true,
                ["www.your-domain.com"] = true,
                ["admin.your-domain.com"] = true,
            }
        end
        cache[cache_key] = allowed_hosts
        _M._allowed_hosts_cache = cache
    end
    local request_host = host:match("^%[.-%]") or host:match("^([^:]+)")
    if request_host and not host_allowed(request_host, allowed_hosts) then
        ngx.status = 403
        ngx.say('{"error":"Forbidden","message":"Invalid Host header","code":403}')
        return ngx.exit(403)
    end

    -- HTTP Smuggling detection
    local smuggling, smuggling_type = utils.detect_smuggling()
    if smuggling then
        ngx.status = 400
        ngx.say('{"error":"Bad Request","message":"HTTP Request Smuggling detected","code":400}')
        return ngx.exit(400)
    end

    local ip = utils.get_client_ip()
    if not ip then
        ip = ngx.var.remote_addr
    end
    if not ip then
        ngx.status = 403
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.say(cjson.encode({error = "Forbidden", message = "Cannot determine client IP", code = 403}))
        return ngx.exit(403)
    end

    ngx.ctx.client_ip = ip
    ngx.ctx.action = "pass"
    ngx.ctx.rule_id = nil
    ngx.ctx.reason = nil
    ngx.ctx.blocked = false

    local lists = get_ip_lists()

    -- Check IP whitelist/blacklist
    local action, reason = ip_control.check(ip, lists)
    if action == "block" then
        ngx.ctx.action = "block"
        ngx.ctx.rule_id = "IP-001"
        ngx.ctx.reason = reason
        ngx.ctx.blocked = true

        -- Record stats
        local stats = ngx.shared.waf_stats
        if stats then
            stats:incr("blocked_total", 1, 0)
            stats:incr("blocked_ip", 1, 0)
        end

        ngx.status = 403
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.say(cjson.encode({
            error = "Forbidden",
            message = "Your IP has been blocked",
            code = 403
        }))
        return ngx.exit(403)
    end

    -- Track connection for CC protection (skip whitelisted IPs)
    -- Mark conn_tracked so log_phase knows to call track_conn_end
    if action == "pass" and reason == "whitelisted" then
        ngx.ctx.conn_tracked = false
    else
        cc_protect.track_conn_start(ip)
        ngx.ctx.conn_tracked = true
    end
end

-- Access phase: CC protection + rule engine
function _M.access_phase()
    local ip = ngx.ctx.client_ip
    local method = ngx.req.get_method()
    local uri = ngx.var.uri

    -- Read request body so rule engine can inspect POST/PUT body content
    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.req.read_body()
    end

    -- CC protection check
    local action, reason = cc_protect.check(ip, method, uri)
    if action == "challenge" then
        local challenge = require("lib.admin.challenge")
        if not challenge.has_valid_challenge() then
            return challenge.generate_challenge(ngx.var.request_uri)
        end
        -- Has valid challenge cookie, allow through
    elseif action == "block" then
        ngx.ctx.action = "block"
        ngx.ctx.rule_id = "CC-001"
        ngx.ctx.reason = reason
        ngx.ctx.blocked = true

        -- Auto-blacklist IPs with excessive hits
        if reason == "rate_exceeded" then
            ip_control.blacklist_ip(ip, BLACKLIST_DURATION)
        end

        local stats = ngx.shared.waf_stats
        if stats then
            stats:incr("blocked_total", 1, 0)
            stats:incr("blocked_cc", 1, 0)
        end

        ngx.status = 429
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.header["Retry-After"] = tostring(BLACKLIST_DURATION)
        ngx.say(cjson.encode({
            error = "Too Many Requests",
            message = "Rate limit exceeded",
            code = 429
        }))
        return ngx.exit(429)
    end

    -- Rule engine check
    local rule_action, rule_id, severity, description = rule_engine.check()
    if rule_action ~= "pass" then
        ngx.ctx.action = rule_action
        ngx.ctx.rule_id = rule_id
        ngx.ctx.reason = description

        -- Record stats by rule category (always, regardless of mode)
        local stats = ngx.shared.waf_stats
        if stats then
            stats:incr("blocked_total", 1, 0)
            if rule_id and rule_id:sub(1, 4) == "SQLI" then
                stats:incr("blocked_sqli", 1, 0)
            elseif rule_id and rule_id:sub(1, 3) == "XSS" then
                stats:incr("blocked_xss", 1, 0)
            elseif rule_id and rule_id:sub(1, 4) == "CMDI" then
                stats:incr("blocked_cmdi", 1, 0)
            else
                stats:incr("blocked_other", 1, 0)
            end
        end

        -- Check WAF mode: "block" (default) or "log_only"
        local waf_mode = ngx.shared.waf_state:get("waf_mode") or "block"
        if waf_mode == "log_only" then
            -- Log-only mode: record but allow request through
            ngx.ctx.blocked = false
            ngx.log(ngx.WARN, "[WAF LOG-ONLY] rule=", rule_id,
                " severity=", severity, " src=", ngx.var.remote_addr,
                " uri=", ngx.var.request_uri)
        else
            -- Block mode: reject the request
            ngx.ctx.blocked = true
            ngx.status = 403
            ngx.header["Content-Type"] = "application/json; charset=utf-8"
            -- Do NOT expose rule_id to clients — it enables targeted rule evasion
            ngx.say(cjson.encode({
                error = "Forbidden",
                message = "Request blocked by WAF",
                code = 403
            }))
            return ngx.exit(403)
        end
    end

    -- Upload detection (in access_phase, before proxy_pass)
    -- Note: ngx.req.get_headers() lowercases header names.
    local req_headers = ngx.req.get_headers()
    local content_type = req_headers["content-type"] or req_headers["Content-Type"] or ""
    if content_type:find("multipart/form-data", 1, true) then
        -- Explicitly read request body so data is available for inspection
        ngx.req.read_body()

        local body_prefix = upload_check.read_body_prefix(8)
        local body_size = upload_check.get_body_size()

        -- Hard limit: reject bodies above WAF_MAX_UPLOAD_SIZE without reading
        -- the whole body into memory. Intentionally independent of waf_mode.
        if body_size and body_size > upload_check.get_max_upload_size() then
            return block_upload(
                "UPLOAD-002",
                "UPLOAD-002: File size exceeds limit",
                "File size exceeds upload limit"
            )
        end

        -- Extract filename from the first multipart part (inside the body).
        -- Falls back to a top-level Content-Disposition header if present.
        local filename = upload_check.get_multipart_filename()
        if not filename then
            local disposition = req_headers["content-disposition"] or req_headers["Content-Disposition"]
            if disposition then
                filename = disposition:match('filename="?([^";]+)"?')
            end
        end
        if not filename then
            filename = "unknown"
        end

        local result
        if body_size and body_size > upload_check.get_scan_limit() then
            -- Large upload: light check only (extension + magic-number prefix),
            -- skip reading the full body / full-content shell-code scan.
            result = upload_check.check_light(filename, content_type, body_prefix)
        else
            local full_body, full_body_err = upload_check.read_full_body()
            if full_body_err == "file_too_large" then
                return block_upload(
                    "UPLOAD-002",
                    "UPLOAD-002: File size exceeds limit",
                    "File size exceeds upload limit"
                )
            end
            if full_body then
                result = upload_check.check(filename, content_type, body_prefix, full_body)
            end
        end

        if result and not result.allowed then
            return block_upload(
                result.reason and result.reason:match("(UPLOAD%-%d+)") or "UPLOAD-001",
                result.reason,
                result.reason or "File upload blocked by WAF"
            )
        end
    end

    -- Record stats
    local stats = ngx.shared.waf_stats
    if stats then
        stats:incr("passed_total", 1, 0)
    end
end

-- Body filter phase: no-op (upload detection moved to access_phase)
function _M.body_filter_phase()
    -- Upload detection now runs in access_phase before proxy_pass.
    -- INVARIANT: Do NOT modify the response body here. nginx has already
    -- begun sending it to the client; any changes cause corruption or
    -- duplicate content. This phase is read-only for inspection/logging.
end

-- Log phase: record request details
function _M.log_phase()
    local ip = ngx.ctx.client_ip

    -- Decrement connection count only if we tracked the start
    if ngx.ctx.conn_tracked then
        cc_protect.track_conn_end(ip)
    end

    -- If blocked, log the event via ngx.log (non-blocking, writes to error log)
    -- Audit log parsing: filter with "grep WAF_AUDIT logs/error.log"
    -- Set nginx vars for logging
    ngx.var.waf_action = ngx.ctx.action or "unknown"
    ngx.var.waf_rule = ngx.ctx.rule_id or ""

    if ngx.ctx.blocked then
        local log_entry = {
            timestamp = ngx.now(),
            source_ip = ip,
            method = ngx.req.get_method(),
            uri = ngx.var.uri,
            query_string = ngx.var.query_string or "",
            rule_id = ngx.ctx.rule_id,
            severity = "critical",
            action = ngx.ctx.action,
            reason = ngx.ctx.reason,
            user_agent = ngx.var.http_user_agent or "",
            host = ngx.var.http_host or ""
        }

        ngx.log(ngx.ERR, "WAF_AUDIT ", cjson.encode(log_entry))

        -- Store in shared dict for admin panel log viewing
        logger.store_blocked_log(log_entry)
    end

    -- Periodic trend sampling (every 5 minutes)
    local shared_state = ngx.shared.waf_state
    if shared_state then
        local last_sample = shared_state:get("last_trend_sample") or 0
        if ngx.time() - last_sample > 300 then
            shared_state:set("last_trend_sample", ngx.time())
            logger.record_trend_sample()
        end
    end
end

return _M
