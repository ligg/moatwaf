-- lib/cc_protect.lua
-- CC protection module: rate limiting, connection limiting, path scan detection
local _M = {}

local DEFAULTS = {
    ip_qps_limit = 100,          -- requests per second per IP
    ip_conn_limit = 50,           -- concurrent connections per IP
    global_qps_limit = 5000,      -- global QPS limit
    window_size = 60,             -- fixed window in seconds
    challenge_enabled = false,    -- JS Challenge mode
    use_sliding_window = false,   -- sliding window algorithm
}

_M.DEFAULTS = DEFAULTS

-- Generate rate limit key from IP, HTTP method, and URI
function _M.make_key(ip, method, uri)
    local key = ip or "unknown"
    if method then
        key = key .. ":" .. method
    end
    if uri then
        key = key .. ":" .. uri
    end
    return key
end

-- Fixed window rate limiter
-- Uses ngx.shared.rate_limit to store per-key counters with TTL
-- Returns true if the request should be blocked
function _M.check_rate_limit(key, limit, window)
    local dict = ngx.shared.rate_limit
    if not dict then
        return false, "no_dict"
    end

    window = window or DEFAULTS.window_size
    local now = ngx.now()

    local cur_key = key
    local prev_key = key .. ":prev"
    local start_key = key .. ":start"

    local window_start = dict:get(start_key)

    if not window_start then
        dict:set(start_key, now, window * 2)
        dict:set(cur_key, 0, window * 2)
        dict:set(prev_key, 0, window * 2)
        window_start = now
    end

    local elapsed = now - window_start
    if elapsed >= window then
        -- Atomic window transition: only one worker performs the reset.
        -- add(start_key+1) succeeds for exactly one worker; all others skip.
        local transition_key = start_key .. ":tr"
        local is_leader = dict:add(transition_key, 1, window)
        if is_leader then
            local snapshot = dict:get(cur_key) or 0
            dict:set(prev_key, snapshot, window * 2)
            -- Atomic drain: subtract snapshot from cur_key instead of zeroing.
            -- Preserves any increments that arrived between get() and this line.
            dict:incr(cur_key, -snapshot, 0, window * 2)
            dict:set(start_key, now, window * 2)
            dict:delete(transition_key)
        end
        window_start = now
        elapsed = 0
    end

    local new_val, err = dict:incr(cur_key, 1, 0, window * 2)
    if not new_val then
        return false, "incr_failed:" .. (err or "unknown")
    end

    local prev_count = dict:get(prev_key) or 0
    local rate = prev_count * (1 - elapsed / window) + new_val

    if rate >= limit then
        return true, "rate_exceeded"
    end

    return false, "pass"
end

-- Track connection start for an IP (increment counter)
function _M.track_conn_start(ip)
    local dict = ngx.shared.rate_limit
    if not dict then
        return false, "no_dict"
    end

    local key = "conn:" .. ip
    local new_val, err = dict:incr(key, 1, 0, 300)
    if not new_val then
        return false, "incr_failed:" .. (err or "unknown")
    end
    return true, new_val
end

-- Track connection end for an IP (decrement counter)
-- Clamps to 0 if counter would go negative; lets TTL handle key expiry
function _M.track_conn_end(ip)
    local dict = ngx.shared.rate_limit
    if not dict then
        return false, "no_dict"
    end

    local key = "conn:" .. ip
    local new_val, err = dict:incr(key, -1)
    if not new_val then
        return true, 0
    end

    local ttl = 300
    if new_val < 0 then
        dict:set(key, 0, ttl)
        new_val = 0
    end

    return true, new_val
end

-- Check concurrent connection limit for an IP
-- Returns true if blocked
function _M.check_conn_limit(ip, limit)
    local dict = ngx.shared.rate_limit
    if not dict then
        return false, "no_dict"
    end

    limit = limit or DEFAULTS.ip_conn_limit
    local key = "conn:" .. ip
    local count, err = dict:get(key)
    if not count then
        return false, "pass"
    end

    if count > limit then
        return true, "conn_exceeded"
    end

    return false, "pass"
end

-- Check global QPS limit
-- Returns true if blocked
function _M.check_global_limit()
    local dict = ngx.shared.rate_limit
    if not dict then
        return false, "no_dict"
    end

    local key = "global:qps"
    local new_val, err = dict:incr(key, 1, 0, 60)
    if not new_val then
        return false, "incr_failed:" .. (err or "unknown")
    end

    if new_val > DEFAULTS.global_qps_limit then
        return true, "global_exceeded"
    end

    return false, "pass"
end

-- Record a 404 response for path scan detection
function _M.record_404(ip)
    local dict = ngx.shared.session_track
    if not dict then
        return false, "no_dict"
    end

    local key = "scan:" .. ip
    local new_val, err = dict:incr(key, 1, 0, DEFAULTS.window_size)
    if not new_val then
        return false, "incr_failed:" .. (err or "unknown")
    end
    return true, new_val
end

-- Check if IP is performing path scanning
-- Default threshold: 20 404s in 60 seconds
function _M.check_path_scan(ip, limit)
    local dict = ngx.shared.session_track
    if not dict then
        return false, "no_dict"
    end

    limit = limit or 20
    local key = "scan:" .. ip
    local count, err = dict:get(key)
    if not count then
        return false, "pass"
    end

    if count >= limit then
        return true, "path_scan_detected"
    end

    return false, "pass"
end

-- Main CC protection check
-- Evaluates: global limit -> per-IP QPS -> per-IP connections -> path scan -> pass
-- Returns: "pass" | "block" | "challenge", reason
function _M.check(ip, method, uri)
    -- Read challenge config from shared dict
    local challenge_enabled = false
    local dict = ngx.shared.session_track
    if dict then
        local ce = dict:get("cc_config:challenge_enabled")
        if ce ~= nil then challenge_enabled = ce
        else challenge_enabled = DEFAULTS.challenge_enabled or false end
    end

    -- 1. Global QPS limit
    local blocked, reason = _M.check_global_limit()
    if blocked then
        return challenge_enabled and "challenge" or "block", reason
    end

    -- 2. Per-IP QPS limit
    local key = ip or "unknown"
    blocked, reason = _M.check_rate_limit(key, DEFAULTS.ip_qps_limit, 1)
    if blocked then
        return challenge_enabled and "challenge" or "block", reason
    end

    -- 3. Per-IP connection limit
    blocked, reason = _M.check_conn_limit(ip)
    if blocked then
        return challenge_enabled and "challenge" or "block", reason
    end

    -- 4. Path scan detection
    blocked, reason = _M.check_path_scan(ip)
    if blocked then
        return challenge_enabled and "challenge" or "block", reason
    end

    return "pass", "ok"
end

return _M
