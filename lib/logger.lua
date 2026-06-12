-- lib/logger.lua
-- Non-blocking WAF logging via ngx.log (writes to nginx error log).
-- Filter entries with: grep WAF_AUDIT logs/error.log
--                       grep WAF_ATTACK logs/error.log
--                       grep WAF_OPERATIONAL logs/error.log
--                       grep WAF_SECURITY logs/error.log
local _M = {}

local ngx = ngx
local cjson = require("cjson")
local utils = require("lib.utils")

-- Log levels
local LEVELS = {
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5
}

local current_level = LEVELS.INFO

-- Set log level
function _M.set_level(level)
    current_level = LEVELS[level] or LEVELS.INFO
end

-- Level number to name lookup (unambiguous, O(1))
local LEVEL_NAMES = { [1] = "DEBUG", [2] = "INFO", [3] = "WARN", [4] = "ERROR", [5] = "CRITICAL" }

-- Get current log level name
function _M.get_level()
    return LEVEL_NAMES[current_level] or "INFO"
end

-- Safe JSON encode: returns json string or nil on encode failure
local function safe_encode(entry, tag)
    local ok, json = pcall(cjson.encode, entry)
    if not ok then
        ngx.log(ngx.ERR, tag .. "_ENCODE_FAILED ", entry.client_ip or "?")
        return nil
    end
    return json
end

-- Shallow-copy a table to avoid mutating the caller's entry
local function copy_entry(entry)
    local out = {}
    for k, v in pairs(entry) do
        out[k] = v
    end
    return out
end

-- Audit log: all blocked requests
function _M.audit(entry)
    local out = copy_entry(entry)
    out.level = "audit"
    out.timestamp = out.timestamp or os.date("!%Y-%m-%dT%H:%M:%SZ")
    out.client_ip = out.client_ip or utils.get_client_ip()
    local json = safe_encode(out, "WAF_AUDIT")
    if json then
        ngx.log(ngx.ERR, "WAF_AUDIT ", json)
    end
end

-- Attack log: high-severity events with full payload
function _M.attack(entry)
    local out = copy_entry(entry)
    out.level = "attack"
    out.timestamp = out.timestamp or os.date("!%Y-%m-%dT%H:%M:%SZ")
    out.client_ip = out.client_ip or utils.get_client_ip()
    local json = safe_encode(out, "WAF_ATTACK")
    if json then
        ngx.log(ngx.ERR, "WAF_ATTACK ", json)
    end
end

-- Operational log: WAF internal state (respects log level filtering)
-- NOTE: set_level() is only safe to call from init_by_lua (shared module-level state)
function _M.operational(entry)
    local out = copy_entry(entry)
    out.level = out.level or "info"
    if type(out.level) ~= "string" then
        out.level = "info"
    end
    local entry_level = LEVELS[out.level:upper()]
    if entry_level and entry_level < current_level then
        return
    end
    out.timestamp = out.timestamp or os.date("!%Y-%m-%dT%H:%M:%SZ")
    local json = safe_encode(out, "WAF_OPERATIONAL")
    if json then
        ngx.log(ngx.ERR, "WAF_OPERATIONAL ", json)
    end
end

-- Security event: WAF self-security events
function _M.security(entry)
    local out = copy_entry(entry)
    out.level = "security"
    out.timestamp = out.timestamp or os.date("!%Y-%m-%dT%H:%M:%SZ")
    out.client_ip = out.client_ip or utils.get_client_ip()
    local json = safe_encode(out, "WAF_SECURITY")
    if json then
        ngx.log(ngx.ERR, "WAF_SECURITY ", json)
    end
end

-- Record stats to shared dict
function _M.record_stats(action, category)
    local stats = ngx.shared.waf_stats
    if not stats then
        return
    end
    stats:incr("total_requests", 1, 0)
    stats:incr(action .. "_total", 1, 0)
    if category then
        stats:incr(action .. "_" .. category, 1, 0)
    end
    stats:set("last_request_time", os.time(), 3600)
end

-- Get current stats
function _M.get_stats()
    local stats = ngx.shared.waf_stats
    if not stats then
        return {}
    end
    local blocked = stats:get("blocked_total") or 0
    local passed = stats:get("passed_total") or 0
    return {
        total_requests = blocked + passed,
        passed_total = passed,
        blocked_total = blocked,
        blocked_sqli = stats:get("blocked_sqli") or 0,
        blocked_xss = stats:get("blocked_xss") or 0,
        blocked_cmdi = stats:get("blocked_cmdi") or 0,
        blocked_cc = stats:get("blocked_cc") or 0,
        blocked_other = stats:get("blocked_other") or 0,
        blocked_ip = stats:get("blocked_ip") or 0,
        last_request_time = stats:get("last_request_time") or 0
    }
end

-- File-based log persistence
local LOG_DIR = os.getenv("WAF_LOG_DIR") or "/opt/moat/logs"

-- Get log directory path
function _M.get_log_dir()
    return LOG_DIR
end

-- Write a single log entry to the date-based log file (JSON Lines format)
function _M.write_log_entry_to_file(entry)
    if not entry then return false end

    local date = os.date("!%Y-%m-%d", math.floor(entry.timestamp or ngx.now()))
    local filepath = LOG_DIR .. "/waf_blocked_" .. date .. ".log"

    -- Ensure directory exists (ignore error if already exists)
    os.execute('mkdir -p "' .. LOG_DIR .. '" 2>/dev/null')

    local f = io.open(filepath, "a")
    if not f then
        ngx.log(ngx.ERR, "WAF_LOG_FILE_OPEN_FAILED ", filepath)
        return false
    end

    local ok, json = pcall(cjson.encode, entry)
    if not ok then
        f:close()
        return false
    end

    f:write(json, "\n")
    f:close()
    return true
end

-- Async timer callback for file writing
local function write_log_async(premature, json_entry)
    if premature then return end

    local ok, entry = pcall(cjson.decode, json_entry)
    if not ok then return end

    _M.write_log_entry_to_file(entry)
end

-- Store blocked request log entry in shared dict (ring buffer, bounded memory)
local LOG_MAX_ENTRIES = 1000

function _M.store_blocked_log(entry)
    local logs_dict = ngx.shared.waf_logs
    if not logs_dict then return end

    local out = copy_entry(entry)
    out.timestamp = out.timestamp or ngx.now()
    out.source_ip = out.source_ip or (ngx.var and ngx.var.remote_addr) or "unknown"
    out.method = out.method or (ngx.req and ngx.req.get_method()) or "UNKNOWN"
    out.uri = out.uri or (ngx.var and ngx.var.uri) or ""
    out.rule_id = out.rule_id or ""
    out.severity = out.severity or "unknown"
    out.action = out.action or "block"
    out.reason = out.reason or ""
    out.user_agent = out.user_agent or (ngx.var and ngx.var.http_user_agent) or ""
    out.host = out.host or (ngx.var and ngx.var.http_host) or ""
    out.id = logs_dict:incr("log_counter", 1, 0)

    local json = safe_encode(out, "WAF_LOG_STORE")
    if not json then return end

    local key = "log:" .. out.id
    logs_dict:set(key, json, 3600)
    logs_dict:set("log_max_id", out.id, 3600)

    -- Async file persistence (non-blocking)
    local timer_ok, timer_err = ngx.timer.at(0, write_log_async, json)
    if not timer_ok then
        ngx.log(ngx.ERR, "WAF_LOG_TIMER_FAILED ", timer_err or "unknown")
    end
end

-- Retrieve logs from shared dict with pagination and optional rule_id filter
function _M.get_logs(page, per_page, rule_id_filter)
    page = page or 1
    per_page = per_page or 20
    if per_page > 100 then per_page = 100 end

    local logs_dict = ngx.shared.waf_logs
    if not logs_dict then
        return { logs = cjson.empty_array, total = 0, page = page, per_page = per_page }
    end

    local max_id = logs_dict:get("log_max_id") or 0
    if max_id == 0 then
        return { logs = cjson.empty_array, total = 0, page = page, per_page = per_page }
    end

    local all_logs = {}
    local start_id = math.max(1, max_id - LOG_MAX_ENTRIES + 1)
    for id = max_id, start_id, -1 do
        local json = logs_dict:get("log:" .. id)
        if json then
            local ok, log_entry = pcall(cjson.decode, json)
            if ok and log_entry then
                if not rule_id_filter or rule_id_filter == "" or log_entry.rule_id == rule_id_filter then
                    table.insert(all_logs, log_entry)
                end
            end
        end
    end

    local total = #all_logs
    local offset = (page - 1) * per_page
    local page_logs = {}
    for i = offset + 1, math.min(offset + per_page, total) do
        table.insert(page_logs, all_logs[i])
    end

    return {
        logs = page_logs,
        total = total,
        page = page,
        per_page = per_page
    }
end

-- Get a single log entry by ID
function _M.get_log_by_id(id)
    local logs_dict = ngx.shared.waf_logs
    if not logs_dict then return nil end

    local json = logs_dict:get("log:" .. id)
    if not json then return nil end

    local ok, log_entry = pcall(cjson.decode, json)
    if ok then return log_entry end
    return nil
end

-- Parse date string (YYYY-MM-DD) to unix timestamp (start of day UTC)
-- Returns nil for invalid input
function _M.parse_date(date_str)
    if not date_str or date_str == "" then return nil end
    local y, m, d = date_str:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)$")
    if not y then return nil end
    y, m, d = tonumber(y), tonumber(m), tonumber(d)
    if not y or not m or not d then return nil end
    if m < 1 or m > 12 or d < 1 or d > 31 then return nil end
    return os.time({ year = y, month = m, day = d, hour = 0, min = 0, sec = 0 })
end

-- Match a single log entry against filter criteria
-- Returns true if entry matches all provided filters
local function matches_filters(entry, filters)
    if not filters then return true end

    if filters.rule_id and filters.rule_id ~= "" then
        if entry.rule_id ~= filters.rule_id then return false end
    end

    if filters.severity and filters.severity ~= "" then
        if entry.severity ~= filters.severity then return false end
    end

    if filters.source_ip and filters.source_ip ~= "" then
        if entry.source_ip ~= filters.source_ip then return false end
    end

    if filters.start_time then
        local ts = entry.timestamp
        if type(ts) == "number" and ts < filters.start_time then return false end
    end

    if filters.end_time then
        local ts = entry.timestamp
        if type(ts) == "number" and ts > filters.end_time then return false end
    end

    return true
end

-- Read logs from date-based log files with filtering and pagination
-- Parameters:
--   filters: { rule_id, severity, source_ip, start_time, end_time } (all optional)
--   page: page number (default 1)
--   per_page: results per page (default 20, max 100)
-- Returns: { logs = {}, total = N, page = N, per_page = N }
function _M.get_logs_from_files(filters, page, page_per_page)
    page = page or 1
    page_per_page = page_per_page or 20
    if page_per_page > 100 then page_per_page = 100 end

    filters = filters or {}

    -- Determine which date files to scan
    local dates_to_scan = {}
    if filters.start_time and filters.end_time then
        -- Scan each day in the range
        local day_start = filters.start_time - (filters.start_time % 86400)
        local day_end = filters.end_time - (filters.end_time % 86400)
        for t = day_start, day_end, 86400 do
            table.insert(dates_to_scan, os.date("!%Y-%m-%d", t))
        end
    elseif filters.start_time then
        -- From start_time to today
        local day_start = filters.start_time - (filters.start_time % 86400)
        local today = os.time() - (os.time() % 86400)
        for t = day_start, today, 86400 do
            table.insert(dates_to_scan, os.date("!%Y-%m-%d", t))
        end
    else
        -- Default: scan last 7 days
        local today = os.time() - (os.time() % 86400)
        for i = 0, 6 do
            table.insert(dates_to_scan, os.date("!%Y-%m-%d", today - i * 86400))
        end
    end

    -- Collect matching entries from all files
    local all_matching = {}
    for _, date_str in ipairs(dates_to_scan) do
        local filepath = LOG_DIR .. "/waf_blocked_" .. date_str .. ".log"
        local f = io.open(filepath, "r")
        if f then
            for line in f:lines() do
                if line and line ~= "" then
                    local ok, entry = pcall(cjson.decode, line)
                    if ok and entry and matches_filters(entry, filters) then
                        table.insert(all_matching, entry)
                    end
                end
            end
            f:close()
        end
    end

    -- Sort by timestamp descending (newest first)
    table.sort(all_matching, function(a, b)
        return (a.timestamp or 0) > (b.timestamp or 0)
    end)

    local total = #all_matching
    local offset = (page - 1) * page_per_page
    local page_logs = {}
    for i = offset + 1, math.min(offset + page_per_page, total) do
        table.insert(page_logs, all_matching[i])
    end

    return {
        logs = page_logs,
        total = total,
        page = page,
        per_page = page_per_page
    }
end

-- Get all logs (memory + files) with unified filtering and pagination
-- Memory layer: recent logs from ngx.shared.waf_logs (fast, bounded)
-- File layer: historical logs from JSON Lines files (complete history)
-- Parameters:
--   filters: { rule_id, severity, source_ip, start_time, end_time } (all optional)
--   page: page number (default 1)
--   per_page: results per page (default 20, max 100)
-- Returns: { logs = {}, total = N, page = N, per_page = N }
function _M.get_all_logs(filters, page, per_page)
    page = page or 1
    per_page = per_page or 20
    if per_page > 100 then per_page = 100 end

    -- Get memory logs
    local mem_result = _M.get_logs(page, per_page, filters and filters.rule_id)
    local mem_logs = mem_result.logs or {}

    -- Get file logs
    local file_result = _M.get_logs_from_files(filters, page, per_page)
    local file_logs = file_result.logs or {}

    -- Merge: memory logs take priority (newer), deduplicate by id
    local seen = {}
    local merged = {}
    for _, entry in ipairs(mem_logs) do
        local id = entry.id
        if id then
            seen[id] = true
        end
        table.insert(merged, entry)
    end
    for _, entry in ipairs(file_logs) do
        local id = entry.id
        if not id or not seen[id] then
            table.insert(merged, entry)
        end
    end

    -- Apply additional filters to memory logs (they only filter by rule_id in get_logs)
    local filtered = {}
    for _, entry in ipairs(merged) do
        if matches_filters(entry, filters) then
            table.insert(filtered, entry)
        end
    end

    -- Sort by timestamp descending
    table.sort(filtered, function(a, b)
        return (a.timestamp or 0) > (b.timestamp or 0)
    end)

    -- Apply pagination
    local total = #filtered
    local offset = (page - 1) * per_page
    local page_logs = {}
    for i = offset + 1, math.min(offset + per_page, total) do
        table.insert(page_logs, filtered[i])
    end

    return {
        logs = page_logs,
        total = total,
        page = page,
        per_page = per_page
    }
end

---------------------------------------------------------------------------
-- Chart data functions
---------------------------------------------------------------------------

-- Record hourly stats snapshot for trend charts
function _M.record_trend_sample()
    local stats = ngx.shared.waf_stats
    if not stats then return end

    local blocked = stats:get("blocked_total") or 0
    local passed = stats:get("passed_total") or 0
    local hour = math.floor(ngx.time() / 3600)
    local hour_key = "trend:hour:" .. hour

    stats:set(hour_key, cjson.encode({
        blocked = blocked,
        passed = passed,
        timestamp = ngx.time()
    }), 86400 * 7)  -- 7 day TTL
end

-- Get trend data for charts
function _M.get_trend_data(range)
    local stats = ngx.shared.waf_stats
    if not stats then return { labels = cjson.empty_array, blocked = cjson.empty_array, passed = cjson.empty_array } end

    local current_hour = math.floor(ngx.time() / 3600)
    local hours_back = (range == "7d") and 168 or 24

    local labels, blocked_arr, passed_arr = {}, {}, {}
    local prev_blocked, prev_passed = 0, 0

    for i = hours_back, 0, -1 do
        local h = current_hour - i
        local raw = stats:get("trend:hour:" .. h)
        if raw then
            local ok, data = pcall(cjson.decode, raw)
            if ok and data then
                table.insert(labels, os.date("%m-%d %H:00", h * 3600))
                table.insert(blocked_arr, math.max(0, data.blocked - prev_blocked))
                table.insert(passed_arr, math.max(0, data.passed - prev_passed))
                prev_blocked = data.blocked
                prev_passed = data.passed
            end
        end
    end

    if #labels == 0 then
        return { labels = cjson.empty_array, blocked = cjson.empty_array, passed = cjson.empty_array }
    end
    return { labels = labels, blocked = blocked_arr, passed = passed_arr }
end

-- Get top attacking IPs from recent logs
function _M.get_top_ips(limit)
    limit = limit or 10
    local logs_dict = ngx.shared.waf_logs
    if not logs_dict then return cjson.empty_array end

    local ip_counts = {}
    local max_id = logs_dict:get("log_max_id") or 0
    local start_id = math.max(1, max_id - 1000)

    for id = max_id, start_id, -1 do
        local json = logs_dict:get("log:" .. id)
        if json then
            local ok, entry = pcall(cjson.decode, json)
            if ok and entry and entry.source_ip then
                ip_counts[entry.source_ip] = (ip_counts[entry.source_ip] or 0) + 1
            end
        end
    end

    local sorted = {}
    for ip, count in pairs(ip_counts) do
        table.insert(sorted, { ip = ip, count = count })
    end
    table.sort(sorted, function(a, b) return a.count > b.count end)

    local result = {}
    for i = 1, math.min(limit, #sorted) do
        table.insert(result, sorted[i])
    end
    if #result == 0 then return cjson.empty_array end
    return result
end

-- Get attack category distribution
function _M.get_categories()
    local stats = ngx.shared.waf_stats
    if not stats then return {} end
    return {
        { name = "SQLi", count = stats:get("blocked_sqli") or 0, color = "#ff006e" },
        { name = "XSS", count = stats:get("blocked_xss") or 0, color = "#8a2be2" },
        { name = "CMDi", count = stats:get("blocked_cmdi") or 0, color = "#00b4ff" },
        { name = "CC", count = stats:get("blocked_cc") or 0, color = "#00ff88" },
        { name = "IP", count = stats:get("blocked_ip") or 0, color = "#a78bfa" },
        { name = "其他", count = stats:get("blocked_other") or 0, color = "#6b5b8a" },
    }
end

return _M
