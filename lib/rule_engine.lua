-- lib/rule_engine.lua
-- Rule engine for pattern matching against request attributes.
-- Loads rules from YAML files, matches against URI, ARGS, BODY, HEADERS, COOKIE.
local _M = {}

local utils = require("lib.utils")

-- Use ngx.re module (built into OpenResty with PCRE support)
local re = ngx and ngx.re or nil
local re_ok = re ~= nil

-- Cache for loaded rules (version-file-based invalidation)
local cached_rules = nil
local cached_rules_version = nil

-- Order of rule files to load (determines priority ordering)
-- Files loaded first are checked first; earlier rules have higher priority.
local RULE_FILES = {
    "sql_injection.yaml",
    "xss.yaml",
    "path_traversal.yaml",
    "cmd_injection.yaml",
    "sensitive_files.yaml",
    "scanner_detection.yaml",
    "ssrf.yaml",
    "proto.yaml",
    "custom.yaml",
}

---------------------------------------------------------------------------
-- Pattern compilation
---------------------------------------------------------------------------

-- Convert a PCRE pattern to a Lua pattern.
-- This handles common PCRE constructs used in WAF rules.
-- For OpenResty, prefer the re module for full PCRE support.
-- Post-process a Lua pattern string to escape bare % and bare - that are not
-- inside character classes. This must run after all other pattern transformations.
--   - Bare % followed by a digit or invalid escape char → %%  (prevents "invalid capture index")
--   - Bare - outside character classes → %-  (prevents non-greedy empty-match quantifier)
local function fix_lua_pattern_metachars(pat)
    local result = {}
    local in_class = false
    local i = 1
    while i <= #pat do
        local c = pat:sub(i, i)
        if c == "[" and not in_class then
            in_class = true
            table.insert(result, c)
            i = i + 1
            -- Handle negated class [^...]
            if i <= #pat and pat:sub(i, i) == "^" then
                table.insert(result, "^")
                i = i + 1
            end
        elseif c == "]" and in_class then
            in_class = false
            table.insert(result, c)
            i = i + 1
        elseif c == "%" then
            if i < #pat then
                local next_c = pat:sub(i + 1, i + 1)
                -- Valid Lua pattern escapes after %:
                --   letters (character classes: %a %A %d %D %l %L %u %U %w %W %s %S %c %C %p %P %x %X %g %G %z %Z)
                --   metacharacters: . ^ $ ( ) [ ] + - * ?
                --   percent itself: %
                if next_c:match("[%a%.%^%$%(%)%[%]%+%-%*%?%%]") then
                    -- Valid escape, keep as-is
                    table.insert(result, c)
                    table.insert(result, next_c)
                else
                    -- Invalid (e.g., %2, %0), escape the %
                    table.insert(result, "%%")
                    table.insert(result, next_c)
                end
                i = i + 2
            else
                -- Trailing bare % at end of pattern
                table.insert(result, "%%")
                i = i + 1
            end
        elseif c == "-" and not in_class then
            -- Escape bare - outside character classes (Lua non-greedy quantifier)
            table.insert(result, "%-")
            i = i + 1
        else
            table.insert(result, c)
            i = i + 1
        end
    end
    return table.concat(result)
end

local function pcre_to_lua(pcre_pat)
    local pat = pcre_pat
    -- Strip inline flags like (?i), (?im), (?ix), etc.
    pat = pat:gsub("%(%?[a-z]+%)", "")
    -- Strip word boundaries (no Lua pattern equivalent)
    pat = pat:gsub("\\b", "")
    -- PCRE character classes -> Lua character classes
    pat = pat:gsub("\\d", "%%d")
    pat = pat:gsub("\\s", "%%s")
    pat = pat:gsub("\\w", "%%w")
    pat = pat:gsub("\\D", "%%D")
    pat = pat:gsub("\\S", "%%S")
    pat = pat:gsub("\\W", "%%W")
    -- Convert PCRE escaped metacharacters to Lua pattern equivalents.
    -- In PCRE, \X where X is a metacharacter means literal X.
    -- In Lua patterns, %X escapes metacharacters.
    -- Lua metacharacters: . ( ) % + - * ? [ ] ^ $
    pat = pat:gsub("\\([%.%%%+%-%*%?%[%]%^%$])", "%%%1")
    -- Convert PCRE literal parens (\) and \() to Lua %) and %(.
    -- Must run BEFORE stripping remaining backslashes and before stripping parens.
    pat = pat:gsub("\\%)", "%%)")
    pat = pat:gsub("\\%(", "%%(")
    -- Strip remaining backslash before any character that isn't % (already escaped).
    -- This handles \/ -> /, \a -> a, etc. (backslash before non-special chars)
    -- Note: \( and \) are already handled above, so this won't strip them.
    pat = pat:gsub("\\([^%%])", "%1")
    -- NOTE: PCRE ? quantifier (zero-or-one) is intentionally NOT converted here.
    -- Using * (zero-or-more) as a substitute causes false positives.
    -- The simplify_for_lua function handles optional groups correctly by generating variants.
    -- Strip remaining parentheses (Lua patterns don't use them for grouping).
    -- But preserve %( and %) which are Lua escapes for literal parentheses.
    pat = pat:gsub("([^%%])[()]", "%1")
    pat = pat:gsub("^[()]", "")  -- Handle paren at start of string
    -- Final fixup: escape bare % and bare - for Lua pattern safety
    pat = fix_lua_pattern_metachars(pat)
    return pat
end

-- Find the innermost balanced parenthesis group in a PCRE pattern.
-- Skips escaped parentheses (\) and \() so they are not treated as group delimiters.
-- Returns: start_pos, end_pos, group_content, after_group (rest of string after closing paren)
-- Returns nil if no group found.
local function find_innermost_group(pat)
    local last_open = nil
    local i = 1
    while i <= #pat do
        local c = pat:sub(i, i)
        if c == "\\" and i < #pat then
            -- Skip escaped character (including \( and \))
            i = i + 2
        elseif c == "(" then
            last_open = i
            i = i + 1
        elseif c == ")" and last_open then
            -- Found a balanced pair with no nested parens inside
            local content = pat:sub(last_open + 1, i - 1)
            local rest = pat:sub(i + 1)
            return last_open, i, content, rest
        else
            i = i + 1
        end
    end
    return nil
end

-- Remove non-capturing group prefix (?:) from content
local function strip_noncapturing(content)
    return content:gsub("^%?:", "")
end

-- Simplify a PCRE pattern for Lua fallback matching.
-- Processes groups from innermost to outermost, handling:
--   (X)?  → optional group: generates two variants (with X, without X)
--   (X|Y) → alternation: generates one variant per alternative
--   (X)   → plain group: strips parentheses
-- Returns a list of Lua pattern strings to try.
local function simplify_for_lua(pcre_pat)
    local pat = pcre_pat
    -- Strip inline flags like (?i), (?s), etc.
    pat = pat:gsub("%(%?[a-z]+%)", "")

    -- Process groups iteratively from innermost outward
    local variants = {pat}

    local changed = true
    while changed do
        changed = false
        local new_variants = {}
        for _, variant in ipairs(variants) do
            local start_pos, end_pos, content, rest = find_innermost_group(variant)
            if not start_pos then
                -- No more groups; add as-is
                table.insert(new_variants, variant)
            else
                changed = true
                local before = variant:sub(1, start_pos - 1)
                content = strip_noncapturing(content)

                -- Check if group is optional: (...)?
                local is_optional = rest:sub(1, 1) == "?"
                if is_optional then
                    rest = rest:sub(2) -- consume the ?
                    -- Two variants: with content and without
                    table.insert(new_variants, before .. content .. rest)
                    table.insert(new_variants, before .. rest)
                else
                    -- Check for alternation: (X|Y|Z)
                    -- Must split on unescaped | only (not on \| which is a literal pipe in PCRE)
                    local has_alternation = content:gsub("\\|", ""):find("|")
                    if has_alternation then
                        -- One variant per alternative
                        -- Protect escaped pipes (\|) from being treated as alternation separators
                        local protected = content:gsub("\\|", "\0")
                        for raw_alt in protected:gmatch("[^|]+") do
                            local alt = raw_alt:gsub("\0", "\\|")
                            table.insert(new_variants, before .. alt .. rest)
                        end
                    else
                        -- Plain grouping: just strip parens
                        table.insert(new_variants, before .. content .. rest)
                    end
                end
            end
        end
        variants = new_variants
    end

    -- After group processing, handle any remaining top-level alternation (|).
    -- Lua patterns don't support | as alternation, so split into separate patterns.
    local expanded = {}
    for _, v in ipairs(variants) do
        -- Only split on unescaped | (not \| which is a literal pipe)
        local has_pipe = v:gsub("\\|", ""):find("|")
        if has_pipe then
            local protected = v:gsub("\\|", "\0")
            for raw_alt in protected:gmatch("[^|]+") do
                table.insert(expanded, (raw_alt:gsub("\0", "\\|")))
            end
        else
            table.insert(expanded, v)
        end
    end
    variants = expanded

    -- Guard against variant explosion: if too many variants were generated,
    -- fall back to returning just the original PCRE pattern (caller uses re module).
    if #variants > 64 then
        if ngx then
            ngx.log(ngx.WARN, "WAF: rule has too many variants (", #variants, "), using re module only")
        end
        return {pcre_to_lua(pcre_pat)}
    end

    -- Convert all variants to Lua patterns and deduplicate
    local seen = {}
    local patterns = {}
    for _, v in ipairs(variants) do
        local lua_pat = pcre_to_lua(v)
        if lua_pat ~= "" and not seen[lua_pat] then
            seen[lua_pat] = true
            table.insert(patterns, lua_pat)
        end
    end

    -- Fallback: if nothing generated, try plain conversion
    if #patterns == 0 then
        local lua_pat = pcre_to_lua(pcre_pat)
        if lua_pat ~= "" then
            table.insert(patterns, lua_pat)
        end
    end

    return patterns
end

-- Check if pattern has the (?i) case-insensitive flag
local function has_case_insensitive_flag(pattern)
    return pattern:find("%(%?i[a-z]*%)") ~= nil
end

-- Strip all (?...) flags from a pattern string
local function strip_flags(pattern)
    return pattern:gsub("%(%?[%a]+%)", "")
end

-- Build a match function for a given pattern.
-- Returns a function(str) -> bool, case_insensitive.
local function compile_pattern(pcre_pattern)
    local ci = has_case_insensitive_flag(pcre_pattern)
    local raw = strip_flags(pcre_pattern)

    -- Use ngx.re.find directly (no compile step — ngx.re doesn't have compile)
    if re_ok then
        local flags = ci and "ij" or "j"
        if ngx then ngx.log(ngx.ERR, "WAF_COMPILE: using ngx.re.find, pattern=" .. raw .. " flags=" .. flags) end
        return function(str)
            local from, to, err = re.find(str, raw, flags)
            if err then
                ngx.log(ngx.ERR, "WAF_MATCH: ngx.re.find error: " .. err .. " pattern=" .. raw)
            end
            return from ~= nil
        end, ci
    else
        if ngx then ngx.log(ngx.ERR, "WAF_COMPILE: ngx.re NOT available, using Lua patterns") end
    end

    -- Fallback: Lua patterns (works in plain Lua for testing)
    -- Generate multiple patterns to handle optional groups
    local lua_patterns = simplify_for_lua(raw)

    -- Debug: print generated patterns
    if _G._RULE_ENGINE_DEBUG then
        print("[DEBUG] PCRE: " .. pcre_pattern .. " -> raw: " .. raw)
        for i, p in ipairs(lua_patterns) do
            print("[DEBUG]   lua_pat[" .. i .. "]: " .. p)
        end
    end

    if ci then
        -- Pre-lowercase all patterns for case-insensitive matching
        local lower_patterns = {}
        for _, p in ipairs(lua_patterns) do
            table.insert(lower_patterns, p:lower())
        end
        return function(str)
            local lower_str = str:lower()
            for _, pat in ipairs(lower_patterns) do
                local ok, match = pcall(function() return lower_str:find(pat) end)
                if ok and match then
                    return true
                end
            end
            return false
        end, ci
    else
        return function(str)
            for _, pat in ipairs(lua_patterns) do
                local ok, match = pcall(function() return str:find(pat) end)
                if ok and match then
                    return true
                end
            end
            return false
        end, ci
    end
end

---------------------------------------------------------------------------
-- YAML parsing
---------------------------------------------------------------------------

-- Process YAML escape sequences in double-quoted strings.
-- Handles: \\ -> \, \" -> ", \n -> newline, \t -> tab
local function yaml_unescape(str)
    local result = {}
    local i = 1
    while i <= #str do
        if i + 1 <= #str and str:byte(i) == 92 and str:byte(i+1) == 92 then
            table.insert(result, "\\")
            i = i + 2
        elseif i + 1 <= #str and str:byte(i) == 92 and str:byte(i+1) == 34 then
            table.insert(result, '"')
            i = i + 2
        elseif i + 1 <= #str and str:byte(i) == 92 and str:byte(i+1) == 110 then
            table.insert(result, "\n")
            i = i + 2
        elseif i + 1 <= #str and str:byte(i) == 92 and str:byte(i+1) == 116 then
            table.insert(result, "\t")
            i = i + 2
        else
            table.insert(result, str:sub(i, i))
            i = i + 1
        end
    end
    return table.concat(result)
end

-- Parse a single YAML rule block (key-value pairs, one per line).
-- Supports quoted string values: "some text with: colons"
local function parse_rule_block(block)
    local rule = {}
    for line in block:gmatch("[^\r\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and not trimmed:match("^#") then
            local key, value = trimmed:match("^([%w_]+):%s*(.+)$")
            if key and value then
                -- Strip surrounding quotes if present
                local double_quoted = value:match('^"(.*)"$')
                local single_quoted = value:match("^'(.*)'$")
                if double_quoted then
                    rule[key] = yaml_unescape(double_quoted)
                elseif single_quoted then
                    rule[key] = single_quoted  -- single-quoted: no escape processing
                else
                    rule[key] = value
                end
            end
        end
    end
    return rule
end

-- Parse a full YAML file containing rules separated by ---
-- Uses a line-by-line state machine to correctly handle multi-rule files.
local function parse_yaml_file(content)
    local rules = {}
    local current_block = {}
    local in_block = false

    for line in content:gmatch("([^\r\n]*)\r?\n?") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed == "---" then
            -- Flush the previous block if any
            if #current_block > 0 then
                local rule = parse_rule_block(table.concat(current_block, "\n"))
                if rule.id and rule.pattern then
                    table.insert(rules, rule)
                end
                current_block = {}
            end
            in_block = true
        elseif in_block then
            table.insert(current_block, line)
        end
    end

    -- Handle last block if content doesn't end with ---
    if #current_block > 0 then
        local rule = parse_rule_block(table.concat(current_block, "\n"))
        if rule.id and rule.pattern then
            table.insert(rules, rule)
        end
    end

    -- Validate that accepted rules have all required fields
    local validated = {}
    for _, rule in ipairs(rules) do
        if rule.id and rule.pattern and rule.target and rule.action then
            table.insert(validated, rule)
        else
            if ngx then
                ngx.log(ngx.WARN, "WAF: skipping incomplete rule - missing required fields (",
                    "id=", tostring(rule.id), " target=", tostring(rule.target),
                    " action=", tostring(rule.action), ")")
            end
        end
    end

    return validated
end

---------------------------------------------------------------------------
-- Rule loading
---------------------------------------------------------------------------

-- Scan the rules directory and load all YAML rule files.
-- Internal function that loads rules from disk without touching the cache.
-- Returns the rules table, or nil plus an error message on failure.
local function load_rules_from_disk()
    local all_rules = {}

    if ngx then ngx.log(ngx.ERR, "WAF_LOAD: starting rule load from disk") end

    -- Load files in defined order for predictable priority
    for _, filename in ipairs(RULE_FILES) do
        local filepath = "/opt/moat/conf/rules/" .. filename
        local f, err = io.open(filepath, "r")
        if ngx then ngx.log(ngx.ERR, "WAF_LOAD: open ", filepath, " => ", f and "OK" or ("FAIL: " .. (err or "unknown"))) end
        if f then
            local content = f:read("*all")
            f:close()
            if ngx then ngx.log(ngx.ERR, "WAF_LOAD: read ", filepath, " content_len=", #(content or "")) end
            local file_rules = parse_yaml_file(content)
            if ngx then ngx.log(ngx.ERR, "WAF_LOAD: parsed ", filepath, " rules_count=", #file_rules) end
            if #file_rules == 0 and ngx then
                ngx.log(ngx.WARN, "WAF: no rules found in ", filepath)
            end
            for _, rule in ipairs(file_rules) do
                -- Compile the PCRE pattern into an executable matcher
                local match_fn, ci = compile_pattern(rule.pattern)
                rule._match_fn = match_fn
                table.insert(all_rules, rule)
            end
        end
    end

    return all_rules
end

-- Version file path for cache invalidation across nginx workers.
local VERSION_FILE = "/opt/moat/conf/rules/.version"

-- Read the version file and return its content, or nil on any error.
local function read_version_file()
    local ok, f = pcall(io.open, VERSION_FILE, "r")
    if ok and f then
        local version = f:read("*l")
        f:close()
        return version
    end
    return nil
end

-- Load rules with version-file-based cache invalidation.
-- Reads conf/rules/.version; if it matches the cached version, returns cached rules.
-- Otherwise reloads from disk and updates the cache.
local function load_cached()
    local file_version = read_version_file()

    -- Cache hit: rules already loaded and version file has not changed
    if cached_rules and #cached_rules > 0 and cached_rules_version == file_version then
        return cached_rules
    end

    -- Cache miss: reload from disk
    if ngx and cached_rules then
        ngx.log(ngx.INFO, "WAF: version change detected, reloading rules from disk")
    end

    local new_rules = load_rules_from_disk()
    if new_rules then
        cached_rules_version = file_version
        cached_rules = new_rules
    else
        if ngx then
            ngx.log(ngx.ERR, "WAF: failed to load rules from disk")
        end
    end

    return cached_rules or {}
end

-- Write a new version string to the version file to invalidate caches
-- across all nginx workers. Called after admin API rule updates.
function _M.bump_version()
    local now = ngx and ngx.now() or (os.time() + (math.random(0, 999) / 1000))
    local pid = ngx and ngx.worker.pid() or math.random(1, 65535)
    local version = string.format("%.3f-%d-%d", now, pid, math.random(100000, 999999))
    local ok, f = pcall(io.open, VERSION_FILE, "w")
    if ok and f then
        local write_ok, write_err = f:write(version, "\n")
        f:close()
        if write_ok then
            cached_rules_version = version
        else
            if ngx then
                ngx.log(ngx.ERR, "WAF: failed to write version file: ", write_err or "unknown")
            end
        end
    else
        if ngx then
            ngx.log(ngx.ERR, "WAF: failed to open version file for writing: ", f or "unknown")
        end
    end
end

function _M.load_rules()
    return load_cached()
end

-- Force reload rules (clear cache and re-read from disk).
-- Only updates cache after a successful load to avoid wiping valid rules on transient errors.
-- Bumps the version file so other nginx workers pick up the change.
function _M.reload_rules()
    local new_rules = load_rules_from_disk()
    if new_rules then
        _M.bump_version()
        cached_rules = new_rules
    else
        if ngx then
            ngx.log(ngx.ERR, "WAF: failed to reload rules, keeping existing cache")
        end
    end
    return cached_rules or {}
end

-- Pre-load rules at startup (call from init_by_lua).
-- This avoids blocking I/O during request processing.
function _M.init()
    local rules = load_cached()
    if not rules or #rules == 0 then
        if ngx then
            ngx.log(ngx.ERR, "WAF: failed to pre-load rules during init")
        end
    end
end

---------------------------------------------------------------------------
-- Rule file operations (for admin API)
---------------------------------------------------------------------------

-- List all rule files with rule counts.
-- Returns an array of { filename, rule_count } tables.
function _M.list_rule_files()
    local result = {}
    for _, filename in ipairs(RULE_FILES) do
        local filepath = "/opt/moat/conf/rules/" .. filename
        local f = io.open(filepath, "r")
        local count = 0
        if f then
            local content = f:read("*all")
            f:close()
            if content then
                local rules = parse_yaml_file(content)
                count = #rules
            end
        end
        table.insert(result, { filename = filename, rule_count = count })
    end
    return result
end

-- Read rules from a specific file.
-- Returns an array of rule tables (without compiled _match_fn).
function _M.get_rules_from_file(filename)
    local filepath = "/opt/moat/conf/rules/" .. filename
    local f, err = io.open(filepath, "r")
    if not f then
        return nil, "Failed to open file: " .. (err or "unknown")
    end
    local content = f:read("*all")
    f:close()
    if not content then
        return {}
    end
    return parse_yaml_file(content)
end

-- Write rules array to custom.yaml file.
-- Serializes rules back to YAML format.
local function write_custom_rules(rules)
    local filepath = "/opt/moat/conf/rules/custom.yaml"
    local f, err = io.open(filepath, "w")
    if not f then
        return false, "Failed to open file for writing: " .. (err or "unknown")
    end

    f:write("# Custom Rules\n")
    f:write("# Add your own WAF rules here. Rules in this file are checked last\n")
    f:write("# (lowest priority). Copy the format below for each new rule.\n")
    f:write("#\n")
    f:write("# Fields:\n")
    f:write("#   id          - Unique rule identifier (e.g., CUSTOM-001)\n")
    f:write("#   description - Human-readable description of what the rule catches\n")
    f:write("#   severity    - critical, high, medium, or low\n")
    f:write("#   target      - Request attribute to match: URI, ARGS, BODY, HEADERS, or COOKIE\n")
    f:write("#   pattern     - PCRE regex pattern\n")
    f:write("#   action      - BLOCK (reject request) or LOG (allow but log)\n")
    f:write("\n")
    f:write("rules:\n")

    for _, rule in ipairs(rules) do
        f:write("---\n")
        f:write("id: ", rule.id, "\n")
        f:write("description: \"", (rule.description or ""):gsub('"', '\\"'), "\"\n")
        f:write("severity: ", rule.severity or "medium", "\n")
        f:write("target: ", rule.target or "URI", "\n")
        f:write("pattern: \"", (rule.pattern or ""):gsub('"', '\\"'), "\"\n")
        f:write("action: ", rule.action or "BLOCK", "\n")
    end

    f:close()
    return true
end

-- Add a rule to custom.yaml.
-- Returns true on success, or nil + error message on failure.
function _M.add_rule_to_custom(rule)
    local rules, err = _M.get_rules_from_file("custom.yaml")
    if not rules then
        rules = {}
    end

    -- Check for duplicate ID
    for _, existing in ipairs(rules) do
        if existing.id == rule.id then
            return nil, "Rule ID already exists: " .. rule.id
        end
    end

    table.insert(rules, rule)
    local ok, write_err = write_custom_rules(rules)
    if not ok then
        return nil, write_err
    end
    _M.bump_version()
    return true
end

-- Update a rule in custom.yaml by ID.
-- Returns true on success, or nil + error message on failure.
function _M.update_rule_in_custom(rule_id, updated_rule)
    local rules, err = _M.get_rules_from_file("custom.yaml")
    if not rules then
        return nil, "No rules found in custom.yaml"
    end

    local found = false
    for i, existing in ipairs(rules) do
        if existing.id == rule_id then
            rules[i] = updated_rule
            found = true
            break
        end
    end

    if not found then
        return nil, "Rule not found: " .. rule_id
    end

    local ok, write_err = write_custom_rules(rules)
    if not ok then
        return nil, write_err
    end
    _M.bump_version()
    return true
end

-- Delete a rule from custom.yaml by ID.
-- Returns true on success, or nil + error message on failure.
function _M.delete_rule_from_custom(rule_id)
    local rules, err = _M.get_rules_from_file("custom.yaml")
    if not rules then
        return nil, "No rules found in custom.yaml"
    end

    local found = false
    local new_rules = {}
    for _, existing in ipairs(rules) do
        if existing.id == rule_id then
            found = true
        else
            table.insert(new_rules, existing)
        end
    end

    if not found then
        return nil, "Rule not found: " .. rule_id
    end

    local ok, write_err = write_custom_rules(new_rules)
    if not ok then
        return nil, write_err
    end
    _M.bump_version()
    return true
end

-- Restore custom.yaml from default baseline (rules/ directory).
-- Backs up current file to custom.yaml.bak first.
-- Returns true on success, or nil + error message on failure.
function _M.restore_default()
    local conf_path = "/opt/moat/conf/rules/custom.yaml"
    local default_path = "/opt/moat/rules/custom.yaml"

    -- Backup current file
    local current = io.open(conf_path, "r")
    if current then
        local content = current:read("*all")
        current:close()
        if content then
            local bak, bak_err = io.open(conf_path .. ".bak", "w")
            if bak then
                bak:write(content)
                bak:close()
            else
                return nil, "Failed to create backup: " .. (bak_err or "unknown")
            end
        end
    end

    -- Read default file
    local default_f, open_err = io.open(default_path, "r")
    if not default_f then
        return nil, "Default rule file not found: " .. (open_err or "unknown")
    end
    local default_content = default_f:read("*all")
    default_f:close()

    -- Write default content to conf path
    local out, write_err = io.open(conf_path, "w")
    if not out then
        return nil, "Failed to write custom.yaml: " .. (write_err or "unknown")
    end
    out:write(default_content)
    out:close()

    _M.bump_version()
    return true
end

-- Validate a rule table. Returns true if valid, or nil + error message.
function _M.validate_rule(rule)
    if not rule or type(rule) ~= "table" then
        return nil, "Rule must be a table"
    end

    if not rule.id or type(rule.id) ~= "string" then
        return nil, "Rule id is required"
    end
    if not rule.id:match("^CUSTOM%-%d+$") then
        return nil, "Rule id must match format CUSTOM-NNN (e.g., CUSTOM-001)"
    end

    if not rule.description or type(rule.description) ~= "string" or rule.description == "" then
        return nil, "Rule description is required"
    end

    local valid_severities = { critical = true, high = true, medium = true, low = true }
    if not rule.severity or not valid_severities[rule.severity] then
        return nil, "Rule severity must be one of: critical, high, medium, low"
    end

    local valid_targets = { URI = true, ARGS = true, BODY = true, HEADERS = true, COOKIE = true }
    if not rule.target or not valid_targets[rule.target] then
        return nil, "Rule target must be one of: URI, ARGS, BODY, HEADERS, COOKIE"
    end

    if not rule.pattern or type(rule.pattern) ~= "string" or rule.pattern == "" then
        return nil, "Rule pattern is required and must be non-empty"
    end

    local valid_actions = { BLOCK = true, LOG = true }
    if not rule.action or not valid_actions[rule.action] then
        return nil, "Rule action must be BLOCK or LOG"
    end

    -- Validate that pattern compiles as PCRE
    local ok, err = pcall(function()
        local match_fn, ci = compile_pattern(rule.pattern)
        if not match_fn then
            error("pattern compilation failed")
        end
    end)
    if not ok then
        return nil, "Invalid PCRE pattern: " .. (err or "unknown error")
    end

    return true
end

---------------------------------------------------------------------------
-- Rule matching
---------------------------------------------------------------------------

-- Format HEADERS table into a searchable string.
-- Returns "Header-Name: value\nHeader-Name: value\n..."
local function format_headers(headers)
    if type(headers) == "string" then
        return headers
    end
    if type(headers) ~= "table" then
        return ""
    end
    local parts = {}
    for k, v in pairs(headers) do
        if type(v) == "table" then
            -- Multi-value header: join with newline
            for _, val in ipairs(v) do
                table.insert(parts, k .. ": " .. tostring(val))
            end
        else
            table.insert(parts, k .. ": " .. tostring(v))
        end
    end
    return table.concat(parts, "\n")
end

-- Match a single rule against the request context.
-- Returns true if the rule matches, false otherwise.
-- Optional third argument: normalized_cache table to avoid redundant normalize() calls.
function _M.match_rule(rule, request, normalized_cache)
    if not rule or not rule._match_fn then
        return false
    end

    local target = rule.target
    local value = request[target]

    -- Handle HEADERS table specially
    if target == "HEADERS" and type(value) == "table" then
        value = format_headers(value)
    end

    if not value or value == "" then
        return false
    end

    -- Ensure value is a string
    local str_value = tostring(value)

    -- Normalize the input to decode encoding bypass attempts.
    -- Use cached normalized value if available to avoid redundant work.
    local normalized
    if normalized_cache then
        local norm_key = target .. ":" .. str_value
        normalized = normalized_cache[norm_key]
        if not normalized then
            normalized = utils.normalize(str_value)
            normalized_cache[norm_key] = normalized
        end
    else
        normalized = utils.normalize(str_value)
    end

    -- Try matching the normalized value first (catches encoded attacks)
    if rule._match_fn(normalized) then
        if ngx then ngx.log(ngx.ERR, "WAF_MATCH: HIT rule=" .. (rule.id or "?") .. " target=" .. target .. " on normalized value") end
        return true
    end

    -- Also match raw value (catches plaintext attacks)
    if normalized ~= str_value and rule._match_fn(str_value) then
        if ngx then ngx.log(ngx.ERR, "WAF_MATCH: HIT rule=" .. (rule.id or "?") .. " target=" .. target .. " on raw value") end
        return true
    end

    return false
end

---------------------------------------------------------------------------
-- Request context
---------------------------------------------------------------------------

-- Build the request context from ngx variables.
-- This is the data structure that rule matching operates on.
function _M.build_request()
    -- When body exceeds client_body_buffer_size, get_body_data() returns nil
    -- and the body is written to a temp file. Read it to avoid silently bypassing BODY rules.
    local body_data = ngx.req.get_body_data()
    if not body_data then
        local body_file = ngx.req.get_body_file()
        if body_file then
            local f = io.open(body_file, "r")
            if f then
                body_data = f:read("*all") or ""
                f:close()
            end
        end
    end
    -- Limit body size to prevent memory issues (max 1MB for rule matching)
    if body_data and #body_data > 1048576 then
        body_data = body_data:sub(1, 1048576)
    end

    return {
        URI = ngx.var.uri or "",
        ARGS = ngx.var.query_string or "",
        BODY = body_data or "",
        HEADERS = ngx.req.get_headers(),
        COOKIE = ngx.var.http_cookie or "",
    }
end

---------------------------------------------------------------------------
-- Evaluation
---------------------------------------------------------------------------

-- Evaluate all rules against a request context.
-- Returns on the FIRST match (priority order from file load order).
-- Returns: action, rule_id, severity, description
--   action is "pass" when no rule matches.
function _M.evaluate(request)
    local rules = _M.load_rules()

    ngx.log(ngx.ERR, "WAF_EVAL: rules_count=" .. #rules .. " URI=" .. (request.URI or "nil") .. " ARGS=" .. (request.ARGS or "nil"))

    -- Cache normalized values per-target to avoid redundant normalize() calls across rules.
    local normalized_cache = {}

    for _, rule in ipairs(rules) do
        if _M.match_rule(rule, request, normalized_cache) then
            -- Record hit statistics
            if ngx then
                local stats = ngx.shared.waf_stats
                if stats then
                    stats:incr("rule_hit:" .. rule.id, 1, 0)
                    stats:set("rule_last_hit:" .. rule.id, ngx.time(), 0)
                end
            end
            return rule.action, rule.id, rule.severity, rule.description
        end
    end

    return "pass", nil, nil, nil
end

-- Get hit statistics for a rule
function _M.get_rule_hit_stats(rule_id)
    local stats = ngx.shared.waf_stats
    if not stats then return { count = 0, last_hit = 0 } end
    return {
        count = stats:get("rule_hit:" .. rule_id) or 0,
        last_hit = stats:get("rule_last_hit:" .. rule_id) or 0
    }
end

-- Main entry point: builds request context and evaluates all rules.
-- Returns: action, rule_id, severity, description
function _M.check()
    local request = _M.build_request()
    return _M.evaluate(request)
end

-- Get the number of currently loaded rules (useful for diagnostics)
function _M.rule_count()
    local rules = _M.load_rules()
    return #rules
end

return _M
