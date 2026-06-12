-- tests/unit/test_rule_engine.lua
-- Tests for lib/rule_engine.lua
--
-- NOTE: This test runs in plain Lua (not OpenResty), so we mock
-- cjson, ngx, and set up the package path appropriately.

-- Set up package path to find lib/ from project root
local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

-- Mock cjson since it's only available in OpenResty
package.loaded["cjson"] = {
    encode = function() return "{}" end,
    decode = function() return {} end,
}

-- Provide bit library shim for Lua 5.4+/5.5
if not bit then
    bit = {}
    function bit.band(a, b) return a & b end
    function bit.bor(a, b) return a | b end
    function bit.bxor(a, b) return a ~ b end
    function bit.lshift(a, n) return a << n end
    function bit.rshift(a, n) return a >> n end
end

-- Set up global ngx mock
if not ngx then
    ngx = {}
    ngx.log = function(level, ...) end  -- silent in tests
    ngx.ERR = 4
    ngx.now = function() return os.time() end
end

---------------------------------------------------------------------------
-- Helpers
---------------------------------------------------------------------------

-- Process YAML escape sequences in double-quoted strings (mirrors lib/rule_engine.lua)
local function yaml_unescape(str)
    str = str:gsub("\\\\", "\0")     -- temporarily replace \\ with placeholder
    str = str:gsub('\\"', '"')       -- \" -> "
    str = str:gsub("\\n", "\n")      -- \n -> newline
    str = str:gsub("\\t", "\t")      -- \t -> tab
    str = str:gsub("\0", "\\")       -- restore \\ as single backslash
    return str
end

local function assert_eq(actual, expected, msg)
    if actual ~= expected then
        error(string.format("FAIL: %s | expected=%q, got=%q", msg or "assert_eq", tostring(expected), tostring(actual)))
    end
end

local function assert_true(val, msg)
    if not val then
        error(string.format("FAIL: %s | expected true, got %s", msg or "assert_true", tostring(val)))
    end
end

local function assert_false(val, msg)
    if val then
        error(string.format("FAIL: %s | expected false, got %s", msg or "assert_false", tostring(val)))
    end
end

local function assert_match(str, pattern, msg)
    if not str:find(pattern) then
        error(string.format("FAIL: %s | %q did not match pattern %q", msg or "assert_match", str, pattern))
    end
end

local function assert_no_match(str, pattern, msg)
    if str:find(pattern) then
        error(string.format("FAIL: %s | %q matched pattern %q unexpectedly", msg or "assert_no_match", str, pattern))
    end
end

local function test_pass(name, fn)
    local ok, err = pcall(fn)
    if ok then
        print("  PASS: " .. name)
    else
        print("  FAIL: " .. name .. " - " .. tostring(err))
        os.exit(1)
    end
end

---------------------------------------------------------------------------
-- Test 1: YAML parsing
---------------------------------------------------------------------------
test_pass("YAML parsing - basic key-value", function()
    -- We test parse_rule_block indirectly through the pattern matching
    -- by checking that rules loaded from YAML have correct fields.
    -- We also directly test the parsing logic here.

    -- Inline test of the YAML parser logic (mirrors lib/rule_engine.lua)
    local function parse_rule_block(block)
        local rule = {}
        for line in block:gmatch("[^\r\n]+") do
            local trimmed = line:match("^%s*(.-)%s*$")
            if trimmed ~= "" and not trimmed:match("^#") then
                local key, value = trimmed:match("^([%w_]+):%s*(.+)$")
                if key and value then
                    local double_quoted = value:match('^"(.*)"$')
                    local single_quoted = value:match("^'(.*)'$")
                    if double_quoted then
                        rule[key] = yaml_unescape(double_quoted)
                    elseif single_quoted then
                        rule[key] = single_quoted
                    else
                        rule[key] = value
                    end
                end
            end
        end
        return rule
    end

    -- Test simple key-value
    local rule = parse_rule_block('id: TEST_001\ndescription: "Test rule"\ntarget: URI\npattern: test\\npattern\naction: block\nseverity: high')
    assert_eq(rule.id, "TEST_001", "id should be parsed")
    assert_eq(rule.description, "Test rule", "description should be unquoted")
    assert_eq(rule.target, "URI", "target should be parsed")
    assert_eq(rule.pattern, "test\\npattern", "pattern should be parsed")
    assert_eq(rule.action, "block", "action should be parsed")
    assert_eq(rule.severity, "high", "severity should be parsed")
end)

test_pass("YAML parsing - comments and blanks", function()
    local function parse_rule_block(block)
        local rule = {}
        for line in block:gmatch("[^\r\n]+") do
            local trimmed = line:match("^%s*(.-)%s*$")
            if trimmed ~= "" and not trimmed:match("^#") then
                local key, value = trimmed:match("^([%w_]+):%s*(.+)$")
                if key and value then
                    local double_quoted = value:match('^"(.*)"$')
                    local single_quoted = value:match("^'(.*)'$")
                    if double_quoted then
                        rule[key] = yaml_unescape(double_quoted)
                    elseif single_quoted then
                        rule[key] = single_quoted
                    else
                        rule[key] = value
                    end
                end
            end
        end
        return rule
    end

    local block = "# This is a comment\n\nid: TEST_002\n# Another comment\ntarget: ARGS\npattern: foo"
    local rule = parse_rule_block(block)
    assert_eq(rule.id, "TEST_002", "id should be parsed despite comments")
    assert_eq(rule.target, "ARGS", "target should be parsed")
end)

test_pass("YAML parsing - quoted values with colons", function()
    local function parse_rule_block(block)
        local rule = {}
        for line in block:gmatch("[^\r\n]+") do
            local trimmed = line:match("^%s*(.-)%s*$")
            if trimmed ~= "" and not trimmed:match("^#") then
                local key, value = trimmed:match("^([%w_]+):%s*(.+)$")
                if key and value then
                    local double_quoted = value:match('^"(.*)"$')
                    local single_quoted = value:match("^'(.*)'$")
                    if double_quoted then
                        rule[key] = yaml_unescape(double_quoted)
                    elseif single_quoted then
                        rule[key] = single_quoted
                    else
                        rule[key] = value
                    end
                end
            end
        end
        return rule
    end

    local block = 'id: TEST_003\ndescription: "SQL Injection - Union Select: testing"'
    local rule = parse_rule_block(block)
    assert_eq(rule.id, "TEST_003", "id parsed")
    assert_eq(rule.description, "SQL Injection - Union Select: testing",
        "description with colons should be unquoted")
end)

test_pass("YAML parsing - incomplete rules are skipped", function()
    local function parse_rule_block(block)
        local rule = {}
        for line in block:gmatch("[^\r\n]+") do
            local trimmed = line:match("^%s*(.-)%s*$")
            if trimmed ~= "" and not trimmed:match("^#") then
                local key, value = trimmed:match("^([%w_]+):%s*(.+)$")
                if key and value then
                    local double_quoted = value:match('^"(.*)"$')
                    local single_quoted = value:match("^'(.*)'$")
                    if double_quoted then
                        rule[key] = yaml_unescape(double_quoted)
                    elseif single_quoted then
                        rule[key] = single_quoted
                    else
                        rule[key] = value
                    end
                end
            end
        end
        return rule
    end

    local function parse_yaml_file(content)
        local rules = {}
        local current_block = {}
        local in_block = false
        for line in content:gmatch("([^\r\n]*)\r?\n?") do
            local trimmed = line:match("^%s*(.-)%s*$")
            if trimmed == "---" then
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
        if #current_block > 0 then
            local rule = parse_rule_block(table.concat(current_block, "\n"))
            if rule.id and rule.pattern then
                table.insert(rules, rule)
            end
        end
        return rules
    end

    local content = "---\nid: GOOD_001\npattern: test\n---\nid: NO_PATTERN\n---\npattern: no_id\n---\nid: GOOD_002\npattern: test2\n---"
    local rules = parse_yaml_file(content)
    assert_eq(#rules, 2, "should skip rules without id or pattern")
    assert_eq(rules[1].id, "GOOD_001", "first valid rule")
    assert_eq(rules[2].id, "GOOD_002", "second valid rule")
end)

---------------------------------------------------------------------------
-- Test 2: Rule loading from YAML files
---------------------------------------------------------------------------
test_pass("Rule loading - loads rules from rules/ directory", function()
    -- Clear any cached rules
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()
    assert_true(#rules > 0, "should load at least some rules from rules/ directory")
    print("    (loaded " .. #rules .. " rules)")
end)

test_pass("Rule loading - rules have required fields", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()
    for i, rule in ipairs(rules) do
        assert_true(rule.id ~= nil and rule.id ~= "",
            "rule " .. i .. " must have an id")
        assert_true(rule.pattern ~= nil and rule.pattern ~= "",
            "rule " .. i .. " must have a pattern")
        assert_true(rule.target ~= nil, "rule " .. i .. " must have a target")
        assert_true(rule.action ~= nil, "rule " .. i .. " must have an action")
        assert_true(rule.severity ~= nil, "rule " .. i .. " must have a severity")
        assert_true(rule._match_fn ~= nil, "rule " .. i .. " must have a compiled matcher")
    end
end)

test_pass("Rule loading - valid targets only", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()
    local valid_targets = { URI = true, ARGS = true, BODY = true, HEADERS = true, COOKIE = true }
    for _, rule in ipairs(rules) do
        assert_true(valid_targets[rule.target],
            "rule " .. rule.id .. " has invalid target: " .. tostring(rule.target))
    end
end)

test_pass("Rule loading - valid actions only", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()
    local valid_actions = { block = true, log = true, pass = true }
    for _, rule in ipairs(rules) do
        assert_true(valid_actions[rule.action],
            "rule " .. rule.id .. " has invalid action: " .. tostring(rule.action))
    end
end)

test_pass("Rule loading - caching works", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules1 = re.load_rules()
    local rules2 = re.load_rules()
    assert_true(rules1 == rules2, "cached rules should be the same table reference")
end)

test_pass("Rule loading - reload clears cache", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules1 = re.load_rules()
    local rules2 = re.reload_rules()
    -- After reload, the cache is cleared and rebuilt
    assert_true(#rules1 == #rules2, "reloaded rules should have same count")
end)

---------------------------------------------------------------------------
-- Test 3: Pattern matching
---------------------------------------------------------------------------
test_pass("Pattern matching - SQL injection UNION SELECT in URI", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    -- Find the SQLI_001 rule
    local rules = re.load_rules()
    local sqli_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "SQLI_001" then
            sqli_rule = rule
            break
        end
    end
    assert_true(sqli_rule ~= nil, "SQLI_001 rule should exist")

    -- Should match
    assert_true(re.match_rule(sqli_rule, { URI = "/path? UNION SELECT * FROM users" }),
        "should match UNION SELECT")
    assert_true(re.match_rule(sqli_rule, { URI = "/path?union all select 1,2,3" }),
        "should match union all select")
    assert_true(re.match_rule(sqli_rule, { URI = "/path?Union Select 1" }),
        "should match case-insensitive Union Select")

    -- Should NOT match
    assert_false(re.match_rule(sqli_rule, { URI = "/path?select=1" }),
        "should not match plain 'select'")
    assert_false(re.match_rule(sqli_rule, { URI = "/users/list" }),
        "should not match normal URI")
end)

test_pass("Pattern matching - XSS script tag in ARGS", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rules = re.load_rules()
    local xss_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "XSS_001" then
            xss_rule = rule
            break
        end
    end
    assert_true(xss_rule ~= nil, "XSS_001 rule should exist")

    assert_true(re.match_rule(xss_rule, { ARGS = "q=<script>alert(1)</script>" }),
        "should match <script> tag")
    assert_true(re.match_rule(xss_rule, { ARGS = "q=<script >" }),
        "should match <script > with space")
    assert_true(re.match_rule(xss_rule, { ARGS = 'q=<SCRIPT src="x.js">' }),
        "should match <SCRIPT> case-insensitive")
    assert_false(re.match_rule(xss_rule, { ARGS = "q=hello world" }),
        "should not match plain text")
end)

test_pass("Pattern matching - Path traversal dot-dot-slash", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rules = re.load_rules()
    local path_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "PATH_001" then
            path_rule = rule
            break
        end
    end
    assert_true(path_rule ~= nil, "PATH_001 rule should exist")

    assert_true(re.match_rule(path_rule, { URI = "/files/../../../etc/passwd" }),
        "should match ../ traversal")
    assert_true(re.match_rule(path_rule, { URI = "/files/..\\..\\..\\windows" }),
        "should match ..\\ traversal (Windows)")
    assert_false(re.match_rule(path_rule, { URI = "/files/test.txt" }),
        "should not match normal file path")
end)

test_pass("Pattern matching - Command injection pipe", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rules = re.load_rules()
    local cmd_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "CMD_001" then
            cmd_rule = rule
            break
        end
    end
    assert_true(cmd_rule ~= nil, "CMD_001 rule should exist")

    assert_true(re.match_rule(cmd_rule, { ARGS = "input=|cat /etc/passwd" }),
        "should match pipe |")
    assert_true(re.match_rule(cmd_rule, { ARGS = "input=||ls" }),
        "should match ||")
    assert_false(re.match_rule(cmd_rule, { ARGS = "input=hello" }),
        "should not match plain text")
end)

test_pass("Pattern matching - Scanner detection in User-Agent", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rules = re.load_rules()
    local scan_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "SCAN_001" then
            scan_rule = rule
            break
        end
    end
    assert_true(scan_rule ~= nil, "SCAN_001 rule should exist")

    assert_true(re.match_rule(scan_rule, { HEADERS = { ["User-Agent"] = "Nikto/2.1" } }),
        "should match Nikto User-Agent")
    assert_true(re.match_rule(scan_rule, { HEADERS = { ["User-Agent"] = "nikto" } }),
        "should match case-insensitive nikto")
    assert_false(re.match_rule(scan_rule, { HEADERS = { ["User-Agent"] = "Mozilla/5.0" } }),
        "should not match normal User-Agent")
end)

test_pass("Pattern matching - sensitive file .git", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rules = re.load_rules()
    local git_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "SENS_001" then
            git_rule = rule
            break
        end
    end
    assert_true(git_rule ~= nil, "SENS_001 rule should exist")

    assert_true(re.match_rule(git_rule, { URI = "/.git/config" }),
        "should match .git/config")
    assert_true(re.match_rule(git_rule, { URI = "/.git" }),
        "should match .git alone")
    assert_false(re.match_rule(git_rule, { URI = "/git/repo" }),
        "should not match /git/repo")
end)

test_pass("Pattern matching - missing target returns false", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rule = { _match_fn = function() return true end, target = "BODY" }
    -- No BODY in request
    assert_false(re.match_rule(rule, { URI = "/test" }),
        "should return false when target is missing from request")
end)

test_pass("Pattern matching - empty string returns false", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rule = { _match_fn = function() return true end, target = "ARGS" }
    assert_false(re.match_rule(rule, { ARGS = "" }),
        "should return false for empty string")
end)

test_pass("Pattern matching - normalize catches encoded attacks", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local rules = re.load_rules()
    local sqli_rule = nil
    for _, rule in ipairs(rules) do
        if rule.id == "SQLI_001" then
            sqli_rule = rule
            break
        end
    end
    assert_true(sqli_rule ~= nil, "SQLI_001 rule should exist")

    -- URL-encoded UNION SELECT
    assert_true(re.match_rule(sqli_rule, { URI = "/path?%20UNION%20SELECT%201" }),
        "should catch URL-encoded UNION SELECT via normalization")
end)

---------------------------------------------------------------------------
-- Test 4: Request evaluation
---------------------------------------------------------------------------
test_pass("Evaluate - returns first matching rule", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/test? UNION SELECT * FROM users",
        ARGS = "q=hello",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block on SQL injection")
    assert_true(rule_id ~= nil, "should return a rule_id")
    assert_true(severity ~= nil, "should return severity")
    assert_true(desc ~= nil, "should return description")
    print("    (matched rule: " .. rule_id .. ")")
end)

test_pass("Evaluate - clean request passes", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/index.html",
        ARGS = "page=1",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
        COOKIE = "session=abc123",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "pass", "clean request should pass")
    assert_eq(rule_id, nil, "no rule should match")
    assert_eq(severity, nil, "no severity")
end)

test_pass("Evaluate - XSS detection in ARGS", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/search",
        ARGS = "q=<script>alert(1)</script>",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block XSS")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

test_pass("Evaluate - path traversal detection", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/files/../../etc/passwd",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block path traversal")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

test_pass("Evaluate - scanner detection in User-Agent", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "sqlmap/1.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block scanner")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

test_pass("Evaluate - cookie injection detection", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "session=<script>steal()</script>",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block XSS in cookie")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

---------------------------------------------------------------------------
-- Test 5: Priority ordering
---------------------------------------------------------------------------
test_pass("Priority - rules loaded in file order", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()

    -- SQL rules should come before XSS rules (sql_injection.yaml loads first)
    local first_sqli_idx = nil
    local first_xss_idx = nil
    for i, rule in ipairs(rules) do
        if rule.id:match("^SQLI_") and not first_sqli_idx then
            first_sqli_idx = i
        end
        if rule.id:match("^XSS_") and not first_xss_idx then
            first_xss_idx = i
        end
    end
    assert_true(first_sqli_idx ~= nil, "should have SQL injection rules")
    assert_true(first_xss_idx ~= nil, "should have XSS rules")
    assert_true(first_sqli_idx < first_xss_idx,
        "SQL injection rules should come before XSS rules (priority)")
end)

test_pass("Priority - first match wins", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    -- Request that matches both SQLI and XSS rules
    -- SQLI should win because sql_injection.yaml loads first
    local request = {
        URI = "/test? UNION SELECT <script> FROM users",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block")
    assert_true(rule_id:match("^SQLI_"), "first match should be SQL injection, got: " .. rule_id)
end)

---------------------------------------------------------------------------
-- Test 6: No match scenario
---------------------------------------------------------------------------
test_pass("No match - clean request on all targets", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "pass", "clean root request should pass")
    assert_eq(rule_id, nil, "no rule should match")
end)

---------------------------------------------------------------------------
-- Test 7: Custom rules
---------------------------------------------------------------------------
test_pass("Custom rules - loaded from custom.yaml", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()

    local has_custom = false
    for _, rule in ipairs(rules) do
        if rule.id:match("^CUSTOM_") then
            has_custom = true
            break
        end
    end
    assert_true(has_custom, "should load custom rules")
end)

test_pass("Custom rules - match /api/internal/ path", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/api/internal/secret",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block /api/internal/ access")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

---------------------------------------------------------------------------
-- Test 8: HEADERS matching
---------------------------------------------------------------------------
test_pass("HEADERS - matches against all headers formatted as string", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    -- Custom rule for header matching
    local rule = { target = "HEADERS", pattern = "(?i)sqlmap" }
    local match_fn, _ = (function()
        local ci = rule.pattern:find("%(%?i[a-z]*%)") ~= nil
        local raw = rule.pattern:gsub("%(%?[%a]+%)", "")
        if not raw:find("%%") then
            raw = raw:gsub("\\d", "%%d"):gsub("\\s", "%%s"):gsub("\\w", "%%w")
        end
        local lua_pat = raw
        if ci then
            return function(str) return str:lower():find(lua_pat:lower()) ~= nil end, ci
        else
            return function(str) return str:find(lua_pat) ~= nil end, ci
        end
    end)()
    rule._match_fn = match_fn

    -- Table headers
    local headers = { ["User-Agent"] = "sqlmap/1.0", ["Accept"] = "*/*" }
    assert_true(re.match_rule(rule, { HEADERS = headers }),
        "should match sqlmap in formatted headers")

    -- String headers
    assert_true(re.match_rule(rule, { HEADERS = "User-Agent: sqlmap/1.0" }),
        "should match sqlmap in string headers")

    -- No match
    assert_false(re.match_rule(rule, { HEADERS = { ["User-Agent"] = "Mozilla/5.0" } }),
        "should not match normal User-Agent")
end)

---------------------------------------------------------------------------
-- Test 9: Missing/malformed rules handled gracefully
---------------------------------------------------------------------------
test_pass("Graceful handling - missing rule files", function()
    -- Temporarily point to a non-existent directory
    -- Since we can't easily change RULE_FILES in the module,
    -- we test that load_rules doesn't error when some files don't exist.
    -- All current files should exist, but the code handles io.open returning nil.
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()
    assert_true(type(rules) == "table", "should return a table even with missing files")
end)

---------------------------------------------------------------------------
-- Test 10: Word boundary patterns
---------------------------------------------------------------------------
test_pass("Word boundary - SQLI_003 matches OR/AND boolean", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local rules = re.load_rules()

    local sqli_003 = nil
    for _, rule in ipairs(rules) do
        if rule.id == "SQLI_003" then
            sqli_003 = rule
            break
        end
    end
    assert_true(sqli_003 ~= nil, "SQLI_003 rule should exist")

    assert_true(re.match_rule(sqli_003, { ARGS = "id=1' or 1=1--" }),
        "should match 'or 1=1'")
    assert_true(re.match_rule(sqli_003, { ARGS = "id=1 and 1=1" }),
        "should match 'and 1=1'")
end)

---------------------------------------------------------------------------
-- Test 11: Null byte detection
---------------------------------------------------------------------------
test_pass("Null byte detection in URI", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/index.html%00.png",
        ARGS = "",
        BODY = "",
        HEADERS = { ["User-Agent"] = "Mozilla/5.0" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block null byte in URI")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

---------------------------------------------------------------------------
-- Test 12: Multiple targets tested
---------------------------------------------------------------------------
test_pass("Multiple targets - BODY content detection", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")

    local request = {
        URI = "/api/data",
        ARGS = "",
        BODY = '{"query": "SELECT * FROM users"}',
        HEADERS = { ["User-Agent"] = "Mozilla/5.0", ["Content-Type"] = "application/json" },
        COOKIE = "",
    }

    local action, rule_id, severity, desc = re.evaluate(request)
    assert_eq(action, "block", "should block SQL injection in body")
    assert_true(rule_id ~= nil, "should match a rule")
    print("    (matched rule: " .. rule_id .. ")")
end)

---------------------------------------------------------------------------
-- Test 13: rule_count diagnostic
---------------------------------------------------------------------------
test_pass("Rule count returns total loaded rules", function()
    package.loaded["lib.rule_engine"] = nil
    local re = require("lib.rule_engine")
    local count = re.rule_count()
    assert_true(count > 0, "rule_count should be positive, got: " .. count)
    print("    (total rules: " .. count .. ")")
end)

---------------------------------------------------------------------------
-- Summary
---------------------------------------------------------------------------
print("\n=== ALL RULE ENGINE TESTS PASSED ===")
print("Total rules loaded: " .. require("lib.rule_engine").rule_count())
