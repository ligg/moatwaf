-- Test with the ACTUAL YAML file content
-- YAML file has: pattern: "\\.\\./"
-- Our YAML parser extracts: \\.\\./ (between quotes)
-- In YAML double-quoted strings, \\ -> \, so \\.\\./ -> \.\./

-- But wait, our CUSTOM yaml parser doesn't handle YAML escapes properly!
-- Let me check what the custom parser actually does

-- Step 1: Read the actual YAML file and parse it
local function load_rules_from_file(filepath)
    local f = io.open(filepath, "r")
    if not f then return nil, "cannot open" end
    local content = f:read("*a")
    f:close()

    -- Parse YAML manually (simplified)
    local rules = {}
    local current = nil
    for line in content:gmatch("[^\r\n]+") do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line:match("^---") then
            if current then table.insert(rules, current) end
            current = {}
        elseif line:match("^[%w]") and current then
            local key, val = line:match("^(%w+):%s*(.*)$")
            if key and val then
                -- Handle quoted values
                local quoted = val:match('^"(.*)"$') or val:match("^'(.*)'$")
                if quoted then
                    current[key] = quoted
                else
                    current[key] = val
                end
            end
        end
    end
    if current then table.insert(rules, current) end
    return rules
end

print("=== Loading rules from actual YAML file ===")
local rules, err = load_rules_from_file("/opt/moat/conf/rules/path_traversal.yaml")
if not rules then
    print("ERROR: " .. tostring(err))
    return
end

local r1 = rules[1]
print("Rule ID: " .. tostring(r1.id))
print("Raw pattern from YAML: [" .. tostring(r1.pattern) .. "]")
print("Pattern length: " .. #r1.pattern)
print("Pattern bytes:")
for i = 1, #r1.pattern do
    print(string.format("  [%d] = %d (%s)", i, r1.pattern:byte(i), r1.pattern:sub(i,i)))
end

-- Now apply yaml_unescape
local function yaml_unescape(str)
    str = str:gsub("\\\\", "\0")
    str = str:gsub('\\"', '"')
    str = str:gsub("\\n", "\n")
    str = str:gsub("\\t", "\t")
    str = str:gsub("\0", "\\")
    return str
end

local after_yaml = yaml_unescape(r1.pattern)
print("\nAfter yaml_unescape: [" .. after_yaml .. "]")
print("Length: " .. #after_yaml)
print("Bytes:")
for i = 1, #after_yaml do
    print(string.format("  [%d] = %d (%s)", i, after_yaml:byte(i), after_yaml:sub(i,i)))
end

-- Now apply pcre_to_lua
local function fix_lua_pattern_metachars(pat)
    local result = {}
    local i = 1
    while i <= #pat do
        local c = pat:sub(i, i)
        if c == "%" and i < #pat then
            local next_c = pat:sub(i + 1, i + 1)
            if next_c == "%" then
                table.insert(result, "%%")
                i = i + 2
            else
                table.insert(result, "%" .. next_c)
                i = i + 2
            end
        elseif c == "-" then
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
    pat = pat:gsub("%(%?[a-z]+%)", "")
    pat = pat:gsub("\\b", "")
    pat = pat:gsub("\\d", "%%d")
    pat = pat:gsub("\\s", "%%s")
    pat = pat:gsub("\\w", "%%w")
    pat = pat:gsub("\\D", "%%D")
    pat = pat:gsub("\\S", "%%S")
    pat = pat:gsub("\\W", "%%W")
    pat = pat:gsub("\\([%.%%%+%-%*%?%[%]%^%$])", "%%1")
    pat = pat:gsub("\\%)", "%%)")
    pat = pat:gsub("\\%(", "%%(")
    pat = pat:gsub("\\([^%%])", "%1")
    pat = pat:gsub("([^%%])[()]", "%1")
    pat = pat:gsub("^[()]", "")
    pat = fix_lua_pattern_metachars(pat)
    return pat
end

local lua_pat = pcre_to_lua(after_yaml)
print("\nFinal Lua pattern: [" .. lua_pat .. "]")
print("Pattern length: " .. #lua_pat)
print("Pattern bytes:")
for i = 1, #lua_pat do
    print(string.format("  [%d] = %d (%s)", i, lua_pat:byte(i), lua_pat:sub(i,i)))
end

-- Match tests
print("\n=== Match tests ===")
local tests = {
    {"/", "root URI"},
    {"/index.html", "normal page"},
    {"../etc/passwd", "path traversal"},
    {"/foo/bar", "normal path"},
    {"/../", "with traversal"},
    {"..", "double dot"},
    {"/etc/passwd", "etc passwd"},
    {"/api/test", "normal API"},
}

for _, t in ipairs(tests) do
    local str, desc = t[1], t[2]
    local ok_find, find_s, find_e = pcall(function() return str:find(lua_pat) end)
    local ok_match, match_r = pcall(function() return str:match(lua_pat) end)
    print(string.format("  %-20s find=%-10s match=%-10s  (%s)",
        str,
        ok_find and tostring(find_s) or "ERR",
        ok_match and tostring(match_r) or "ERR",
        desc))
end
