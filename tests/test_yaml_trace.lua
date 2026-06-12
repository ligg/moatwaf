-- Test the exact YAML parsing pipeline for PTRV-001

local function yaml_unescape(str)
    str = str:gsub("\\\\", "\0")
    str = str:gsub('\\"', "\"")
    str = str:gsub("\\n", "\n")
    str = str:gsub("\\t", "\t")
    str = str:gsub("\0", "\\")
    return str
end

-- Read the actual YAML file
local f = io.open("/opt/moat/conf/rules/path_traversal.yaml", "r")
if not f then print("ERROR: cannot open file") return end
local content = f:read("*a")
f:close()

-- Find PTRV-001 block - extract lines between first --- and second ---
local in_ptrv = false
local block_lines = {}
for line in content:gmatch("([^\r\n]*)\r?\n?") do
    if line:match("^id: PTRV%-001") then
        in_ptrv = true
        table.insert(block_lines, line)
    elseif in_ptrv and line == "---" then
        break
    elseif in_ptrv then
        table.insert(block_lines, line)
    end
end
local ptrv_block = table.concat(block_lines, "\n")
print("PTRV-001 block:")
print(ptrv_block)
print("---")

-- Extract pattern line (process line by line, like parse_rule_block)
local pattern_line = nil
for line in ptrv_block:gmatch("[^\r\n]+") do
    local trimmed = line:match("^%s*(.-)%s*$")
    if trimmed:match("^pattern:") then
        pattern_line = trimmed:match("^pattern:%s*(.+)$")
        break
    end
end
print("\nPattern line: [" .. tostring(pattern_line) .. "]")
print("Pattern line length: " .. #pattern_line)
print("Pattern line bytes:")
for i = 1, #pattern_line do
    print(string.format("  [%d] = %d = %q", i, pattern_line:byte(i), pattern_line:sub(i,i)))
end

-- Extract between quotes (like parse_rule_block does)
local double_quoted = pattern_line:match('^"(.*)"$')
print("\nDouble quoted content: [" .. tostring(double_quoted) .. "]")
print("Double quoted length: " .. #double_quoted)
print("Double quoted bytes:")
for i = 1, #double_quoted do
    print(string.format("  [%d] = %d = %q", i, double_quoted:byte(i), double_quoted:sub(i,i)))
end

-- Apply yaml_unescape
local after_yaml = yaml_unescape(double_quoted)
print("\nAfter yaml_unescape: [" .. after_yaml .. "]")
print("After yaml_unescape length: " .. #after_yaml)
print("After yaml_unescape bytes:")
for i = 1, #after_yaml do
    print(string.format("  [%d] = %d = %q", i, after_yaml:byte(i), after_yaml:sub(i,i)))
end

-- Apply pcre_to_lua
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
print("Lua pattern length: " .. #lua_pat)
print("Lua pattern bytes:")
for i = 1, #lua_pat do
    print(string.format("  [%d] = %d = %q", i, lua_pat:byte(i), lua_pat:sub(i,i)))
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
