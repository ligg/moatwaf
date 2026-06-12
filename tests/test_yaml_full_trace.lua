-- Trace full yaml_unescape on actual YAML file content
local function yaml_unescape(str)
    local orig_len = #str
    print("  input: len=" .. #str)
    for i = 1, #str do io.write(string.format(" %d", str:byte(i))) end
    print("")

    str = str:gsub("\\\\", "\0")
    print("  after gsub(\\\\\\\\, \\0): len=" .. #str)
    for i = 1, #str do io.write(string.format(" %d", str:byte(i))) end
    print("")

    str = str:gsub('\\"', '"')
    print('  after gsub(\\\\" , "): len=' .. #str)
    for i = 1, #str do io.write(string.format(" %d", str:byte(i))) end
    print("")

    str = str:gsub("\\n", "\n")
    print("  after gsub(\\\\n, \\n): len=" .. #str)

    str = str:gsub("\\t", "\t")
    print("  after gsub(\\\\t, \\t): len=" .. #str)

    str = str:gsub("\0", "\\")
    print("  after gsub(\\0, \\\\): len=" .. #str)
    for i = 1, #str do io.write(string.format(" %d", str:byte(i))) end
    print("")

    return str
end

-- Read the ACTUAL YAML file
local f = io.open("/opt/moat/conf/rules/path_traversal.yaml", "r")
if not f then print("ERROR: cannot open file") return end
local content = f:read("*a")
f:close()

-- Find PTRV-001 pattern line
local pattern_value = nil
local in_ptrv = false
for line in content:gmatch("[^\r\n]+") do
    if line:match("^id: PTRV%-001") then
        in_ptrv = true
    end
    if in_ptrv then
        local val = line:match('^%s*pattern:%s*"(.+)"')
        if val then
            pattern_value = val
            break
        end
    end
end

if not pattern_value then
    print("ERROR: could not find PTRV-001 pattern")
    return
end

print("Raw pattern_value from file: [" .. pattern_value .. "]")
print("Raw length: " .. #pattern_value)
for i = 1, #pattern_value do
    io.write(string.format(" %d", pattern_value:byte(i)))
end
print("")
print("")

print("=== yaml_unescape trace ===")
local result = yaml_unescape(pattern_value)
print("\nResult: [" .. result .. "]")
print("Result length: " .. #result)
for i = 1, #result do
    io.write(string.format(" %d", result:byte(i)))
end
print("")

-- Now test what the ACTUAL rule_engine.lua does vs our fixed version
print("\n=== Fixed yaml_unescape ===")
local function yaml_unescape_fixed(str)
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
        elseif str:byte(i) == 92 and i + 1 <= #str then
            table.insert(result, str:sub(i, i+1))
            i = i + 2
        else
            table.insert(result, str:sub(i, i))
            i = i + 1
        end
    end
    return table.concat(result)
end

local fixed = yaml_unescape_fixed(pattern_value)
print("Fixed result: [" .. fixed .. "]")
print("Fixed length: " .. #fixed)
for i = 1, #fixed do
    io.write(string.format(" %d", fixed:byte(i)))
end
print("")

-- Now test pcre_to_lua on both
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
    return pat
end

local lua_pat_broken = pcre_to_lua(result)
local lua_pat_fixed = pcre_to_lua(fixed)

print("\n=== Lua patterns ===")
print("Broken pattern: [" .. lua_pat_broken .. "] len=" .. #lua_pat_broken)
print("Fixed pattern: [" .. lua_pat_fixed .. "] len=" .. #lua_pat_fixed)

-- Match tests
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

print("\n=== Match with BROKEN pattern ===")
for _, t in ipairs(tests) do
    local str, desc = t[1], t[2]
    local ok, s, e = pcall(function() return str:find(lua_pat_broken) end)
    print(string.format("  %-20s find=%-10s (%s)", str, ok and tostring(s) or "ERR", desc))
end

print("\n=== Match with FIXED pattern ===")
for _, t in ipairs(tests) do
    local str, desc = t[1], t[2]
    local ok, s, e = pcall(function() return str:find(lua_pat_fixed) end)
    print(string.format("  %-20s find=%-10s (%s)", str, ok and tostring(s) or "ERR", desc))
end
