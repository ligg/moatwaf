-- Trace pcre_to_lua step by step on the FIXED yaml_unescape output

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

local function show(s, label)
    io.write(label .. ": [" .. s .. "] len=" .. #s .. " bytes:")
    for i = 1, #s do io.write(string.format(" %d", s:byte(i))) end
    print("")
end

-- Input is what yaml_unescape_fixed produces from the YAML file content
local input = "\\.\\./"  -- This is what the YAML file has between quotes
show(input, "Raw YAML value")

local after_yaml = yaml_unescape_fixed(input)
show(after_yaml, "After fixed yaml_unescape")

-- Now trace pcre_to_lua step by step
local pat = after_yaml
show(pat, "pcre_to_lua input")

pat = pat:gsub("%(%?[a-z]+%)", "")
show(pat, "Step 1: remove flags")

pat = pat:gsub("\\b", "")
show(pat, "Step 2: remove \\b")

pat = pat:gsub("\\d", "%%d")
show(pat, "Step 3: \\d -> %%d")

pat = pat:gsub("\\s", "%%s")
show(pat, "Step 4: \\s -> %%s")

pat = pat:gsub("\\w", "%%w")
show(pat, "Step 5: \\w -> %%w")

pat = pat:gsub("\\D", "%%D")
show(pat, "Step 6: \\D -> %%D")

pat = pat:gsub("\\S", "%%S")
show(pat, "Step 7: \\S -> %%S")

pat = pat:gsub("\\W", "%%W")
show(pat, "Step 8: \\W -> %%W")

-- This is the critical step
pat = pat:gsub("\\([%.%%%+%-%*%?%[%]%^%$])", "%%1")
show(pat, "Step 9: escape metachar")

pat = pat:gsub("\\%)", "%%)")
show(pat, "Step 10: escape %)")

pat = pat:gsub("\\%(", "%%(")
show(pat, "Step 11: escape %(")

pat = pat:gsub("\\([^%%])", "%1")
show(pat, "Step 12: remove backslash")

pat = pat:gsub("([^%%])[()]", "%1")
show(pat, "Step 13: remove parens")

pat = pat:gsub("^[()]", "")
show(pat, "Step 14: remove leading paren")

-- Also test: what does \\ mean in a Lua pattern?
print("\n=== Lua pattern matching test ===")
local test_str = "../etc/passwd"
show(test_str, "Test string")

-- Does \\. match a literal dot?
local s, e = test_str:find("\\.")
print("find('\\\\.'): " .. tostring(s) .. "-" .. tostring(e))

-- Does %. match a literal dot?
s, e = test_str:find("%.")
print("find('%%.'): " .. tostring(s) .. "-" .. tostring(e))

-- Does .. match any two chars?
s, e = test_str:find("..")
print("find('..'): " .. tostring(s) .. "-" .. tostring(e))

-- Does \.\./ match?
s, e = test_str:find("\\.\\./")
print("find('\\\\.\\\\./'): " .. tostring(s) .. "-" .. tostring(e))

-- Does %.%.%/ match?
s, e = test_str:find("%%.%%.%%/")
print("find('%%.%%.%%/'): " .. tostring(s) .. "-" .. tostring(e))

-- What about the actual pattern from the test?
local broken_pat = " %1 %1/\\"  -- from the test output
print("\nBroken pattern test:")
show(broken_pat, "Broken pattern")
local ok, rs, re = pcall(function() return test_str:find(broken_pat) end)
print("find broken: " .. tostring(ok) .. " " .. tostring(rs) .. "-" .. tostring(re))

local fixed_pat = "%1%1/"  -- from the test output
show(fixed_pat, "Fixed pattern")
ok, rs, re = pcall(function() return test_str:find(fixed_pat) end)
print("find fixed: " .. tostring(ok) .. " " .. tostring(rs) .. "-" .. tostring(re))

-- What SHOULD the pattern be?
local correct_pat = "%.%.%/"
show(correct_pat, "Correct pattern")
ok, rs, re = pcall(function() return test_str:find(correct_pat) end)
print("find correct: " .. tostring(ok) .. " " .. tostring(rs) .. "-" .. tostring(re))

-- Test matching various URIs with correct pattern
print("\n=== Match with correct pattern ===")
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
    local ok2, s2, e2 = pcall(function() return str:find(correct_pat) end)
    print(string.format("  %-20s find=%-10s (%s)", str, ok2 and tostring(s2) or "ERR", desc))
end
