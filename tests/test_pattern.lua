-- Test: does the Lua pattern %.%.%/ match "/" ?
local pat = "%.%./"
print("Pattern: " .. pat)
print("Length: " .. #pat)

local test_cases = {
    {"/", "normal root URI"},
    {"../etc/passwd", "path traversal"},
    {"/foo/bar", "normal path"},
    {"./file", "relative path"},
    {"..", "double dot only"},
    {"/../", "path with traversal"},
}

for _, tc in ipairs(test_cases) do
    local str, desc = tc[1], tc[2]
    local find_result = str:find(pat)
    print(string.format("  %-20s find=%-5s  match=%-5s  (%s)",
        str,
        tostring(find_result),
        tostring(str:match(pat) ~= nil),
        desc))
end

-- Now test what actual pcre_to_lua produces from the YAML pattern: \.\./
-- The YAML loads as literal: \.\./  (4 chars: backslash dot backslash dot slash)
print("\n--- Simulating pcre_to_lua('\\x5c.\\x5c./') ---")
-- In Lua, to get a string with literal backslash-dot-backslash-dot-slash:
local pcre_pat = "\\.\\./"
print("Input PCRE string bytes:")
for i = 1, #pcre_pat do
    print(string.format("  [%d] = %d (%s)", i, pcre_pat:byte(i), pcre_pat:sub(i,i)))
end

-- Step by step pcre_to_lua
local pat2 = pcre_pat
-- Step 1: gsub("%(%?[a-z]+%)", "") - remove flags
-- Step 2: gsub("\\b", "") - remove word boundary
-- Step 3-8: \d -> %d, \s -> %s, \w -> %w, etc.
-- Step 9: gsub("\\([%.%%%+%-%*%?%[%]%^%$])", "%%1") - escape metachar after backslash
print("\nStep: escape metachar after backslash")
local s9 = pat2:gsub("\\([%.%%%+%-%*%?%[%]%^%$])", "%%1")
print("Result: " .. s9)
for i = 1, #s9 do
    print(string.format("  [%d] = %d (%s)", i, s9:byte(i), s9:sub(i,i)))
end

-- Step 10: gsub("\\%)", "%%)")
-- Step 11: gsub("\\%(", "%%(")
-- Step 12: gsub("\\([^%%])", "%1") - strip remaining backslash
print("\nStep: strip remaining backslash")
local s12 = s9:gsub("\\([^%%])", "%1")
print("Result: " .. s12)
for i = 1, #s12 do
    print(string.format("  [%d] = %d (%s)", i, s12:byte(i), s12:sub(i,i)))
end

print("\n--- Final pattern test ---")
for _, tc in ipairs(test_cases) do
    local str, desc = tc[1], tc[2]
    local find_result = str:find(s12)
    print(string.format("  %-20s find=%-5s  match=%-5s  (%s)",
        str,
        tostring(find_result),
        tostring(str:match(s12) ~= nil),
        desc))
end
