-- Debug PTRV-001 pattern compilation

local function yaml_unescape(str)
    str = str:gsub("\\\\", "\0")
    str = str:gsub('\\"', '"')
    str = str:gsub("\\n", "\n")
    str = str:gsub("\\t", "\t")
    str = str:gsub("\0", "\\")
    return str
end

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

local function strip_flags(pattern)
    return pattern:gsub("%(%?[%a]+%)", "")
end

-- Step 1: What YAML parser gets from: pattern: "\\.\\./"
-- The YAML file has literal bytes: " \ . \ . / "
-- YAML parser strips quotes, gets: \.\./
local yaml_raw = "\\.\\./"  -- In Lua: \.\./ (5 bytes: 92, 46, 92, 46, 47)
print("=== YAML raw (after quote strip) ===")
print("String: [" .. yaml_raw .. "] Length: " .. #yaml_raw)
for i = 1, #yaml_raw do
    print(string.format("  [%d] = %d (%s)", i, yaml_raw:byte(i), yaml_raw:sub(i,i)))
end

-- Step 2: yaml_unescape
local after_yaml = yaml_unescape(yaml_raw)
print("\n=== After yaml_unescape ===")
print("String: [" .. after_yaml .. "] Length: " .. #after_yaml)
for i = 1, #after_yaml do
    print(string.format("  [%d] = %d (%s)", i, after_yaml:byte(i), after_yaml:sub(i,i)))
end

-- Step 3: strip_flags (no flags in this pattern)
local stripped = strip_flags(after_yaml)
print("\n=== After strip_flags ===")
print("String: [" .. stripped .. "] Length: " .. #stripped)

-- Step 4: simplify_for_lua - check for groups
local function find_innermost_group(pat)
    local last_open = nil
    local i = 1
    while i <= #pat do
        local c = pat:sub(i, i)
        if c == "\\" and i < #pat then
            i = i + 2
        elseif c == "(" then
            last_open = i
            i = i + 1
        elseif c == ")" and last_open then
            local content = pat:sub(last_open + 1, i - 1)
            local rest = pat:sub(i + 1)
            return last_open, i, content, rest
        else
            i = i + 1
        end
    end
    return nil
end

local has_group = find_innermost_group(stripped)
print("Has innermost group: " .. tostring(has_group))

-- Check for top-level alternation
local has_alt = false
local depth = 0
for i = 1, #stripped do
    local c = stripped:sub(i, i)
    if c == "\\" then
        -- skip next
    elseif c == "(" then
        depth = depth + 1
    elseif c == ")" then
        depth = depth - 1
    elseif c == "|" and depth == 0 then
        has_alt = true
        break
    end
end
print("Has top-level alternation: " .. tostring(has_alt))

-- Step 5: pcre_to_lua
local lua_pat = pcre_to_lua(stripped)
print("\n=== Final Lua pattern ===")
print("Pattern: [" .. lua_pat .. "] Length: " .. #lua_pat)
for i = 1, #lua_pat do
    print(string.format("  [%d] = %d (%s)", i, lua_pat:byte(i), lua_pat:sub(i,i)))
end

-- Step 6: Match tests
print("\n=== Match tests ===")
local tests = {
    {"/", "root URI"},
    {"/index.html", "normal page"},
    {"../etc/passwd", "path traversal"},
    {"/foo/bar", "normal path"},
    {"/../", "with traversal"},
    {"..", "double dot"},
    {"/etc/passwd", "etc passwd"},
}

for _, t in ipairs(tests) do
    local str, desc = t[1], t[2]
    local ok_find, find_s, find_e = pcall(function() return str:find(lua_pat) end)
    local ok_match, match_r = pcall(function() return str:match(lua_pat) end)
    print(string.format("  %-20s find=%-10s match=%-10s  (%s)",
        str,
        ok_find and tostring(find_s) or "ERR:" .. tostring(find_s),
        ok_match and tostring(match_r) or "ERR:" .. tostring(match_r),
        desc))
end

-- Step 7: Also test what the ACTUAL file content looks like
print("\n=== Testing with raw PCRE string (as stored in Lua variable) ===")
local raw_pcre = "\\.\\./"
print("raw_pcre bytes: ")
for i = 1, #raw_pcre do
    print(string.format("  [%d] = %d (%s)", i, raw_pcre:byte(i), raw_pcre:sub(i,i)))
end
print("yaml_unescape(raw_pcre): [" .. yaml_unescape(raw_pcre) .. "]")
print("pcre_to_lua(yaml_unescape(raw_pcre)): [" .. pcre_to_lua(yaml_unescape(raw_pcre)) .. "]")
