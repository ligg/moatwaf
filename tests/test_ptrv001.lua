-- Test: trace exactly what PTRV-001 pattern produces

-- Step 1: What does the YAML parser produce from: "\.\\./"
-- In YAML double-quoted string: \\. = literal backslash + dot, \\. = literal backslash + dot
-- So the raw string after YAML parsing should be: \.\./
local yaml_raw = "\\.\\./"  -- This is Lua string "\.\./" (5 bytes)
print("=== YAML raw string ===")
print("String: [" .. yaml_raw .. "]")
print("Length: " .. #yaml_raw)
for i = 1, #yaml_raw do
    print(string.format("  [%d] = %d (%s)", i, yaml_raw:byte(i), yaml_raw:sub(i,i)))
end

-- Step 2: yaml_unescape
local function yaml_unescape(str)
    str = str:gsub("\\\\", "\0")
    str = str:gsub('\\"', '"')
    str = str:gsub("\\n", "\n")
    str = str:gsub("\\t", "\t")
    str = str:gsub("\0", "\\")
    return str
end

local after_yaml = yaml_unescape(yaml_raw)
print("\n=== After yaml_unescape ===")
print("String: [" .. after_yaml .. "]")
print("Length: " .. #after_yaml)
for i = 1, #after_yaml do
    print(string.format("  [%d] = %d (%s)", i, after_yaml:byte(i), after_yaml:sub(i,i)))
end

-- Step 3: pcre_to_lua
local function fix_lua_pattern_metachars(pat)
    local result = {}
    local i = 1
    while i <= #pat do
        local c = pat:sub(i, i)
        if c == "%" and i < #pat then
            local next = pat:sub(i + 1, i + 1)
            if next == "%" then
                table.insert(result, "%%")
                i = i + 2
            else
                table.insert(result, "%" .. next)
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
    print("  pcre_to_lua input: [" .. pat .. "] (" .. #pat .. " bytes)")

    pat = pat:gsub("%(%?[a-z]+%)", "")
    print("  after strip flags: [" .. pat .. "]")

    pat = pat:gsub("\\b", "")
    print("  after \\b: [" .. pat .. "]")

    pat = pat:gsub("\\d", "%%d")
    pat = pat:gsub("\\s", "%%s")
    pat = pat:gsub("\\w", "%%w")
    pat = pat:gsub("\\D", "%%D")
    pat = pat:gsub("\\S", "%%S")
    pat = pat:gsub("\\W", "%%W")
    print("  after char classes: [" .. pat .. "]")

    -- Step 9: escape metachar after backslash
    pat = pat:gsub("\\([%.%%%+%-%*%?%[%]%^%$])", "%%1")
    print("  after escape metachar: [" .. pat .. "]")

    pat = pat:gsub("\\%)", "%%)")
    print("  after \\%): [" .. pat .. "]")

    pat = pat:gsub("\\%(", "%%(")
    print("  after \\%(: [" .. pat .. "]")

    -- Strip remaining backslash
    pat = pat:gsub("\\([^%%])", "%1")
    print("  after strip backslash: [" .. pat .. "]")

    pat = pat:gsub("([^%%])[()]", "%1")
    pat = pat:gsub("^[()]", "")
    print("  after strip parens: [" .. pat .. "]")

    pat = fix_lua_pattern_metachars(pat)
    print("  after fix_metachars: [" .. pat .. "]")

    return pat
end

local lua_pat = pcre_to_lua(after_yaml)

print("\n=== Final Lua pattern ===")
print("Pattern: [" .. lua_pat .. "]")
print("Length: " .. #lua_pat)
for i = 1, #lua_pat do
    print(string.format("  [%d] = %d (%s)", i, lua_pat:byte(i), lua_pat:sub(i,i)))
end

-- Step 4: Test matching
print("\n=== Match tests ===")
local test_cases = {
    {"/", "normal root URI"},
    {"/index.html", "normal page"},
    {"../etc/passwd", "path traversal"},
    {"/foo/bar", "normal path"},
    {"/../", "path with traversal"},
    {"..", "double dot only"},
}

for _, tc in ipairs(test_cases) do
    local str, desc = tc[1], tc[2]
    local find_s, find_e = str:find(lua_pat)
    local match_result = str:match(lua_pat)
    print(string.format("  %-20s find=%-5s match=[%s]  (%s)",
        str,
        find_s and (find_s .. "-" .. find_e) or "nil",
        tostring(match_result),
        desc))
end

-- Step 5: Also test simplify_for_lua behavior
print("\n=== simplify_for_lua test ===")
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

local has_group = find_innermost_group(after_yaml)
print("Has innermost group: " .. tostring(has_group))

-- Check for alternation at top level
local has_alt = false
local depth = 0
for i = 1, #after_yaml do
    local c = after_yaml:sub(i, i)
    if c == "\\" then
        -- skip next char
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
print("Conclusion: pattern goes directly to pcre_to_lua, result = [" .. lua_pat .. "]")
