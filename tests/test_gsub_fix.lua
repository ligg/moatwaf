-- Test gsub behavior with backslash pairs
local input = "\\\\.\\\\./"  -- 7 bytes
print("Input length: " .. #input)
for i = 1, #input do
    io.write(string.format("%d ", input:byte(i)))
end
print("")

-- Method 1: Current yaml_unescape approach
local s1 = input:gsub("\\\\", "\0")
print("gsub(\\\\\\\\, \\0) length: " .. #s1)
for i = 1, #s1 do
    io.write(string.format("%d ", s1:byte(i)))
end
print("")

-- Method 2: Fixed approach - byte-level
local function fix_backslashes(s)
    local result = {}
    local i = 1
    while i <= #s do
        if i + 1 <= #s and s:byte(i) == 92 and s:byte(i+1) == 92 then
            table.insert(result, "\\")
            i = i + 2
        else
            table.insert(result, s:sub(i, i))
            i = i + 1
        end
    end
    return table.concat(result)
end

local s2 = fix_backslashes(input)
print("fix_backslashes length: " .. #s2)
for i = 1, #s2 do
    io.write(string.format("%d ", s2:byte(i)))
end
print("")
