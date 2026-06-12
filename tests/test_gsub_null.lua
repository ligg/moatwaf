-- Isolate the gsub("\0", "\\") issue
print("=== Test: gsub with null bytes ===")

-- Create a 5-byte string with null bytes
local s = string.char(0, 46, 0, 46, 47)
print("Input: len=" .. #s)
for i = 1, #s do io.write(string.format(" %d", s:byte(i))) end
print("")

-- Test gsub("\0", "\\")
local r1 = s:gsub("\0", "\\")
print("gsub(\\0, \\\\): len=" .. #r1)
for i = 1, #r1 do io.write(string.format(" %d", r1:byte(i))) end
print("")

-- Test with a character class approach
local r2 = s:gsub("\0", function() return "\\" end)
print("gsub(\\0, fn): len=" .. #r2)
for i = 1, #r2 do io.write(string.format(" %d", r2:byte(i))) end
print("")

-- Test: what does "\\" mean in gsub replacement?
-- In Lua, the replacement string uses % as escape, NOT \
-- So "\\" should be literal backslash
-- But let me check if there's a LuaJIT bug with null bytes

-- Test 3: byte-level approach (avoid gsub entirely)
local parts = {}
local i = 1
while i <= #s do
    if s:byte(i) == 0 then
        table.insert(parts, "\\")
    else
        table.insert(parts, s:sub(i, i))
    end
    i = i + 1
end
local r3 = table.concat(parts)
print("byte-level: len=" .. #r3)
for i = 1, #r3 do io.write(string.format(" %d", r3:byte(i))) end
print("")

-- Test 4: What if we use string.char(92) instead of "\\"?
local r4 = s:gsub("\0", string.char(92))
print("gsub(\\0, char(92)): len=" .. #r4)
for i = 1, #r4 do io.write(string.format(" %d", r4:byte(i))) end
print("")

-- Test 5: What if we escape differently?
local r5 = s:gsub("%z", "\\")
print("gsub(%%z, \\\\): len=" .. #r5)
for i = 1, #r5 do io.write(string.format(" %d", r5:byte(i))) end
print("")

-- Test 6: What if the issue is Lua pattern vs Lua string for null byte?
-- In Lua patterns, %z matches null byte
local r6 = s:gsub("%z", string.char(92))
print("gsub(%%z, char(92)): len=" .. #r6)
for i = 1, #r6 do io.write(string.format(" %d", r6:byte(i))) end
print("")

-- Test 7: Try replacing null with something else entirely
local r7 = s:gsub("\0", "X")
print("gsub(\\0, X): len=" .. #r7)
for i = 1, #r7 do io.write(string.format(" %d", r7:byte(i))) end
print("")

-- Test 8: What if gsub replacement treats \ as escape?
-- In some Lua implementations, \ in replacement might be treated specially
-- Let's test with a known-safe replacement
local test_str = "hello\0world"
print("\nTest with hello\\0world:")
print("  gsub(\\0, X): [" .. test_str:gsub("\0", "X") .. "]")
print("  gsub(\\0, \\\\): [" .. test_str:gsub("\0", "\\") .. "]")

-- Test 9: Check if the issue is specific to strings with multiple nulls
local s2 = string.char(0, 46, 47)
print("\n3-byte test [0, 46, 47]:")
local r9 = s2:gsub("\0", "\\")
print("  gsub result: len=" .. #r9)
for i = 1, #r9 do io.write(string.format(" %d", r9:byte(i))) end
print("")

-- Test 10: What about using rep?
local r10 = s:gsub("\0", string.rep("\\", 1))
print("gsub(\\0, rep(\\\\,1)): len=" .. #r10)
for i = 1, #r10 do io.write(string.format(" %d", r10:byte(i))) end
print("")
