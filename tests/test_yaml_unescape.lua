-- Test yaml_unescape step by step
local input = "\\.\\./"  -- 5 bytes: 92,46,92,46,47
print("Input: [" .. input .. "] bytes=" .. #input)

-- Step 1: gsub("\\\\", "\0")
local s1 = input:gsub("\\\\", "\0")
print("After step1 (\\\\\\ -> \\0): [" .. s1 .. "] bytes=" .. #s1)
for i = 1, #s1 do print(string.format("  [%d] = %d", i, s1:byte(i))) end

-- Step 2: gsub('\\"', '"')
local s2 = s1:gsub('\\"', '"')
print("After step2 (\\\\\" -> \"): [" .. s2 .. "] bytes=" .. #s2)

-- Step 3: gsub("\\n", "\n")
local s3 = s2:gsub("\\n", "\n")
print("After step3: [" .. s3 .. "] bytes=" .. #s3)

-- Step 4: gsub("\\t", "\t")
local s4 = s3:gsub("\\t", "\t")
print("After step4: [" .. s4 .. "] bytes=" .. #s4)

-- Step 5: gsub("\0", "\\")
local s5 = s4:gsub("\0", "\\")
print("After step5 (\\0 -> \\\\): [" .. s5 .. "] bytes=" .. #s5)
for i = 1, #s5 do print(string.format("  [%d] = %d", i, s5:byte(i))) end

print("\n--- What if the real problem is the YAML parser? ---")
-- The YAML file has: pattern: "\\.\\./"
-- What does the YAML parser actually produce?
-- In YAML double-quoted: \\ = \, \. = error? or \. = \.?
-- YAML spec: in double-quoted, \\ -> \, and \. is NOT a valid escape
-- so \. might be kept as-is (\.), or the \ might be stripped

-- Test: what if YAML parser strips the \ before . ?
local yaml_v1 = "\\.\./"  -- YAML strips \ before .: 4 bytes: 92,46,46,47
print("yaml_v1 (if YAML strips \\ before .): [" .. yaml_v1 .. "] bytes=" .. #yaml_v1)
for i = 1, #yaml_v1 do print(string.format("  [%d] = %d", i, yaml_v1:byte(i))) end

-- Test: what if YAML keeps \. as-is?
local yaml_v2 = "\\.\\./"  -- 5 bytes
print("yaml_v2 (keeps \\.): [" .. yaml_v2 .. "] bytes=" .. #yaml_v2)

-- The REAL question: what does our CUSTOM YAML parser produce?
-- Let's just read the actual YAML file content and parse it
print("\n--- Testing with the ACTUAL yaml_unescape from rule_engine ---")
local function yaml_unescape(str)
    str = str:gsub("\\\\", "\0")
    str = str:gsub('\\"', '"')
    str = str:gsub("\\n", "\n")
    str = str:gsub("\\t", "\t")
    str = str:gsub("\0", "\\")
    return str
end

-- What our YAML parser gets from the file
-- The YAML file line is: pattern: "\\.\\./"
-- Our parser extracts the value between quotes: \\.\\./
-- In Lua source code, to represent \\\.\\. / we write: "\\\\\\./"

-- Actually, let's think about what the YAML FILE contains as raw bytes:
-- pattern: "\\.\\./"
-- The bytes in the file: p a t t e r n : " \ \ . \ \ . / "
-- Wait, is it \\.\\. or \.\.? Let me check the actual YAML file content

-- From the earlier context, the YAML file has:
-- pattern: "\\.\\./"
-- That means the file contains: \ . \ . / (with backslash-dot-backslash-dot-slash)
-- The YAML parser strips the outer quotes, giving: \.\./

print("Testing yaml_unescape with '\\\\.\\\\./' (escaped Lua for \\\\.\\\\./):")
local test1 = "\\\\.\\\\./"
print("  input bytes: " .. #test1)
for i = 1, #test1 do print(string.format("  [%d] = %d", i, test1:byte(i))) end
local r1 = yaml_unescape(test1)
print("  result: [" .. r1 .. "] bytes=" .. #r1)
for i = 1, #r1 do print(string.format("  [%d] = %d", i, r1:byte(i))) end
