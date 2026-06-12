-- lib/upload_check.lua
-- File upload validation module
-- Checks file extensions, magic numbers, content type consistency, and shell code injection
local _M = {}

local cjson = require "cjson"

---------------------------------------------------------------------------
-- Magic number definitions: hex_prefix -> MIME type
---------------------------------------------------------------------------

local MAGIC_NUMBERS = {
    -- Images
    { prefix = "FFD8FF",       mime = "image/jpeg" },
    { prefix = "89504E47",     mime = "image/png" },
    { prefix = "47494638",     mime = "image/gif" },
    { prefix = "52494646",     mime = "image/webp" },
    -- Documents
    { prefix = "25504446",     mime = "application/pdf" },
    { prefix = "D0CF11E0",     mime = "application/msword" },
    -- Archives
    { prefix = "504B0304",     mime = "application/zip" },
    { prefix = "1F8B08",       mime = "application/gzip" },
    -- Executables (CRITICAL - must be blocked)
    { prefix = "4D5A",         mime = "application/x-dosexec" },
    { prefix = "7F454C46",     mime = "application/x-elf" },
}

---------------------------------------------------------------------------
-- Extension lists
---------------------------------------------------------------------------

-- Dangerous extensions that should be blocked in uploads
local DANGEROUS_EXTENSIONS = {
    -- PHP variants
    ["php"]   = true,
    ["php3"]  = true,
    ["php4"]  = true,
    ["php5"]  = true,
    ["php7"]  = true,
    ["phtml"] = true,
    ["pht"]   = true,
    -- ASP variants
    ["asp"]   = true,
    ["aspx"]  = true,
    ["asa"]   = true,
    ["asax"]  = true,
    ["ascx"]  = true,
    ["ashx"]  = true,
    ["asmx"]  = true,
    -- Java
    ["jsp"]   = true,
    ["jspx"]  = true,
    ["jsw"]   = true,
    ["jsv"]   = true,
    ["jspf"]  = true,
    -- Scripting / shell
    ["cgi"]   = true,
    ["pl"]    = true,
    ["py"]    = true,
    ["rb"]    = true,
    ["sh"]    = true,
    ["bash"]  = true,
    ["csh"]   = true,
    -- Windows executables
    ["exe"]   = true,
    ["bat"]   = true,
    ["cmd"]   = true,
    ["com"]   = true,
    ["msi"]   = true,
    ["scr"]   = true,
    -- Java archives
    ["war"]   = true,
    ["ear"]   = true,
    ["jar"]   = true,
    -- Config / sensitive
    ["htaccess"]  = true,
    ["htpasswd"]  = true,
    ["config"]    = true,
    ["ini"]       = true,
    ["env"]       = true,
}

-- Allowed extensions for upload
local ALLOWED_EXTENSIONS = {
    ["jpg"]  = true,
    ["jpeg"] = true,
    ["png"]  = true,
    ["gif"]  = true,
    ["webp"] = true,
    ["pdf"]  = true,
    ["doc"]  = true,
    ["docx"] = true,
    ["xls"]  = true,
    ["xlsx"] = true,
    ["ppt"]  = true,
    ["pptx"] = true,
    ["txt"]  = true,
    ["csv"]  = true,
    ["zip"]  = true,
    ["rar"]  = true,
    ["7z"]   = true,
}

-- Known MIME type to extension mapping for content-type validation
local MIME_TO_EXTENSIONS = {
    ["image/jpeg"]                = { "jpg", "jpeg" },
    ["image/png"]                 = { "png" },
    ["image/gif"]                 = { "gif" },
    ["image/webp"]                = { "webp" },
    ["application/pdf"]           = { "pdf" },
    ["application/msword"]        = { "doc" },
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = { "docx" },
    ["application/vnd.ms-excel"]  = { "xls" },
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = { "xlsx" },
    ["application/vnd.ms-powerpoint"] = { "ppt" },
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = { "pptx" },
    ["text/plain"]                = { "txt" },
    ["text/csv"]                  = { "csv" },
    ["application/zip"]           = { "zip" },
    ["application/x-rar-compressed"] = { "rar" },
    ["application/x-7z-compressed"]  = { "7z" },
}

-- Parse size string with optional k/m/K/M suffix to bytes
-- Returns nil for invalid input
function _M.parse_size(str)
    if not str or str == "" then return nil end
    str = str:match("^%s*(.-)%s*$")
    local num, unit = str:match("^(%d+%.?%d*)([kKmM]?)$")
    if not num then return nil end
    num = tonumber(num)
    if not num then return nil end
    if unit == "m" or unit == "M" then
        return math.floor(num * 1024 * 1024)
    elseif unit == "k" or unit == "K" then
        return math.floor(num * 1024)
    end
    return math.floor(num)
end

-- Get max upload size from WAF_MAX_UPLOAD_SIZE env var, default 10MB
function _M.get_max_upload_size()
    local env_val = os.getenv("WAF_MAX_UPLOAD_SIZE")
    if env_val then
        local bytes = _M.parse_size(env_val)
        if bytes and bytes > 0 then return bytes end
    end
    return 10 * 1024 * 1024
end

local MAX_UPLOAD_SIZE = _M.get_max_upload_size()

---------------------------------------------------------------------------
-- Utility functions
---------------------------------------------------------------------------

-- Extract file extension from filename (lowercase, without dot)
-- Returns nil if no extension found
function _M.get_extension(filename)
    if not filename or filename == "" then
        return nil
    end
    filename = filename:gsub("%z", "")
    filename = filename:gsub("[%.%s]+$", "")
    if filename == "" then
        return nil
    end
    local basename = filename:match("([^/\\]+)$") or filename
    local ext = basename:match("%.([^.]+)$")
    if ext then
        return ext:lower()
    end
    return nil
end

-- Read first N bytes of request body for magic number detection
-- Uses ngx.req.read_body() + ngx.req.get_body_file() for large bodies
function _M.read_body_prefix(max_bytes)
    max_bytes = max_bytes or 8  -- default 8 bytes for magic number check

    -- First try in-memory body data
    local body_data = ngx.req.get_body_data()
    if body_data then
        if #body_data >= max_bytes then
            return body_data:sub(1, max_bytes)
        end
        return body_data
    end

    -- Body written to temp file (large body)
    local body_file = ngx.req.get_body_file()
    if body_file then
        local f = io.open(body_file, "rb")
        if f then
            local prefix = f:read(max_bytes)
            f:close()
            return prefix
        end
    end

    return nil
end

-- Read full request body (from memory or temp file)
-- Returns body string or nil
function _M.read_full_body()
    local body_data = ngx.req.get_body_data()
    if body_data then
        if #body_data > MAX_UPLOAD_SIZE then
            return nil, "file_too_large"
        end
        return body_data
    end

    local body_file = ngx.req.get_body_file()
    if body_file then
        local f = io.open(body_file, "rb")
        if f then
            -- Check file size before reading into memory
            f:seek("end")
            local size = f:tell()
            f:seek("set")
            if size > MAX_UPLOAD_SIZE then
                f:close()
                return nil, "file_too_large"
            end
            local data = f:read("*all")
            f:close()
            return data
        end
    end

    return nil
end

-- Convert bytes string to hex string (uppercase)
function _M.bytes_to_hex(bytes)
    if not bytes or bytes == "" then
        return ""
    end
    local hex_parts = {}
    for i = 1, #bytes do
        table.insert(hex_parts, string.format("%02X", string.byte(bytes, i)))
    end
    return table.concat(hex_parts)
end

-- Detect file type from magic number bytes
-- Returns MIME type string or nil if unknown
function _M.detect_type(data_prefix)
    if not data_prefix or #data_prefix < 2 then
        return nil
    end

    local hex = _M.bytes_to_hex(data_prefix)

    -- Check each known magic number (longest prefix first to avoid partial matches)
    for _, entry in ipairs(MAGIC_NUMBERS) do
        if hex:sub(1, #entry.prefix) == entry.prefix then
            return entry.mime
        end
    end

    return nil
end

-- Check if file content contains shell code / code injection patterns
-- Returns true if shell code detected, false otherwise
function _M.contains_shell_code(data)
    if not data or data == "" then
        return false
    end

    local shell_patterns = {
        { pattern = "<?php",              desc = "PHP tag" },
        { pattern = "<%",                 desc = "ASP tag" },
        { pattern = "<script",            desc = "Script tag" },
        { pattern = "#!/bin/",            desc = "Shell shebang" },
        { pattern = "#!/usr/bin/",        desc = "Shell shebang" },
        { pattern = "import os",          desc = "Python import os" },
        { pattern = "import subprocess",  desc = "Python subprocess" },
        { pattern = "os.system(",         desc = "Python os.system" },
        { pattern = "eval(",              desc = "eval() call" },
        { pattern = "exec(",              desc = "exec() call" },
        { pattern = "system(",            desc = "PHP system()" },
        { pattern = "passthru(",          desc = "PHP passthru()" },
        { pattern = "shell_exec(",        desc = "PHP shell_exec()" },
        { pattern = "popen(",             desc = "PHP popen()" },
        { pattern = "proc_open(",         desc = "PHP proc_open()" },
        { pattern = "runtime.getruntime()", desc = "Java Runtime.exec" },
        { pattern = "processbuilder",       desc = "Java ProcessBuilder" },
        { pattern = "cfexecute",            desc = "CFML cfexecute" },
        { pattern = "cfhttp",               desc = "CFML cfhttp" },
    }

    -- Check both raw data and null-byte-stripped data
    -- Raw check catches payloads hidden behind null bytes in the source
    -- Stripped check catches payloads where nulls are inserted within keywords
    local check_data = data:gsub("%z", "")
    local lower_raw = data:lower()
    local lower_stripped = check_data:lower()
    for _, entry in ipairs(shell_patterns) do
        local p = entry.pattern:lower()
        if lower_raw:find(p, 1, true) or lower_stripped:find(p, 1, true) then
            return true, entry.desc
        end
    end

    return false, nil
end

---------------------------------------------------------------------------
-- Main check function
---------------------------------------------------------------------------

-- Validate uploaded file
-- Parameters:
--   filename: original filename from Content-Disposition
--   content_type: Content-Type header value
--   body_prefix: first N bytes of body (optional, will be read if nil)
--   full_body: full body data (optional, will be read if nil)
-- Returns: { allowed = bool, reason = string|nil, detected_type = string|nil }
function _M.check(filename, content_type, body_prefix, full_body)
    local result = {
        allowed = true,
        reason = nil,
        detected_type = nil,
    }

    -- Extract extension
    local ext = _M.get_extension(filename)

    ---------------------------------------------------------------
    -- Check 1: Dangerous extension blocklist
    ---------------------------------------------------------------
    if filename and filename ~= "" then
        local sanitized = filename:gsub("%z", ""):gsub("[%.%s]+$", "")
        local basename_d = sanitized:match("([^/\\]+)$") or sanitized
        for segment in basename_d:gmatch("%.([^.]+)") do
            local seg_lower = segment:lower()
            if DANGEROUS_EXTENSIONS[seg_lower] then
                result.allowed = false
                result.reason = "UPLOAD-001: Dangerous file extension blocked: ." .. seg_lower
                return result
            end
        end
    end

    ---------------------------------------------------------------
    -- Check 2: File size (10 MB limit)
    ---------------------------------------------------------------
    if full_body and #full_body > MAX_UPLOAD_SIZE then
        result.allowed = false
        result.reason = string.format(
            "UPLOAD-002: File size exceeds limit (%d MB max, got %d bytes)",
            MAX_UPLOAD_SIZE / (1024 * 1024), #full_body
        )
        return result
    end

    ---------------------------------------------------------------
    -- Check 3: Read body prefix for magic number check
    ---------------------------------------------------------------
    if not body_prefix then
        body_prefix = _M.read_body_prefix(8)
    end

    ---------------------------------------------------------------
    -- Check 4: Detect file type from magic number
    ---------------------------------------------------------------
    if body_prefix and #body_prefix >= 4 then
        local detected = _M.detect_type(body_prefix)
        result.detected_type = detected

        -- Block executables detected by magic number
        if detected == "application/x-dosexec" or detected == "application/x-elf" then
            result.allowed = false
            result.reason = "UPLOAD-001: Executable file detected by magic number: " .. detected
            return result
        end

        -- Content-type mismatch detection
        if ext and detected and content_type and content_type ~= "" then
            -- Strip parameters from content_type (e.g., "image/jpeg; charset=..." -> "image/jpeg")
            local ct_base = content_type:match("^([^;]+)")
            if ct_base then
                ct_base = ct_base:match("^%s*(.-)%s*$") -- trim whitespace
                -- Check if the declared content type matches the detected type
                if ct_base ~= detected then
                    -- Special case: MS Office compound documents share magic number D0CF11E0
                    -- but may have various MIME types
                    local ext_matches_mime = false
                    local allowed_mimes = MIME_TO_EXTENSIONS[ct_base]
                    if allowed_mimes then
                        for _, allowed_ext in ipairs(allowed_mimes) do
                            if allowed_ext == ext then
                                ext_matches_mime = true
                                break
                            end
                        end
                    end

                    if not ext_matches_mime then
                        result.allowed = false
                        result.reason = string.format(
                            "UPLOAD-003: Content type mismatch - declared '%s' but file content is '%s'",
                            ct_base, detected
                        )
                        return result
                    end
                end
            end
        end
    end

    ---------------------------------------------------------------
    -- Check 5: Shell code detection
    ---------------------------------------------------------------
    if not full_body then
        full_body = _M.read_full_body()
    end

    if full_body then
        local has_shell, shell_desc = _M.contains_shell_code(full_body)
        if has_shell then
            result.allowed = false
            result.reason = "UPLOAD-004: Shell code detected in file content: " .. (shell_desc or "unknown")
            return result
        end
    end

    ---------------------------------------------------------------
    -- Check 6: Extension must be in allowed list (if extension present)
    ---------------------------------------------------------------
    if ext and not ALLOWED_EXTENSIONS[ext] and not DANGEROUS_EXTENSIONS[ext] then
        -- Unknown extension that isn't explicitly dangerous but also not allowed
        result.allowed = false
        result.reason = "UPLOAD-001: File extension not in allowed list: ." .. ext
        return result
    end

    return result
end

return _M
