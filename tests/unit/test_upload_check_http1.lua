-- tests/unit/test_upload_check_http1.lua
-- Regression test: HTTP/1.1 multipart uploads must not be blocked by UPLOAD-005.
--
-- The WAF pre-reads the request body in access_phase (the rule engine inspects
-- POST bodies) and only then calls check_multipart(). resty.upload:new() needs
-- an unread body: it calls ngx.req.socket(), which fails with
-- "request body already exists" once the body has been read. That used to make
-- every HTTP/1.1 multipart upload fail with UPLOAD-005, so legitimate uploads
-- (e.g. POST /cpi/files/upload) were rejected with 403.

local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

package.loaded["cjson"] = {
    encode = function() return "{}" end,
    decode = function() return {} end,
}

-- Simulate resty.upload being available (as in OpenResty) but unable to
-- initialize because the request body was already consumed.
local resty_new_called = false
local current_body = ""
package.loaded["resty.upload"] = {
    new = function()
        resty_new_called = true
        return nil, "request body already exists"
    end,
}

_G.ngx = {
    ERR = 4,
    log = function() end,
    var = {
        remote_addr = "127.0.0.1",
    },
    req = {
        http_version = function() return 1 end,
        get_headers = function() return {} end,
        get_body_data = function() return current_body end,
        get_body_file = function() return nil end,
        read_body = function() end,
    },
}

package.loaded["lib.upload_check"] = nil
local upload_check = require("lib.upload_check")

local function multipart_body(filename, content_type, file_bytes)
    return (
        "--BOUNDARY\r\n" ..
        'Content-Disposition: form-data; name="file"; filename="' .. filename .. '"\r\n' ..
        "Content-Type: " .. content_type .. "\r\n" ..
        "\r\n" ..
        file_bytes ..
        "\r\n--BOUNDARY--\r\n"
    )
end

current_body = multipart_body("photo.png", "image/png", "\x89PNG\r\n\x1A\nhello")
local result = upload_check.check_multipart("multipart/form-data; boundary=BOUNDARY")

assert(type(result) == "table", "check_multipart should return a result table")
assert(
    result.allowed == true,
    "HTTP/1.1 multipart PNG upload should be allowed, got reason: " ..
        tostring(result and result.reason)
)
assert(
    tostring(result.reason):find("UPLOAD-005", 1, true) == nil,
    "a pre-read body must not surface as UPLOAD-005"
)

-- Dangerous uploads must still be blocked after falling back to the
-- buffered-body parser.
current_body = multipart_body("shell.php", "application/octet-stream", "<?php echo 1;")
local dangerous = upload_check.check_multipart("multipart/form-data; boundary=BOUNDARY")

assert(type(dangerous) == "table", "dangerous multipart should return a result table")
assert(
    dangerous.allowed == false,
    "HTTP/1.1 multipart PHP upload must still be blocked"
)
assert(
    tostring(dangerous.reason):find("UPLOAD-001", 1, true) ~= nil,
    "dangerous extension should be reported as UPLOAD-001, got: " ..
        tostring(dangerous and dangerous.reason)
)

assert(resty_new_called == true, "the streaming parser should be attempted first")

print("ALL upload_check http1 regression tests PASSED")
