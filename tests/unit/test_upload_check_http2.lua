-- tests/unit/test_upload_check_http2.lua
-- Regression test: HTTP/2 multipart uploads must not invoke resty.upload.
-- resty.upload raises "http v2 not supported yet" under OpenResty, which makes
-- the WAF return 500 before the request reaches Kong/backend.

local script_path = arg[0]:match("^(.-)[^/\\]*$")
package.path = (script_path or "") .. "../../?.lua;" .. package.path

package.loaded["cjson"] = {
    encode = function() return "{}" end,
    decode = function() return {} end,
}

local resty_new_called = false
local current_body = ""
package.loaded["resty.upload"] = {
    new = function()
        resty_new_called = true
        error("http v2 not supported yet")
    end,
}

_G.ngx = {
    ERR = 4,
    log = function() end,
    var = {
        remote_addr = "127.0.0.1",
    },
    req = {
        http_version = function() return 2 end,
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
    "HTTP/2 multipart PNG upload should be allowed, got reason: " ..
        tostring(result and result.reason)
)
assert(
    resty_new_called == false,
    "HTTP/2 multipart upload must not invoke resty.upload:new()"
)

current_body = multipart_body("shell.php", "application/octet-stream", "<?php echo 1;")
local dangerous = upload_check.check_multipart("multipart/form-data; boundary=BOUNDARY")

assert(type(dangerous) == "table", "dangerous multipart should return a result table")
assert(
    dangerous.allowed == false,
    "HTTP/2 multipart PHP upload should still be blocked"
)
assert(
    tostring(dangerous.reason):find("UPLOAD-001", 1, true) ~= nil,
    "dangerous extension should be reported as UPLOAD-001"
)

print("ALL upload_check http2 regression tests PASSED")
