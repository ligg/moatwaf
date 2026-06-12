-- tests/unit/upload_check_spec.lua
-- Unit tests for lib/upload_check.lua using busted framework
-- Tests run outside nginx with mocked ngx.* APIs

package.path = "./?.lua;./lib/?.lua;" .. package.path

-- Set up global ngx mock before requiring upload_check module
_G.ngx = _G.ngx or {}
ngx.shared = ngx.shared or {}
ngx.ERR = 4
ngx.log = function(...) end
ngx.var = { remote_addr = "127.0.0.1" }
ngx.req = {
    get_headers = function() return {} end,
    get_body_data = function() return nil end,
    get_body_file  = function() return nil end,
    read_body      = function() end,
}

describe("upload_check", function()
    local upload_check

    setup(function()
        package.loaded["lib.upload_check"] = nil
        upload_check = require("lib.upload_check")
    end)

    -----------------------------------------------------------------------
    -- get_extension
    -----------------------------------------------------------------------
    describe("get_extension", function()
        it("should return extension for simple filename", function()
            assert.equals("jpg", upload_check.get_extension("file.jpg"))
        end)

        it("should return last extension for filename with multiple dots", function()
            assert.equals("jpg", upload_check.get_extension("file.backup.jpg"))
        end)

        it("should return lowercase extension for uppercase filename", function()
            assert.equals("jpg", upload_check.get_extension("FILE.JPG"))
        end)

        it("should return nil for filename with no extension", function()
            assert.is_nil(upload_check.get_extension("Makefile"))
        end)

        it("should return nil for empty string", function()
            assert.is_nil(upload_check.get_extension(""))
        end)

        it("should return nil for nil input", function()
            assert.is_nil(upload_check.get_extension(nil))
        end)

        it("should extract extension after stripping directory path", function()
            assert.equals("php", upload_check.get_extension("dir/file.php"))
        end)

        it("should extract extension after stripping Windows path", function()
            assert.equals("png", upload_check.get_extension("dir\\subdir\\image.png"))
        end)
    end)

    -----------------------------------------------------------------------
    -- bytes_to_hex
    -----------------------------------------------------------------------
    describe("bytes_to_hex", function()
        it("should convert bytes to uppercase hex string", function()
            local bytes = "\xFF\xD8\xFF"
            assert.equals("FFD8FF", upload_check.bytes_to_hex(bytes))
        end)

        it("should return empty string for nil input", function()
            assert.equals("", upload_check.bytes_to_hex(nil))
        end)

        it("should return empty string for empty input", function()
            assert.equals("", upload_check.bytes_to_hex(""))
        end)

        it("should convert single byte correctly", function()
            assert.equals("4D", upload_check.bytes_to_hex("M"))
        end)

        it("should convert multi-byte PNG header", function()
            local bytes = "\x89\x50\x4E\x47"
            assert.equals("89504E47", upload_check.bytes_to_hex(bytes))
        end)
    end)

    -----------------------------------------------------------------------
    -- detect_type
    -----------------------------------------------------------------------
    describe("detect_type", function()
        it("should detect JPEG from magic bytes", function()
            local data = "\xFF\xD8\xFF\xE0\x00\x10JFIF"
            assert.equals("image/jpeg", upload_check.detect_type(data))
        end)

        it("should detect PNG from magic bytes", function()
            local data = "\x89PNG\r\n\x1A\n"
            assert.equals("image/png", upload_check.detect_type(data))
        end)

        it("should detect GIF from magic bytes", function()
            local data = "GIF89a\x01\x00\x01"
            assert.equals("image/gif", upload_check.detect_type(data))
        end)

        it("should detect PDF from magic bytes", function()
            local data = "%PDF-1.4"
            assert.equals("application/pdf", upload_check.detect_type(data))
        end)

        it("should detect ZIP from magic bytes", function()
            local data = "PK\x03\x04\x14\x00\x00\x00"
            assert.equals("application/zip", upload_check.detect_type(data))
        end)

        it("should detect PE/EXE from magic bytes", function()
            local data = "MZ\x90\x00\x03\x00\x00\x00"
            assert.equals("application/x-dosexec", upload_check.detect_type(data))
        end)

        it("should detect ELF from magic bytes", function()
            local data = "\x7FELF\x02\x01\x01\x00"
            assert.equals("application/x-elf", upload_check.detect_type(data))
        end)

        it("should detect gzip from magic bytes", function()
            local data = "\x1F\x8B\x08\x00\x00\x00\x00\x00"
            assert.equals("application/gzip", upload_check.detect_type(data))
        end)

        it("should return nil for unknown prefix", function()
            local data = "\x00\x00\x00\x00\x00\x00\x00\x00"
            assert.is_nil(upload_check.detect_type(data))
        end)

        it("should return nil for nil input", function()
            assert.is_nil(upload_check.detect_type(nil))
        end)

        it("should return nil for empty input", function()
            assert.is_nil(upload_check.detect_type(""))
        end)

        it("should return nil for input shorter than 2 bytes", function()
            assert.is_nil(upload_check.detect_type("X"))
        end)
    end)

    -----------------------------------------------------------------------
    -- contains_shell_code
    -----------------------------------------------------------------------
    describe("contains_shell_code", function()
        it("should detect PHP opening tag", function()
            local detected, desc = upload_check.contains_shell_code("<?php echo 'hi';")
            assert.is_true(detected)
            assert.is_truthy(desc:find("PHP"))
        end)

        it("should detect HTML script tag", function()
            local detected, desc = upload_check.contains_shell_code("<script>alert(1)</script>")
            assert.is_true(detected)
            assert.is_truthy(desc:find("Script"))
        end)

        it("should detect shell shebang", function()
            local detected, desc = upload_check.contains_shell_code("#!/bin/bash\nrm -rf /")
            assert.is_true(detected)
            assert.is_truthy(desc:find("shebang"))
        end)

        it("should detect Python os.system call", function()
            local detected, desc = upload_check.contains_shell_code("os.system('rm -rf /')")
            assert.is_true(detected)
            assert.is_truthy(desc:find("os.system"))
        end)

        it("should detect eval() call", function()
            local detected, desc = upload_check.contains_shell_code("eval('malicious')")
            assert.is_true(detected)
            assert.is_truthy(desc:find("eval"))
        end)

        it("should return false for clean content", function()
            local detected, desc = upload_check.contains_shell_code("Hello, this is a normal text file.")
            assert.is_false(detected)
            assert.is_nil(desc)
        end)

        it("should return false for nil input", function()
            local detected, desc = upload_check.contains_shell_code(nil)
            assert.is_false(detected)
        end)

        it("should return false for empty input", function()
            local detected, desc = upload_check.contains_shell_code("")
            assert.is_false(detected)
        end)
    end)

    -----------------------------------------------------------------------
    -- check
    -----------------------------------------------------------------------
    describe("check", function()
        -- JPEG magic bytes (FFD8FF)
        local jpeg_prefix = "\xFF\xD8\xFF\xE0\x00\x10JFIF"

        it("should allow valid JPEG upload", function()
            local result = upload_check.check(
                "photo.jpg",        -- filename
                "image/jpeg",       -- content_type
                jpeg_prefix,        -- body_prefix
                jpeg_prefix .. "data" -- full_body
            )
            assert.is_true(result.allowed)
            assert.is_nil(result.reason)
            assert.equals("image/jpeg", result.detected_type)
        end)

        it("should block dangerous extension: php", function()
            local result = upload_check.check("shell.php", "application/octet-stream", nil, nil)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-001"))
            assert.is_truthy(result.reason:find("php"))
        end)

        it("should block dangerous extension: asp", function()
            local result = upload_check.check("page.asp", "text/html", nil, nil)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-001"))
        end)

        it("should block dangerous extension: exe", function()
            local result = upload_check.check("trojan.exe", "application/octet-stream", nil, nil)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-001"))
        end)

        it("should block file that exceeds size limit", function()
            -- Create a body larger than 10MB
            local big_body = string.rep("X", 10 * 1024 * 1024 + 1)
            local result = upload_check.check("image.jpg", "image/jpeg", jpeg_prefix, big_body)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-002"))
        end)

        it("should block unknown extension not in allowed list", function()
            local result = upload_check.check("file.xyz", "application/octet-stream", jpeg_prefix, jpeg_prefix)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-001"))
            assert.is_truthy(result.reason:find("not in allowed list"))
        end)

        it("should block PE executable detected by magic number", function()
            local pe_prefix = "MZ\x90\x00\x03\x00\x00\x00"
            local result = upload_check.check("innocent.jpg", "image/jpeg", pe_prefix, pe_prefix)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-001"))
            assert.is_truthy(result.reason:find("Executable"))
            assert.equals("application/x-dosexec", result.detected_type)
        end)

        it("should block ELF executable detected by magic number", function()
            local elf_prefix = "\x7FELF\x02\x01\x01\x00"
            local result = upload_check.check("library.so", "application/octet-stream", elf_prefix, elf_prefix)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-001"))
            assert.is_truthy(result.reason:find("Executable"))
            assert.equals("application/x-elf", result.detected_type)
        end)

        it("should block file containing shell code", function()
            local body = jpeg_prefix .. "<?php system('whoami'); ?>"
            local result = upload_check.check("photo.jpg", "image/jpeg", jpeg_prefix, body)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-004"))
            assert.is_truthy(result.reason:find("Shell code"))
        end)

        it("should block content-type mismatch (declared image/jpeg but body is PDF)", function()
            local pdf_prefix = "%PDF-1.4"
            local result = upload_check.check("doc.pdf", "image/jpeg", pdf_prefix, pdf_prefix)
            assert.is_false(result.allowed)
            assert.is_truthy(result.reason:find("UPLOAD-003"))
            assert.is_truthy(result.reason:find("mismatch"))
        end)

        it("should allow matching content-type and extension", function()
            local pdf_prefix = "%PDF-1.4"
            local result = upload_check.check("doc.pdf", "application/pdf", pdf_prefix, pdf_prefix)
            assert.is_true(result.allowed)
            assert.equals("application/pdf", result.detected_type)
        end)

        it("should allow file with no extension when content is clean", function()
            -- No extension -> ext is nil, so it skips extension-based checks
            local result = upload_check.check("README", "text/plain", nil, "Hello world")
            assert.is_true(result.allowed)
        end)

        it("should return detected_type in result for known magic numbers", function()
            local result = upload_check.check("pic.png", "image/jpeg", jpeg_prefix, jpeg_prefix)
            assert.equals("image/jpeg", result.detected_type)
        end)
    end)
end)
