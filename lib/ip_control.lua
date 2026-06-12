-- lib/ip_control.lua
local _M = {}

local ngx = ngx
local utils = require("lib.utils")
local cjson = require("cjson")

-- Load IP lists from config files
function _M.load_lists()
    local lists = {
        blacklist = {},
        whitelist = {},
        geo_block = {}
    }

    -- Load blacklist
    local bl_file = io.open("/opt/moat/conf/ip_blacklist.txt", "r")
    if bl_file then
        for line in bl_file:lines() do
            line = line:match("^%s*(.-)%s*$")
            if line ~= "" and not line:match("^#") then
                lists.blacklist[line] = true
            end
        end
        bl_file:close()
    end

    -- Load whitelist
    local wl_file = io.open("/opt/moat/conf/ip_whitelist.txt", "r")
    if wl_file then
        for line in wl_file:lines() do
            line = line:match("^%s*(.-)%s*$")
            if line ~= "" and not line:match("^#") then
                lists.whitelist[line] = true
            end
        end
        wl_file:close()
    end

    -- Load geo block list
    local geo_file = io.open("/opt/moat/conf/geo_block.txt", "r")
    if geo_file then
        for line in geo_file:lines() do
            line = line:match("^%s*(.-)%s*$")
            if line ~= "" and not line:match("^#") then
                lists.geo_block[line] = true
            end
        end
        geo_file:close()
    end

    return lists
end

-- Check IP against whitelist (returns true if whitelisted)
function _M.is_whitelisted(ip, lists)
    if lists.whitelist[ip] then
        return true
    end
    -- Check CIDR ranges in whitelist
    for cidr, _ in pairs(lists.whitelist) do
        if cidr:find("/") then
            if utils.ip_in_cidr(ip, cidr) then
                return true
            end
        end
    end
    return false
end

-- Check IP against blacklist (returns true if blacklisted)
function _M.is_blacklisted(ip, lists)
    if lists.blacklist[ip] then
        return true
    end
    for cidr, _ in pairs(lists.blacklist) do
        if cidr:find("/") then
            if utils.ip_in_cidr(ip, cidr) then
                return true
            end
        end
    end
    return false
end

-- Dynamic blacklist via shared dict
function _M.is_dynamic_blacklisted(ip)
    local blacklist = ngx.shared.ip_blacklist
    local val = blacklist:get(ip)
    return val ~= nil
end

-- Add IP to dynamic blacklist
function _M.blacklist_ip(ip, ttl)
    ttl = ttl or 3600  -- default 1 hour
    local blacklist = ngx.shared.ip_blacklist
    blacklist:set(ip, 1, ttl)
end

-- Remove IP from dynamic blacklist
function _M.unblacklist_ip(ip)
    local blacklist = ngx.shared.ip_blacklist
    blacklist:delete(ip)
end

-- Main check function: returns action
-- "pass" = allow, "block" = deny
function _M.check(ip, lists)
    -- Whitelist check first
    if _M.is_whitelisted(ip, lists) then
        return "pass", "whitelisted"
    end

    -- Static blacklist
    if _M.is_blacklisted(ip, lists) then
        return "block", "static_blacklisted"
    end

    -- Dynamic blacklist
    if _M.is_dynamic_blacklisted(ip) then
        return "block", "dynamic_blacklisted"
    end

    return "pass", "ok"
end

return _M
