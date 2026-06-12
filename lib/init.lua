-- lib/init.lua
local _M = {}

local loaded_modules = {}

function _M.load(name)
    if not loaded_modules[name] then
        loaded_modules[name] = require("lib." .. name)
    end
    return loaded_modules[name]
end

function _M.reload(name)
    package.loaded["lib." .. name] = nil
    loaded_modules[name] = nil
    return _M.load(name)
end

return _M
