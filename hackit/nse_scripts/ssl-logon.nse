local stdnse = require "stdnse"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[Connects via HTTPS and checks if the page contains login forms, authentication fields, or common logon page indicators. Uses multiple paths and response analysis.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 443 or port.service == "https") end

local paths = {"/", "/login", "/admin", "/signin", "/auth", "/logon", "/wp-login.php", "/admin/login.php"}

action = function(host, port)
    local all_indicators = {}
    for _, path in ipairs(paths) do
        local ok, response = pcall(function()
            return http.get(host, port, path)
        end)
        if ok and response and response.body then
            local body = response.lower(body)
            local indicators = {
                {"password field", find(body, 'type="password"')},
                {"login form", find(body, 'action="[^"]*login') or find(body, "action='[^']*login")},
                {"username field", find(body, 'name="username"') or find(body, 'name="user"') or find(body, 'name="login"')},
                {"login keyword in title", find(body, "<title>.*login.*</title>")},
                {"sign-in", find(body, "sign.?in")},
                {"logon", find(body, "logon")},
                {"auth", find(body, "authenticate") or find(body, "authorization")},
                {"form", find(body, "<form")},
            }
            for _, ind in ipairs(indicators) do
                if ind[2] then
                    all_indicators[ind[1]] = (all_indicators[ind[1]] or 0) + 1
                end
            end
        end
    end
    if next(all_indicators) then
        local result = output_table()
        result.url = "https://" .. host.ip .. ":" .. port.number .. "/"
        result.indicators = {}
        for k, v in pairs(all_indicators) do
            insert(result.indicators, k)
        end
        result.paths_scanned = #paths
        return result
    end
    return format_output(false, "No logon page detected")
end
