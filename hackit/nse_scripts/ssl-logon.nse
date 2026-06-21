local stdnse = require "stdnse"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
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
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
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
            local body = response.body:lower()
            local indicators = {
                {"password field", body:find('type="password"')},
                {"login form", body:find('action="[^"]*login') or body:find("action='[^']*login")},
                {"username field", body:find('name="username"') or body:find('name="user"') or body:find('name="login"')},
                {"login keyword in title", body:find("<title>.*login.*</title>")},
                {"sign-in", body:find("sign.?in")},
                {"logon", body:find("logon")},
                {"auth", body:find("authenticate") or body:find("authorization")},
                {"form", body:find("<form")},
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
