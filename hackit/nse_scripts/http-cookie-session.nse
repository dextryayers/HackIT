local http = require "http"
local stdnse = require "stdnse"
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

description = [[Analyzes session cookies for randomness, length, and security attributes.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.header then
        return format_output(false, "No response")
    end
    local cookies = resp.header["set-cookie"]
    if not cookies then
        return format_output(false, "No session cookies set")
    end
    if type(cookies) == "string" then
        cookies = {cookies}
    end
    local results = {}
    for _, cookie in ipairs(cookies) do
        local name = cookie:match("^([^=]+)")
        local value = cookie:match("^[^=]+=([^;]+)")
        local analysis = {}
        if name then
            if name:find("[Ss]ession") or name:find("PHPSESSID") or name:find("JSESSIONID") or name:find("ASP%.NET") or name:find("laravel") then
                insert(analysis, "Session cookie detected")
            end
        end
        if value then
            insert(analysis, "Length: " .. #value .. " chars")
            local entropy = 0
            for c in value:gmatch(".") do
                if c:find("[a-z]") then entropy = entropy + 1 end
                if c:find("[A-Z]") then entropy = entropy + 1 end
                if c:find("[0-9]") then entropy = entropy + 2 end
            end
            if entropy < #value * 0.5 then
                insert(analysis, "Low entropy (possible predictability)")
            end
            if value:match("^%d+$") then
                insert(analysis, "WARNING: Numeric only (predictable)")
            end
        end
        if cookie:find("HttpOnly") then
            insert(analysis, "HttpOnly: Yes")
        else
            insert(analysis, "HttpOnly: No")
        end
        if cookie:find("Secure") then
            insert(analysis, "Secure: Yes")
        else
            insert(analysis, "Secure: No")
        end
        local max_age = cookie:match("Max%-Age=(%d+)")
        if max_age then
            insert(analysis, "Max-Age: " .. max_age .. "s")
        end
        insert(results, name .. ": " .. concat(analysis, ", "))
    end
    return format_output(true, concat(results, "\n"))
end
