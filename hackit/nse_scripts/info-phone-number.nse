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

description = [[Discovers phone numbers embedded in web pages or service banners.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local phone_patterns = {
    {pattern = "([%+][%d][%d%-%s%.%(%)]{" .. 7 .. ",})", desc = "International format"},
    {pattern = "([%(%d][%d][%d%)]%s*[%d][%d][%d]%-[%d][%d][%d][%d])", desc = "US format (555) 123-4567"},
    {pattern = "(%d%d%d[%-%.]%d%d%d[%-%.]%d%d%d%d)", desc = "Numeric format xxx-xxx-xxxx"},
    {pattern = "(%+[%d]+[%-][%d]+[%-][%d]+)", desc = "E.164 format"},
}

local http_paths = {"/", "/contact", "/about", "/support", "/help", "/about-us", "/contact-us", "/index.html"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443 or port.number == 8080) end

action = function(host, port)
    local out = output_table()
    out.service = "Phone Number Discovery"
    out.target = host.ip
    out.port = port.number
    local all_phones = {}
    for _, path in ipairs(http_paths) do
        local socket = new_socket()
        socket:set_timeout(5000)
        local ok, resp = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            socket:send("GET " .. path .. " HTTP/1.1\r\nHost: " .. host.ip .. "\r\nConnection: close\r\n\r\n")
            local _, r = socket:receive_bytes(8192)
            socket:close()
            return r
        end)
        if not ok then pcall(socket.close, socket) end
        if resp then
            for _, pat_entry in ipairs(phone_patterns) do
                for match in gmatch(resp, pat_entry.pattern) do
                    local clean = gsub(match, "[%s%(%)]", "")
                    if #clean >= 10 then
                        local already = false
                        for _, p in ipairs(all_phones) do
                            if p.number == clean then already = true end
                        end
                        if not already then
                            insert(all_phones, {number = clean, format = pat_entry.desc, source = path})
                        end
                    end
                end
            end
        end
    end
    if #all_phones > 0 then
        out.status = "PHONE_NUMBERS_FOUND"
        out.phone_numbers = all_phones
        out.phone_count = #all_phones
    else
        out.status = "NONE_FOUND"
        out.message = "No phone numbers discovered"
    end
    return out
end
