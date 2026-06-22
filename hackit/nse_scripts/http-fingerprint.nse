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

description = [[Fingerprints the web server by analyzing Server header, response patterns, X-Powered-By, and cookie naming conventions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local resp = http.get(host, port, "/")
    if not resp or not resp.header then
        return format_output(false, "No response")
    end
    local h = resp.header
    local sigs = {}
    if h["server"] then
        insert(sigs, "Server: " .. h["server"])
    end
    if h["x-powered-by"] then
        insert(sigs, "X-Powered-By: " .. h["x-powered-by"])
    end
    if h["x-aspnet-version"] then
        insert(sigs, "ASP.NET: " .. h["x-aspnet-version"])
    end
    if h["x-generator"] then
        insert(sigs, "Generator: " .. h["x-generator"])
    end
    if h["via"] then
        insert(sigs, "Via: " .. h["via"])
    end
    if resp.body then
        if resp.find(body, "wp%-content") or resp.find(body, "wp%-includes") then
            insert(sigs, "CMS: WordPress")
        end
        if resp.find(body, "Joomla") then
            insert(sigs, "CMS: Joomla")
        end
        if resp.find(body, "Drupal") then
            insert(sigs, "CMS: Drupal")
        end
        if resp.find(body, "nginx") then
            insert(sigs, "Server: nginx (body hint)")
        end
    end
    if #sigs == 0 then
        return format_output(false, "No fingerprinting signatures found")
    end
    return format_output(true, concat(sigs, "\n"))
end
