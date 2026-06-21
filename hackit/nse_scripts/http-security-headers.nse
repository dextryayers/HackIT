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

description = [[Audits HTTP security headers including HSTS, X-Frame-Options, X-Content-Type-Options, CSP, and more.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.header then
        return format_output(false, "No response")
    end
    local h = response.header
    local checks = {
        {"Strict-Transport-Security", "HSTS"},
        {"X-Frame-Options", "Clickjacking protection"},
        {"X-Content-Type-Options", "MIME sniffing protection"},
        {"Content-Security-Policy", "CSP"},
        {"X-XSS-Protection", "XSS filter"},
        {"Referrer-Policy", "Referrer policy"},
        {"Permissions-Policy", "Permissions policy"},
        {"X-Permitted-Cross-Domain-Policies", "Cross-domain policy"}
    }
    local present = {}
    local missing = {}
    for _, check in ipairs(checks) do
        if h[check[1]:lower()] then
            insert(present, check[2] .. ": " .. h[check[1]:lower()])
        else
            insert(missing, check[2] .. " (" .. check[1] .. ")")
        end
    end
    local result = ""
    if #present > 0 then
        result = result .. "Present headers:\n" .. concat(present, "\n")
    end
    if #missing > 0 then
        result = result .. (#present > 0 and "\n\n" or "") .. "Missing headers:\n" .. concat(missing, "\n")
    end
    if result == "" then
        return format_output(false, "No security headers detected")
    end
    return format_output(true, result)
end
