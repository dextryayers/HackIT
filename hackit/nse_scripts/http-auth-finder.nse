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

description = [[Scans the target for authentication forms, login endpoints, and HTTP authentication prompts.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return format_output(false, "No response body")
    end
    local findings = {}
    if response.header and response.header["www-authenticate"] then
        insert(findings, "HTTP Basic/Digest auth: " .. response.header["www-authenticate"])
    end
    local login_paths = {"/login", "/admin", "/wp-admin", "/administrator", "/auth", "/user/login", "/signin", "/account/login"}
    for _, path in ipairs(login_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.status and resp.status < 400 then
            if resp.match(body, "<input.-[Tt]ype=[\"']password[\"']") or resp.match(body, "<form.-[Pp]assword") then
                insert(findings, "Login form at " .. path)
            end
        end
    end
    if response.match(body, "<input.-[Tt]ype=[\"']password[\"']") then
        insert(findings, "Password field found on /")
    end
    if #findings == 0 then
        return format_output(false, "No authentication endpoints detected")
    end
    return format_output(true, concat(findings, "\n"))
end
