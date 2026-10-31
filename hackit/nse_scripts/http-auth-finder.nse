local http = require "http"
local stdnse = require "stdnse"
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
