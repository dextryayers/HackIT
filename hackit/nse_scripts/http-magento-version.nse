local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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
local new_socket = nmap.new_socket
local resolve = nmap.resolve

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

description = [[
Detects Magento CMS version by analyzing HTML source, favicon, and
Magento-specific paths. Checks for Magento version indicators in
generator tags, JavaScript/CSS path patterns, and release notes.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local response = http.get(host, port, "/")
    if not response then
        return format_output(false, "No response")
    end
    local body = response.body or ""
    local is_magento = match(body, "Magento") or match(body, "mage") or match(body, "mage/") or false
    if not is_magento then
        local static_resp = http.get(host, port, "/static/version/")
        if static_resp and static_resp.status and static_resp.status < 500 then
            is_magento = true
        end
    end
    if not is_magento then
        insert(result, "Target does not appear to be Magento")
        return format_output(true, result)
    end
    insert(result, "Magento CMS detected")
    local ver_paths = {
        "/RELEASE_NOTES.txt",
        "/magento_version",
        "/version",
        "/index.php/RELEASE_NOTES.txt",
    }
    for _, path in ipairs(ver_paths) do
        local resp2 = http.get(host, port, path)
        if resp2 and resp2.status == 200 and resp2.body then
            local ver = match(resp2.body or "", "Magento[^%d]*([%d.]+)")
                or match(resp2.body or "", "([%d]%.[%d]%.[%d])")
            if ver then
                insert(result, ("Version: %s (from %s)"):format(ver, path))
            end
        end
    end
    local gen_tag = match(body, '<meta name="generator" content="([^"]*Magento[^"]*)"')
    if gen_tag then
        insert(result, "Generator: " .. gen_tag)
        local ver = match(gen_tag, "[%d]%.[%d]%.[%d]+")
        if ver then
            insert(result, "Magento version: " .. ver)
        end
    end
    return format_output(true, result)
end
