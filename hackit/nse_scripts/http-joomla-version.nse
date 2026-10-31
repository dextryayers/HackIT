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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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
Detects Joomla CMS version by analyzing the HTML source, XML manifests,
and metadata files. Checks for Joomla-specific paths and version indicators
including the Joomla generator tag and manifest files.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local response = http.get(host, port, "/")
    if not response then
        return format_output(false, "No response from server")
    end
    local body = response.body or ""
    if match(body, "joomla") or match(body, "Joomla") or match(body, "com_content") then
        insert(result, "Joomla CMS detected")
    else
        insert(result, "Not identified as Joomla")
        return format_output(true, result)
    end
    local version_paths = {
        {"/administrator/manifests/files/joomla.xml", "XML manifest"},
        {"/language/en-GB/en-GB.xml", "Language XML"},
        {"/plugins/system/cache/cache.xml", "Cache XML"},
        {"/templates/system/offline.php", "Offline page"},
        {"/htaccess.txt", "htaccess"},
        {"/README.txt", "Readme"},
    }
    for _, vp in ipairs(version_paths) do
        local resp2 = http.get(host, port, vp[1])
        if resp2 and resp2.status == 200 and resp2.body then
            local ver = match(resp2.body or "", 'version%s*=%s*"([%d.]+)') or match(resp2.body or "", 'version="([%d.]+)"')
            if ver then
                insert(result, ("Version (%s): %s"):format(vp[2], ver))
            end
        end
    end
    local gen_tag = match(body, '<meta name="generator" content="Joomla!?%s*([^"]+)"')
    if gen_tag then
        insert(result, "Generator tag: " .. gen_tag)
        local ver = match(gen_tag, "[%d.]+")
        if ver then
            insert(result, "Joomla version: " .. ver)
        end
    end
    if #result == 1 then
        insert(result, "Joomla detected but version not determined")
    end
    return format_output(true, result)
end
