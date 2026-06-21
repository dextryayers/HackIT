local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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
    if body:match("joomla") or body:match("Joomla") or body:match("com_content") then
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
            local ver = resp2.body:match('version%s*=%s*"([%d.]+)') or resp2.body:match('version="([%d.]+)"')
            if ver then
                insert(result, ("Version (%s): %s"):format(vp[2], ver))
            end
        end
    end
    local gen_tag = body:match('<meta name="generator" content="Joomla!?%s*([^"]+)"')
    if gen_tag then
        insert(result, "Generator tag: " .. gen_tag)
        local ver = gen_tag:match("[%d.]+")
        if ver then
            insert(result, "Joomla version: " .. ver)
        end
    end
    if #result == 1 then
        insert(result, "Joomla detected but version not determined")
    end
    return format_output(true, result)
end
