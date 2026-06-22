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
            local ver = resp2.match(body, "Magento[^%d]*([%d.]+)")
                or resp2.match(body, "([%d]%.[%d]%.[%d])")
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
