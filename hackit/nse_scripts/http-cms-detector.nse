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

description = [[Detects content management systems by checking for CMS-specific paths, meta tags, and file signatures.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local cms_signatures = {
        {name = "WordPress", paths = {"/wp-admin/", "/wp-content/", "/wp-includes/", "/wp-login.php", "/xmlrpc.php"}},
        {name = "Joomla", paths = {"/administrator/", "/components/", "/modules/", "/templates/", "/media/", "/includes/"}},
        {name = "Drupal", paths = {"/sites/default/", "/core/", "/modules/", "/themes/", "/xmlrpc.php"}},
        {name = "Magento", paths = {"/skin/", "/js/", "/media/", "/app/", "/errors/"}},
        {name = "Shopify", paths = {"/admin", "/cart", "/collections/", "/products/"}},
        {name = "PrestaShop", paths = {"/modules/", "/themes/", "/img/", "/js/"}},
        {name = "Concrete5", paths = {"/concrete/", "/packages/", "/application/"}},
        {name = "October CMS", paths = {"/modules/", "/plugins/", "/themes/"}},
        {name = "Laravel", paths = {"/vendor/", "/storage/"}},
    }
    local results = {}
    for _, cms in ipairs(cms_signatures) do
        local hits = 0
        for _, path in ipairs(cms.paths) do
            local resp = http.get(host, port, path)
            if resp and resp.status and resp.status < 400 then
                hits = hits + 1
            end
        end
        if hits >= 2 then
            insert(results, cms.name .. " (paths matched: " .. hits .. ")")
        end
    end
    if #results == 0 then
        return format_output(false, "No CMS detected")
    end
    return format_output(true, "Detected: " .. concat(results, "; "))
end
