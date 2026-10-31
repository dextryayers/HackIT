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
Detects Shopify-powered stores by examining HTTP response headers and HTML
content for Shopify-specific indicators including X-ShopId, X-Shopify-CLI,
Shopify CDN references, and Shopify JavaScript assets.
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
    local headers = response.headers
    local body = response.body or ""
    local indicators = {}
    if headers then
        if headers["x-shopid"] or headers["X-ShopId"] then
            insert(indicators, "X-ShopId header")
        end
        if headers["x-shopify-cli"] or headers["X-Shopify-CLI"] then
            insert(indicators, "X-Shopify-CLI header")
        end
        if headers["x-shopify-stage"] or headers["X-Shopify-Stage"] then
            insert(indicators, "X-Shopify-Stage header")
        end
        if headers["powered-by"] and headers["powered-by"]:match("[Ss]hopify") then
            insert(indicators, "Powered-By: Shopify")
        end
    end
    if body then
        if match(body, "shopify") or match(body, "Shopify") then
            insert(indicators, "Shopify reference in HTML")
        end
        if match(body, "myshopify%.com") then
            insert(indicators, "myshopify.com domain reference")
        end
        if match(body, "cdn%.shopify%.com") then
            insert(indicators, "Shopify CDN asset detected")
        end
        if match(body, "/cart%.js") or match(body, "/collections/") then
            insert(indicators, "Shopify URL patterns detected")
        end
    end
    if #indicators > 0 then
        insert(result, "Shopify store detected")
        for _, ind in ipairs(indicators) do
            insert(result, "  " .. ind)
        end
        local response2 = http.get(host, port, "/admin")
        if response2 and response2.status then
            insert(result, ("  /admin endpoint: HTTP %d"):format(response2.status))
        end
    else
        insert(result, "No Shopify indicators found")
    end
    return format_output(true, result)
end
