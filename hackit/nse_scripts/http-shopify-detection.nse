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
