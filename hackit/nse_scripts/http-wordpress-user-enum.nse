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
Enumerates WordPress users via the WordPress REST API endpoint
/wp-json/wp/v2/users. Extracts user IDs, usernames, display names,
and other available user information from exposed REST API endpoints.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local api_endpoints = {
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/users/1",
        "/?rest_route=/wp/v2/users",
        "/wp-json/wp/v2/users?per_page=100",
    }
    local found_wp = false
    local response = http.get(host, port, "/")
    if response and response.body then
        if response.match(body, "wp%-content") or response.match(body, "wordpress") or response.match(body, "WordPress") then
            found_wp = true
            insert(result, "WordPress detected")
        end
    end
    if not found_wp then
        insert(result, "Target does not appear to be WordPress, probing anyway")
    end
    for _, endpoint in ipairs(api_endpoints) do
        local resp = http.get(host, port, endpoint)
        if resp and resp.status and resp.status == 200 and resp.body then
            local users_found = 0
            for uid, uname, dname in resp.gmatch(body, '"id"%s*:%s*(%d+).-"name"%s*:%s*"([^"]+)".-"slug"%s*:%s*"([^"]+)"') do
                insert(result, ("  User #%s: %s (slug: %s)"):format(uid, dname, uname))
                users_found = users_found + 1
            end
            if users_found > 0 then
                insert(result, ("User enumeration via %s: %d users found"):format(endpoint, users_found))
            else
                local single_match = resp.match(body, '"slug"%s*:%s*"([^"]+)"')
                if single_match then
                    insert(result, ("  User found (slug): %s"):format(single_match))
                end
            end
        end
    end
    if #result == 1 then
        insert(result, "No WordPress user enumeration possible")
    end
    return format_output(true, result)
end
