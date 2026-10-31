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
Explores the Docker Registry v2 API to enumerate repositories, tags, and
manifests. Checks if the registry is accessible without authentication and
attempts to list available container images and their tags.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5000, "http")

action = function(host, port)
    local result = {}
    local api_endpoints = {
        {"/v2/", "Docker Registry v2 API"},
        {"/v2/_catalog", "Repository catalog"},
    }
    for _, ep in ipairs(api_endpoints) do
        local response = http.get(host, port, ep[1])
        if response and response.status then
            if response.status == 200 then
                insert(result, (ep[2] .. " accessible (status %d)"):format(response.status))
                if ep[1] == "/v2/_catalog" and response.body then
                    local repos = response.match(body, '"repositories"%s*:%s*%[([^]]+)%]')
                    if repos then
                        for repo in gmatch(repos, '"([^"]+)"') do
                            insert(result, "  Repository: " .. repo)
                            local tag_resp = http.get(host, port, "/v2/" .. repo .. "/tags/list")
                            if tag_resp and tag_resp.status == 200 and tag_resp.body then
                                local tags = tag_resp.match(body, '"tags"%s*:%s*%[([^]]+)%]')
                                if tags then
                                    for tag in gmatch(tags, '"([^"]+)"') do
                                        insert(result, "    Tag: " .. tag)
                                    end
                                end
                            end
                        end
                    end
                end
            elseif response.status == 401 or response.status == 403 then
                insert(result, (ep[2] .. " requires authentication (status %d)"):format(response.status))
            end
        end
    end
    if #result == 0 then
        insert(result, "Docker Registry API not detected")
    end
    return format_output(true, result)
end
