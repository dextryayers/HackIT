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
Queries the Azure Instance Metadata Service (IMDS) at 169.254.169.254 to
retrieve information about the Azure VM instance including compute metadata,
network configuration, and scheduled events.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    local result = {}
    local meta_host = "169.254.169.254"
    local socket = new_socket()
    socket:set_timeout(3000)
    local status, err = socket:connect(meta_host, 80)
    if not status then
        return format_output(false, "Azure IMDS not accessible: " .. tostring(err))
    end
    local headers = "Metadata: true\r\n"
    local api_endpoints = {
        "/metadata/instance?api-version=2021-02-01",
        "/metadata/instance/compute?api-version=2021-02-01",
        "/metadata/instance/network?api-version=2021-02-01",
        "/metadata/scheduledevents?api-version=2020-07-01",
    }
    for _, path in ipairs(api_endpoints) do
        socket:send("GET " .. path .. " HTTP/1.1\r\nHost: metadata\r\n" .. headers .. "Connection: close\r\n\r\n")
        local status, response = socket:receive_bytes(1)
        if status and response then
            local body = match(response, "\r\n\r\n(.*)")
            if body and #body > 0 and not match(body, "error") and not match(body, "404") then
                if match(body, "compute") or match(body, "vmId") or match(body, "name") then
                    insert(result, ("Azure IMDS accessible via %s"):format(path))
                    local fields = {"name", "location", "vmId", "subscriptionId", "resourceGroupName"}
                    for _, f in ipairs(fields) do
                        local val = match(body, '"' .. f .. '"%s*:%s*"([^"]+)"')
                        if val then
                            insert(result, ("  %s: %s"):format(f, val))
                        end
                    end
                end
            end
        end
    end
    socket:close()
    if #result == 0 then
        insert(result, "Azure IMDS not available or inaccessible")
    end
    return format_output(true, result)
end
