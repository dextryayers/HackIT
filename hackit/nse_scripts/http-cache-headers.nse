local http = require "http"
local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



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

description = [[Analyzes Cache-Control, Pragma, Expires, and ETag headers to assess caching behavior and potential information leakage.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local paths = {"/", "/login", "/admin", "/dashboard", "/profile"}
    local results = {}
    for _, path in ipairs(paths) do
        local resp = http.get(host, port, path)
        if resp and resp.header then
            local h = resp.header
            local line = path
            local cache_control = h["cache-control"]
            local pragma = h["pragma"]
            local expires = h["expires"]
            local etag = h["etag"]
            local issues = {}
            if cache_control then
                line = line .. " CC:" .. cache_control
                if find(cache_control, "no%-store") then
                elseif find(cache_control, "private") then
                    insert(issues, "Private cache (may contain sensitive data)")
                elseif find(cache_control, "public") and (path == "/login" or path == "/admin") then
                    insert(issues, "Sensitive path publicly cacheable")
                end
                if not find(cache_control, "no%-store") and not find(cache_control, "no%-cache") and not find(cache_control, "private") then
                    if path ~= "/" then
                        insert(issues, "No cache restriction directive")
                    end
                end
            else
                insert(issues, "No Cache-Control header")
            end
            if expires then
                line = line .. " Expires:" .. expires
            end
            if pragma then
                line = line .. " Pragma:" .. pragma
            end
            if etag then
                line = line .. " ETag:" .. etag
            end
            if #issues > 0 then
                line = line .. " [" .. concat(issues, "; ") .. "]"
            end
            insert(results, line)
        end
    end
    if #results == 0 then
        return format_output(false, "No cache header data available")
    end
    return format_output(true, concat(results, "\n"))
end
