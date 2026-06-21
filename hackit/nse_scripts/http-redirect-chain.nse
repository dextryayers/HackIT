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

description = [[Follows the redirect chain from the target root URL and reports each hop's status, location, and headers.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local max_hops = 10
    local chain = {}
    local current_url = {host = host, port = port, path = "/", ssl = false}
    local scheme = "http"
    for i = 1, max_hops do
        local resp = http.get(current_url.host, current_url.port, current_url.path, {header = {["User-Agent"] = "HackIT Framework"}})
        if not resp then
            insert(chain, "Hop " .. i .. ": No response")
            break
        end
        local status = resp.status or 0
        local loc = resp.header and resp.header["location"]
        local info = "Hop " .. i .. ": " .. scheme .. "://" .. current_url.host .. ":" .. current_url.port .. current_url.path
        info = info .. " -> HTTP " .. status
        if loc then
            info = info .. " (Location: " .. loc .. ")"
        end
        local server = resp.header and resp.header["server"]
        if server then
            info = info .. " [Server: " .. server .. "]"
        end
        insert(chain, info)
        if status < 300 or status >= 400 then
            insert(chain, "Final destination (status " .. status .. ")")
            break
        end
        if loc then
            local new_host, new_port, new_path = loc:match("http[s]?://([^:/]+):?(%d*)(.*)")
            if new_host then
                current_url.host = new_host
                current_url.port = tonumber(new_port) or (loc:find("https") and 443 or 80)
                current_url.path = new_path ~= "" and new_path or "/"
                scheme = loc:find("https") and "https" or "http"
            else
                current_url.path = loc
            end
        else
            break
        end
    end
    if #chain == 0 then
        return format_output(false, "No redirect chain data")
    end
    return format_output(true, concat(chain, "\n"))
end
