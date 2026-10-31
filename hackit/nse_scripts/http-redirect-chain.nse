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
            local new_host, new_port, new_path = match(loc, "http[s]?://([^:/]+):?(%d*)(.*)")
            if new_host then
                current_url.host = new_host
                current_url.port = tonumber(new_port) or (find(loc, "https") and 443 or 80)
                current_url.path = new_path ~= "" and new_path or "/"
                scheme = find(loc, "https") and "https" or "http"
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
