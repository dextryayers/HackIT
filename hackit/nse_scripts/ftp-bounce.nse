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

description = [[Tests for the FTP bounce attack by issuing a PORT command with a third-party IP address, attempting to instruct the server to connect to an arbitrary host. Uses structured output with CVE mapping.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 21 or port.service == "ftp") end

local test_targets = {
    {"10,0,0,1", "4,210"},
    {"127,0,0,1", "7,112"},
    {"0,0,0,0", "0,0"},
}

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local vulnerable = false
        local last_code
        for _, target in ipairs(test_targets) do
            local s = new_socket()
            s:set_timeout(5000)
            local ok2 = s:connect(host.ip, port)
            if ok2 then
                s:receive_buf("\n", 3000)
                s:send("PORT " .. target[1] .. "," .. target[2] .. "\r\n")
                local _, r = s:receive_buf("\n", 3000)
                s:close()
                if r then
                    local code = match(r, "^(%d%d%d)")
                    if code == "200" then
                        vulnerable = true
                        last_code = code
                        break
                    elseif code ~= "500" and code ~= "501" and code ~= "502" then
                        last_code = code
                    end
                end
            end
        end
        sock:close()
        if vulnerable then
            local res = output_table()
            res.vulnerability = true
            res.name = "FTP Bounce"
            res.details = "PORT command accepted for arbitrary host"
            res.severity = "MEDIUM"
            res.recommendation = "Disable PORT command or restrict to local addresses"
            return res
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if result then
        return result
    end
    return format_output(false, "Not vulnerable to FTP bounce")
end
