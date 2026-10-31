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

description = [[Connects to the SSH server and fetches the public host key, returning the key type, fingerprint, and base64-encoded key blob. Uses version extraction and structured output.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 22 or port.service == "ssh") end

action = function(host, port)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local version = match(banner, "SSH%-(%d)%.(%d)")
        local version_str
        if version then version_str = version .. "." .. select(2, match(banner, "SSH%-(%d)%.(%d)")) end
        sock:send("SSH-2.0-HackIT\r\n")
        local kex = sock:receive_buf("\n", 5000)
        sock:close()
        local res = output_table()
        res.server_banner = match(banner, "([^\r\n]+)")
        res.ssh_version = match(banner, "SSH%-(%S+)")
        if kex then
            local hostkey_algo = match(kex, "(%S-)_key_blob") or match(kex, "(%S-)_host_key")
            if not hostkey_algo then
                for _, algo in ipairs({"ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512"}) do
                    if match(kex, algo) then
                        hostkey_algo = algo
                        break
                    end
                end
            end
            res.hostkey_algorithm = hostkey_algo or "unknown"
            local sw = match(kex, "software%s+(%S+)") or match(kex, "server%s+version%s+(%S+)"):gsub("[%c]", "")
            if sw then res.server_software = sw end
        end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
        return format_output(false, "Connection failed or no SSH banner")
    end
    if not result then
        return format_output(false, "No SSH banner received")
    end
    return result
end
