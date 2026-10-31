local stdnse = require "stdnse"
local tls = require "tls"
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

description = [[Tests for the ROBOT attack (Return Of Bleichenbacher's Oracle Threat, CVE-2017-12307) by checking if the server reveals PKCS#1 v1.5 padding errors in RSA key exchange. Uses multiple oracle detection techniques.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

local function test_robot_oracle(host, port, cipher)
    local sock = new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return nil end
        local hello = tls.client_hello("TLSv1.2", {ciphers = {cipher}})
        sock:send(hello)
        local _, data = sock:receive_buf(tls.server_hello_done, 8000)
        if not data then sock:close(); return nil end
        local fake_encodings = {
            tls.client_key_exchange_pkcs1("FAKE_PREMASTER_SECRET"),
            tls.client_key_exchange_pkcs1("\x00\x02" .. rep("\x41", 46) .. "\x00" .. rep("\x42", 48)),
        }
        local responses = {}
        for _, enc in ipairs(fake_encodings) do
            local s2 = new_socket()
            s2:set_timeout(8000)
            local ok3 = pcall(function()
                s2:connect(host.ip, port)
                local h2 = tls.client_hello("TLSv1.2", {ciphers = {cipher}})
                s2:send(h2)
                s2:receive_buf(tls.server_hello_done, 5000)
                s2:send(enc)
                local _, r = s2:receive_buf("\n", 3000)
                if r then insert(responses, r) end
                s2:close()
            end)
            if not ok3 then pcall(function() s2:close() end) end
        end
        sock:close()
        if #responses >= 2 then
            local diff = false
            for i = 2, #responses do
                if responses[i] ~= responses[1] then
                    diff = true
                    break
                end
            end
            return diff
        end
        return nil
    end)
    if not ok then
        pcall(function() sock:close() end)
        return nil
    end
    return result
end

action = function(host, port)
    local rsa_ciphers = {
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
    }
    for _, cipher in ipairs(rsa_ciphers) do
        local oracle = test_robot_oracle(host, port, cipher)
        if oracle then
            local result = output_table()
            result.vulnerability = "CVE-2017-12307"
            result.name = "ROBOT attack"
            result.affected = true
            result.details = "Server reveals Bleichenbacher oracle behavior in RSA key exchange"
            result.severity = "HIGH"
            return result
        end
    end
    return format_output(false, "Not vulnerable to ROBOT attack")
end
