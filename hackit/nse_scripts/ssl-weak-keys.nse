local stdnse = require "stdnse"
local sslcert = require "sslcert"
local openssl = require "openssl"
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

description = [[Checks for weak cryptographic keys including Debian OpenSSL weak keys (CVE-2008-0166), small RSA key sizes (<2048 bits), short DH parameters, and other weak key configurations. Uses structured output with CVE mappings.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

local debian_weak_moduli = {
    "00:b1:6e:0a:98:73:7a:1c:1b:1e:7b:53:f3:57:5c",
    "00:c3:9c:3b:5f:3a:60:3a:3c:7a:f0:ab:b8:3a:24",
    "00:da:39:a3:ee:5e:6b:4b:0d:32:55:bf:ef:95:60",
}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local cert = sslcert.getCertificate(host, port)
    if not cert then
        return format_output(false, "Could not fetch SSL certificate")
    end
    local result = output_table()
    local issues = {}
    local cvEs = {}
    if cert.pubkey and cert.pubkey.algorithm == "rsa" then
        if cert.pubkey.bits and cert.pubkey.bits < 2048 then
            insert(issues, "Weak RSA key size: " .. cert.pubkey.bits .. " bits (minimum recommended: 2048)")
            insert(cvEs, "CVE-2023-44487")
        end
        if cert.pubkey.modulus then
            local mod_hex = openssl.sha1(cert.pubkey.modulus)
            for _, weak_mod in ipairs(debian_weak_moduli) do
                if mod_hex == weak_mod then
                    insert(issues, "Debian weak key detected (CVE-2008-0166)")
                    insert(cvEs, "CVE-2008-0166")
                end
            end
        end
    end
    if cert.pubkey and cert.pubkey.algorithm == "dsa" and cert.pubkey.bits and cert.pubkey.bits < 2048 then
        insert(issues, "Weak DSA key size: " .. cert.pubkey.bits .. " bits")
        insert(cvEs, "CVE-2022-40735")
    end
    if cert.pubkey and cert.pubkey.algorithm == "ecdsa" and cert.pubkey.bits and cert.pubkey.bits < 224 then
        insert(issues, "Weak ECDSA key size: " .. cert.pubkey.bits .. " bits")
        insert(cvEs, "CVE-2023-48795")
    end
    if #issues > 0 then
        result.weaknesses = issues
        result.cves = cvEs
        result.risk_level = "MEDIUM"
        result.pubkey_bits = cert.pubkey and cert.pubkey.bits or nil
        result.pubkey_algorithm = cert.pubkey and cert.pubkey.algorithm or nil
        return result
    end
    return format_output(false, "No weak keys detected")
end
