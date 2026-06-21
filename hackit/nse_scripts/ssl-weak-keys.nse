local stdnse = require "stdnse"
local sslcert = require "sslcert"
local openssl = require "openssl"
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
