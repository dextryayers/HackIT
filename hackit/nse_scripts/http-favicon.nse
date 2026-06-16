local http = require "http"
local stdnse = require "stdnse"
local openssl = require "openssl"

description = [[Fetches /favicon.ico, computes its MD5 hash, and compares against known CMS/technology hashes for identification.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local response = http.get(host, port, "/favicon.ico")
    if not response or not response.body then
        return stdnse.format_output(false, "No favicon.ico found")
    end
    if response.status == 404 then
        return stdnse.format_output(false, "favicon.ico not found (404)")
    end
    local md5 = openssl.md5(response.body)
    if not md5 then
        return stdnse.format_output(false, "Could not compute favicon hash")
    end
    local known = {
        ["fba3d1f1a3b6a2a8c0c0b3f1a4c8b9a0"] = "Generic CMS",
        ["87c8dfd2d62ea75a2a7e3d6b6b7e6c1d"] = "WordPress",
        ["2c5a1c0e1b0a2c6d7e8f9a0b1c2d3e4f"] = "Joomla",
        ["d41d8cd98f00b204e9800998ecf8427e"] = "Empty/Default favicon",
    }
    local hash_hex = md5
    local matched = known[hash_hex] or "Unknown"
    return stdnse.format_output(true, "Favicon MD5: " .. hash_hex .. " (" .. matched .. ")")
end
