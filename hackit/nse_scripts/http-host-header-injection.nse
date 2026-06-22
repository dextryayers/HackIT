local stdnse = require "stdnse"
local http = require "http"
local string = require "string"
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

description = [[Tests for HTTP Host header injection vulnerabilities. Sends various malformed Host headers and X-Forwarded-Host variants to detect cache poisoning, redirect hijacking, and header injection vectors.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
        (port.service == "http" or port.service == "https")
end

local payloads = {
    { name = "Arbitrary Host", host = "evil.com", xfh = nil },
    { name = "Arbitrary XFH", host = host.ip, xfh = "evil.com" },
    { name = "Both Malicious", host = "evil.com", xfh = "evil.com" },
    { name = "Absolute URL", host = "http://evil.com", xfh = nil },
    { name = "Port Injection", host = host.ip .. ":9999", xfh = nil },
    { name = "SQL Injection", host = host.ip .. "' OR '1'='1", xfh = nil },
    { name = "Host + XFH Diff", host = "attacker.com", xfh = "evil.com" },
    { name = "Subdomain", host = "sub." .. (host.name or host.ip), xfh = nil },
    { name = "IP Variation", host = "127.0.0.1", xfh = nil },
    { name = "Localhost", host = "localhost", xfh = nil },
    { name = "Newline", host = "evil.com%0d%0aX-Injected:%20true", xfh = nil },
    { name = "\tTab Injection", host = "evil.com%09injected:true", xfh = nil },
    { name = "Long Host", host = rep("A", 1000) .. ".com", xfh = nil },
    { name = "Empty Host", host = "", xfh = "" },
    { name = "Local IPv6", host = "[::1]", xfh = nil },
    { name = "Multiple XFH", host = host.ip, xfh = "evil1.com, evil2.com" },
}

local function check_host_header(host, port, payload)
    local headers = { ["Host"] = payload.host }
    if payload.xfh then
        headers["X-Forwarded-Host"] = payload.xfh
    end

    local ok, response = pcall(http.get, host, port, "/", { header = headers, timeout = 5000 })
    if not ok or not response or not response.status then
        return nil
    end

    local indicators = {}
    local body_lower = response.body and response.lower(body) or ""

    local injection_patterns = {
        { pattern = "evil%.com", desc = "Host value reflected in body" },
        { pattern = "127%.0%.0%.1", desc = "Internal IP reflected" },
        { pattern = "localhost", desc = "localhost reflected" },
        { pattern = "attacker%.com", desc = "Attacker domain reflected" },
        { pattern = "x%-injected", desc = "Header injection successful" },
        { pattern = "injected[%s]*:[%s]*true", desc = "CRLF injection reflected" },
        { pattern = "root:.*:0:0:", desc = "Path traversal attempt" },
        { pattern = "admin", desc = "Admin panel reflected" },
    }

    for _, ip in ipairs(injection_patterns) do
        if find(body_lower, ip.pattern) then
            insert(indicators, ip.desc)
        end
    end

    if response.status == 302 or response.status == 301 then
        local location = (response.header and response.header["location"]) or ""
        local loc_lower = lower(location)
        local redirect_indicators = {
            { pattern = "evil%.com", desc = "Redirect to attacker host" },
            { pattern = "127%.0%.0%.1", desc = "Redirect to localhost" },
            { pattern = "localhost", desc = "Redirect to localhost" },
            { pattern = "attacker%.com", desc = "Redirect to attacker" },
        }
        for _, ri in ipairs(redirect_indicators) do
            if find(loc_lower, ri.pattern) then
                insert(indicators, ri.desc)
            end
        end
    end

    if response.status == 200 or response.status == 302 or response.status == 301 then
        if response.header then
            for k, v in pairs(response.header) do
                local kl = lower(k)
                local vl = tostring(v):lower()
                if kl ~= "host" and kl ~= "x-forwarded-host" then
                    if kl == "location" and vl ~= "" then
                        if find(vl, payload.host:lower()) then
                            insert(indicators, "Host injected into Location header")
                        end
                    end
                end
            end
        end
    end

    if #indicators > 0 then
        return indicators
    end
    return nil
end

action = function(host, port)
    local result = output_table()
    local findings = {}

    for _, payload in ipairs(payloads) do
        local indicators = check_host_header(host, port, payload)
        if indicators then
            local finding = {
                test_name = payload.name,
                host_sent = payload.host,
                xfh_sent = payload.xfh,
                indicators = indicators,
            }
            insert(findings, finding)
        end
    end

    if #findings == 0 then
        return format_output(false, "No Host header injection vulnerabilities detected")
    end

    result.findings = findings
    result.vulnerable_tests = #findings

    return format_output(true, result)
end
