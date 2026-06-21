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

description = [[Tests password policy strength by analyzing banners and error messages that reveal password requirements.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "audit"}

local policy_indicators = {
    {patterns = {"minimum", "min length", "at least", "must be at least", "too short"}, category = "Minimum Length", severity = "INFO"},
    {patterns = {"special", "symbol", "special char", "non%-alphanumeric"}, category = "Special Characters", severity = "INFO"},
    {patterns = {"uppercase", "capital", "upper case", "capital letter"}, category = "Uppercase Required", severity = "INFO"},
    {patterns = {"lowercase", "lower case"}, category = "Lowercase Required", severity = "INFO"},
    {patterns = {"digit", "number", "numeric", "at least one digit"}, category = "Digit Required", severity = "INFO"},
    {patterns = {"complexity", "must contain", "character classes"}, category = "Complexity", severity = "INFO"},
    {patterns = {"expired", "expir"}, category = "Password Expiration", severity = "WARNING"},
    {patterns = {"history", "cannot reuse", "recently used"}, category = "Password History", severity = "INFO"},
    {patterns = {"lockout", "locked", "too many"}, category = "Account Lockout", severity = "WARNING"},
    {patterns = {"common", "dictionary", "weak"}, category = "Weak Password Detection", severity = "INFO"},
}

local test_inputs = {"test", "Password1", "P@ssw0rd", "admin", "123456", "Aa1", "a", "A", "1"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Password Policy Audit"
    out.target = host.ip
    out.port = port.number
    local findings = {}

    for _, input in ipairs(test_inputs) do
        local socket = new_socket()
        socket:set_timeout(5000)
        local ok, resp = pcall(function()
            local status, err = socket:connect(host, port)
            if not status then return nil end
            socket:send(input .. "\r\n")
            local _, r = socket:receive_bytes(512)
            socket:close()
            return r
        end)
        if not ok then pcall(socket.close, socket) end

        if resp then
            for _, indicator in ipairs(policy_indicators) do
                for _, pat in ipairs(indicator.patterns) do
                    if resp:lower():find(pat) then
                        local already = false
                        for _, f in ipairs(findings) do
                            if f.category == indicator.category then already = true end
                        end
                        if not already then
                            insert(findings, {category = indicator.category, severity = indicator.severity, evidence = resp:sub(1, 80):gsub("[\r\n]", " ")})
                        end
                    end
                end
            end
        end
    end

    if #findings > 0 then
        out.status = "POLICY_HINTS_REVEALED"
        out.policy_findings = findings
        out.risk = "MEDIUM"
        out.message = "Password policy hints disclosed in server responses"
    else
        out.status = "NO_POLICY_DISCLOSURE"
        out.risk = "LOW"
        out.message = "No password policy info disclosed"
    end
    return out
end
