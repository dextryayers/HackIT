local stdnse = require "stdnse"
local nmap = require "nmap"

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
    local out = stdnse.output_table()
    out.service = "Password Policy Audit"
    out.target = host.ip
    out.port = port.number
    local findings = {}

    for _, input in ipairs(test_inputs) do
        local socket = nmap.new_socket()
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
                            findings[#findings + 1] = {category = indicator.category, severity = indicator.severity, evidence = resp:sub(1, 80):gsub("[\r\n]", " ")}
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
