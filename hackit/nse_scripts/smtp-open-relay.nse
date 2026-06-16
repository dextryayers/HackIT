local stdnse = require "stdnse"

description = [[Tests if the SMTP server is an open relay by attempting to send an email through the server to an external address without authentication. Uses structured output with detailed SMTP dialog.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "vuln"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_domains = {"example.com", "test.org", "mailinator.com"}

action = function(host, port)
    local relay_found = false
    local dialog = {}
    for _, domain in ipairs(test_domains) do
        if relay_found then break end
        local sock = nmap.new_socket()
        sock:set_timeout(15000)
        local ok = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local banner = sock:receive_buf("\n", 5000)
            table.insert(dialog, "BANNER: " .. (banner:match("([^\r\n]+)") or banner))
            sock:send("EHLO hackit.local\r\n")
            local ehlo = sock:receive_buf("\n", 5000)
            table.insert(dialog, "EHLO: +OK")
            if ehlo then
                sock:send("MAIL FROM:<test@hackit.local>\r\n")
                local mf = sock:receive_buf("\n", 5000)
                table.insert(dialog, "MAIL FROM: " .. (mf:match("([^\r\n]+)") or mf))
                if mf and (mf:match("^250 ") or mf:match("^251 ")) then
                    sock:send("RCPT TO:<relay-test@" .. domain .. ">\r\n")
                    local rcpt = sock:receive_buf("\n", 5000)
                    table.insert(dialog, "RCPT TO: " .. (rcpt:match("([^\r\n]+)") or rcpt))
                    if rcpt and (rcpt:match("^250 ") or rcpt:match("^251 ")) then
                        relay_found = true
                    end
                end
            end
            sock:send("QUIT\r\n")
            sock:close()
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
    end
    if relay_found then
        local result = stdnse.output_table()
        result.vulnerability = true
        result.name = "SMTP Open Relay"
        result.severity = "HIGH"
        result.details = "SMTP server accepts mail for external domains without authentication"
        result.dialog = dialog
        return result
    end
    return stdnse.format_output(false, "Not an open relay")
end
