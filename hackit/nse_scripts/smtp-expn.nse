local stdnse = require "stdnse"

description = [[Tests the SMTP EXPN command by attempting to expand common aliases to reveal mailing list memberships and delivery addresses. Uses structured output with alias details.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_aliases = {"root", "postmaster", "mailer-daemon", "bin", "daemon", "adm", "lp", "sync", "shutdown", "halt", "news", "uucp", "operator", "games", "gopher", "ftp", "nobody", "mail", "list", "owner"}

action = function(host, port)
    local found = {}
    for _, alias in ipairs(test_aliases) do
        local sock = nmap.new_socket()
        sock:set_timeout(5000)
        local ok = pcall(function()
            local ok2 = sock:connect(host.ip, port)
            if ok2 then
                sock:receive_buf("\n", 3000)
                sock:send("EHLO hackit.local\r\n")
                sock:receive_buf("\n", 3000)
                sock:send("EXPN " .. alias .. "\r\n")
                local _, resp = sock:receive_buf("\n", 3000)
                sock:close()
                if resp and (resp:match("^250 ") or resp:match("^252 ")) then
                    local expand = resp:match("250[%- ]([^\r\n]+)")
                    table.insert(found, {alias = alias, expands_to = expand or alias})
                end
            else
                sock:close()
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
    end
    if #found > 0 then
        local result = stdnse.output_table()
        result.expn_enabled = true
        result.aliases = found
        result.alias_count = #found
        return result
    end
    return stdnse.format_output(false, "EXPN not enabled")
end
