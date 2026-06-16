local stdnse = require "stdnse"

description = [[Tests the SMTP VRFY command by querying common usernames to determine if the server reveals valid user accounts, which aids in user enumeration. Uses multiplexed connections for efficiency.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

local test_users = {"root", "admin", "postmaster", "nobody", "test", "info", "sales", "support", "hostmaster", "webmaster", "mail", "contact", "help", "administrator", "backup"}

action = function(host, port)
    local found = {}
    for _, user in ipairs(test_users) do
        local s = nmap.new_socket()
        s:set_timeout(5000)
        local ok = pcall(function()
            local ok2 = s:connect(host.ip, port)
            if ok2 then
                s:receive_buf("\n", 3000)
                s:send("EHLO hackit.local\r\n")
                s:receive_buf("\n", 3000)
                s:send("VRFY " .. user .. "\r\n")
                local _, resp = s:receive_buf("\n", 3000)
                s:close()
                if resp and (resp:match("^250 ") or resp:match("^252 ")) then
                    local detail = resp:match("250[%- ]([^\r\n]+)")
                    table.insert(found, {user = user, response = detail or user})
                end
            else
                s:close()
            end
        end)
        if not ok then
            pcall(function() s:close() end)
        end
    end
    if #found > 0 then
        local result = stdnse.output_table()
        result.vrfy_enabled = true
        result.valid_users = found
        result.user_count = #found
        return result
    end
    return stdnse.format_output(false, "VRFY not enabled or no users found")
end
