local stdnse = require "stdnse"

description = [[Connects to the SMTP server and enumerates supported commands by sending the EHLO/HELO command and parsing the response for supported ESMTP extensions and commands. Uses structured output with version extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 25 or port.service == "smtp") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        sock:send("EHLO hackit.local\r\n")
        local resp = sock:receive_buf("\n", 5000)
        local all_extensions = {}
        if resp then
            local lines = resp:gmatch("250[%- ]([^\r\n]+)")
            for line in lines do
                table.insert(all_extensions, line)
            end
        end
        sock:send("HELO hackit.local\r\n")
        local helo_resp = sock:receive_buf("\n", 3000)
        sock:close()
        local res = stdnse.output_table()
        res.banner = banner:match("220[%s-]([^\r\n]+)") or banner:match("220([^\r\n]+)")
        if #all_extensions > 0 then
            res.esmtp_extensions = all_extensions
        end
        local commands = {}
        for _, ext in ipairs(all_extensions) do
            local name = ext:match("^(%w+)")
            if name then
                commands[name] = true
            end
        end
        res.command_summary = {}
        for k in pairs(commands) do
            table.insert(res.command_summary, k)
        end
        local ver = banner:match("([%d%.]+)") or (resp and resp:match("([%d%.]+)"))
        if ver then res.version = ver end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return stdnse.format_output(false, "Could not enumerate SMTP commands")
    end
    return result
end
