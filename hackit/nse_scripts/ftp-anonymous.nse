local stdnse = require "stdnse"

description = [[Tests if the FTP server allows anonymous login using "anonymous" or "ftp" as the username with any password. Uses structured output with version extraction from banner.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 21 or port.service == "ftp") end

local credentials = {
    {"anonymous", "guest@"},
    {"ftp", "ftp@"},
    {"anonymous", "anonymous@"},
    {"ftp", "password"},
}

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("\n", 5000)
        if not banner then sock:close(); return end
        local found_access = false
        local last_msg
        for _, cred in ipairs(credentials) do
            local s = nmap.new_socket()
            s:set_timeout(5000)
            local ok2 = s:connect(host.ip, port)
            if ok2 then
                s:receive_buf("\n", 3000)
                s:send("USER " .. cred[1] .. "\r\n")
                s:receive_buf("\n", 3000)
                s:send("PASS " .. cred[2] .. "\r\n")
                local _, r = s:receive_buf("\n", 3000)
                s:close()
                if r and (r:match("230 ") or r:match("User logged in")) then
                    found_access = true
                    last_msg = r
                    break
                end
            end
        end
        sock:close()
        local res = stdnse.output_table()
        res.banner = banner:match("220[%s-]([^\r\n]+)") or banner:match("220([^\r\n]+)")
        res.anonymous_access = found_access
        local ver = banner:match("([%d%.]+)[%s_]?ftp") or banner:match("FTP%s+version%s+([%d%.]+)") or banner:match("vsFTP[d]%s+([%d%.]+)")
        if ver then res.version = ver end
        if found_access then
            if last_msg then
                res.message = last_msg:match("%d%d%d ([^\r\n]+)")
            end
        end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return stdnse.format_output(false, "Could not test FTP anonymous access")
    end
    return result
end
