local stdnse = require "stdnse"

description = [[Connects to a MySQL server and extracts the version information from the initial handshake banner packet. Uses structured output with version regex extraction.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 3306 or port.service == "mysql") end

action = function(host, port)
    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local ok, result = pcall(function()
        local status = sock:connect(host.ip, port)
        if not status then return end
        local banner = sock:receive_buf("", 5000)
        sock:close()
        if not banner or #banner < 5 then return end
        local protocol_version = banner:byte(5)
        local server_version = ""
        local pos = 6
        while pos <= #banner do
            local byte = banner:byte(pos)
            if byte == 0 then break end
            server_version = server_version .. string.char(byte)
            pos = pos + 1
        end
        local connection_id_bytes = ""
        if pos < #banner then
            pos = pos + 1
            for i = 1, 4 do
                if pos <= #banner then
                    connection_id_bytes = connection_id_bytes .. string.char(banner:byte(pos))
                    pos = pos + 1
                end
            end
        end
        local res = stdnse.output_table()
        res.protocol_version = protocol_version
        res.server_version = server_version
        local ver_num = server_version:match("([%d]+%.?[%d]*%.?[%d]*)")
        if ver_num then
            res.version = ver_num
            local major, minor, patch = server_version:match("(%d+)%.(%d+)%.(%d+)")
            if major then
                res.version_major = tonumber(major)
                res.version_minor = tonumber(minor)
                res.version_patch = tonumber(patch)
            end
        end
        if connection_id_bytes ~= "" then
            res.connection_id = connection_id_bytes
        end
        local auth_plugin = banner:match("caching_sha2_password") or banner:match("mysql_native_password") or banner:match("sha256_password")
        if auth_plugin then
            res.auth_plugin = auth_plugin
        end
        return res
    end)
    if not ok then
        pcall(function() sock:close() end)
    end
    if not result then
        return stdnse.format_output(false, "No MySQL banner received")
    end
    return result
end
