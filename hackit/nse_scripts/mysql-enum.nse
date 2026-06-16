local stdnse = require "stdnse"

description = [[Authenticates to a MySQL server and issues the SHOW DATABASES command to enumerate all accessible databases on the server. Uses structured output with database list.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 3306 or port.service == "mysql") end

local test_creds = {
    {user = "root", pass = ""},
    {user = "root", pass = "root"},
}

action = function(host, port)
    for _, cred in ipairs(test_creds) do
        local sock = nmap.new_socket()
        sock:set_timeout(10000)
        local ok, databases = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local banner = sock:receive_buf("", 5000)
            if not banner then sock:close(); return end
            local auth_suffix = string.char(0x00)
            if cred.pass == "" then
                auth_suffix = string.char(0x00) .. string.char(#cred.user) .. cred.user .. string.char(0x00)
            else
                auth_suffix = string.char(0x00) .. string.char(#cred.user) .. cred.user .. string.char(0x00) .. string.char(#cred.pass) .. cred.pass .. string.char(0x00)
            end
            local auth_payload = string.char(0x85, 0xa2, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) .. auth_suffix
            sock:send(auth_payload)
            local _, auth_resp = sock:receive_buf("", 5000)
            if not auth_resp or auth_resp:byte(5) ~= 0x00 then
                sock:close()
                return
            end
            local query = string.char(0x03, 0x00, 0x00, 0x00, 0x03) .. "SHOW DATABASES"
            local qlen = #query
            local header = string.char(0x00, 0x00, 0x00, 0x00, qlen % 256, math.floor(qlen / 256), 0x00, 0x00)
            sock:send(header .. query)
            local _, data = sock:receive_buf("", 5000)
            sock:close()
            if data and #data > 5 then
                local dbs = {}
                local skip = 5
                while skip < #data do
                    local col_len = data:byte(skip + 1)
                    if col_len == 0 or col_len > 64 then break end
                    local db_name = data:sub(skip + 2, skip + 1 + col_len)
                    if db_name and #db_name > 0 and not db_name:match("[%z%c]") then
                        table.insert(dbs, db_name)
                    end
                    skip = skip + 1 + col_len + 1
                end
                return dbs
            end
        end)
        if not ok then
            pcall(function() sock:close() end)
        end
        if databases and #databases > 0 then
            local result = stdnse.output_table()
            result.databases = databases
            result.database_count = #databases
            result.credentials_used = cred.user
            return result
        end
    end
    return stdnse.format_output(false, "Could not enumerate databases")
end
