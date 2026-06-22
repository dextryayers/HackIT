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
        local sock = new_socket()
        sock:set_timeout(10000)
        local ok, databases = pcall(function()
            local status = sock:connect(host.ip, port)
            if not status then return end
            local banner = sock:receive_buf("", 5000)
            if not banner then sock:close(); return end
            local auth_suffix = char(0x00)
            if cred.pass == "" then
                auth_suffix = char(0x00) .. char(#cred.user) .. cred.user .. char(0x00)
            else
                auth_suffix = char(0x00) .. char(#cred.user) .. cred.user .. char(0x00) .. char(#cred.pass) .. cred.pass .. char(0x00)
            end
            local auth_payload = char(0x85, 0xa2, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) .. auth_suffix
            sock:send(auth_payload)
            local _, auth_resp = sock:receive_buf("", 5000)
            if not auth_resp or byte(auth_resp, 5) ~= 0x00 then
                sock:close()
                return
            end
            local query = char(0x03, 0x00, 0x00, 0x00, 0x03) .. "SHOW DATABASES"
            local qlen = #query
            local header = char(0x00, 0x00, 0x00, 0x00, qlen % 256, math.floor(qlen / 256), 0x00, 0x00)
            sock:send(header .. query)
            local _, data = sock:receive_buf("", 5000)
            sock:close()
            if data and #data > 5 then
                local dbs = {}
                local skip = 5
                while skip < #data do
                    local col_len = byte(data, skip + 1)
                    if col_len == 0 or col_len > 64 then break end
                    local db_name = sub(data, skip + 2, skip + 1 + col_len)
                    if db_name and #db_name > 0 and not match(db_name, "[%z%c]") then
                        insert(dbs, db_name)
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
            local result = output_table()
            result.databases = databases
            result.database_count = #databases
            result.credentials_used = cred.user
            return result
        end
    end
    return format_output(false, "Could not enumerate databases")
end
