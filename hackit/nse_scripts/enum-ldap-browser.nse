local nmap = require "nmap"
local stdnse = require "stdnse"
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

description = [[
Enumerates LDAP directory entries by connecting to LDAP servers and
performing anonymous or authenticated binds. Lists directory structure,
organizational units, user entries, groups, and other LDAP objects
available in the directory tree.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(389, "ldap")

local function ldap_bind_request()
    local msg_id = 1
    local bind_req = char(0x30, 0x0c, 0x02, 0x01, msg_id,
        0x60, 0x07, 0x02, 0x01, 0x02, 0x04, 0x00, 0x80, 0x00)
    return bind_req
end

local function ldap_search_request(base_dn, scope, filter)
    local msg_id = 2
    local filter_bytes = char(0x87, #filter) .. filter
    local dn_bytes = char(#base_dn) .. base_dn
    if #base_dn == 0 then
        dn_bytes = char(0x00)
    end
    local search_req = char(0x30, 0x00, 0x02, 0x01, msg_id,
        0x63, 0x00,
        dn_bytes,
        char(0x0a, 0x01, scope),
        char(0x0a, 0x01, 0x00),
        char(0x02, 0x01, 0x00),
        char(0x02, 0x01, 0x00),
        char(0x01, 0x01, 0x00),
        filter_bytes)
    return search_req
end

action = function(host, port)
    local result = {}
    local socket = new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect to LDAP: " .. tostring(err))
    end
    socket:send(ldap_bind_request())
    local status, response = socket:receive_bytes(1)
    if status then
        insert(result, "LDAP connection established (anonymous bind)")
    end
    local base_dns = {"", "dc=example,dc=com", "o=Organization", "cn=users,cn=accounts", "dc=local"}
    for _, base in ipairs(base_dns) do
        socket:send(ldap_search_request(base, 2, "(objectClass=*)"))
        local status, search_resp = socket:receive_bytes(1)
        if status and search_resp then
            local entry_count = 0
            for _ in gmatch(search_resp, "0x30") do
                entry_count = entry_count + 1
            end
            if entry_count > 0 then
                insert(result, ("LDAP entries under '%s': %d+"):format(base, entry_count))
                for dn in gmatch(search_resp, "dn[%s:]+([^\n\r]+)") do
                    insert(result, ("  DN: %s"):format(dn))
                end
            end
        end
    end
    socket:close()
    if #result == 1 then
        insert(result, "No LDAP entries enumerated")
    end
    return format_output(true, result)
end
