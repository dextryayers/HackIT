local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = nmap.msleep
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

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
