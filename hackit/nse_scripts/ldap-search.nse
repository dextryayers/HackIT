local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local math = require "math"
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

description = [[Performs LDAP anonymous search against common base DNs. Attempts to enumerate users, groups, computers, OUs, and other directory objects via anonymous or null binds.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and (port.number == 389 or port.number == 3268)
end

local search_configs = {
    { dn = "", desc = "Root DSE", filter = "(objectClass=*)" },
    { dn = "dc=company,dc=com", desc = "company.com", filter = "(objectClass=*)" },
    { dn = "dc=corp,dc=local", desc = "corp.local", filter = "(objectClass=*)" },
    { dn = "dc=ad,dc=local", desc = "ad.local", filter = "(objectClass=*)" },
    { dn = "dc=domain,dc=com", desc = "domain.com", filter = "(objectClass=*)" },
    { dn = "dc=test,dc=local", desc = "test.local", filter = "(objectClass=*)" },
    { dn = "o=Organization", desc = "Organization", filter = "(objectClass=*)" },
    { dn = "cn=users,dc=company,dc=com", desc = "Users", filter = "(objectClass=user)" },
    { dn = "cn=computers,dc=company,dc=com", desc = "Computers", filter = "(objectClass=computer)" },
    { dn = "ou=people,dc=company,dc=com", desc = "People", filter = "(objectClass=inetOrgPerson)" },
}

local function ber_integer(val)
    if val < 128 then
        return char(0x02, val)
    end
    local bytes = {}
    while val > 0 do
        insert(bytes, 1, char(val % 256))
        val = math.floor(val / 256)
    end
    return char(0x02, #bytes) .. concat(bytes)
end

local function ber_string(s)
    return char(0x04, #s) .. s
end

local function ber_sequence(contents)
    return char(0x30, #contents) .. contents
end

local function build_search_request(base_dn, filter_str, scope_val)
    local msg_id = ber_integer(1)
    local base_obj = ber_string(base_dn)
    local scope = char(0x0a, 0x01, scope_val or 2)
    local deref = char(0x0a, 0x01, 0x00)
    local size_limit = ber_integer(0)
    local time_limit = ber_integer(0)
    local types_only = char(0x01, 0x01, 0x00)

    local filter
    if filter_str == "(objectClass=*)" then
        filter = ber_sequence(char(0x05, 0x00))
    elseif filter_str:match("objectClass=(%w+)") then
        local oc = filter_str:match("objectClass=(%w+)")
        filter = ber_sequence(char(0x04, #oc) .. oc)
    else
        filter = ber_sequence(char(0x05, 0x00))
    end

    local attrs = ber_sequence(
        ber_string("objectClass") ..
        ber_string("cn") ..
        ber_string("sn") ..
        ber_string("mail") ..
        ber_string("memberOf") ..
        ber_string("distinguishedName") ..
        ber_string("sAMAccountName") ..
        ber_string("userPrincipalName") ..
        ber_string("displayName") ..
        ber_string("description") ..
        ber_string("whenChanged") ..
        ber_string("whenCreated") ..
        ber_string("uSNChanged") ..
        ber_string("uSNCreated") ..
        ber_string("objectSid") ..
        ber_string("objectGUID")
    )

    local search_body = base_obj .. scope .. deref .. size_limit .. time_limit .. types_only .. filter .. attrs
    local search_req = ber_sequence(char(0x63, #search_body) .. search_body)
    return ber_sequence(msg_id .. search_req)
end

local function count_entries(response)
    if not response or #response < 10 then return 0 end
    local count = 0
    local search_done = response:find("SearchResultDone") or
                        response:find("LDAPResult") or
                        response:find("\x30\x0c\x02\x01\x02\x65\x07\x0a\x01\x00\x04\x00\x04\x00")
    local pos = 1
    while true do
        local s, e = response:find("\x64\x04\x02\x01", pos)
        if not s then break end
        count = count + 1
        pos = e + 1
    end

    for dn in response:gmatch("\x04..([^\x00]+)") do
        count = count + 1
    end
    return count
end

action = function(host, port)
    local result = output_table()
    local found_bases = {}

    for _, cfg in ipairs(search_configs) do
        local socket = new_socket()
        socket:set_timeout(5000)

        local ok, err = pcall(socket.connect, socket, host.ip, port.number)
        if not ok then
            pcall(socket.close, socket)
            break
        end

        local req = build_search_request(cfg.dn, cfg.filter, cfg.dn == "" and 0 or 2)
        local ok2 = pcall(socket.send, socket, req)
        if not ok2 then
            pcall(socket.close, socket)
            break
        end

        local ok3, response = pcall(socket.receive_buf, socket, "\x30", 5)
        pcall(socket.close, socket)

        if ok3 and response and #response > 20 then
            local entry_count = count_entries(response)
            local dn_desc = cfg.desc
            local base_entry = {
                base_dn = cfg.dn,
                description = dn_desc,
                entries_found = entry_count or 1,
                response_size = #response,
            }

            if response:find("sAMAccountName") then
                base_entry.has_sam_account = true
            end
            if response:find("userPrincipalName") then
                base_entry.has_upn = true
            end
            if response:find("objectSid") then
                base_entry.has_sid = true
            end
            if response:find("mail@") or response:find("MAIL@") then
                base_entry.has_email = true
            end

            insert(found_bases, base_entry)
        end
    end

    if #found_bases == 0 then
        return format_output(false, "No anonymous LDAP search results")
    end

    result.searchable_base_dns = found_bases
    result.searchable_count = #found_bases

    return format_output(true, result)
end
