local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local math = require "math"

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
        return string.char(0x02, val)
    end
    local bytes = {}
    while val > 0 do
        table.insert(bytes, 1, string.char(val % 256))
        val = math.floor(val / 256)
    end
    return string.char(0x02, #bytes) .. table.concat(bytes)
end

local function ber_string(s)
    return string.char(0x04, #s) .. s
end

local function ber_sequence(contents)
    return string.char(0x30, #contents) .. contents
end

local function build_search_request(base_dn, filter_str, scope_val)
    local msg_id = ber_integer(1)
    local base_obj = ber_string(base_dn)
    local scope = string.char(0x0a, 0x01, scope_val or 2)
    local deref = string.char(0x0a, 0x01, 0x00)
    local size_limit = ber_integer(0)
    local time_limit = ber_integer(0)
    local types_only = string.char(0x01, 0x01, 0x00)

    local filter
    if filter_str == "(objectClass=*)" then
        filter = ber_sequence(string.char(0x05, 0x00))
    elseif filter_str:match("objectClass=(%w+)") then
        local oc = filter_str:match("objectClass=(%w+)")
        filter = ber_sequence(string.char(0x04, #oc) .. oc)
    else
        filter = ber_sequence(string.char(0x05, 0x00))
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
    local search_req = ber_sequence(string.char(0x63, #search_body) .. search_body)
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
    local result = stdnse.output_table()
    local found_bases = {}

    for _, cfg in ipairs(search_configs) do
        local socket = nmap.new_socket()
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

            table.insert(found_bases, base_entry)
        end
    end

    if #found_bases == 0 then
        return stdnse.format_output(false, "No anonymous LDAP search results")
    end

    result.searchable_base_dns = found_bases
    result.searchable_count = #found_bases

    return stdnse.format_output(true, result)
end
