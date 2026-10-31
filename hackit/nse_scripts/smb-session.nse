local stdnse = require "stdnse"
local smb = require "smb"
local string = require "string"
local nmap = require "nmap"
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

description = [[Tests SMB session setup with null session and common credentials. Attempts to enumerate users, shares, and OS info for each successful authentication method.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and port.number == 445
end

local credential_tests = {
    { user = "", pass = "", desc = "Null session" },
    { user = "guest", pass = "", desc = "Guest (empty password)" },
    { user = "Administrator", pass = "", desc = "Administrator (empty password)" },
    { user = "guest", pass = "guest", desc = "Guest (guest/guest)" },
    { user = "admin", pass = "", desc = "admin (empty password)" },
    { user = "user", pass = "", desc = "user (empty password)" },
    { user = "backup", pass = "", desc = "backup (empty password)" },
    { user = "test", pass = "", desc = "test (empty password)" },
    { user = "nobody", pass = "", desc = "nobody (empty password)" },
    { user = "root", pass = "", desc = "root (empty password)" },
}

action = function(host, port)
    local result = output_table()
    local session_results = {}

    for _, c in ipairs(credential_tests) do
        local entry = { user = c.user, description = c.desc }

        local ok, smbstate = pcall(smb.start, host, port)
        if not ok or not smbstate then
            entry.status = "connection_failed"
            insert(session_results, entry)
            goto continue
        end

        local ok2, smbstate2 = pcall(smb.negotiate_protocol, smbstate)
        if not ok2 then
            pcall(smb.stop, smbstate)
            entry.status = "negotiate_failed"
            insert(session_results, entry)
            goto continue
        end
        smbstate = smbstate2

        local ok3, smbstate3 = pcall(smb.session_setup, smbstate, c.user, c.pass)
        if ok3 then
            smbstate = smbstate3
            entry.status = "session_established"
            entry.native_os = smbstate.native_os
            entry.domain = smbstate.domain

            local ok4, shares = pcall(smb.list_shares, smbstate)
            if ok4 and shares then
                entry.shares_accessible = {}
                for _, sh in ipairs(shares) do
                    insert(entry.shares_accessible, sh.name)
                end
                entry.share_count = #shares
            end
        else
            local err_msg = tostring(smbstate3)
            if find(err_msg, "ACCESS_DENIED") or find(err_msg, "STATUS_LOGON_FAILURE") then
                entry.status = "access_denied"
            elseif find(err_msg, "invalid") then
                entry.status = "invalid_credentials"
            else
                entry.status = "failed: " .. err_msg
            end
        end

        pcall(smb.stop, smbstate)
        insert(session_results, entry)
        ::continue::
    end

    result.session_tests = session_results
    result.tests_conducted = #session_results

    local success_count = 0
    for _, entry in ipairs(session_results) do
        if entry.status == "session_established" then
            success_count = success_count + 1
        end
    end
    result.successful_sessions = success_count

    return format_output(true, result)
end
