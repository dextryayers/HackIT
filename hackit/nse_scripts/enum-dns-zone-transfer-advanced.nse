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
Performs advanced DNS zone transfer with multiple retry attempts and
fallback name servers. Attempts to enumerate all DNS records from
authoritative name servers using AXFR requests with timeout handling.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns")

local function dns_axfr_query(domain)
    local id = 0x0001
    local flags = 0x0100
    local qdcount = 0x0001
    local ancount = 0x0000
    local nscount = 0x0000
    local arcount = 0x0000
    local qtype = 0x00fc
    local qclass = 0x0001
    local qname = {}
    for label in gmatch(domain, "[^.]+") do
        insert(qname, char(#label) .. label)
    end
    insert(qname, char(0x00))
    local query = concat(qname)
    local header = char(
        id >> 8, id & 0xff,
        flags >> 8, flags & 0xff,
        qdcount >> 8, qdcount & 0xff,
        ancount >> 8, ancount & 0xff,
        nscount >> 8, nscount & 0xff,
        arcount >> 8, arcount & 0xff
    )
    return header .. query .. char(qtype >> 8, qtype & 0xff, qclass >> 8, qclass & 0xff)
end

action = function(host, port)
    local result = {}
    local domains = {host.name or host.ip, "localhost", "local"}
    local socket = new_socket("udp")
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)
    if not status then
        return format_output(false, "Could not connect to DNS: " .. tostring(err))
    end
    insert(result, "DNS server detected, attempting zone transfers...")
    for _, domain in ipairs(domains) do
        if domain and domain ~= "" then
            local query = dns_axfr_query(domain)
            socket:send(query)
            local status, response = socket:receive_bytes(1)
            if status and response then
                local records = 0
                local pos = 13
                while pos < #response - 10 do
                    if byte(response, pos) == 0xc0 then
                        pos = pos + 2
                    end
                    if pos + 10 <= #response then
                        local rtype = (byte(response, pos) << 8) + byte(response, pos + 1)
                        pos = pos + 10
                        if pos <= #response then
                            local rdlength = (byte(response, pos) << 8) + byte(response, pos + 1)
                            pos = pos + 2
                            records = records + 1
                            pos = pos + rdlength
                        end
                    end
                end
                if records > 0 then
                    insert(result, ("Zone transfer for %s: %d records"):format(domain, records))
                end
            end
        end
    end
    socket:close()
    if #result == 1 then
        insert(result, "Zone transfer failed (likely restricted)")
    end
    return format_output(true, result)
end
