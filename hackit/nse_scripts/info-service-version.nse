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

description = [[Detects service version via banner analysis and fingerprint matching.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

local version_map = {
    {sig = "OpenSSH",       name = "OpenSSH",       category = "SSH"},
    {sig = "vsFTPd",        name = "vsFTPd",        category = "FTP"},
    {sig = "ProFTPD",       name = "ProFTPD",       category = "FTP"},
    {sig = "Apache",        name = "Apache HTTP",   category = "HTTP"},
    {sig = "nginx",         name = "nginx",         category = "HTTP"},
    {sig = "Microsoft-IIS", name = "IIS",            category = "HTTP"},
    {sig = "lighttpd",      name = "Lighttpd",       category = "HTTP"},
    {sig = "PostgreSQL",    name = "PostgreSQL",     category = "DB"},
    {sig = "MySQL",         name = "MySQL",          category = "DB"},
    {sig = "MariaDB",       name = "MariaDB",        category = "DB"},
    {sig = "Redis",         name = "Redis",          category = "DB"},
    {sig = "MongoDB",       name = "MongoDB",        category = "DB"},
    {sig = "Exim",          name = "Exim",           category = "SMTP"},
    {sig = "Postfix",       name = "Postfix",        category = "SMTP"},
    {sig = "Dovecot",       name = "Dovecot",        category = "IMAP/POP3"},
    {sig = "Sendmail",      name = "Sendmail",       category = "SMTP"},
    {sig = "Courier",       name = "Courier",        category = "IMAP/POP3"},
    {sig = "Tomcat",        name = "Apache Tomcat",  category = "Application"},
    {sig = "Jetty",         name = "Eclipse Jetty",  category = "Application"},
    {sig = "CouchDB",       name = "CouchDB",        category = "DB"},
    {sig = "Elasticsearch", name = "Elasticsearch",  category = "DB"},
    {sig = "RabbitMQ",      name = "RabbitMQ",       category = "Message Queue"},
}

local function extract_version(banner, name)
    local patterns = {
        ["OpenSSH"] = "OpenSSH[ _]([%d.]+p?[%d]*)",
        ["vsFTPd"] = "vsFTPd ([%d.]+)",
        ["ProFTPD"] = "ProFTPD ([%d.]+)",
        ["Apache HTTP"] = "Apache/([%d.]+)",
        ["nginx"] = "nginx/([%d.]+)",
        ["IIS"] = "Microsoft%-IIS/([%d.]+)",
        ["Lighttpd"] = "lighttpd/([%d.]+)",
        ["PostgreSQL"] = "PostgreSQL ([%d.]+)",
        ["MySQL"] = "MySQL ([%d.]+)",
        ["MariaDB"] = "MariaDB ([%d.]+)",
        ["Exim"] = "Exim ([%d.]+)",
        ["Postfix"] = "Postfix ([%d.]+)",
        ["Dovecot"] = "Dovecot ([%d.]+)",
        ["Sendmail"] = "Sendmail ([%d.]+)",
        ["Tomcat"] = "Tomcat/([%d.]+)",
        ["Jetty"] = "Jetty/([%d.]+)",
    }
    if patterns[name] then
        local v = banner:match(patterns[name])
        if v then return v end
    end
    if name == "Redis" then
        local v = banner:match("redis_version:([%d.]+)")
        if v then return v end
    end
    return banner:match("([%d]+%.[%d]+%.[%d]+)") or banner:match("([%d]+%.[%d]+)")
end

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local out = output_table()
    out.service = "Service Version Detection"
    out.target = host.ip
    out.port = port.number
    local socket = new_socket()
    socket:set_timeout(5000)
    local ok, banner = pcall(function()
        local status, err = socket:connect(host, port)
        if not status then return nil end
        local b = socket:receive_bytes(512)
        if port.number == 80 or port.number == 443 or port.number == 8080 then
            socket:send("GET / HTTP/1.0\r\nHost: " .. host.ip .. "\r\n\r\n")
            b = socket:receive_bytes(4096)
        end
        socket:close()
        if b then
            return b:gsub("[\r\n]+", " "):sub(1, 300)
        end
        return nil
    end)
    if not ok then pcall(socket.close, socket) end
    if banner then
        out.banner = banner
        local matched = nil
        local version = nil
        for _, entry in ipairs(version_map) do
            if banner:find(entry.sig, 1, true) then
                matched = entry
                version = extract_version(banner, entry.name)
                break
            end
        end
        if matched then
            out.status = "IDENTIFIED"
            out.software = matched.name
            out.category = matched.category
            if version then out.version = version end
        else
            out.status = "UNIDENTIFIED"
            out.message = "Unrecognized service"
        end
    else
        out.status = "NO_BANNER"
        out.message = "Could not detect service version"
    end
    return out
end
