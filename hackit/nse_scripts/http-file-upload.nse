local http = require "http"
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

description = [[Scans for file upload endpoints by probing common upload paths and analyzing forms that accept file inputs.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"web", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" end

action = function(host, port)
    local upload_paths = {"/upload", "/uploads", "/file/upload", "/upload.php", "/upload.aspx", "/upload.jsp", "/file-upload", "/api/upload", "/media/upload"}
    local results = {}
    for _, path in ipairs(upload_paths) do
        local resp = http.get(host, port, path)
        if resp and resp.status and resp.status < 400 then
            if resp.body then
                if resp.find(body, 'type%s*=%s*["\']file["\']') or resp.find(body, 'enctype%s*=%s*["\']multipart/form%-data["\']') then
                    insert(results, "Upload form at " .. path)
                end
            end
            if resp.status < 300 then
                insert(results, "Upload endpoint accessible: " .. path)
            end
        end
    end
    local home_resp = http.get(host, port, "/")
    if home_resp and home_resp.body then
        for form in home_resp.gmatch(body, "<form.-</form>") do
            if find(form, 'type%s*=%s*["\']file["\']') then
                local action = match(form, 'action%s*=%s*["\'](.-)["\']') or "?"
                insert(results, "File upload form found on / (action: " .. action .. ")")
            end
        end
    end
    if #results == 0 then
        return format_output(false, "No file upload endpoints found")
    end
    return format_output(true, concat(results, "\n"))
end
