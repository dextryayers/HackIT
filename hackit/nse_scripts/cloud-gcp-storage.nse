local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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
Detects Google Cloud Storage buckets by probing common bucket names against
the storage.googleapis.com endpoint. Checks for publicly accessible buckets
and attempts to list their contents.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

local function check_gcs_bucket(host, port, name)
    local response = http.get(host, port, "/" .. name)
    if not response then return nil end
    if response.status == 200 then
        local listing = response.body:match("Contents") and true or false
        return {accessible = true, listing = listing, status = response.status}
    elseif response.status == 403 then
        return {accessible = true, listing = false, status = response.status}
    elseif response.status == 404 then
        return {accessible = false, status = response.status}
    end
    return nil
end

action = function(host, port)
    local result = {}
    local bucket_names = {"backup", "assets", "media", "static", "uploads",
        "data", "public", "config", "test", "prod", "storage", "app-data",
        "files", "images", "videos", "docs", "logs", "archive"}
    insert(result, "Checking Google Cloud Storage buckets...")
    for _, name in ipairs(bucket_names) do
        local res = check_gcs_bucket(host, port, name)
        if res and res.accessible then
            local msg = ("GCS bucket 'gs://%s' - "):format(name)
            if res.listing then
                insert(result, msg .. "PUBLIC LISTING")
            else
                insert(result, msg .. "exists but listing denied")
            end
        end
    end
    if #result == 1 then
        insert(result, "No GCS buckets detected")
    end
    return format_output(true, result)
end
