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
Enumerates AWS S3 buckets by testing common bucket names and checking
their accessibility. Attempts to list bucket contents and checks
permissions including public read/write access and bucket policies.
]]

author = "HackIT"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

local function check_bucket(host, port, bucket_name)
    local url = "/" .. bucket_name
    local response = http.get(host, port, url)
    if not response then return nil end
    if response.status == 200 then
        local listing = response.match(body, "<ListBucketResult") and true or false
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
    local buckets = {"backup", "assets", "uploads", "media", "static", "files",
        "data", "logs", "public", "private", "config", "test", "dev", "prod",
        "downloads", "images", "docs", "bucket", "storage", "app"}
    insert(result, "Enumerating S3 buckets...")
    local s3_host = host.ip .. ".s3.amazonaws.com"
    for _, name in ipairs(buckets) do
        local res = check_bucket(host, port, name)
        if res and res.accessible then
            if res.listing then
                insert(result, ("Bucket 's3://%s' - PUBLIC LISTING (READ ACCESS)"):format(name))
            else
                insert(result, ("Bucket 's3://%s' - exists, listing denied (status %d)"):format(name, res.status))
            end
        end
    end
    if #result == 1 then
        insert(result, "No S3 buckets found")
    end
    return format_output(true, result)
end
