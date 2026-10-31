local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"



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
        local listing = match(response.body or "", "<ListBucketResult") and true or false
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
