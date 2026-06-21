local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
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

description = [[Checks for publicly accessible AWS S3 buckets. Attempts to list bucket contents, check bucket policy/ACL configuration, versioning, website hosting, and CORS settings. Tests multiple S3 endpoint patterns.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443)
end

local s3_endpoints = {
  "s3.amazonaws.com", "s3-us-east-1.amazonaws.com",
  "s3-us-west-1.amazonaws.com", "s3-us-west-2.amazonaws.com",
  "s3-eu-west-1.amazonaws.com", "s3-eu-central-1.amazonaws.com",
  "s3-ap-southeast-1.amazonaws.com", "s3-ap-northeast-1.amazonaws.com",
}

local s3_queries = {
  "", "?acl", "?versioning", "?website", "?cors", "?logging",
  "?tagging", "?lifecycle", "?replication", "?policy",
  "?publicAccessBlock", "?encryption", "?notification",
  "?accelerate", "?requestPayment", "?versionId=",
}

action = function(host, port)
  local result = output_table()
  local bucket_host = host.name or host.ip

  local bucket_name
  local s3_region

  bucket_name = bucket_host:match("^(.-)%.s3[.-]")
  if not bucket_name then
    bucket_name = bucket_host:match("^(.-)%.s3%.amazonaws%.com$")
  end
  if not bucket_name then
    for _, ep in ipairs(s3_endpoints) do
      if bucket_host == ep then
        bucket_name = "direct-endpoint"
        break
      end
    end
  end

  if not bucket_name then
    return format_output(false, "Target does not appear to be an S3 bucket endpoint")
  end

  result.bucket_name = bucket_name
  result.target = bucket_host

  for _, q in ipairs(s3_queries) do
    local path = "/" .. q
    local ok, resp = pcall(http.get, bucket_host, port.number, path, { timeout = 5000 })
    if ok and resp then
      local query_key = q == "" and "list" or q:gsub("^%?", ""):gsub("=.*", "")
      if resp.status == 200 then
        result[query_key .. "_accessible"] = true
        if q == "" then
          result.publicly_listable = true
          if resp.body then
            local file_count = 0
            for _ in resp.body:gmatch("<Key>([^<]+)</Key>") do
              file_count = file_count + 1
            end
            if file_count > 0 then
              result.objects_count = file_count
            end
            local prefixes = {}
            for prefix in resp.body:gmatch("<CommonPrefixes><Prefix>([^<]+)</Prefix></CommonPrefixes>") do
              insert(prefixes, prefix)
            end
            if #prefixes > 0 then
              result.folder_prefixes = prefixes
            end
          end
        elseif q == "?acl" and resp.body then
          local grants = {}
          for grant in resp.body:gmatch("<Grant>.-</Grant>") do
            if grant:match("AllUsers") or grant:match("AuthenticatedUsers") then
              insert(grants, "public")
            end
          end
          if #grants > 0 then
            result.public_acl = true
            result.acl_grants = grants
          end
        end
      elseif resp.status == 403 then
        if q == "" then
          result.publicly_listable = false
          result.access = "AccessDenied — bucket exists but listing requires authentication"
        end
      end
    end
  end

  return format_output(true, result)
end
