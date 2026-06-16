local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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
  local result = stdnse.output_table()
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
    return stdnse.format_output(false, "Target does not appear to be an S3 bucket endpoint")
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
              table.insert(prefixes, prefix)
            end
            if #prefixes > 0 then
              result.folder_prefixes = prefixes
            end
          end
        elseif q == "?acl" and resp.body then
          local grants = {}
          for grant in resp.body:gmatch("<Grant>.-</Grant>") do
            if grant:match("AllUsers") or grant:match("AuthenticatedUsers") then
              table.insert(grants, "public")
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

  return stdnse.format_output(true, result)
end
