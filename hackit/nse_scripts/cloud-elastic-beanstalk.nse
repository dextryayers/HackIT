local stdnse = require "stdnse"
local http = require "http"
local json = require "json"
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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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

description = [[Detects AWS Elastic Beanstalk environments by checking for Beanstalk-specific response headers (x-beanstalk-*), environment endpoints, and body content signatures. Probes multiple paths and header variations.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443)
end

local beanstalk_headers = {
  "x-beanstalk", "x-amz-beanstalk", "x-elastic-beanstalk",
}

local beanstalk_paths = {
  "/", "/health", "/healthcheck", "/status", "/info",
  "/api/health", "/api/status", "/errors",
  "/health.json", "/status.json",
}

local beanstalk_body_patterns = {
  "Elastic Beanstalk", "aws.*beanstalk", "beanstalk.*aws",
  "EB-", "AWSEB", "aws-elastic-beanstalk",
  "ElasticBeanstalk",
}

action = function(host, port)
  local result = output_table()

  for _, path in ipairs(beanstalk_paths) do
    local ok, response = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
    if ok and response and response.status and response.status ~= 0 then
      local found = false
      local found_indicators = {}

      if response.headers then
        for hname, hvalue in pairs(response.headers) do
          local lname = lower(hname)
          for _, pattern in ipairs(beanstalk_headers) do
            if find(lname, pattern) then
              found = true
              result[hname] = hvalue
              insert(found_indicators, "header:" .. hname)
            end
          end
        end
      end

      if response.body then
        local lbody = lower(response.body or "")
        for _, pattern in ipairs(beanstalk_body_patterns) do
          if find(lbody, pattern:lower()) then
            found = true
            insert(found_indicators, "body:" .. pattern)
          end
        end
      end

      if found then
        result.platform = "AWS Elastic Beanstalk"
        result.status_code = response.status
        result.server_header = response.headers and response.headers["server"]
        result.detected_on_path = path
        result.indicators = found_indicators
        return format_output(true, result)
      end
    end
  end

  return format_output(false, "No Elastic Beanstalk indicators detected")
end
