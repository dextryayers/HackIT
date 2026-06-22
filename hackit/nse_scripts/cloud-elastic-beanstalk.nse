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
        local lbody = response.lower(body)
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
