local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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
  local result = stdnse.output_table()

  for _, path in ipairs(beanstalk_paths) do
    local ok, response = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
    if ok and response and response.status and response.status ~= 0 then
      local found = false
      local found_indicators = {}

      if response.headers then
        for hname, hvalue in pairs(response.headers) do
          local lname = hname:lower()
          for _, pattern in ipairs(beanstalk_headers) do
            if lname:find(pattern) then
              found = true
              result[hname] = hvalue
              table.insert(found_indicators, "header:" .. hname)
            end
          end
        end
      end

      if response.body then
        local lbody = response.body:lower()
        for _, pattern in ipairs(beanstalk_body_patterns) do
          if lbody:find(pattern:lower()) then
            found = true
            table.insert(found_indicators, "body:" .. pattern)
          end
        end
      end

      if found then
        result.platform = "AWS Elastic Beanstalk"
        result.status_code = response.status
        result.server_header = response.headers and response.headers["server"]
        result.detected_on_path = path
        result.indicators = found_indicators
        return stdnse.format_output(true, result)
      end
    end
  end

  return stdnse.format_output(false, "No Elastic Beanstalk indicators detected")
end
