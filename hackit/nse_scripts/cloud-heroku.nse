local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Detects Heroku-hosted applications by checking for Heroku-specific headers (x-heroku-*), routing infrastructure, and body content signatures. Probes multiple paths and analyzes response patterns.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 80 or port.number == 443)
end

local heroku_indicators = {
  headers = {
    "x-heroku", "x-powered-by", "via",
  },
  body_patterns = {
    "Heroku", "heroku", "herokuapp%.com", "herokussl%.com",
    "heroku%-pages", "heroku%-cdn",
  },
  header_values = {
    "heroku", "Fly/",
  },
}

local probe_paths = {
  "/", "/health", "/status", "/info",
  "/.well-known/app-meta", "/api/health",
  "/heroku", "/version",
}

action = function(host, port)
  local result = stdnse.output_table()

  for _, path in ipairs(probe_paths) do
    local ok, response = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
    if ok and response and response.status and response.status ~= 0 then
      local found = false
      local indicators = {}

      if response.headers then
        for hname, hvalue in pairs(response.headers) do
          local lname = hname:lower()
          for _, pattern in ipairs(heroku_indicators.headers) do
            if lname:find(pattern:lower()) then
              found = true
              result["header_" .. lname] = hvalue
              table.insert(indicators, "header:" .. hname)
            end
          end
          if type(hvalue) == "string" then
            for _, val_pattern in ipairs(heroku_indicators.header_values) do
              if hvalue:lower():find(val_pattern:lower()) then
                found = true
                result["header_" .. lname] = hvalue
                table.insert(indicators, "header_val:" .. lname)
              end
            end
          end
        end
      end

      if response.body then
        for _, pattern in ipairs(heroku_indicators.body_patterns) do
          if response.body:find(pattern) then
            found = true
            table.insert(indicators, "body:" .. pattern)
          end
        end
      end

      if found then
        result.platform = "Heroku"
        result.status_code = response.status
        result.server_header = response.headers and response.headers["server"]
        result.via_header = response.headers and response.headers["via"]
        result.detected_on_path = path
        result.indicators = indicators
        return stdnse.format_output(true, result)
      end
    end
  end

  return stdnse.format_output(false, "No Heroku indicators detected")
end
