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
  local result = output_table()

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
              insert(indicators, "header:" .. hname)
            end
          end
          if type(hvalue) == "string" then
            for _, val_pattern in ipairs(heroku_indicators.header_values) do
              if hvalue:lower():find(val_pattern:lower()) then
                found = true
                result["header_" .. lname] = hvalue
                insert(indicators, "header_val:" .. lname)
              end
            end
          end
        end
      end

      if response.body then
        for _, pattern in ipairs(heroku_indicators.body_patterns) do
          if response.body:find(pattern) then
            found = true
            insert(indicators, "body:" .. pattern)
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
        return format_output(true, result)
      end
    end
  end

  return format_output(false, "No Heroku indicators detected")
end
