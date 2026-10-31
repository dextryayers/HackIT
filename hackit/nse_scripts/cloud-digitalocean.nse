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

description = [[Detects DigitalOcean Droplet metadata by querying the DigitalOcean metadata endpoint at 169.254.169.254. Returns droplet ID, region, hostname, networking, block storage, and user data if accessible.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local metadata_paths = {
  "id", "hostname", "region", "size", "floating_ip",
  "reserved_ip", "interfaces/public/0/ipv4/address",
  "interfaces/public/0/ipv4/gateway",
  "interfaces/public/0/ipv4/netmask",
  "interfaces/public/0/ipv6/address",
  "interfaces/private/0/ipv4/address",
  "interfaces/private/0/ipv4/gateway",
  "interfaces/private/0/ipv4/netmask",
  "dns/nameservers",
  "tags",
  "features",
}

action = function(host, port)
  local result = output_table()

  if host.ip ~= "169.254.169.254" then
    return nil
  end

  local ok, response = pcall(http.get, "169.254.169.254", 80, "/metadata/v1.json", { timeout = 3000 })
  if not ok or not response or response.status ~= 200 then
    return format_output(false, "DigitalOcean metadata endpoint not accessible")
  end

  local ok2, data = pcall(json.parse, response.body)
  if ok2 and data then
    for k, v in pairs(data) do
      result[gsub(k, "-", "_")] = v
    end
  end

  for _, path in ipairs(metadata_paths) do
    local ok3, resp = pcall(http.get, "169.254.169.254", 80, "/metadata/v1/" .. path, { timeout = 2000 })
    if ok3 and resp and resp.status == 200 and resp.body and #resp.body > 0 then
      local key = gsub(path, "/", "_"):gsub("-", "_")
      result[key] = gsub(resp.body or "", "%s+$", "")
    end
  end

  local ok4, user_data = pcall(http.get, "169.254.169.254", 80, "/metadata/v1/user-data", { timeout = 2000 })
  if ok4 and user_data and user_data.status == 200 and user_data.body and #user_data.body > 0 then
    result.user_data_present = true
    result.user_data_size = #user_data.body
  end

  local ok5, vendor_data = pcall(http.get, "169.254.169.254", 80, "/metadata/v1/vendor_data", { timeout = 2000 })
  if ok5 and vendor_data and vendor_data.status == 200 then
    result.vendor_data_present = true
  end

  return format_output(true, result)
end
