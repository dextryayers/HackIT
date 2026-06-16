local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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
  local result = stdnse.output_table()

  if host.ip ~= "169.254.169.254" then
    return nil
  end

  local ok, response = pcall(http.get, "169.254.169.254", 80, "/metadata/v1.json", { timeout = 3000 })
  if not ok or not response or response.status ~= 200 then
    return stdnse.format_output(false, "DigitalOcean metadata endpoint not accessible")
  end

  local ok2, data = pcall(json.parse, response.body)
  if ok2 and data then
    for k, v in pairs(data) do
      result[k:gsub("-", "_")] = v
    end
  end

  for _, path in ipairs(metadata_paths) do
    local ok3, resp = pcall(http.get, "169.254.169.254", 80, "/metadata/v1/" .. path, { timeout = 2000 })
    if ok3 and resp and resp.status == 200 and resp.body and #resp.body > 0 then
      local key = path:gsub("/", "_"):gsub("-", "_")
      result[key] = resp.body:gsub("%s+$", "")
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

  return stdnse.format_output(true, result)
end
