local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Attempts to retrieve instance metadata from the Azure IMDS endpoint (169.254.169.254). Returns VM name, resource group, location, subscription ID, and other metadata if accessible. Tests multiple API versions and endpoints.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local api_versions = {
  "2021-02-01", "2020-09-01", "2020-06-01", "2020-04-30",
  "2019-11-01", "2019-08-15", "2019-06-04", "2019-04-30",
  "2019-03-11", "2018-10-01", "2018-04-02", "2017-12-01",
  "2017-08-01", "2017-04-02", "2017-03-01",
}

local metadata_endpoints = {
  "instance?api-version=",
  "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
}

action = function(host, port)
  local result = stdnse.output_table()
  local headers = { ["Metadata"] = "true" }

  if host.ip ~= "169.254.169.254" then
    return nil
  end

  local best_api = api_versions[1]

  for _, ver in ipairs(api_versions) do
    local ok, resp = pcall(http.get, "169.254.169.254", 80, "/metadata/instance?api-version=" .. ver, { timeout = 3000, header = headers })
    if ok and resp and resp.status == 200 then
      best_api = ver
      break
    end
  end

  local ok, response = pcall(http.get, "169.254.169.254", 80, "/metadata/instance?api-version=" .. best_api, { timeout = 3000, header = headers })
  if not ok or not response or response.status ~= 200 then
    return stdnse.format_output(false, "Azure metadata endpoint not accessible")
  end

  result.api_version = best_api

  local ok2, data = pcall(json.parse, response.body)
  if not ok2 or not data then
    return stdnse.format_output(false, "Failed to parse Azure metadata response")
  end

  if data.compute then
    for k, v in pairs(data.compute) do
      local key = k:gsub("([A-Z])", "_%1"):lower():gsub("^_", "")
      result[key] = v
    end
  end

  if data.network then
    result.network_interface_count = #data.network.interface
    local interfaces = {}
    for i, iface in ipairs(data.network.interface) do
      local if_info = {}
      for k, v in pairs(iface) do
        if_info[k:gsub("([A-Z])", "_%1"):lower():gsub("^_", "")] = v
      end
      interfaces["interface_" .. i] = if_info
    end
    result.network_interfaces = interfaces
  end

  local ok3, identity_resp = pcall(http.get, "169.254.169.254", 80, "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", { timeout = 3000, header = headers })
  if ok3 and identity_resp and identity_resp.status == 200 then
    local ok4, token_data = pcall(json.parse, identity_resp.body)
    if ok4 and token_data then
      result.managed_identity_present = true
      result.identity_access_token_present = token_data.access_token and true or nil
      result.identity_expiry = token_data.expires_on
    end
  end

  local ok5, lb_resp = pcall(http.get, "169.254.169.254", 80, "/metadata/loadbalancer?api-version=2020-10-01", { timeout = 2000, header = headers })
  if ok5 and lb_resp and lb_resp.status == 200 then
    result.load_balancer_metadata = true
  end

  return stdnse.format_output(true, result)
end
