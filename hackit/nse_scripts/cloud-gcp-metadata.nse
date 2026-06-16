local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Attempts to retrieve instance metadata from the GCP metadata endpoint (169.254.169.254). Returns project, zone, instance name, and other metadata if accessible. Probes recursive and individual endpoints.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

local metadata_endpoints = {
  "project/project-id", "project/numeric-project-id",
  "instance/name", "instance/id", "instance/zone",
  "instance/machine-type", "instance/hostname",
  "instance/cpu-platform", "instance/scheduling",
  "instance/attributes/ssh-keys",
  "instance/network-interfaces/",
  "instance/network-interfaces/0/ip",
  "instance/network-interfaces/0/network",
  "instance/network-interfaces/0/subnetmask",
  "instance/network-interfaces/0/gateway",
  "instance/network-interfaces/0/access-configs/0/external-ip",
  "instance/service-accounts/default/scopes",
  "instance/service-accounts/default/token",
  "instance/tags",
  "instance/disks/0/",
  "instance/attributes/",
}

action = function(host, port)
  local result = stdnse.output_table()
  local headers = { ["Metadata-Flavor"] = "Google" }

  if host.ip ~= "169.254.169.254" then
    return nil
  end

  local ok, recursive = pcall(http.get, "169.254.169.254", 80, "/computeMetadata/v1/instance/?recursive=true", { timeout = 3000, header = headers })
  if not ok or not recursive or recursive.status ~= 200 then
    return stdnse.format_output(false, "GCP metadata endpoint not accessible")
  end

  if recursive.body then
    local ok2, data = pcall(json.parse, recursive.body)
    if ok2 and data then
      if data.serviceAccounts then
        result.service_accounts = {}
        for sa, sa_data in pairs(data.serviceAccounts) do
          result.service_accounts[sa] = sa_data
        end
      end
      if data.networkInterfaces then
        result.network_count = #data.networkInterfaces
      end
      if data.disks then
        result.disk_count = #data.disks
      end
    end
  end

  for _, ep in ipairs(metadata_endpoints) do
    local ok3, resp = pcall(http.get, "169.254.169.254", 80, "/computeMetadata/v1/" .. ep, { timeout = 3000, header = headers })
    if ok3 and resp and resp.status == 200 and resp.body and #resp.body > 0 then
      local key = ep:gsub("/", "_"):gsub("-", "_"):gsub("^instance_", "")
      result[key] = resp.body:gsub("%s+$", "")
    end
  end

  local ok4, sa_list = pcall(http.get, "169.254.169.254", 80, "/computeMetadata/v1/instance/service-accounts/", { timeout = 3000, header = headers })
  if ok4 and sa_list and sa_list.status == 200 and sa_list.body then
    result.service_account_list = sa_list.body
  end

  if result.token then
    local ok5, token_data = pcall(json.parse, result.token)
    if ok5 and token_data then
      result.access_token_present = true
      result.token_scopes = token_data.scopes
      result.token_expiry = token_data.expires_in
    end
  end

  return stdnse.format_output(true, result)
end
