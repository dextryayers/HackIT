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
  local result = output_table()
  local headers = { ["Metadata-Flavor"] = "Google" }

  if host.ip ~= "169.254.169.254" then
    return nil
  end

  local ok, recursive = pcall(http.get, "169.254.169.254", 80, "/computeMetadata/v1/instance/?recursive=true", { timeout = 3000, header = headers })
  if not ok or not recursive or recursive.status ~= 200 then
    return format_output(false, "GCP metadata endpoint not accessible")
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
      local key = gsub(ep, "/", "_"):gsub("-", "_"):gsub("^instance_", "")
      result[key] = resp.gsub(body, "%s+$", "")
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

  return format_output(true, result)
end
