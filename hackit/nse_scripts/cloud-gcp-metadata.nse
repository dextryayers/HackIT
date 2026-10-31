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
