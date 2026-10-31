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

description = [[Retrieves information from Apache CouchDB instances. Queries root endpoint for version, vendor, and available databases if accessible. Probes stats, config, active tasks, and replication endpoints.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 5984
end

local couchdb_paths = {
  "/", "/_all_dbs", "/_stats", "/_active_tasks",
  "/_config", "/_replication", "/_scheduler/jobs",
  "/_scheduler/docs", "/_membership", "/_cluster_setup",
  "/_node/_local/", "/_node/_local/stats",
  "/_node/_local/system", "/_utils/",
  "/_up", "/_uuids",
}

action = function(host, port)
  local result = output_table()

  local ok, response = pcall(http.get, host.ip, port.number, "/", { timeout = 5000 })
  if not ok or not response or response.status ~= 200 then
    return format_output(false, "CouchDB not detected or not accessible")
  end

  local ok2, data = pcall(json.parse, response.body)
  if not ok2 or not data then
    return format_output(false, "Failed to parse CouchDB response")
  end

  result.couchdb = data.couchdb
  result.version = data.version
  result.vendor = data.vendor
  result.git_sha = data.git_sha
  result.uuid = data.uuid

  if data.features then
    result.features = data.features
  end

  if data.roles then
    result.roles = data.roles
  end

  for _, path in ipairs(couchdb_paths) do
    local ok3, resp = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
    if ok3 and resp and resp.status == 200 and resp.body then
      local path_key = gsub(path, "^/", ""):gsub("/", "_"):gsub("^_", ""):gsub("_local", "local"):gsub("_", "_")
      local ok4, path_data = pcall(json.parse, resp.body)
      if ok4 and path_data then
        result[path_key .. "_accessible"] = true
        if type(path_data) == "table" and #path_data > 0 then
          result[path_key .. "_count"] = #path_data
        end
      end
    end
  end

  return format_output(true, result)
end
