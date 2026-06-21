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

description = [[Retrieves information from Neo4j graph database instances via the HTTP API (port 7474). Returns version, edition, database status, kernel info, transaction API status, and available extensions.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 7474
end

local neo4j_paths = {
  "/", "/db/data/", "/db/manage/",
  "/db/data/transaction",
  "/db/data/transaction/commit",
  "/db/data/labels", "/db/data/relationship/types",
  "/db/data/property.keys",
  "/db/data/schema/index",
  "/db/data/schema/constraint",
  "/db/manage/server/jmx",
  "/db/manage/server/console",
}

action = function(host, port)
  local result = output_table()

  local ok, response = pcall(http.get, host.ip, port.number, "/", { timeout = 5000 })
  if not ok or not response or response.status ~= 200 then
    return format_output(false, "Neo4j not detected on this port")
  end

  local ok2, data = pcall(json.parse, response.body)
  if not ok2 or not data then
    return format_output(false, "Failed to parse Neo4j response")
  end

  result.neo4j_version = data.neo4j_version
  result.edition = data.neo4j_edition
  result.name = data.neo4j_name

  for _, path in ipairs(neo4j_paths) do
    local ok3, resp = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
    if ok3 and resp and resp.status == 200 and resp.body then
      local path_key = path:gsub("^/", ""):gsub("/", "_"):gsub("db_", ""):gsub("manage_", "")
      local ok4, pd = pcall(json.parse, resp.body)
      if ok4 and pd then
        if path == "/db/data/" then
          result.data_api_accessible = true
          result.extensions = pd.extensions

          if pd.neo4j_version then
            result.db_data_version = pd.neo4j_version
          end
          if pd.node_count then
            result.node_count = pd.node_count
          end
          if pd.relationship_count then
            result.relationship_count = pd.relationship_count
          end
        elseif path == "/db/data/labels" then
          result.labels = pd
          result.labels_count = #pd
        elseif path == "/db/data/relationship/types" then
          result.relationship_types = pd
          result.relationship_types_count = #pd
        else
          result[path_key .. "_accessible"] = true
        end
      end
    end
  end

  return format_output(true, result)
end
