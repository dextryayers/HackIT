local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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
  local result = stdnse.output_table()

  local ok, response = pcall(http.get, host.ip, port.number, "/", { timeout = 5000 })
  if not ok or not response or response.status ~= 200 then
    return stdnse.format_output(false, "Neo4j not detected on this port")
  end

  local ok2, data = pcall(json.parse, response.body)
  if not ok2 or not data then
    return stdnse.format_output(false, "Failed to parse Neo4j response")
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

  return stdnse.format_output(true, result)
end
