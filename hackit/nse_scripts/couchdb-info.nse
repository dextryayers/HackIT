local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

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
  local result = stdnse.output_table()

  local ok, response = pcall(http.get, host.ip, port.number, "/", { timeout = 5000 })
  if not ok or not response or response.status ~= 200 then
    return stdnse.format_output(false, "CouchDB not detected or not accessible")
  end

  local ok2, data = pcall(json.parse, response.body)
  if not ok2 or not data then
    return stdnse.format_output(false, "Failed to parse CouchDB response")
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
      local path_key = path:gsub("^/", ""):gsub("/", "_"):gsub("^_", ""):gsub("_local", "local"):gsub("_", "_")
      local ok4, path_data = pcall(json.parse, resp.body)
      if ok4 and path_data then
        result[path_key .. "_accessible"] = true
        if type(path_data) == "table" and #path_data > 0 then
          result[path_key .. "_count"] = #path_data
        end
      end
    end
  end

  return stdnse.format_output(true, result)
end
