local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Retrieves cluster information from Elasticsearch instances. Queries root endpoint for version, cluster name, and node details. Probes cluster health, node stats, indices, and other diagnostic endpoints.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and (port.number == 9200 or port.number == 9300)
end

local es_paths = {
  "/", "/_cluster/health", "/_cluster/stats",
  "/_cat/indices?v", "/_cat/nodes?v",
  "/_cat/shards?v", "/_cat/snapshots?v",
  "/_cat/repositories?v", "/_cat/aliases?v",
  "/_cat/templates?v", "/_cat/pipelines?v",
  "/_nodes/stats", "/_nodes/info",
  "/_cluster/settings", "/_cluster/state",
  "/_mapping", "/_all/_settings",
  "/_snapshot", "/_template",
  "/_xpack", "/_license",
  "/_nodes",
}

action = function(host, port)
  local result = stdnse.output_table()

  local ok, response = pcall(http.get, host.ip, port.number, "/", { timeout = 5000 })
  if not ok or not response or response.status ~= 200 then
    return stdnse.format_output(false, "Elasticsearch not detected")
  end

  local ok2, data = pcall(json.parse, response.body)
  if not ok2 or not data then
    return stdnse.format_output(false, "Failed to parse Elasticsearch response")
  end

  result.cluster_name = data.cluster_name
  result.cluster_uuid = data.cluster_uuid
  result.node_name = data.name

  if data.version then
    result.version = data.version.number
    result.lucene_version = data.version.lucene_version
    result.build_flavor = data.version.build_flavor
    result.build_type = data.version.build_type
    result.build_hash = data.version.build_hash
    result.build_date = data.version.build_date
    result.min_wire_compat_version = data.version.minimum_wire_compatibility_version
    result.min_index_compat_version = data.version.minimum_index_compatibility_version
  end

  if response.headers and response.headers["x-elastic-product"] then
    result.elastic_product = response.headers["x-elastic-product"]
  end

  for _, path in ipairs(es_paths) do
    local ok3, resp = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
    if ok3 and resp and resp.status == 200 and resp.body then
      local path_key = path:gsub("^/", ""):gsub("[%?=]", "_"):gsub("/", "_"):gsub("^_", ""):gsub("_", "_")
      local ok4, pd = pcall(json.parse, resp.body)
      if ok4 and pd then
        if path == "/_cluster/health" then
          result.status = pd.status
          result.nodes_count = pd.number_of_nodes
          result.data_nodes = pd.number_of_data_nodes
          result.active_primary_shards = pd.active_primary_shards
          result.active_shards = pd.active_shards
          result.relocating_shards = pd.relocating_shards
          result.initializing_shards = pd.initializing_shards
          result.unassigned_shards = pd.unassigned_shards
          result.pending_tasks = pd.number_of_pending_tasks
          result.timed_out = pd.timed_out
        elseif path == "/_cluster/stats" and pd.indices then
          result.index_count = pd.indices.count
          result.docs_count = pd.indices.docs and pd.indices.docs.count
          result.store_size = pd.indices.store and pd.indices.store.size_in_bytes
        elseif path == "/_nodes" and pd.nodes then
          result.node_details = {}
          for id, node in pairs(pd.nodes) do
            table.insert(result.node_details, {
              id = id,
              name = node.name,
              version = node.version,
              roles = node.roles,
              transport_address = node.transport_address,
              http_address = node.http_address,
            })
          end
        end
      end
    end
  end

  return stdnse.format_output(true, result)
end
