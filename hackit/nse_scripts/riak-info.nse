local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Retrieves information from Basho Riak KV or Riak TS databases via the HTTP API (port 8098). Returns server version, node information, ring state, bucket statistics, and active connections.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 8098
end

local riak_paths = {
  "/ping", "/stats", "/buckets?buckets=true",
  "/buckets?buckets=stream", "/types",
  "/admin/ring", "/admin/ring-state",
  "/admin/partitions", "/admin/stats",
  "/riak/", "/explore",
}

action = function(host, port)
  local result = stdnse.output_table()

  local ok, ping_resp = pcall(http.get, host.ip, port.number, "/ping", { timeout = 5000 })
  if not ok or not ping_resp or ping_resp.body ~= "OK" then
    return stdnse.format_output(false, "Riak not detected on this port")
  end

  result.ping = true

  local ok2, stats_resp = pcall(http.get, host.ip, port.number, "/stats", { timeout = 5000 })
  if ok2 and stats_resp and stats_resp.status == 200 then
    local ok3, stats = pcall(json.parse, stats_resp.body)
    if ok3 and stats then
      result.node = stats.node
      result.server_version = stats.riak_kv_version
      result.ring_size = stats.ring_size
      result.ring_min = stats.ring_min
      result.ring_max = stats.ring_max
      result.ring_members = stats.ring_members
      result.ring_num_partitions = stats.ring_num_partitions
      result.vnodes = stats.vnode_count
      result.connected_nodes = stats.connected_nodes
      result.vnode_index_count = stats.vnode_index_count
      result.cpu_count = stats.cpu_count
      result.memory_total = stats.memory_total and string.format("%.1f MB", stats.memory_total / 1048576)
      result.memory_processes = stats.memory_processes and string.format("%.1f MB", stats.memory_processes / 1048576)
      result.disk_total = stats.disk_total
      result.disk_free = stats.disk_free
      result.storage_backend = stats.storage_backend
      result.object_count = stats.object_count or stats.kv_vnode_count
      result.bucket_count = stats.bucket_count or stats.buckets_count
      result.executing_mappers = stats.executing_mappers
      result.pbc_active = stats.pbc_active or stats.pbc_connects
      result.pbc_connects = stats.pbc_connects
      result.node_put_fsm_time_mean = stats.node_put_fsm_time_mean
      result.node_get_fsm_time_mean = stats.node_get_fsm_time_mean
      result.pbc_connects_total = stats.pbc_connects_total
    end
  end

  for _, path in ipairs(riak_paths) do
    if path ~= "/ping" and path ~= "/stats" then
      local ok4, resp = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
      if ok4 and resp and resp.status == 200 and resp.body then
        local path_key = path:gsub("^/", ""):gsub("[?=]", "_"):gsub("/", "_")
        local ok5, pd = pcall(json.parse, resp.body)
        if ok5 and pd then
          if path == "/buckets?buckets=true" and pd.buckets then
            result.buckets = pd.buckets
            result.bucket_count = #pd.buckets
          elseif path == "/admin/ring" then
            result.ring_accessible = true
          else
            result[path_key .. "_accessible"] = true
          end
        end
      end
    end
  end

  return stdnse.format_output(true, result)
end
