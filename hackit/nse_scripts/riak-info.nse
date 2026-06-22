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
  local result = output_table()

  local ok, ping_resp = pcall(http.get, host.ip, port.number, "/ping", { timeout = 5000 })
  if not ok or not ping_resp or ping_resp.body ~= "OK" then
    return format_output(false, "Riak not detected on this port")
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
      result.memory_total = stats.memory_total and format("%.1f MB", stats.memory_total / 1048576)
      result.memory_processes = stats.memory_processes and format("%.1f MB", stats.memory_processes / 1048576)
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
        local path_key = gsub(path, "^/", ""):gsub("[?=]", "_"):gsub("/", "_")
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

  return format_output(true, result)
end
