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
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
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

description = [[Retrieves information from CockroachDB instances via the HTTP API (port 8080). Returns cluster ID, node ID, build version, SQL health status, node metrics, and range statistics.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 8080
end

local crdb_paths = {
  "/health", "/health?ready=1",
  "/_status/nodes", "/_status/range_sizes",
  "/_status/sessions", "/_status/hotranges",
  "/_admin/v1/settings", "/_admin/v1/health",
  "/_admin/v1/events", "/_admin/v1/databases",
  "/sqlusers", "/metrics", "/_status/stores",
  "/_status/statements",
  "/debug/pprof/",
}

action = function(host, port)
  local result = output_table()

  local ok, health_resp = pcall(http.get, host.ip, port.number, "/health", { timeout = 5000 })
  if not ok or not health_resp or health_resp.status ~= 200 then
    return format_output(false, "CockroachDB not detected or health endpoint not accessible")
  end

  local ok2, health = pcall(json.parse, health_resp.body)
  if ok2 and health then
    result.health_status = health.status or "ok"
  end

  for _, path in ipairs(crdb_paths) do
    if path ~= "/health" then
      local ok3, resp = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
      if ok3 and resp and resp.status == 200 and resp.body then
        local path_key = gsub(path, "^/", ""):gsub("[?=]", "_"):gsub("/", "_"):gsub("^_", "")
        local ok4, pd = pcall(json.parse, resp.body)
        if ok4 and pd then
          if path == "/_status/nodes" and pd.nodes and #pd.nodes > 0 then
            local node = pd.nodes[1]
            result.nodes_count = #pd.nodes
            result.node_id = node.desc and node.desc.node_id
            result.build_tag = node.build and node.build.tag
            result.build_release = node.build and node.build.release_version
            result.build_time = node.build and node.build.time
            result.build_platform = node.build and node.build.platform
            result.build_type = node.build and node.build.type
            result.build_cgo = node.build and node.build.cgo_compiler
            result.uptime_seconds = node.uptime
            result.uptime_human = node.uptime and format("%.1f hours", node.uptime / 3600)

            if node.metrics then
              result.live_bytes = node.metrics.livebytes
              result.system_bytes = node.metrics.sysbytes
              result.gc_count = node.metrics.gc_count
              result.total_sql_connections = node.metrics.sql_conns
              result.active_sql_connections = node.metrics.sql_active_conns
            end

            if node.store_statuses then
              result.store_count = #node.store_statuses
              for i, store in ipairs(node.store_statuses) do
                result["store_" .. i .. "_id"] = store.desc and store.desc.store_id
              end
            end
          elseif path == "/_status/range_sizes" then
            result.range_stats = pd
          elseif path == "/_status/sessions" and pd.sessions then
            result.active_sessions = #pd.sessions
          elseif path == "/sqlusers" then
            result.sql_users = pd.users or pd
            result.sql_users_count = result.sql_users and #result.sql_users
          elseif path == "/_admin/v1/databases" and pd.databases then
            result.databases = pd.databases
            result.database_count = #pd.databases
          elseif path == "metrics" then
            result.metrics_endpoint_exposed = true
          else
            result[path_key .. "_accessible"] = true
          end
        end
      end
    end
  end

  local ok5, sql_ready = pcall(http.get, host.ip, port.number, "/health?ready=1", { timeout = 3000 })
  if ok5 and sql_ready and sql_ready.status == 200 then
    result.sql_ready = true
  end

  return format_output(true, result)
end
