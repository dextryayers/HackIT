local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Retrieves information from InfluxDB instances via the HTTP API (port 8086). Returns version, status, available databases, retention policies, continuous queries, users, and diagnostic data. Supports both InfluxDB 1.x and 2.x.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and port.number == 8086
end

local influx_paths = {
  "/ping", "/metrics", "/health",
  "/query?q=SHOW+DATABASES",
  "/query?q=SHOW+RETENTION+POLICIES",
  "/query?q=SHOW+CONTINUOUS+QUERIES",
  "/query?q=SHOW+USERS",
  "/query?q=SHOW+SHARDS",
  "/query?q=SHOW+SUBSCRIPTIONS",
  "/query?q=SHOW+STATS",
  "/query?q=SHOW+DIAGNOSTICS",
  "/query?q=SHOW+MEASUREMENTS",
  "/debug/vars",
  "/api/v2/ping",
  "/api/v2/health",
  "/api/v2/buckets",
  "/api/v2/users",
  "/api/v2/orgs",
}

action = function(host, port)
  local result = stdnse.output_table()

  local ok, ping_resp = pcall(http.get, host.ip, port.number, "/ping", { timeout = 5000 })
  if not ok or not ping_resp then
    return stdnse.format_output(false, "InfluxDB not detected")
  end

  if ping_resp.status == 204 then
    result.status = "running (1.x)"
    if ping_resp.headers then
      result.version = ping_resp.headers["x-influxdb-version"]
    end
  end

  if not result.status then
    local ok2, ping2 = pcall(http.get, host.ip, port.number, "/api/v2/ping", { timeout = 3000 })
    if ok2 and ping2 and ping2.status == 204 then
      result.status = "running (2.x)"
      if ping2.headers then
        result.version = ping2.headers["x-influxdb-version"]
      end
    else
      result.status = "unknown"
    end
  end

  for _, path in ipairs(influx_paths) do
    if path ~= "/ping" then
      local ok3, resp = pcall(http.get, host.ip, port.number, path, { timeout = 5000 })
      if ok3 and resp and resp.status == 200 and resp.body then
        local path_key = path:gsub("^/", ""):gsub("[?=]", "_"):gsub("/", "_")
        path_key = path_key:gsub("SHOW_", ""):gsub("api_v2_", "v2_"):lower()

        if path:find("query") then
          local ok4, pd = pcall(json.parse, resp.body)
          if ok4 and pd and pd.results and pd.results[1] then
            local r = pd.results[1]
            if r.series and r.series[1] and r.series[1].values then
              local values = {}
              for _, row in ipairs(r.series[1].values) do
                table.insert(values, row[1])
              end
              if path:find("SHOW+DATABASES") then
                result.databases = values
                result.database_count = #values
              elseif path:find("SHOW+USERS") then
                result.users = values
                result.user_count = #values
              elseif path:find("SHOW+RETENTION") then
                result.retention_policies = values
              elseif path:find("SHOW+MEASUREMENTS") then
                result.measurements = values
                result.measurement_count = #values
              else
                result[path_key .. "_count"] = #values
              end
            end
            if r.error then
              result[path_key .. "_error"] = r.error
            end
          end
        elseif path == "/metrics" then
          result.metrics_endpoint = "exposed"
        elseif path == "/health" then
          local ok5, hd = pcall(json.parse, resp.body)
          if ok5 and hd then
            result.health = hd.status or hd.name
          end
        elseif path == "/debug/vars" then
          result.debug_vars_accessible = true
        elseif path:find("api/v2") then
          local ok6, pd2 = pcall(json.parse, resp.body)
          if ok6 and pd2 then
            if pd2.buckets then
              result.v2_buckets = pd2.buckets
              result.v2_bucket_count = #pd2.buckets
            elseif pd2.users then
              result.v2_users = pd2.users
              result.v2_user_count = #pd2.users
            elseif pd2.orgs then
              result.v2_orgs = pd2.orgs
              result.v2_org_count = #pd2.orgs
            end
          end
        end
      end
    end
  end

  return stdnse.format_output(true, result)
end
