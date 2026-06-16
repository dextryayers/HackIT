local stdnse = require "stdnse"
local http = require "http"
local json = require "json"

description = [[Detects a Kubernetes API server and retrieves version information, available endpoints, API groups, namespaces, pods, and health status if accessible. Probes ports 6443, 443, 8443, 10250, and 10255.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery", "cloud"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open" and
    (port.number == 6443 or port.number == 443 or port.number == 8443 or
     port.number == 10250 or port.number == 10255)
end

local k8s_paths = {
  "/version", "/api", "/api/v1", "/apis",
  "/healthz", "/readyz", "/livez",
  "/api/v1/namespaces",
  "/api/v1/pods",
  "/api/v1/nodes",
  "/api/v1/services",
  "/api/v1/endpoints",
  "/api/v1/configmaps",
  "/api/v1/secrets",
  "/openapi/v2",
  "/swagger.json",
  "/swaggerapi",
}

action = function(host, port)
  local result = stdnse.output_table()
  local endpoint = host.ip

  local ok, version_resp = pcall(http.get, endpoint, port.number, "/version", { timeout = 5000 })
  if not ok or not version_resp or version_resp.status ~= 200 then
    return stdnse.format_output(false, "Kubernetes API server not detected")
  end

  result.api_server_detected = true
  result.endpoint = endpoint .. ":" .. port.number

  local ok2, version_data = pcall(json.parse, version_resp.body)
  if ok2 and version_data then
    result.git_version = version_data.gitVersion
    result.platform = version_data.platform
    result.major = version_data.major
    result.minor = version_data.minor
    result.compiler = version_data.compiler
    result.go_version = version_data.goVersion
    result.build_date = version_data.buildDate
  end

  for _, path in ipairs(k8s_paths) do
    local ok3, resp = pcall(http.get, endpoint, port.number, path, { timeout = 5000 })
    if ok3 and resp and resp.status == 200 then
      local key = path:gsub("^/", ""):gsub("/", "_"):gsub("-", "_")
      if resp.body then
        local ok4, data = pcall(json.parse, resp.body)
        if ok4 and data then
          if data.kind then
            result[key .. "_kind"] = data.kind
          end
          if data.apiVersion then
            result[key .. "_api_version"] = data.apiVersion
          end
          if data.items then
            result[key .. "_count"] = #data.items
            if #data.items <= 5 then
              result[key .. "_items"] = data.items
            end
          end
          if data.groups then
            result[key .. "_groups"] = {}
            for _, g in ipairs(data.groups) do
              table.insert(result[key .. "_groups"], g.name)
            end
          end
          if data.resources then
            result[key .. "_resources"] = #data.resources
          end
        else
          if #resp.body < 500 then
            result[key] = resp.body
          else
            result[key .. "_accessible"] = true
            result[key .. "_size"] = #resp.body
          end
        end
      end
    end
  end

  local ok5, healthz = pcall(http.get, endpoint, port.number, "/healthz", { timeout = 3000 })
  if ok5 and healthz and healthz.status == 200 then
    result.health_status = "healthy"
  end

  return stdnse.format_output(true, result)
end
