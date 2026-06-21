local http = require "http"
local stdnse = require "stdnse"
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

description = [[Detects JBoss Java deserialization vulnerability via JMX console, HTTP invoker, and JMXInvokerServlet (CVE-2015-7501, CVE-2017-12149).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "http" end

local function check_endpoint(host, port, ep)
  local req = http.get(host, port, ep.path)
  if not req then return false end

  local result = {path = ep.path, name = ep.name, status = req.status}
  local body = req.body or ""
  local server_header = ""
  if req.headers and req.headers["server"] then
    server_header = type(req.headers["server"]) == "table" and req.headers["server"][1] or req.headers["server"]
  end

  if req.status < 400 then
    for _, ind in ipairs(ep.indicators) do
      if body:match(ind) then
        result.found = true
        result.indicator = ind
        result.body_preview = body:sub(1, 100):gsub("\n", " "):gsub("\r", "")
        return result
      end
    end
    if server_header:match("JBoss") or server_header:match("WildFly") then
      result.found = true
      result.indicator = ("server header: %s"):format(server_header)
      return result
    end
  elseif req.status == 302 or req.status == 301 then
    local loc = req.headers and req.headers["location"]
    local loc_str = type(loc) == "table" and concat(loc, " ") or tostring(loc or "")
    if loc_str:match("jboss") or loc_str:match("admin") then
      result.found = true
      result.indicator = ("redirects to %s"):format(loc_str:sub(1, 60))
      return result
    end
  end

  if server_header:match("JBoss") or server_header:match("WildFly") then
    result.found_server = true
    result.server_info = server_header
    return result
  end

  return result
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""

    local jboss_endpoints = {
      {path = "/jmx-console/", name = "JMX Console", indicators = {"JMX", "jmx", "MBean", "HtmlAdaptor"}},
      {path = "/web-console/", name = "Web Console", indicators = {"Web Console", "web-console", "ServerInfo"}},
      {path = "/invoker/JMXInvokerServlet", name = "JMXInvokerServlet", indicators = {"invoker", "jboss", "serializable", "html"}},
      {path = "/invoker/EJBInvokerServlet", name = "EJBInvokerServlet", indicators = {"invoker", "jboss", "html"}},
      {path = "/admin-console/", name = "Admin Console", indicators = {"Admin", "admin", "jboss"}},
      {path = "/jboss-http-invoker/", name = "HTTP Invoker", indicators = {"jboss", "http-invoker"}},
      {path = "/jmx-invoker/", name = "JMX Invoker", indicators = {"jmx", "invoker"}},
      {path = "/jbossweb/", name = "JBoss Web", indicators = {"jbossweb", "JBoss"}},
      {path = "/jbossas/", name = "JBoss AS", indicators = {"jboss", "JBoss"}},
      {path = "/console/", name = "Console", indicators = {"console", "jboss", "JMX"}},
    }

    local banner_req = http.get(host, port, "/")
    if banner_req and banner_req.headers and banner_req.headers["server"] then
      local sv = banner_req.headers["server"]
      server_banner = type(sv) == "table" and sv[1] or sv
    end

    for _, ep in ipairs(jboss_endpoints) do
      local chk = check_endpoint(host, port, ep)
      if chk and chk.found then
        insert(findings, {
          path = chk.path,
          name = chk.name,
          status = chk.status,
          indicator = chk.indicator,
          detail = ("%s (HTTP %d) - %s"):format(chk.name, chk.status, chk.indicator),
          severity = "HIGH",
        })
      elseif chk and chk.found_server then
        insert(findings, {
          path = chk.path,
          name = chk.name,
          status = chk.status,
          indicator = chk.server_info,
          detail = ("%s - server header indicates JBoss/WildFly"):format(chk.server_info),
          severity = "MEDIUM",
        })
      end
    end

    local jboss_version = server_banner:match("JBoss[^/]*/([%d%.]+)") or server_banner:match("WildFly/([%d%.]+)")
    if not jboss_version then
      local jmx_req = http.get(host, port, "/jmx-console/")
      if jmx_req and jmx_req.body then
        jboss_version = jmx_req.body:match("JBoss/([%d%.]+)")
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2015-7501, CVE-2017-12149"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.version = jboss_version or "unknown"
      result.detail = ("JBoss deserialization risk - %d exposed endpoint(s) found"):format(#findings)
      for i, f in ipairs(findings) do
        result[("endpoint_%d"):format(i)] = f.detail
      end
      if jboss_version then
        local parts = {}
        for v in jboss_version:gmatch("%d+") do insert(parts, tonumber(v)) end
        if #parts >= 2 then
          if (parts[1] == 4 and parts[2] < 22) or (parts[1] == 5 and parts[2] < 2) or (parts[1] == 6) then
            result.version_note = ("JBoss %s is within vulnerable range"):format(jboss_version)
          end
        end
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2015-7501, CVE-2017-12149"
    result.severity = (server_banner:match("JBoss") or server_banner:match("WildFly")) and "MEDIUM" or "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.version = jboss_version or "unknown"
    result.detail = (server_banner:match("JBoss") or server_banner:match("WildFly")) and "JBoss/WildFly detected but no exposed deserialization endpoints found" or "No JBoss detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2015-7501"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
