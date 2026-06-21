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

description = [[Detects Spring4Shell (CVE-2022-22965) via class.module.classLoader manipulation in parameters and headers.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "http" end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""
    local banner_req = http.get(host, port, "/")
    if banner_req and banner_req.headers and banner_req.headers["server"] then
      local sv = banner_req.headers["server"]
      server_banner = type(sv) == "table" and sv[1] or sv
    end

    local probes = {
      {path = "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%%25%7Btest%7Di", method = "GET"},
      {path = "/spring4shell?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp", method = "GET"},
      {path = "/", method = "POST", data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%%25%7Btest%7Di"},
      {path = "/?class.module.classLoader.DefaultContext=true", method = "GET"},
      {path = "/?class.classLoader.resources.context.parent.pipeline.first.pattern=%%25%7Boops%7Di", method = "GET"},
    }

    for _, probe in ipairs(probes) do
      local req
      if probe.method == "POST" then
        req = http.post(host, port, probe.path, {
          header = {["Content-Type"] = "application/x-www-form-urlencoded"},
          data = probe.data
        })
      else
        req = http.get(host, port, probe.path, {header = {["Accept-Language"] = "en"}})
      end
      if req and req.status then
        local body = req.body or ""
        local body_upper = body:upper()
        if body_upper:match("CLASS%.MODULE") or body_upper:match("CLASS%.CLASSLOADER") then
          insert(findings, {path = probe.path, method = probe.method, status = req.status, detail = "class.module reflection in response body"})
        end
        if body:match("org%.springframework") or body:match("java%.lang%.Class") then
          insert(findings, {path = probe.path, method = probe.method, status = req.status, detail = "Java class name disclosed"})
        end
      end
    end

    local header_probes = {
      {header = "test", value = "${class.module.classLoader.DefaultContext}"},
      {header = "X-Forwarded-For", value = "${class.module.classLoader.resources.context.parent.pipeline.first.pattern=test}"},
      {header = "User-Agent", value = "${class.module.classLoader.DefaultContext}"},
    }

    for _, hp in ipairs(header_probes) do
      local headers = {[hp.header] = hp.value}
      local req = http.get(host, port, "/", {header = headers})
      if req and req.body then
        local body = req.body
        if body:match("class%.module") or body:match("DefaultContext") or body:match("classLoader") then
          insert(findings, {path = "/ (via " .. hp.header .. ")", method = "GET", status = req.status, detail = "Header-based injection reflected"})
        end
      end
    end

    local cookie_probe = http.get(host, port, "/", {
      header = {["Cookie"] = "class.module.classLoader.DefaultContext=true"}
    })
    if cookie_probe and cookie_probe.body and cookie_probe.body:match("class%.module") then
      insert(findings, {path = "/ (via Cookie)", method = "GET", status = cookie_probe.status, detail = "Cookie-based injection reflected"})
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2022-22965"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.detail = ("Spring4Shell (CVE-2022-22965) - class.module injection via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("%s -> HTTP %d: %s"):format(f.path, f.status, f.detail)
      end
      if server_banner:match("Apache%-Tomcat") or server_banner:match("Spring") then
        result.version_note = "Spring/Tomcat stack detected - verify Spring version < 5.3.18, 5.2.20"
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2022-22965"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No Spring4Shell detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2022-22965"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
