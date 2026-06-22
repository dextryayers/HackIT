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

description = [[Detects Apache Struts2 devMode enabled allowing remote command execution (CVE-2017-9791, S2-048, S2-045).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "http" end

action = function(host, port)
  local ok, result = pcall(function()
    local endpoints = {
      "/devmode.action",
      "/struts2/devmode.action",
      "/${%23%70%31%32%33}/devmode.action",
      "/struts/webconsole.html",
      "/webconsole.html",
      "/struts2/showcase/",
      "/%24%7B%23%63%6F%6E%74%65%78%74%7D/devmode.action",
      "/orders/devmode.action",
      "/examples/devmode.action",
    }

    local findings = {}
    local server_banner = ""

    local banner_req = http.get(host, port, "/")
    if banner_req and banner_req.headers and banner_req.headers["server"] then
      local sv = banner_req.headers["server"]
      server_banner = type(sv) == "table" and sv[1] or sv
    end

    for _, ep in ipairs(endpoints) do
      local req = http.get(host, port, ep)
      if req and req.status then
        local body = req.body or ""
        if req.status == 200 then
          local devmode_indicators = {"DevMode", "devMode", "ValueStack", "struts", "OGNL", "ognl", "Debugging", "WebConsole"}
          for _, ind in ipairs(devmode_indicators) do
            if match(body, ind) then
              insert(findings, {path = ep, status = req.status, indicator = ind})
              break
            end
          end
        elseif req.status == 302 then
          local loc = req.headers and req.headers["location"]
          local location_str = type(loc) == "table" and concat(loc, " ") or tostring(loc or "")
          if match(location_str, "devmode") or match(location_str, "struts") then
            insert(findings, {path = ep, status = req.status, indicator = "redirect to struts"})
          end
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2017-9791 (S2-048)"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.detail = "Struts2 devMode enabled - remote command execution possible"
      for i, f in ipairs(findings) do
        result[("endpoint_%d"):format(i)] = ("%s -> HTTP %d (matched: %s)"):format(f.path, f.status, f.indicator)
      end
      if match(server_banner, "Struts") or match(server_banner, "Tomcat") then
        local ver = match(server_banner, "([%d%.]+)")
        if ver then result.version = ver end
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2017-9791 (S2-048)"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No Struts2 devMode detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2017-9791"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
