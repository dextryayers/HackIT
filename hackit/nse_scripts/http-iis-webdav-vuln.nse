local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
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

description = [[Detects IIS WebDAV misconfiguration allowing write access to web folders (CVE-2009-1535, CVE-2017-7269).]]
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

    local vectors = {
      {method = "PROPFIND", path = "/", depth = "0"},
      {method = "PROPFIND", path = "/webdav/", depth = "0"},
      {method = "PROPFIND", path = "/_vti_bin/", depth = "0"},
      {method = "PROPFIND", path = "/DavWWWRoot/", depth = "0"},
      {method = "OPTIONS", path = "/", depth = nil},
      {method = "MKCOL", path = "/hackit_test_dir/", depth = nil},
      {method = "PUT", path = "/hackit_test.txt", depth = nil},
    }

    for _, vec in ipairs(vectors) do
      local req
      if vec.method == "PROPFIND" then
        req = http.generic_request(host, port, "PROPFIND", vec.path, {["Depth"] = vec.depth, ["Content-Type"] = "application/xml"}, "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:displayname/></D:prop></D:propfind>")
      elseif vec.method == "PUT" then
        req = http.generic_request(host, port, "PUT", vec.path, {["Content-Type"] = "text/plain"}, "HackIT test")
      elseif vec.method == "MKCOL" then
        req = http.generic_request(host, port, "MKCOL", vec.path, {}, "")
      else
        req = http.generic_request(host, port, "OPTIONS", vec.path)
      end
      if req and req.status then
        local body = req.body or ""
        if vec.method == "PROPFIND" and (req.status == 207 or (req.status < 300 and match(body, "DAV:"))) then
          insert(findings, {vector = ("%s %s"):format(vec.method, vec.path), status = req.status, detail = "WebDAV PROPFIND succeeded"})
        elseif vec.method == "OPTIONS" then
          local allow = (req.headers and req.headers["allow"]) or ""
          local all = type(allow) == "table" and concat(allow, ", ") or allow
          if match(all, "PROPFIND") or match(all, "MKCOL") or match(all, "MOVE") then
            insert(findings, {vector = "OPTIONS /", status = req.status, detail = ("WebDAV methods allowed: %s"):format(all)})
          end
        elseif vec.method == "PUT" and req.status == 201 then
          insert(findings, {vector = "PUT /hackit_test.txt", status = req.status, detail = "Write access confirmed - file upload succeeded"})
          http.generic_request(host, port, "DELETE", "/hackit_test.txt", {}, "")
        elseif vec.method == "MKCOL" and req.status == 201 then
          insert(findings, {vector = "MKCOL /hackit_test_dir/", status = req.status, detail = "Directory creation allowed"})
          http.generic_request(host, port, "DELETE", "/hackit_test_dir/", {}, "")
        end
      end
    end

    if #findings > 0 then
      local vuln_version = false
      if server_banner then
        local ver = match(server_banner, "Microsoft%-IIS/([%d%.]+)")
        if ver then
          local parts = {}
          for v in gmatch(ver, "%d+") do insert(parts, tonumber(v)) end
          if #parts >= 2 then
            if (parts[1] == 6 and parts[2] < 1) or (parts[1] == 7 and parts[2] < 5) or (parts[1] == 8) then
              vuln_version = true
            end
          end
        end
      end

      local result = output_table()
      result.cve = "CVE-2009-1535, CVE-2017-7269"
      result.severity = "HIGH"
      result.vulnerable = true
      result.server = server_banner
      result.detail = "WebDAV enabled with potential write access"
      result.findings = findings
      for _, f in ipairs(findings) do
        result[f.vector] = ("HTTP %d - %s"):format(f.status, f.detail)
      end
      if vuln_version then
        result.version_note = ("IIS %s is known vulnerable to WebDAV-related RCE"):format(match(server_banner, "Microsoft%-IIS/([%d%.]+)") or "unknown")
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2009-1535, CVE-2017-7269"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No WebDAV misconfiguration detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2009-1535, CVE-2017-7269"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
