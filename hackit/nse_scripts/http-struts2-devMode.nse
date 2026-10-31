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
