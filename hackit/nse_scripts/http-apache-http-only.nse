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

description = [[Checks for cookies missing HttpOnly/Secure flags and response splitting vulnerabilities (CVE-2004-0488, CVE-2012-0053).]]
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

    local paths = {
      "/",
      "/admin/",
      "/login",
      "/login.php",
      "/wp-login.php",
      "/administrator/",
      "/admin/login.php",
      "/session",
      "/api/auth",
      "/user/login",
      "/signin",
    }

    for _, p in ipairs(paths) do
      local req = http.get(host, port, p)
      if req and req.headers then
        local set_cookies = {}
        local raw = req.headers["set-cookie"]
        if type(raw) == "table" then
          set_cookies = raw
        elseif type(raw) == "string" then
          set_cookies = {raw}
        end

        for _, c in ipairs(set_cookies) do
          local cookie_name = c:match("^([^=]+)")
          local has_httponly = c:match("HttpOnly")
          local has_secure = c:match("Secure")
          local has_samesite = c:match("SameSite")

          if not has_httponly then
            insert(findings, {
              path = p,
              cookie = cookie_name or "unknown",
              missing = "HttpOnly",
              detail = ("Cookie '%s' missing HttpOnly flag at %s"):format(cookie_name or "unknown", p),
              severity = "MEDIUM",
            })
          end
          if not has_secure then
            insert(findings, {
              path = p,
              cookie = cookie_name or "unknown",
              missing = "Secure",
              detail = ("Cookie '%s' missing Secure flag at %s"):format(cookie_name or "unknown", p),
              severity = "MEDIUM",
            })
          end
          if not has_samesite then
            insert(findings, {
              path = p,
              cookie = cookie_name or "unknown",
              missing = "SameSite",
              detail = ("Cookie '%s' missing SameSite flag at %s"):format(cookie_name or "unknown", p),
              severity = "LOW",
            })
          end
        end
      end
    end

    local crlf_vectors = {
      {path = "/%0d%0aSet-Cookie:TEST=HackIT;path=/", header = "", value = "", label = "URL CRLF injection"},
      {path = "/", header = "Cookie", value = "%0d%0aSet-Cookie:TEST=HackIT;path=/", label = "Header CRLF injection"},
      {path = "/", header = "X-Forwarded-For", value = "%0d%0aSet-Cookie:TEST2=HackIT;path=/", label = "XFF CRLF injection"},
      {path = "/test?%0d%0aSet-Cookie:TEST3=HackIT;path=/", header = "", value = "", label = "Query CRLF injection"},
      {path = "/test%0d%0aSet-Cookie:TEST4=HackIT;path=/", header = "", value = "", label = "Path CRLF injection"},
    }

    for _, vec in ipairs(crlf_vectors) do
      local headers = {}
      if vec.header ~= "" then
        headers[vec.header] = vec.value
      end
      local req = http.get(host, port, vec.path, {header = headers})
      if req and req.headers then
        local raw = req.headers["set-cookie"]
        local cookies = {}
        if type(raw) == "table" then
          cookies = raw
        elseif type(raw) == "string" then
          cookies = {raw}
        end
        for _, c in ipairs(cookies) do
          if c:match("TEST") then
            insert(findings, {
              path = vec.path,
              label = vec.label,
              cookie = c:sub(1, 60),
              detail = ("CRLF injection via %s - Set-Cookie reflected"):format(vec.label),
              severity = "CRITICAL",
            })
            break
          end
        end
      end
    end

    if #findings > 0 then
      local max_severity = "LOW"
      for _, f in ipairs(findings) do
        local order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
        if (order[f.severity] or 0) > (order[max_severity] or 0) then
          max_severity = f.severity
        end
      end

      local result = output_table()
      result.cve = "CVE-2004-0488, CVE-2012-0053"
      result.severity = max_severity
      result.vulnerable = true
      result.server = server_banner
      result.detail = ("Cookie security issues found: %d cookie(s) missing flags, %d CRLF vector(s)"):format(
        (function() local n = 0; for _, f in ipairs(findings) do if f.missing then n = n + 1 end end; return n end)(),
        (function() local n = 0; for _, f in ipairs(findings) do if f.label then n = n + 1 end end; return n end)()
      )
      for i, f in ipairs(findings) do
        if f.label then
          result[("issue_%d"):format(i)] = ("[%s] %s: %s via %s"):format(f.severity, f.label, f.detail, f.path)
        else
          result[("issue_%d"):format(i)] = ("[%s] %s"):format(f.severity, f.detail)
        end
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2004-0488, CVE-2012-0053"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "All cookies appear to have proper HttpOnly/Secure/SameSite flags, no CRLF injection detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2004-0488"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
