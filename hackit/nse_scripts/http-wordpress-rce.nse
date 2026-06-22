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

description = [[Checks for WordPress RCE vectors including plugin/theme vulns, file write, config exposure, and sensitive file disclosure.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "http" end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""
    local wp_version = nil

    local banner_req = http.get(host, port, "/")
    if banner_req and banner_req.headers and banner_req.headers["server"] then
      local sv = banner_req.headers["server"]
      server_banner = type(sv) == "table" and sv[1] or sv
    end

    local is_wp = false
    if banner_req and banner_req.body then
      local body = banner_req.body
      if match(body, "wordpress") or match(body, "WordPress") or match(body, "wp%-content") or match(body, "wp%-admin") then
        is_wp = true
        wp_version = match(body, "WordPress%s+([%d%.]+)") or match(body, "ver=([%d%.]+)") or match(body, "wp%-includes")
      end
    end

    local critical_paths = {
      {path = "/wp-config.php.bak", checks = {"DB_NAME", "DB_PASSWORD", "DB_USER", "table_prefix"}, severity = "CRITICAL"},
      {path = "/wp-config.php~", checks = {"DB_NAME", "DB_PASSWORD"}, severity = "CRITICAL"},
      {path = "/wp-config.php.old", checks = {"DB_NAME", "DB_PASSWORD"}, severity = "CRITICAL"},
      {path = "/wp-config.php.swp", checks = {"DB_NAME", "DB_PASSWORD"}, severity = "CRITICAL"},
      {path = "/wp-content/debug.log", checks = {"PHP", "Stack trace", "Warning", "Error", "Fatal"}, severity = "HIGH"},
      {path = "/wp-content/uploads/wp_all_backup/wp-config.php", checks = {"DB_NAME"}, severity = "CRITICAL"},
      {path = "/.wp-config.php.swp", checks = {"DB_NAME"}, severity = "CRITICAL"},
      {path = "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php", checks = {"DB_NAME", "DB_PASSWORD"}, severity = "CRITICAL"},
      {path = "/wp-content/plugins/akismet/akismet.php", checks = {"Plugin Name", "Akismet"}, severity = "INFO"},
      {path = "/wp-content/plugins/hello.php", checks = {"Plugin Name", "Hello"}, severity = "INFO"},
      {path = "/wp-json/wp/v2/users", checks = {"name", "slug", "avatar_urls"}, severity = "MEDIUM"},
      {path = "/wp-json/wp/v2/users?per_page=100", checks = {"name", "slug"}, severity = "MEDIUM"},
      {path = "/wp-content/debug.log", checks = {"PHP Notice", "PHP Warning", "PHP Fatal"}, severity = "HIGH"},
      {path = "/wp-content/uploads/", checks = {"Index of", "wp-content"}, severity = "MEDIUM"},
    }

    for _, cp in ipairs(critical_paths) do
      local req = http.get(host, port, cp.path)
      if req and req.status == 200 then
        local body = req.body or ""
        for _, check in ipairs(cp.checks) do
          if match(body, check) then
            local excerpt = sub(body, 1, 100):gsub("\n", " "):gsub("\r", "")
            insert(findings, {path = cp.path, check = check, excerpt = excerpt, status = req.status, severity = cp.severity})
            break
          end
        end
        if cp.match(path, "wp%-config") and match(body, "define") and match(body, "%$table_prefix") then
          insert(findings, {path = cp.path, check = "wp-config signature", excerpt = sub(body, 1, 120), status = req.status, severity = "CRITICAL"})
        end
      elseif req and req.status ~= 404 then
        if cp.match(path, "wp%-json") and req.status == 200 then
          local body = req.body or ""
          if match(body, "%[") then
            insert(findings, {path = cp.path, check = "REST API exposed", excerpt = sub(body, 1, 80), status = req.status, severity = "MEDIUM"})
          end
        end
      end
    end

    local rce_tests = {
      {path = "/wp-admin/admin-ajax.php", data = "action=wp_ajax_foo", severity = "MEDIUM"},
      {path = "/wp-content/plugins/revslider/temp/update_extract/revslider/temp.php", severity = "CRITICAL"},
    }

    for _, rt in ipairs(rce_tests) do
      local req
      if rt.data then
        req = http.post(host, port, rt.path, {
          header = {["Content-Type"] = "application/x-www-form-urlencoded"},
          data = rt.data
        })
      else
        req = http.get(host, port, rt.path)
      end
      if req and req.status and req.status < 400 then
        local body = req.body or ""
        if match(body, "HackIT") or match(body, "revslider") or match(body, "temp") then
          insert(findings, {path = rt.path, check = "RCE vector", excerpt = sub(body, 1, 60), status = req.status, severity = rt.severity})
        end
      end
    end

    if not is_wp then
      local wp_indicators = {"/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-includes/"}
      for _, p in ipairs(wp_indicators) do
        local req = http.get(host, port, p)
        if req and req.status and req.status < 400 then
          is_wp = true
          break
        end
      end
    end

    if #findings > 0 then
      local result = output_table()
      result.cve = "CVE-2017-1001000 (RevSlider), multiple plugin CVEs"
      result.severity = "HIGH"
      result.vulnerable = true
      result.server = server_banner
      result.version = wp_version or "unknown"
      result.detail = ("WordPress exposure found - %d issue(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("issue_%d"):format(i)] = ("[%s] %s -> %s"):format(f.severity, f.path, f.check)
      end
      return result
    end

    local result = output_table()
    result.cve = "N/A"
    result.severity = is_wp and "MEDIUM" or "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.version = wp_version or "unknown"
    result.detail = is_wp and "WordPress detected but no exposure found" or "No WordPress detected"
    return result
  end)
  if not ok then
    local result = output_table()
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
