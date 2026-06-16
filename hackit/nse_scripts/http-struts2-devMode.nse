local http = require "http"
local stdnse = require "stdnse"

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
            if body:match(ind) then
              table.insert(findings, {path = ep, status = req.status, indicator = ind})
              break
            end
          end
        elseif req.status == 302 then
          local loc = req.headers and req.headers["location"]
          local location_str = type(loc) == "table" and table.concat(loc, " ") or tostring(loc or "")
          if location_str:match("devmode") or location_str:match("struts") then
            table.insert(findings, {path = ep, status = req.status, indicator = "redirect to struts"})
          end
        end
      end
    end

    if #findings > 0 then
      local result = stdnse.output_table()
      result.cve = "CVE-2017-9791 (S2-048)"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.detail = "Struts2 devMode enabled - remote command execution possible"
      for i, f in ipairs(findings) do
        result[("endpoint_%d"):format(i)] = ("%s -> HTTP %d (matched: %s)"):format(f.path, f.status, f.indicator)
      end
      if server_banner:match("Struts") or server_banner:match("Tomcat") then
        local ver = server_banner:match("([%d%.]+)")
        if ver then result.version = ver end
      end
      return result
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2017-9791 (S2-048)"
    result.severity = "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.detail = "No Struts2 devMode detected"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2017-9791"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
