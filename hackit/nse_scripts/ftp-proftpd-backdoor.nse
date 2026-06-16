local stdnse = require "stdnse"

description = [[Detects ProFTPD 1.3.3b backdoor (CVE-2010-4221) via crafted ACCT command and version fingerprinting.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "ftp" or port.number == 21) end

local backdoor_commands = {
  "ACCT HackIT_Test",
  "ACCT HackIT",
  "ACCT id",
  "ACCT /bin/echo HackIT",
}

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local banner_str = ""
    local ftpd_version = nil

    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = stdnse.output_table()
      result.cve = "CVE-2010-4221 (ProFTPD Backdoor)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local banner, banner_err = sock:receive_buf("\n", 3)
    if not banner then sock:close()
      local result = stdnse.output_table()
      result.cve = "CVE-2010-4221"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No FTP banner"
      return result
    end

    banner_str = banner:gsub("\r?\n", ""):gsub("%s+$", "")
    ftpd_version = banner_str:match("ProFTPD ([%d%.]+[a-z]*)")
    local pureftpd = banner_str:match("Pure%-FTPD")
    local vsftpd = banner_str:match("vsFTPd")
    local server_type = "unknown"
    if ftpd_version then
      server_type = "ProFTPD " .. ftpd_version
    elseif pureftpd then
      server_type = "Pure-FTPD"
    elseif vsftpd then
      server_type = "vsFTPd"
    end

    table.insert(findings, {check = "FTP banner", detail = banner_str, severity = "INFO"})

    sock:send("USER anonymous\r\n")
    local rcv = sock:receive_buf("\n", 3)
    if rcv and rcv:match("331") then
      table.insert(findings, {check = "Anonymous login", detail = "Anonymous login allowed", severity = "MEDIUM"})
    end

    sock:send("PASS test@test.com\r\n")
    rcv = sock:receive_buf("\n", 3)

    if rcv and (rcv:match("230") or rcv:match("202")) then
      table.insert(findings, {check = "Login success", detail = "Authenticated successfully", severity = "INFO"})

      for _, cmd in ipairs(backdoor_commands) do
        local cmd_sock = nmap.new_socket()
        cmd_sock:set_timeout(8000)
        local ok_cmd = cmd_sock:connect(host.ip, port.number)
        if ok_cmd then
          cmd_sock:receive_buf("\n", 3)
          cmd_sock:send("USER anonymous\r\n")
          cmd_sock:receive_buf("\n", 3)
          cmd_sock:send("PASS test@test.com\r\n")
          cmd_sock:receive_buf("\n", 3)
          cmd_sock:send(cmd .. "\r\n")
          local cmd_rcv, cmd_err = cmd_sock:receive_buf("\n", 3)
          if cmd_rcv then
            local resp = cmd_rcv:gsub("\r?\n", "")
            if resp:match("HackIT") or resp:match("uid=") or resp:match("root") or resp:match("nobody") then
              table.insert(findings, {
                check = ("Backdoor via %s"):format(cmd),
                detail = ("Command executed: %s"):format(resp),
                severity = "CRITICAL",
              })
            elseif resp:match("211") or resp:match("230") or resp:match("202") then
              if cmd:match("ACCT") then
                table.insert(findings, {
                  check = ("ACCT command response"),
                  detail = ("ACCT accepted: %s"):format(resp),
                  severity = "HIGH",
                })
              end
            end
          end
          cmd_sock:send("QUIT\r\n")
          cmd_sock:close()
        end
      end
    end

    sock:send("SYST\r\n")
    rcv = sock:receive_buf("\n", 3)
    if rcv then
      table.insert(findings, {check = "SYST response", detail = rcv:gsub("\r?\n", ""), severity = "INFO"})
    end

    sock:send("QUIT\r\n")
    sock:close()

    if ftpd_version then
      local major, minor, patch = ftpd_version:match("(%d+)%.(%d+)%.(%d+)([a-z]*)")
      if major and minor and patch then
        local full_ver = tonumber(major) * 10000 + tonumber(minor) * 100 + tonumber(patch) + (({b = 0, c = 1, d = 2})[patch or ""] or 0)
        if full_ver <= 10303 then
          table.insert(findings, {check = "ProFTPD version", detail = ("ProFTPD %s - known vulnerable version (CVE-2010-4221)"):format(ftpd_version), severity = "CRITICAL"})
        end
      end
    end

    local max_severity = "LOW"
    for _, f in ipairs(findings) do
      local order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
      if (order[f.severity] or 0) > (order[max_severity] or 0) then
        max_severity = f.severity
      end
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2010-4221 (ProFTPD Backdoor)"
    result.severity = max_severity
    result.vulnerable = max_severity ~= "LOW" and max_severity ~= "INFO"
    result.banner = banner_str
    result.version = ftpd_version or "unknown"
    result.server_type = server_type
    result.detail = (result.vulnerable) and "ProFTPD backdoor indicators found" or "No ProFTPD backdoor detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
    end
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2010-4221"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
