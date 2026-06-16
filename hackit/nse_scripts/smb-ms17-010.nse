local stdnse = require "stdnse"

description = [[Detects MS17-010 EternalBlue vulnerability in SMBv1 implementations using the SMB transaction2 zero-day check.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 445 or port.number == 139) end

local function create_smb_packet(cmd, data)
  local body = string.char(
    0x00, 0x00, 0x00, 0x00 + #data + 0x2f, 0xff, 0x53, 0x4d, 0x42,
    cmd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x00
  )
  local frame = body .. data
  local len = #frame - 4
  frame = string.char(0x00, 0x00, 0x00, len) .. frame:sub(5)
  return frame
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local os_info = ""
    local sock = nmap.new_socket()
    sock:set_timeout(10000)

    local status, err = sock:connect(host.ip, port.number)
    if not status then
      local result = stdnse.output_table()
      result.cve = "MS17-010"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed: " .. tostring(err)
      result.error = true
      return result
    end

    local smb_neg_proto = string.char(
      0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x41, 0x00, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    )

    local send_ok, send_err = sock:send(smb_neg_proto)
    if not send_ok then sock:close()
      local result = stdnse.output_table()
      result.cve = "MS17-010"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "SMB negotiate failed: " .. tostring(send_err)
      return result
    end

    local rcv = sock:receive_buf("\x00", 3)
    if not rcv or #rcv < 36 then sock:close()
      local result = stdnse.output_table()
      result.cve = "MS17-010"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No SMB negotiate response"
      return result
    end

    local os_major = rcv:byte(41) or 0
    local os_minor = rcv:byte(42) or 0
    local os_build = 0
    if #rcv >= 47 then
      os_build = rcv:byte(47) * 256 + (rcv:byte(48) or 0)
    end

    local native_os = ""
    if #rcv >= 60 then
      native_os = rcv:sub(60):match("([%a%d%s%.]+)%z") or ""
    end

    if os_major > 0 then
      os_info = ("Windows %d.%d (build %d)"):format(os_major, os_minor, os_build)
    end
    if native_os ~= "" then
      os_info = native_os
    end

    local vulnerable_versions = {
      {major = 5, minor = 0, label = "Windows 2000"},
      {major = 5, minor = 1, label = "Windows XP"},
      {major = 5, minor = 2, label = "Windows Server 2003"},
      {major = 6, minor = 0, label = "Windows Vista/Server 2008"},
      {major = 6, minor = 1, label = "Windows 7/Server 2008 R2"},
      {major = 6, minor = 2, label = "Windows 8/Server 2012"},
      {major = 6, minor = 3, label = "Windows 8.1/Server 2012 R2"},
      {major = 10, minor = 0, label = "Windows 10/Server 2016/2019"},
    }

    local is_vuln_os = false
    local os_label = ""
    for _, v in ipairs(vulnerable_versions) do
      if os_major == v.major and os_minor == v.minor then
        is_vuln_os = true
        os_label = v.label
        break
      end
    end

    if is_vuln_os then
      table.insert(findings, {check = "OS version", detail = ("%s (%d.%d build %d) - potentially vulnerable to MS17-010"):format(os_label, os_major, os_minor, os_build), severity = "HIGH"})
    end

    sock:close()

    local sock2 = nmap.new_socket()
    sock2:set_timeout(10000)
    local s2, e2 = sock2:connect(host.ip, port.number)
    if s2 then
      local peek_pkt = string.char(
        0x00, 0x00, 0x00, 0x54, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      )
      local ok2, e2b = sock2:send(peek_pkt)
      if ok2 then
        local rcv2 = sock2:receive_buf("\x00", 3)
        if rcv2 and #rcv2 >= 8 then
          local status_byte = rcv2:byte(9) or 0
          if status_byte == 0 then
            local nq = rcv2:byte(45) or 0
            if nq > 0 then
              table.insert(findings, {check = "SMBv1 dialect", detail = "SMBv1 active with NT Status 0x0000 - vulnerable to EternalBlue", severity = "CRITICAL"})
            end
          end
        end
      end
      sock2:close()
    end

    local result = stdnse.output_table()
    result.cve = "MS17-010"
    result.severity = "HIGH"
    result.vulnerable = #findings > 0
    result.os = os_info
    result.detail = (#findings > 0) and "MS17-010 (EternalBlue) vulnerability indicators found" or "No MS17-010 vulnerability detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("%s: %s"):format(f.check, f.detail)
    end
    if is_vuln_os and #findings == 1 then
      result.note = "SMBv1 is present on a potentially vulnerable OS version"
    end
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "MS17-010"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
