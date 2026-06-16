local stdnse = require "stdnse"

description = [[Detects BlueKeep (CVE-2019-0708) RDP vulnerability via crafted initial packets with version fingerprinting.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 3389 end

local function create_rdp_connect_init()
  return string.char(
    0x03, 0x00, 0x00, 0x2c, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
end

local function create_bluekeep_channel_pdu()
  return string.char(
    0x03, 0x00, 0x01, 0x0c, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local rdp_info = ""

    local sock = nmap.new_socket()
    sock:set_timeout(12000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = stdnse.output_table()
      result.cve = "CVE-2019-0708 (BlueKeep)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local rdp_neg = string.char(0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00)
    sock:send(rdp_neg)
    local rcv = sock:receive_buf("\x00", 3)
    if not rcv or rcv:len() < 4 then sock:close()
      local result = stdnse.output_table()
      result.cve = "CVE-2019-0708"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No RDP negotiation response"
      return result
    end

    local msrpc_version = rcv:byte(2) or 0
    local protocol = rcv:byte(3) or 0
    local rdp_neg_type = rcv:byte(11) or 0
    local rdp_version = rcv:byte(13) or 0

    rdp_info = ("RDP v%d.%d type=%d proto=%d"):format(msrpc_version, protocol, rdp_neg_type, rdp_version)

    if msrpc_version == 3 then
      table.insert(findings, {check = "RDP protocol", detail = ("RDP version %d detected"):format(msrpc_version), severity = "INFO"})
    end

    if rdp_neg_type == 0 then
      table.insert(findings, {check = "RDP security", detail = "RDP standard security (no NLA) - potentially vulnerable to BlueKeep", severity = "HIGH"})
    elseif rdp_neg_type == 1 then
      table.insert(findings, {check = "RDP security", detail = "RDP with NLA/CredSSP - less likely vulnerable to BlueKeep", severity = "LOW"})
    elseif rdp_neg_type == 3 then
      table.insert(findings, {check = "RDP security", detail = "RDP with CredSSP/NLA - BlueKeep not exploitable", severity = "LOW"})
    end

    if rdp_neg_type == 0 then
      sock:send(create_rdp_connect_init())
      local rcv2, err2 = sock:receive_buf("\x00", 3)
      if rcv2 and #rcv2 >= 13 then
        local selected_proto = rcv2:byte(13) or 0
        if selected_proto == 0 then
          local rdp_ver_check = create_bluekeep_channel_pdu()
          sock:send(rdp_ver_check)
          local rcv3, err3 = sock:receive_buf("\x00", 3)
          if not rcv3 and err3 and err3:match("TIMEOUT") then
            table.insert(findings, {check = "BlueKeep channel request", detail = "Connection hang after channel request - BlueKeep vulnerability likely (CVE-2019-0708)", severity = "CRITICAL"})
          elseif rcv3 then
            table.insert(findings, {check = "BlueKeep channel request", detail = "Server responded - not vulnerable via this vector", severity = "LOW"})
          end
        end
      end
    end
    sock:close()

    local os_hint = ""
    if rdp_version == 5 then os_hint = "Windows 2000/XP/2003"
    elseif rdp_version == 6 then os_hint = "Windows Vista/2008/7/2008R2"
    elseif rdp_version == 7 then os_hint = "Windows 8/2012"
    elseif rdp_version == 8 then os_hint = "Windows 8.1/2012R2"
    elseif rdp_version == 10 then os_hint = "Windows 10/2016/2019"
    end
    if os_hint ~= "" then
      table.insert(findings, {check = "RDP version hint", detail = ("RDP %d - %s"):format(rdp_version, os_hint), severity = "INFO"})
    end

    local max_severity = "LOW"
    for _, f in ipairs(findings) do
      local order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
      if (order[f.severity] or 0) > (order[max_severity] or 0) then
        max_severity = f.severity
      end
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2019-0708 (BlueKeep)"
    result.severity = max_severity
    result.vulnerable = max_severity ~= "LOW" and max_severity ~= "INFO"
    result.banner = rdp_info
    result.detail = (result.vulnerable) and "BlueKeep (CVE-2019-0708) vulnerability indicators found" or "No BlueKeep vulnerability detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
    end
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2019-0708"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
