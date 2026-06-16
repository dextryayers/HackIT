local stdnse = require "stdnse"

description = [[Detects DoublePulsar backdoor via SMB ping-pong handshake (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.number == 445 or port.number == 139) end

local function create_smb_trans2_packet(trans_cmd)
  local body = string.char(
    0x00, 0x00, 0x00, 0x54, 0xff, 0x53, 0x4d, 0x42,
    trans_cmd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x00, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
  return body
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local os_info = ""

    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = stdnse.output_table()
      result.cve = "CVE-2017-0143 (DoublePulsar)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local negotiate_pkt = string.char(
      0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x41, 0x00, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    )

    local ok_neg, err_neg = sock:send(negotiate_pkt)
    if not ok_neg then sock:close()
      local result = stdnse.output_table()
      result.cve = "CVE-2017-0143"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "SMB negotiate failed: " .. tostring(err_neg)
      return result
    end

    local rcv_neg = sock:receive_buf("\x00", 3)
    if not rcv_neg or #rcv_neg < 36 then sock:close()
      local result = stdnse.output_table()
      result.cve = "CVE-2017-0143"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No SMB negotiate response"
      return result
    end

    local os_major = rcv_neg:byte(41) or 0
    local os_minor = rcv_neg:byte(42) or 0
    if os_major > 0 then
      os_info = ("Windows %d.%d"):format(os_major, os_minor)
    end

    local trans_commands = {0x73, 0x75, 0x25}
    for _, trans_cmd in ipairs(trans_commands) do
      local ping_pkt = create_smb_trans2_packet(trans_cmd)

      local ping_ok, ping_err = sock:send(ping_pkt)
      if ping_ok then
        local rcv_ping = sock:receive_buf("\x00", 3)
        if rcv_ping and #rcv_ping >= 72 then
          local trans_status = string.byte(rcv_ping, 9) or 0
          local pid = string.byte(rcv_ping, 50) or 0
          local signature = string.byte(rcv_ping, 68) or 0
          local mpid = string.byte(rcv_ping, 52) or 0

          if trans_status == 0 and pid > 0 and signature == 0x80 then
            table.insert(findings, {cmd = trans_cmd, status_byte = trans_status, pid = pid, signature = signature, detail = "DoublePulsar ping response signature matched", severity = "CRITICAL"})
          elseif trans_status == 0 and mpid == 0x80 then
            table.insert(findings, {cmd = trans_cmd, status_byte = trans_status, mpid = mpid, detail = "DoublePulsar alternative signature matched", severity = "CRITICAL"})
          elseif trans_status == 0 and #rcv_ping >= 80 and rcv_ping:byte(77) ~= 0 then
            table.insert(findings, {cmd = trans_cmd, status_byte = trans_status, detail = "Unusual trans2 response - potential DoublePulsar", severity = "HIGH"})
          end
        end
      end
    end

    sock:close()

    local pong_sock = nmap.new_socket()
    pong_sock:set_timeout(8000)
    local pong_ok = pong_sock:connect(host.ip, port.number)
    if pong_ok then
      local pong_pkt = create_smb_trans2_packet(0x73)
      pong_sock:send(pong_pkt)
      local rcv_pong = pong_sock:receive_buf("\x00", 3)
      if rcv_pong and #rcv_pong >= 72 then
        local sig2 = string.byte(rcv_pong, 68) or 0
        if sig2 == 0x80 then
          for _, f in ipairs(findings) do
            if f.severity ~= "CRITICAL" then
              f.detail = "DoublePulsar ping-pong confirmed"
              f.severity = "CRITICAL"
            end
          end
        end
      end
      pong_sock:close()
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2017-0143, CVE-2017-0144, CVE-2017-0145"
    result.severity = (#findings > 0) and "CRITICAL" or "LOW"
    result.vulnerable = #findings > 0
    result.os = os_info
    result.detail = (#findings > 0) and "DoublePulsar backdoor detected via SMB ping-pong handshake" or "No DoublePulsar backdoor detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = f.detail
    end
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2017-0143"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
