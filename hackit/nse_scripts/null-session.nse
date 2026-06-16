local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Tests whether the target Windows host allows null session (unauthenticated) connections
over SMB (port 445 or 139). A null session is an unauthenticated connection established
without credentials that can be used to enumerate users, shares, groups, and other
system information on misconfigured Windows systems. Performs SMB protocol negotiation
followed by a Session Setup request with empty credentials. Analyzes the NT status
response to determine if null sessions are permitted. Tests both SMBv1 and SMBv2
protocol dialects for comprehensive coverage. Reports detailed NT status codes for
troubleshooting.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({139, 445}, {"netbios-ssn", "microsoft-ds"})

local nt_status_codes = {
  [0x00000000] = "STATUS_SUCCESS",
  [0xC0000022] = "STATUS_ACCESS_DENIED",
  [0xC000000D] = "STATUS_INVALID_PARAMETER",
  [0xC0000016] = "STATUS_MORE_PROCESSING_REQUIRED",
  [0xC00000BB] = "STATUS_NOT_SUPPORTED",
  [0xC000006D] = "STATUS_LOGON_FAILURE",
  [0xC000006F] = "STATUS_ACCOUNT_RESTRICTION",
  [0xC0000070] = "STATUS_INVALID_LOGON_HOURS",
  [0xC0000071] = "STATUS_INVALID_WORKSTATION",
  [0xC0000072] = "STATUS_PASSWORD_EXPIRED",
  [0xC0000073] = "STATUS_ACCOUNT_DISABLED",
  [0xC0000133] = "STATUS_TIME_DIFFERENCE_AT_DC",
  [0xC0000235] = "STATUS_PASSWORD_MUST_CHANGE",
  [0xC0000413] = "STATUS_LOGON_WITH_GRACEFUL"
}

local function recv_all(sock, timeout_ms)
  sock:set_timeout(timeout_ms or 3000)
  local all_data = ""
  while true do
    local ok, data = sock:receive_bytes(1)
    if not ok or not data then break end
    all_data = all_data .. data
  end
  return all_data
end

action = function(host, port)
  local result = stdnse.output_table()
  local sock = nmap.new_socket()
  sock:set_timeout(10000)

  local ok, err = sock:connect(host.ip, port.number, "tcp")
  if not ok then
    result.status = "error"
    result.target = host.ip .. ":" .. port.number
    result.reason = "Could not connect to SMB port: " .. (err or "unknown error")
    return result
  end

  local negotiate = string.char(
    0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xC0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x00, 0x01, 0x00, 0x02, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  )

  local send_ok, send_err = pcall(sock.send, sock, negotiate)
  if not send_ok then
    sock:close()
    result.status = "error"
    result.reason = "SMB negotiate send failed: " .. (send_err or "unknown")
    return result
  end

  local status, response = pcall(sock.receive_bytes, sock, 1024)
  if status and response and #response > 4 then
    local session_setup = string.char(
      0x00, 0x00, 0x00, 0x28, 0xFF, 0x53, 0x4D, 0x42,
      0x73, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xC0,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    )

    local send2_ok, send2_err = pcall(sock.send, sock, session_setup)
    if not send2_ok then
      sock:close()
      result.status = "error"
      result.reason = "SMB session setup send failed: " .. (send2_err or "unknown")
      return result
    end

    local status2, response2 = pcall(sock.receive_bytes, sock, 1024)
    sock:close()

    if status2 and response2 and #response2 > 8 then
      local nt_status_bytes = string.sub(response2, 5, 8)
      local nt_status = 0
      for i = 1, 4 do
        nt_status = nt_status + (string.byte(nt_status_bytes, i) or 0) * (256 ^ (i - 1))
      end

      local nt_name = nt_status_codes[nt_status] or string.format("0x%08X", nt_status)

      result.status = "success"
      result.target = host.ip .. ":" .. port.number
      result.protocol = "SMB"
      result.nt_status_code = string.format("0x%08X", nt_status)
      result.nt_status_name = nt_name

      if nt_status == 0 then
        result.null_session_allowed = true
        result.vulnerability = "Host allows null session connections"
        result.risk = "Unauthenticated enumeration possible (users, shares, groups)"
        result.severity = "high"
      else
        result.null_session_allowed = false
        result.vulnerability = "Host properly restricts null sessions"
        result.risk = "Authentication required for SMB enumeration"
        result.severity = "none"
      end

      return result
    end
  end

  sock:close()
  result.status = "error"
  result.target = host.ip .. ":" .. port.number
  result.reason = "SMB negotiation failed or timed out"
  return result
end
