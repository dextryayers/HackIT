local stdnse = require "stdnse"
local tls = require "tls"

description = [[Detects DROWN / SSLv2 enabled on the SSL/TLS service (CVE-2016-0800, CVE-2016-0703).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "https" or port.service == "ssl" or port.number == 443) end

local function build_sslv2_hello(ciphers)
  local ciph_bytes = {}
  for _, c in ipairs(ciphers) do
    ciph_bytes[#ciph_bytes + 1] = string.char(0x00, c)
  end
  local cipher_spec = table.concat(ciph_bytes)
  local cipher_len = #cipher_spec

  local session_id = ""
  local challenge = "HackIT"

  local length = 2 + 2 + 2 + 2 + cipher_len + #session_id + #challenge
  if length > 127 then
    local packet = string.char(0x80, 0x80 + math.floor(length / 256), length % 256)
  else
    local packet = string.char(0x80, length)
  end

  packet = packet .. string.char(0x01)
  packet = packet .. string.char(0x00, cipher_len / 2)
  packet = packet .. string.char(#session_id)
  packet = packet .. string.char(#challenge)
  packet = packet .. cipher_spec
  packet = packet .. session_id
  packet = packet .. challenge

  packet = packet .. string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  return packet
end

local function test_sslv2(host, port_num)
  local sock = nmap.new_socket()
  sock:set_timeout(10000)
  local status = sock:connect(host.ip, port_num)
  if not status then return nil, "connect failed" end

  local sslv2_ciphers = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}
  local sslv2_hello = build_sslv2_hello(sslv2_ciphers)

  local ok_send, send_err = sock:send(sslv2_hello)
  if not ok_send then sock:close(); return nil, "send failed" end

  local rcv, recv_err = sock:receive_buf("\x00", 3)
  sock:close()
  if not rcv then return nil, recv_err end

  return rcv, nil
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""

    local tls_req = tls.hello(host, port)
    if tls_req and tls_req.server_hello then
      server_banner = tostring(tls_req.server_hello):sub(1, 100)
    end

    local rcv, err = test_sslv2(host, port.number)
    if rcv and #rcv >= 2 then
      local first_byte = rcv:byte(1)
      local second_byte = rcv:byte(2)

      if (first_byte == 0x80 or first_byte == 0x04) and second_byte < 0x80 then
        local error_code = rcv:byte(3) or 0
        if error_code == 0 then
          table.insert(findings, {check = "SSLv2 server hello", detail = "SSLv2 ServerHello received - server supports SSLv2", severity = "CRITICAL"})
        end
      end

      if #rcv > 10 then
        local session_id_hit = rcv:sub(3, 3)
        if session_id_hit == string.char(0x00) then
          local cert_len = rcv:byte(4) * 256 + (rcv:byte(5) or 0)
          local cipher_len = rcv:byte(6) * 256 + (rcv:byte(7) or 0)
          if cipher_len > 0 then
            local offset = 8 + cert_len
            local ciphers_received = {}
            for i = 1, cipher_len, 3 do
              if offset + i + 2 <= #rcv then
                ciphers_received[#ciphers_received + 1] = rcv:byte(offset + i) * 256 + rcv:byte(offset + i + 1)
              end
            end
            table.insert(findings, {check = "SSLv2 ciphers", detail = ("Server offered %d SSLv2 cipher suites - DROWN attack possible"):format(#ciphers_received), severity = "CRITICAL"})
          end
        end
      end

      local sslv2_signature = (first_byte == 0x80 or first_byte == 0x04)
      if sslv2_signature and not findings[1] then
        table.insert(findings, {check = "SSLv2 response", detail = "SSLv2 response format detected", severity = "HIGH"})
      end
    elseif err and not err:match("TIMEOUT") then
      table.insert(findings, {check = "SSLv2 test", detail = ("No SSLv2 response: %s"):format(tostring(err)), severity = "LOW"})
    end

    if rcv and #rcv > 2 and rcv:match("SSLv2") then
      table.insert(findings, {check = "SSLv2 banner", detail = "SSLv2 reference found in response", severity = "HIGH"})
    end

    if #findings == 0 then
      table.insert(findings, {check = "SSLv2 test", detail = "No SSLv2 response - DROWN likely not exploitable", severity = "LOW"})
    end

    local max_severity = "LOW"
    for _, f in ipairs(findings) do
      local order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
      if (order[f.severity] or 0) > (order[max_severity] or 0) then
        max_severity = f.severity
      end
    end

    local result = stdnse.output_table()
    result.cve = "CVE-2016-0800 (DROWN), CVE-2016-0703"
    result.severity = max_severity
    result.vulnerable = max_severity ~= "LOW" and max_severity ~= "INFO"
    result.banner = server_banner
    result.detail = (result.vulnerable) and "DROWN attack possible - SSLv2 enabled" or "No DROWN / SSLv2 detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
    end
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-2016-0800"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
