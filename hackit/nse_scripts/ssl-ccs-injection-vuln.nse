local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[Detects OpenSSL CCS injection vulnerability (CVE-2014-0224) via premature CCS packet injection during handshake.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and (port.service == "https" or port.service == "ssl" or port.number == 443) end

local function build_tls_client_hello()
  local client_hello = char(
    0x01, 0x00, 0x00, 0x56, 0x03, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17,
    0x00, 0x16, 0x00, 0x15
  )

  local hello_len = #client_hello
  local tls_record = char(0x16, 0x03, 0x01)
  tls_record = tls_record .. char(0x00, hello_len)
  tls_record = tls_record .. client_hello

  return tls_record
end

local function build_ccs_packet(major, minor)
  local ccs = char(0x01)
  local ccs_record = char(0x14, major, minor, 0x00, 0x01)
  ccs_record = ccs_record .. ccs

  local fin_enc = char(0x01)
  local finished = char(0x16, major, minor, 0x00, 0x20) ..
    char(0x14, 0x00, 0x00, 0x1c) ..
    char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  return ccs_record .. finished
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local server_banner = ""

    local sock = new_socket()
    sock:set_timeout(12000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = output_table()
      result.cve = "CVE-2014-0224 (CCS Injection)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local client_hello = build_tls_client_hello()
    local ok_send, send_err = sock:send(client_hello)
    if not ok_send then sock:close()
      local result = output_table()
      result.cve = "CVE-2014-0224"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Client hello send failed"
      return result
    end

    local rcv, recv_err = sock:receive_buf("\x00", 3)
    if not rcv then sock:close()
      local result = output_table()
      result.cve = "CVE-2014-0224"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No server hello response"
      return result
    end

    if #rcv >= 5 then
      local content_type = rcv:byte(1)
      local ver_major = rcv:byte(2)
      local ver_minor = rcv:byte(3)
      server_banner = ("TLS %d.%d"):format(ver_major, ver_minor)
      if content_type == 22 then
        insert(findings, {check = "TLS handshake", detail = ("Server hello received (TLS %d.%d)"):format(ver_major, ver_minor), severity = "INFO"})
      end
    end

    local ccs_payload = build_ccs_packet(3, 1)
    local ok_ccs, ccs_err = sock:send(ccs_payload)
    if not ok_ccs then sock:close()
      local result = output_table()
      result.cve = "CVE-2014-0224"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "CCS send failed"
      return result
    end

    local rcv2, err2 = sock:receive_buf("\x00", 3)
    sock:close()

    if not rcv2 and err2 then
      if err2:match("TIMEOUT") then
        insert(findings, {check = "CCS injection", detail = "Server hung after CCS packet - vulnerable to CVE-2014-0224", severity = "CRITICAL"})
      else
        insert(findings, {check = "CCS injection", detail = ("CCS response error: %s"):format(err2), severity = "MEDIUM"})
      end
    elseif rcv2 then
      if #rcv2 >= 5 then
        local ct = rcv2:byte(1)
        if ct == 21 then
          local alert_desc = rcv2:byte(6) or 0
          if alert_desc == 40 or alert_desc == 20 then
            insert(findings, {check = "CCS injection", detail = ("Server sent TLS alert (%d) - not vulnerable (properly rejects CCS)"):format(alert_desc), severity = "LOW"})
          else
            insert(findings, {check = "CCS injection", detail = ("Server sent TLS alert %d - not vulnerable"):format(alert_desc), severity = "LOW"})
          end
        elseif ct == 22 and rcv2:match("finished") then
          insert(findings, {check = "CCS injection", detail = "Server accepted CCS and sent Finished - not vulnerable", severity = "LOW"})
        else
          insert(findings, {check = "CCS injection", detail = ("Unexpected response type %d after CCS injection"):format(ct), severity = "MEDIUM"})
        end
      end
    end

    if #findings == 0 then
      insert(findings, {check = "CCS injection", detail = "No response after CCS injection", severity = "MEDIUM"})
    end

    local max_severity = "LOW"
    for _, f in ipairs(findings) do
      local order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
      if (order[f.severity] or 0) > (order[max_severity] or 0) then
        max_severity = f.severity
      end
    end

    local result = output_table()
    result.cve = "CVE-2014-0224 (CCS Injection)"
    result.severity = max_severity
    result.vulnerable = max_severity ~= "LOW" and max_severity ~= "INFO"
    result.banner = server_banner
    result.detail = (result.vulnerable) and "OpenSSL CCS injection vulnerability (CVE-2014-0224) detected" or "No CCS injection vulnerability detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
    end
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2014-0224"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
