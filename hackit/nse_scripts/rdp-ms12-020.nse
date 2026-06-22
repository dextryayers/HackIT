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

description = [[Detects MS12-020 RDP denial-of-service vulnerability (CVE-2012-0002) via crafted channel request.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.number == 3389 end

local function create_rdp_connect_pdu()
  return char(
    0x03, 0x00, 0x00, 0x2c, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
end

local function create_ms12_channel_pdu()
  return char(
    0x03, 0x00, 0x01, 0x0c, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local rdp_banner = ""

    local sock = new_socket()
    sock:set_timeout(10000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = output_table()
      result.cve = "CVE-2012-0002 (MS12-020)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local rdp_neg = char(0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00)
    sock:send(rdp_neg)
    local rcv, err = sock:receive_buf("\x00", 3)
    if not rcv then sock:close()
      local result = output_table()
      result.cve = "CVE-2012-0002"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No RDP negotiation response"
      return result
    end

    if rcv:len() >= 4 then
      local proto = byte(rcv, 3) or 0
      local vers = byte(rcv, 2) or 0
      rdp_banner = ("RDP proto=%d ver=%d"):format(proto, vers)
      if vers == 3 then
        insert(findings, {check = "RDP protocol", detail = ("RDP %d.%d detected"):format(vers, proto), severity = "INFO"})
      end
    end

    sock:send(create_rdp_connect_pdu())
    local rcv2 = sock:receive_buf("\x00", 3)
    if not rcv2 then sock:close()
      local result = output_table()
      result.cve = "CVE-2012-0002"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No RDP connect response"
      return result
    end

    local selected_proto = byte(rcv2, 13) or 255
    insert(findings, {check = "RDP security", detail = (selected_proto == 0) and "RDP Security (no NLA)" or "NLA/CredSSP enabled", severity = selected_proto == 0 and "HIGH" or "LOW"})

    sock:send(create_ms12_channel_pdu())
    local rcv3, err3 = sock:receive_buf("\x00", 3)
    sock:close()

    if not rcv3 and err3 and match(err3, "TIMEOUT") then
      insert(findings, {check = "MS12-020 channel request", detail = "Server hung after channel request - MS12-020 DoS likely", severity = "CRITICAL"})
    elseif rcv3 and #rcv3 >= 4 then
      local resp_type = byte(rcv3, 2) or 0
      if resp_type == 0x03 then
        insert(findings, {check = "MS12-020 channel request", detail = "Server responded normally (not vulnerable to this test vector)", severity = "LOW"})
      end
    end

    local max_severity = "LOW"
    for _, f in ipairs(findings) do
      local sev_order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
      if (sev_order[f.severity] or 0) > (sev_order[max_severity] or 0) then
        max_severity = f.severity
      end
    end

    local result = output_table()
    result.cve = "CVE-2012-0002 (MS12-020)"
    result.severity = max_severity
    result.vulnerable = max_severity ~= "LOW" and max_severity ~= "INFO"
    result.banner = rdp_banner
    result.detail = (result.vulnerable) and "MS12-020 vulnerability indicators found" or "No MS12-020 vulnerability detected"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
    end
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2012-0002"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
