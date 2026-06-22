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

description = [[Detects open DNS resolvers susceptible to amplification attacks (CVE-1999-0265, DNS amplification).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "domain" end

local function create_dns_query(id, qtype, name)
  local name_bytes = {}
  for part in gmatch(name, "[^.]+") do
    insert(name_bytes, char(#part) .. part)
  end
  insert(name_bytes, char(0x00))
  local qname = concat(name_bytes)

  local id_bytes = char(math.floor(id / 256), id % 256)
  local flags = char(0x01, 0x00)
  local qdcount = char(0x00, 0x01)
  local ancount = char(0x00, 0x00)
  local nscount = char(0x00, 0x00)
  local arcount = char(0x00, 0x00)
  local qtype_bytes = char(0x00, qtype)
  local qclass = char(0x00, 0x01)

  return id_bytes .. flags .. qdcount .. ancount .. nscount .. arcount .. qname .. qtype_bytes .. qclass
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local query_types = {
      {id = 1, qtype = 1, name = "example.com", label = "A"},
      {id = 2, qtype = 15, name = "example.com", label = "MX"},
      {id = 3, qtype = 255, name = "example.com", label = "ANY"},
      {id = 4, qtype = 16, name = "example.com", label = "TXT"},
      {id = 5, qtype = 28, name = "example.com", label = "AAAA"},
      {id = 6, qtype = 255, name = "isc.org", label = "ANY (isc.org)"},
      {id = 7, qtype = 255, name = "google.com", label = "ANY (google.com)"},
      {id = 8, qtype = 99, name = "example.com", label = "SPF"},
    }

    local sock = new_socket()
    sock:set_timeout(8000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = output_table()
      result.cve = "CVE-1999-0265 (DNS Amplification)"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    for _, qt in ipairs(query_types) do
      local query = create_dns_query(qt.id, qt.qtype, qt.name)
      local ok_send, send_err = sock:send(query)
      if ok_send then
        local rcv, recv_err = sock:receive_buf("\x00", 3)
        if rcv then
          local query_size = #query
          local response_size = #rcv
          local amplification_factor = response_size / math.max(query_size, 1)

          local query_id = byte(rcv, 1) * 256 + byte(rcv, 2)
          local response_flags = byte(rcv, 3) * 256 + byte(rcv, 4)

          if response_flags > 0 then
            local tc_bit = (response_flags & 0x0200) > 0
            local ra_bit = (response_flags & 0x0080) > 0

            insert(findings, {
              query = ("%s %s"):format(qt.label, qt.name),
              qsize = query_size,
              rsize = response_size,
              factor = amplification_factor,
              tc = tc_bit,
              ra = ra_bit,
              id_match = (query_id == qt.id),
            })
          end
        end
      end
    end

    sock:close()

    if #findings > 0 then
      local max_factor = 0
      local max_finding = nil
      for _, f in ipairs(findings) do
        if f.factor > max_factor then
          max_factor = f.factor
          max_finding = f
        end
      end

      local is_open = false
      for _, f in ipairs(findings) do
        if f.ra then
          is_open = true
          break
        end
      end

      local result = output_table()
      result.cve = "CVE-1999-0265 (DNS Amplification)"
      result.severity = "HIGH"
      result.vulnerable = is_open or max_factor > 10
      result.detail = (result.vulnerable) and "Open DNS resolver with amplification potential" or "DNS resolver detected but not clearly open"
      result.amplification_factor = ("%.1fx"):format(max_factor)
      result.max_response_size = max_finding and max_finding.rsize or 0
      result.queries_answered = #findings

      if is_open then
        result.recursion_available = "Yes - resolver is open to recursive queries"
        result.severity = "CRITICAL"
      end

      for i, f in ipairs(findings) do
        result[("query_%d"):format(i)] = ("%s: %d bytes -> %d bytes (%.1fx amp)"):format(f.query, f.qsize, f.rsize, f.factor)
      end

      return result
    end

    local result = output_table()
    result.cve = "CVE-1999-0265"
    result.severity = "LOW"
    result.vulnerable = false
    result.detail = "DNS resolver appears properly configured - no amplification responses"
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-1999-0265"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
