local stdnse = require "stdnse"

description = [[Detects open DNS resolvers susceptible to amplification attacks (CVE-1999-0265, DNS amplification).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "domain" end

local function create_dns_query(id, qtype, name)
  local name_bytes = {}
  for part in name:gmatch("[^.]+") do
    name_bytes[#name_bytes + 1] = string.char(#part) .. part
  end
  name_bytes[#name_bytes + 1] = string.char(0x00)
  local qname = table.concat(name_bytes)

  local id_bytes = string.char(math.floor(id / 256), id % 256)
  local flags = string.char(0x01, 0x00)
  local qdcount = string.char(0x00, 0x01)
  local ancount = string.char(0x00, 0x00)
  local nscount = string.char(0x00, 0x00)
  local arcount = string.char(0x00, 0x00)
  local qtype_bytes = string.char(0x00, qtype)
  local qclass = string.char(0x00, 0x01)

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

    local sock = nmap.new_socket()
    sock:set_timeout(8000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = stdnse.output_table()
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

          local query_id = rcv:byte(1) * 256 + rcv:byte(2)
          local response_flags = rcv:byte(3) * 256 + rcv:byte(4)

          if response_flags > 0 then
            local tc_bit = (response_flags & 0x0200) > 0
            local ra_bit = (response_flags & 0x0080) > 0

            table.insert(findings, {
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

      local result = stdnse.output_table()
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

    local result = stdnse.output_table()
    result.cve = "CVE-1999-0265"
    result.severity = "LOW"
    result.vulnerable = false
    result.detail = "DNS resolver appears properly configured - no amplification responses"
    return result
  end)
  if not ok then
    local result = stdnse.output_table()
    result.cve = "CVE-1999-0265"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
