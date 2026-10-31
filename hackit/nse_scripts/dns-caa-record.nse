local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"



-- Fast-path bindings for the stdlib and nmap API used by this script.
-- Kept strict-mode safe: every name below is a declared local.
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
local move = table.move
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select

local clock = nmap.clock
local msleep = function(ms)
    if stdnse and stdnse.sleep then
        return stdnse.sleep((ms or 0) / 1000)
    end
    if nmap.msleep then
        return nmap.msleep(ms or 0)
    end
    local deadline = nmap.clock() + (ms or 0) / 1000
    while nmap.clock() < deadline do end
    return true
end
local new_socket = nmap.new_socket
local resolve = nmap.resolve

-- stdnse.sleep / stdnse.strsplit are not present in every NSE runtime.
local sleep = function(seconds)
    if stdnse and stdnse.sleep then
        return stdnse.sleep(seconds)
    end
    if nmap.msleep then
        return nmap.msleep(math.max(0, math.floor((seconds or 0) * 1000)))
    end
    local deadline = nmap.clock() + (seconds or 0)
    while nmap.clock() < deadline do end
    return true
end

local strsplit = function(sep, str, max)
    local out, pos, n = {}, 1, 0
    if str == nil then return out end
    while true do
        if max and n >= max - 1 then
            out[#out + 1] = sub(str, pos)
            return out
        end
        local s, e = find(str, sep, pos)
        if not s then
            out[#out + 1] = sub(str, pos)
            return out
        end
        if e < pos then e = pos end
        out[#out + 1] = sub(str, pos, s - 1)
        pos = e + 1
        n = n + 1
        if pos > #str then
            out[#out + 1] = ""
            return out
        end
    end
end

local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[
Retrieves and analyzes DNS Certification Authority Authorization (CAA) records for the
target domain. CAA records (RFC 6844) specify which Certificate Authorities (CAs) are
permitted to issue SSL/TLS certificates for the domain. This security mechanism helps
prevent unauthorized certificate issuance by rogue or compromised CAs. The script
queries for CAA records and identifies three property tags: "issue" (permits specific
CA to issue certificates), "issuewild" (controls wildcard certificate issuance), and
"iodef" (specifies reporting URI for CAA violation reports). Analyzes the critical
flag to identify mandatory properties that must be enforced. Reports compliance with
CAA best practices.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

action = function(host, port)
  local result = output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "CAA", timeout = 5000, retries = 2 }

  local ok, caa_result = pcall(dns.query, domain, opts)
  if not ok then
    local ok2, caa_result2 = pcall(dns.query, domain, {
      host = host.ip, port = port.number, dtype = "CAA", timeout = 8000, retries = 1
    })
    if not ok2 then
      result.status = "success"
      result.domain = domain
      result.caa_records_found = false
      result.reason = "CAA query failed (server may not support CAA)"
      return result
    end
    caa_result = caa_result2
  end

  result.status = "success"
  result.domain = domain
  result.server = host.ip

  if caa_result and #caa_result > 0 then
    result.caa_records_found = true
    result.total_records = #caa_result

    local records = {}
    local has_issue = false
    local has_issuewild = false
    local has_iodef = false
    local critical_properties = 0

    for _, record in ipairs(caa_result) do
      local entry = {
        flags = record.flags or 0,
        tag = record.tag or "?",
        value = record.value or tostring(record)
      }

      if entry.tag == "issue" then has_issue = true end
      if entry.tag == "issuewild" then has_issuewild = true end
      if entry.tag == "iodef" then has_iodef = true end
      if entry.flags and entry.flags & 0x80 ~= 0 then
        critical_properties = critical_properties + 1
        entry.critical = true
      end

      insert(records, entry)
    end

    result.records = records
    result.caa_analysis = {}
    result.caa_analysis.permitted_cas = {}
    result.caa_analysis.wildcard_restricted = has_issuewild
    result.caa_analysis.violation_reporting = has_iodef

    for _, r in ipairs(records) do
      if r.tag == "issue" then
        result.caa_analysis.permitted_cas[#result.caa_analysis.permitted_cas + 1] = r.value
      end
    end

    result.caa_analysis.critical_properties = critical_properties

    if not has_issue then
      result.caa_analysis.note = "No 'issue' tag — ANY Certificate Authority can issue certificates for this domain"
    end

    if has_issuewild then
      result.caa_analysis.wildcard_note = "Wildcard certificate issuance is explicitly restricted"
    end
  else
    result.caa_records_found = false
    result.reason = "No CAA records found — any CA may issue certificates for this domain"
    result.caa_analysis = {
      permitted_cas = {},
      wildcard_restricted = false,
      violation_reporting = false,
      note = "CAA not configured. Consider adding CAA records to prevent unauthorized certificate issuance."
    }
  end

  return result
end
