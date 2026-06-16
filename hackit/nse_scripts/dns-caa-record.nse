local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

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
  local result = stdnse.output_table()
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

      records[#records + 1] = entry
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
