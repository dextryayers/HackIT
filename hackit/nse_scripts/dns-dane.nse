local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Checks DANE (DNS-based Authentication of Named Entities) TLSA records for the target
domain and common service ports. DANE (RFC 6698) allows TLS certificate validation
to be performed via DNS, reducing dependency on external Certificate Authorities
(CAs). The script queries for TLSA records on common service ports (443, 25, 465,
993, 995, 143, 110, 587, 5222, 8443, 636, 389) and analyzes the four TLSA fields:
usage (how the certificate is associated with the domain), selector (which part of
the certificate is used), matching type (how the certificate data is presented),
and certificate data. Classifies each record's security level from PKIX-CA
(dependent on CAs) to DANE-EE (self-signed but secure via DNS trust).
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local usage_names = {
  [0] = { name = "PKIX-TA", desc = "CA constraint", ca_reliant = true },
  [1] = { name = "PKIX-EE", desc = "Service certificate constraint", ca_reliant = true },
  [2] = { name = "DANE-TA", desc = "Trust anchor assertion", ca_reliant = false },
  [3] = { name = "DANE-EE", desc = "Domain-issued certificate", ca_reliant = false }
}

local selector_names = {
  [0] = "Full certificate (Cert)",
  [1] = "SubjectPublicKeyInfo (SPKI)"
}

local match_names = {
  [0] = "Full data (Full)",
  [1] = "SHA-256 hash",
  [2] = "SHA-512 hash"
}

local service_ports = {443, 25, 465, 993, 995, 143, 110, 587, 5222, 8443, 636, 389}

action = function(host, port)
  local result = stdnse.output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local found = {}

  for _, svc_port in ipairs(service_ports) do
    local qname = "_" .. svc_port .. "._tcp." .. domain
    local opts = {
      host = host.ip,
      port = host.number or 53,
      dtype = "TLSA",
      timeout = 5000,
      retries = 1
    }

    local ok, tlsa_result = pcall(dns.query, qname, opts)
    if ok and tlsa_result and #tlsa_result > 0 then
      for _, record in ipairs(tlsa_result) do
        local usage = tonumber(record.usage or record[1]) or 0
        local selector = tonumber(record.selector or record[2]) or 0
        local match_type = tonumber(record.match_type or record[3]) or 0
        local cert_data = record.cert_data or record[4] or record.data or ""

        local usage_info = usage_names[usage] or { name = "Unknown (" .. usage .. ")", ca_reliant = nil }
        local cert_str
        if type(cert_data) == "string" then
          cert_str = nmap.base64 and nmap.base64(cert_data) or cert_data
        else
          cert_str = tostring(cert_data)
        end
        if cert_str and #cert_str > 50 then
          cert_str = string.sub(cert_str, 1, 50) .. "..."
        end

        found[#found + 1] = {
          service_port = svc_port,
          query = qname,
          usage = usage,
          usage_name = usage_info.name,
          usage_description = usage_info.desc,
          ca_reliant = usage_info.ca_reliant,
          selector = selector,
          selector_name = selector_names[selector] or ("Unknown (" .. selector .. ")"),
          match_type = match_type,
          match_name = match_names[match_type] or ("Unknown (" .. match_type .. ")"),
          certificate_data = cert_str
        }
      end
    end
  end

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number
  result.ports_checked = #service_ports

  if #found > 0 then
    result.tlsa_records_found = #found
    result.records = found

    local ports_with_dane = {}
    for _, f in ipairs(found) do
      ports_with_dane[f.service_port] = (ports_with_dane[f.service_port] or 0) + 1
    end
    result.ports_with_tlsa = {}
    for p, _ in pairs(ports_with_dane) do
      result.ports_with_tlsa[#result.ports_with_tlsa + 1] = p
    end
    table.sort(result.ports_with_tlsa)

    local has_ca_independent = false
    local all_ca_reliant = true
    for _, f in ipairs(found) do
      if f.ca_reliant == false then
        has_ca_independent = true
        all_ca_reliant = false
      elseif f.ca_reliant == true then
      end
    end

    if has_ca_independent then
      result.dane_type = "CA-independent (DANE-TA or DANE-EE)"
      result.ca_independent_records = true
    else
      result.dane_type = "CA-dependent (PKIX-TA or PKIX-EE)"
      result.ca_independent_records = false
    end

    local has_dane_ee = false
    for _, f in ipairs(found) do
      if f.usage == 3 then
        has_dane_ee = true
        break
      end
    end
    result.dane_ee_present = has_dane_ee
  else
    result.tlsa_records_found = 0
    result.dane_type = "not_configured"
    result.reason = "No DANE TLSA records found for any common service port"
    result.recommendation = "Consider deploying DANE to enable DNSSEC-based TLS certificate validation"
  end

  return result
end
