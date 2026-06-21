local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"



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

description = [[
Retrieves and analyzes RRSIG (Resource Record Signature) records for the target domain
to assess DNSSEC signature configuration and health. RRSIG records contain
cryptographic signatures for each DNS record set in a DNSSEC-signed zone. The script
extracts detailed metadata for each signature: type covered (which record type is
signed), algorithm, key tag (identifying the signing key), original TTL, signature
inception and expiration times, signer name, and signature validity period. Each
signature is checked against the current time to determine if it is valid or expired.
Reports signature coverage gaps, identifies algorithms in use, and detects expired
signatures that would cause DNSSEC validation failures.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local algorithm_names = {
  [3] = "DSA", [5] = "RSA/SHA-1", [7] = "RSASHA1-NSEC3",
  [8] = "RSA/SHA-256", [10] = "RSA/SHA-512",
  [12] = "ECC-GOST", [13] = "ECDSA/P-256",
  [14] = "ECDSA/P-384", [15] = "Ed25519", [16] = "Ed448"
}

action = function(host, port)
  local result = output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "RRSIG", timeout = 5000, retries = 2 }
  local ok, rrsig_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not rrsig_result or #rrsig_result == 0 then
    result.rrsig_records_found = false
    result.reason = "No RRSIG records found — zone may not be DNSSEC-signed"
    return result
  end

  local signatures = {}
  local now = os.time()
  local expired_count = 0
  local valid_count = 0
  local types_covered = {}
  local algorithms_used = {}

  for _, record in ipairs(rrsig_result) do
    local type_covered = record.type_covered or "?"
    local algorithm = tonumber(record.algorithm) or 0
    local labels = tonumber(record.labels) or 0
    local orig_ttl = tonumber(record.orig_ttl) or 0
    local sig_exp = tonumber(record.sig_exp or record.expiration) or 0
    local sig_inc = tonumber(record.sig_inc or record.inception) or 0
    local key_tag = tonumber(record.key_tag) or 0
    local signer = (record.signer or "?"):gsub("%.$", "")
    local sig_data = record.signature or ""

    local sig_str
    if type(sig_data) == "string" then
      sig_str = nmap.base64 and nmap.base64(sig_data) or sub(sig_data, 1, 20)
    else
      sig_str = tostring(sig_data)
    end

    local signature_validity = "valid"
    if now > sig_exp then
      signature_validity = "expired"
      expired_count = expired_count + 1
    elseif now < sig_inc then
      signature_validity = "not_yet_valid"
      expired_count = expired_count + 1
    else
      valid_count = valid_count + 1
    end

    types_covered[type_covered] = (types_covered[type_covered] or 0) + 1
    algorithms_used[algorithm] = (algorithms_used[algorithm] or 0) + 1

    local sig_entry = {
      type_covered = tostring(type_covered),
      algorithm = algorithm,
      algorithm_name = algorithm_names[algorithm] or ("Unknown (" .. algorithm .. ")"),
      labels = labels,
      original_ttl = orig_ttl,
      key_tag = key_tag,
      signer = signer,
      inception = os.date("%Y-%m-%d %H:%M:%S", sig_inc),
      expiration = os.date("%Y-%m-%d %H:%M:%S", sig_exp),
      validity_days = format("%.1f", (sig_exp - sig_inc) / 86400),
      status = signature_validity,
      signature_preview = sig_str and (sub(sig_str, 1, 40) .. "...") or "N/A"
    }

    insert(signatures, sig_entry)
  end

  result.rrsig_records_found = true
  result.total_signatures = #signatures
  result.signatures = signatures
  result.valid_count = valid_count
  result.expired_count = expired_count

  local algo_names_used = {}
  for algo_num, count in pairs(algorithms_used) do
    local name = algorithm_names[algo_num] or ("Unknown-" .. algo_num)
    algo_names_used[name] = count
  end
  result.algorithms_used = algo_names_used
  result.signature_coverage = types_covered

  if expired_count > 0 then
    result.has_expired_signatures = true
    result.expired_risk = "DNSSEC validation will fail for " .. expired_count .. " signature(s)"
    result.health_status = "degraded"
  else
    result.has_expired_signatures = false
    result.health_status = "healthy"
  end

  result.signature_validity_summary = {
    total = #signatures,
    valid = valid_count,
    expired = expired_count,
    valid_percentage = format("%.1f%%", (valid_count / #signatures) * 100)
  }

  return result
end
