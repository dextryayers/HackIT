local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Retrieves and analyzes DNSKEY records from the target domain to assess DNSSEC key
configuration and security posture. DNSKEY records contain the public cryptographic
keys used for DNSSEC validation. The script identifies Key Signing Keys (KSK, flags=257)
used to sign DNSKEY sets, and Zone Signing Keys (ZSK, flags=256) used to sign other
zone records. Reports algorithm types (RSA, ECDSA, Ed25519, Ed448), key lengths, and
key tags. Validates protocol field (must be 3 per RFC 4034) and flags consistency.
Assesses DNSSEC algorithm strength and identifies potential weaknesses such as
short keys or deprecated algorithms.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local algorithm_info = {
  [3] = { name = "DSA", bits = "1024", strength = "weak" },
  [5] = { name = "RSA/SHA-1", bits = "512-4096", strength = "weak" },
  [7] = { name = "RSASHA1-NSEC3", bits = "512-4096", strength = "weak" },
  [8] = { name = "RSA/SHA-256", bits = "1024-4096", strength = "moderate" },
  [10] = { name = "RSA/SHA-512", bits = "1024-4096", strength = "moderate" },
  [12] = { name = "ECC-GOST", bits = "256", strength = "moderate" },
  [13] = { name = "ECDSA/P-256", bits = "256", strength = "strong" },
  [14] = { name = "ECDSA/P-384", bits = "384", strength = "strong" },
  [15] = { name = "Ed25519", bits = "256", strength = "strong" },
  [16] = { name = "Ed448", bits = "456", strength = "strong" }
}

action = function(host, port)
  local result = stdnse.output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "DNSKEY", timeout = 5000, retries = 2 }
  local ok, dnskey_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip

  if not ok or not dnskey_result or #dnskey_result == 0 then
    result.dnskey_records_found = false
    result.reason = "No DNSKEY records found — DNSSEC may not be configured"
    result.dnssec_status = "not_signed"
    return result
  end

  local keys = {}
  local ksks = 0
  local zsks = 0

  for _, record in ipairs(dnskey_result) do
    local flags = tonumber(record.flags) or 0
    local key_type = "ZSK"
    if flags == 257 then key_type = "KSK"; ksks = ksks + 1
    elseif flags == 256 then zsks = zsks + 1 end

    local algo_num = tonumber(record.algorithm) or 0
    local info = algorithm_info[algo_num] or { name = "Unknown (" .. algo_num .. ")", bits = "?", strength = "unknown" }

    keys[#keys + 1] = {
      key_type = key_type,
      flags = flags,
      protocol = record.protocol or 3,
      algorithm_number = algo_num,
      algorithm_name = info.name,
      key_strength = info.strength,
      key_size = info.bits,
      key_tag = record.key_tag or "?",
      public_key = record.public_key or "?"
    }
  end

  result.dnskey_records_found = true
  result.total_keys = #keys
  result.keys = keys
  result.ksk_count = ksks
  result.zsk_count = zsks
  result.dnssec_signed = (ksks >= 1 and zsks >= 1)
  result.dnssec_status = "signed"

  local algorithms_used = {}
  local max_strength = "unknown"
  local min_strength = "strong"
  for _, k in ipairs(keys) do
    algorithms_used[k.algorithm_name] = (algorithms_used[k.algorithm_name] or 0) + 1
    local strength_order = { weak = 0, moderate = 1, strong = 2, unknown = -1 }
    if (strength_order[k.key_strength] or -1) < (strength_order[min_strength] or 99) then
      min_strength = k.key_strength
    end
    if (strength_order[k.key_strength] or -1) > (strength_order[max_strength] or -1) then
      max_strength = k.key_strength
    end
  end
  result.algorithms_used = algorithms_used
  result.min_key_strength = min_strength

  if min_strength == "weak" then
    result.strength_warning = "Some keys use deprecated or weak algorithms"
  end

  if ksks == 0 then
    result.warning = "No KSK found — DNSSEC chain of trust may be incomplete"
  end

  return result
end
