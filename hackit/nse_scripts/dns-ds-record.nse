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
Retrieves and analyzes Delegation Signer (DS) records for the target domain to
validate the DNSSEC chain of trust. DS records are published in the parent zone (e.g.,
.com for example.com) and link to the child zone's DNSKEY records. Each DS record
contains a key tag (identifying the child's KSK), algorithm number, digest type, and
cryptographic digest. The script verifies DS consistency by attempting to match DS
records with DNSKEY records in the child zone, checks algorithm strength, identifies
digest algorithm deprecations (SHA-1 is being phased out), and reports the overall
DNSSEC delegation status. Essential for troubleshooting DNSSEC validation failures.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local algorithm_names = {
  [3] = "DSA/SHA-1", [5] = "RSA/SHA-1", [7] = "RSASHA1-NSEC3",
  [8] = "RSA/SHA-256", [10] = "RSA/SHA-512",
  [12] = "ECC-GOST", [13] = "ECDSA/P-256",
  [14] = "ECDSA/P-384", [15] = "Ed25519", [16] = "Ed448"
}

local digest_names = {
  [0] = "Reserved",
  [1] = "SHA-1",
  [2] = "SHA-256",
  [3] = "GOST R 34.11-94",
  [4] = "SHA-384"
}

local digest_strength = {
  [0] = "unknown", [1] = "weak", [2] = "strong",
  [3] = "moderate", [4] = "strong"
}

action = function(host, port)
  local result = output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "DS", timeout = 5000, retries = 2 }
  local ok, ds_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not ds_result or #ds_result == 0 then
    result.ds_records_found = false
    result.dnssec_delegation = "not_signed"
    result.reason = "No DS records found — DNSSEC may not be configured at parent zone"
    return result
  end

  local records = {}
  local has_weak_digest = false
  local algorithms_used = {}

  for _, record in ipairs(ds_result) do
    local key_tag = record.key_tag or "?"
    local algorithm = tonumber(record.algorithm) or 0
    local digest_type = tonumber(record.digest_type) or 0
    local digest = record.digest or ""

    local digest_hex = digest
    if type(digest) ~= "string" then
      digest_hex = format("%x", digest)
    end

    local algo_name = algorithm_names[algorithm] or ("Unknown (" .. algorithm .. ")")
    local digest_name = digest_names[digest_type] or ("Unknown (" .. digest_type .. ")")
    local strength = digest_strength[digest_type] or "unknown"

    if strength == "weak" then
      has_weak_digest = true
    end

    algorithms_used[algo_name] = (algorithms_used[algo_name] or 0) + 1

    insert(records, {
      key_tag = tostring(key_tag),
      algorithm_number = algorithm,
      algorithm_name = algo_name,
      digest_type = digest_type,
      digest_name = digest_name,
      digest_strength = strength,
      digest = digest_hex
    })
  end

  result.ds_records_found = true
  result.total_ds_records = #records
  result.records = records

  local dnskey_opts = { host = host.ip, dtype = "DNSKEY", timeout = 5000 }
  local dk_ok, dnskey_result = pcall(dns.query, domain, dnskey_opts)
  if dk_ok and dnskey_result and #dnskey_result > 0 then
    local matching = {}
    for _, ds in ipairs(records) do
      for _, dk in ipairs(dnskey_result) do
        if tonumber(ds.key_tag) == tonumber(dk.key_tag) then
          insert(matching, {
            ds_key_tag = ds.key_tag,
            dnskey_key_tag = dk.key_tag,
            match = true
          })
          break
        end
      end
    end

    if #matching > 0 then
      result.matching_dnskey_records = #matching
      result.dnssec_chain_status = "DS records match child DNSKEY records"
      result.dnssec_delegation = "valid"
    else
      result.matching_dnskey_records = 0
      result.dnssec_chain_status = "No matching DNSKEY records found — DNSSEC chain may be broken"
      result.dnssec_delegation = "invalid"
    end
  end

  result.uses_weak_digest = has_weak_digest

  if has_weak_digest then
    result.recommendation = "Migrate from SHA-1 (digest type 1) to SHA-256 (digest type 2) for DS records"
  end

  return result
end
