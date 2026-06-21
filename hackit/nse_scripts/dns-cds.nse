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
Retrieves and analyzes Child DS (CDS) records from the target domain. CDS records
(RFC 8078, RFC 7344) are published by the child zone to signal desired DS record
changes to the parent zone, enabling automated DNSSEC key rollover without manual
parent zone updates. The presence of CDS records indicates the child zone supports
automated DNSSEC key management (CDS/CDNSKEY publish mechanism). The script analyzes
each CDS record's key tag, algorithm, digest type, and digest value, comparing them
with existing DS records and DNSKEY records to assess key rollover status. Useful
for evaluating DNSSEC automation maturity.
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
  [1] = "SHA-1", [2] = "SHA-256", [3] = "GOST R 34.11-94", [4] = "SHA-384"
}

action = function(host, port)
  local result = output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local opts = { host = host.ip, port = port.number, dtype = "CDS", timeout = 5000, retries = 2 }
  local ok, cds_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not cds_result or #cds_result == 0 then
    result.cds_records_found = false
    result.automated_key_management = "not_advertised"
    result.reason = "No CDS records found — automated DNSSEC key management not advertised"
    return result
  end

  local records = {}
  for _, record in ipairs(cds_result) do
    local key_tag = record.key_tag or 0
    local algorithm = tonumber(record.algorithm) or 0
    local digest_type = tonumber(record.digest_type) or 0
    local digest = record.digest or ""

    local digest_hex = digest
    if type(digest) ~= "string" then
      digest_hex = format("%x", digest)
    end
    if digest_hex and #digest_hex > 40 then
      digest_hex = sub(digest_hex, 1, 40) .. "..."
    end

    insert(records, {)
      key_tag = tonumber(key_tag),
      algorithm = algorithm,
      algorithm_name = algorithm_names[algorithm] or ("Unknown (" .. algorithm .. ")"),
      digest_type = digest_type,
      digest_name = digest_names[digest_type] or ("Unknown (" .. digest_type .. ")"),
      digest = digest_hex
    }
  end

  result.cds_records_found = true
  result.total_cds_records = #records
  result.records = records

  local dnskey_opts = { host = host.ip, dtype = "DNSKEY", timeout = 5000 }
  local dk_ok, dnskey_result = pcall(dns.query, domain, dnskey_opts)

  if dk_ok and dnskey_result and #dnskey_result > 0 then
    local matching_dnskey = {}
    for _, cds in ipairs(records) do
      for _, dk in ipairs(dnskey_result) do
        if cds.key_tag == tonumber(dk.key_tag) then
          insert(matching_dnskey, cds.key_tag)
          break
        end
      end
    end
    result.matching_dnskey_tags = matching_dnskey
    result.dnskey_reconciliation = (#matching_dnskey == #records) and "all_match" or "partial_match"
  end

  local ds_opts = { host = host.ip, dtype = "DS", timeout = 5000 }
  local ds_ok, ds_result = pcall(dns.query, domain, ds_opts)
  if ds_ok and ds_result then
    local cds_key_tags = {}
    for _, r in ipairs(records) do
      cds_key_tags[r.key_tag] = true
    end
    local ds_key_tags = {}
    for _, r in ipairs(ds_result) do
      ds_key_tags[tonumber(r.key_tag) or 0] = true
    end

    local same_as_current_ds = true
    for tag, _ in pairs(cds_key_tags) do
      if not ds_key_tags[tag] then
        same_as_current_ds = false
        break
      end
    end
    result.same_as_current_ds = same_as_current_ds

    if same_as_current_ds then
      result.rollover_status = "stable (CDS matches current DS)"
    else
      result.rollover_status = "pending (CDS differs from current DS — key rollover in progress)"
    end
  end

  result.automated_key_management = "advertised"
  result.rfc_8078_support = true
  result.recommendation = "Parent zone should process CDS/CDNSKEY records for automated key management"

  return result
end
