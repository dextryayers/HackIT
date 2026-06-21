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
Retrieves and analyzes Child DNSKEY (CDNSKEY) records from the target domain. CDNSKEY
records (RFC 7344, RFC 8078) are published by the child zone to signal desired DNSKEY
changes to the parent zone, enabling automated DNSSEC key rollover. These records
mirror the format of DNSKEY records — containing flags, protocol, algorithm, and
public key data — and indicate the child's intent to update keys in the parent zone.
The script identifies key types (KSK/ZSK), extracts algorithm details, and compares
with existing DNSKEY records to assess rollover synchronization. Useful for
evaluating DNSSEC automation and key lifecycle management.
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

  local opts = { host = host.ip, port = port.number, dtype = "CDNSKEY", timeout = 5000, retries = 2 }
  local ok, cdnskey_result = pcall(dns.query, domain, opts)

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if not ok or not cdnskey_result or #cdnskey_result == 0 then
    result.cdnskey_records_found = false
    result.automated_key_rollover = "not_advertised"
    result.reason = "No CDNSKEY records found — automated key rollover not advertised"
    return result
  end

  local records = {}
  for _, record in ipairs(cdnskey_result) do
    local flags = tonumber(record.flags) or 256
    local protocol = tonumber(record.protocol) or 3
    local algorithm = tonumber(record.algorithm) or 0
    local public_key = record.public_key or record.key or ""

    local key_type = "ZSK"
    if flags == 257 then key_type = "KSK" end

    local algo_name = algorithm_names[algorithm] or ("Unknown (" .. algorithm .. ")")
    local algo_id = tostring(algorithm)

    local pk_str
    if type(public_key) == "string" then
      pk_str = nmap.base64 and nmap.base64(public_key) or public_key
    else
      pk_str = stdnse.tojson(public_key)
    end
    if pk_str and #pk_str > 60 then
      pk_str = sub(pk_str, 1, 60) .. "..."
    end

    insert(records, {)
      key_type = key_type,
      flags = flags,
      protocol = protocol,
      algorithm = algorithm,
      algorithm_name = algo_name,
      public_key_preview = pk_str or "N/A"
    }
  end

  result.cdnskey_records_found = true
  result.total_cdnskey_records = #records
  result.records = records
  result.automated_key_rollover = "advertised"
  result.rfc_7344_support = true

  local ksk_count = 0
  local zsk_count = 0
  for _, r in ipairs(records) do
    if r.key_type == "KSK" then ksk_count = ksk_count + 1
    else zsk_count = zsk_count + 1 end
  end
  result.ksk_count = ksk_count
  result.zsk_count = zsk_count

  local dnskey_opts = { host = host.ip, dtype = "DNSKEY", timeout = 5000 }
  local dk_ok, dnskey_result = pcall(dns.query, domain, dnskey_opts)

  if dk_ok and dnskey_result and #dnskey_result > 0 then
    local same_as_current = true
    for _, cdnskey in ipairs(records) do
      local found_match = false
      for _, dnskey in ipairs(dnskey_result) do
        if tonumber(cdnskey.flags) == tonumber(dnskey.flags) and
           tonumber(cdnskey.algorithm) == tonumber(dnskey.algorithm) then
          found_match = true
          break
        end
      end
      if not found_match then
        same_as_current = false
        break
      end
    end

    result.same_as_current_dnskey = same_as_current
    if same_as_current then
      result.rollover_status = "stable (CDNSKEY matches current DNSKEY)"
    else
      result.rollover_status = "pending (CDNSKEY differs from current DNSKEY — key rollover in progress)"
    end
  end

  return result
end
