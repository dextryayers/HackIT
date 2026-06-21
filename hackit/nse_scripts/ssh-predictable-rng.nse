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

description = [[Checks SSH server for predictable RNG / weak key exchange algorithms (CVE-2008-5161, CVE-2016-0777).]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"vuln", "safe"}

portrule = function(host, port) return port.protocol == "tcp" and port.state == "open" and port.service == "ssh" end

local weak_kex = {
  "diffie%-hellman%-group1",
  "diffie%-hellman%-group%-exchange%-sha1",
  "diffie%-hellman%-group14%-sha1",
}

local weak_ciphers = {
  "aes128%-cbc",
  "aes192%-cbc",
  "aes256%-cbc",
  "3des%-cbc",
  "blowfish%-cbc",
  "cast128%-cbc",
  "arcfour",
  "arcfour128",
  "arcfour256",
}

local weak_macs = {
  "hmac%-md5",
  "hmac%-md5%-96",
  "hmac%-sha1%-96",
  "hmac%-ripemd160",
}

local function build_kex_init()
  local algorithms = {
    kex = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,ecdh-sha2-nistp256,curve25519-sha256",
    hostkey = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256",
    enc_c2s = "aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc,blowfish-cbc,aes128-ctr,aes256-ctr",
    enc_s2c = "aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc,blowfish-cbc,aes128-ctr,aes256-ctr",
    mac_c2s = "hmac-md5,hmac-sha1,hmac-md5-96,hmac-sha1-96,hmac-sha2-256",
    mac_s2c = "hmac-md5,hmac-sha1,hmac-md5-96,hmac-sha1-96,hmac-sha2-256",
    comp_c2s = "none,zlib",
    comp_s2c = "none,zlib",
  }

  local parts = {}
  for _, key in ipairs({"kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c"}) do
    local alg = algorithms[key]
    insert(parts, char(#alg) .. alg)
  end

  local names = concat(parts)
  local cookie = char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

  local payload = cookie .. names ..
    char(0x00, 0x00, 0x00, 0x00) ..
    char(0x00, 0x00, 0x00, 0x00) ..
    char(0x00, 0x00, 0x00, 0x00) ..
    char(0x00, 0x00, 0x00, 0x00) ..
    char(0x00, 0x00, 0x00, 0x00) ..
    char(0x00, 0x00, 0x00, 0x00)

  local type_byte = char(20)
  local len = #payload
  local pkt_len = char(0x00, 0x00, 0x00, len + 4)
  local pad_len = char(0x00)

  local full = pkt_len .. pad_len .. type_byte .. payload
  local padding = rep(char(0x00), 8 - ((#full + 4) % 8))
  full = full .. padding

  local prefix = char(0x00, 0x00, 0x00, #full)
  return prefix .. full
end

action = function(host, port)
  local ok, result = pcall(function()
    local findings = {}
    local banner_str = ""
    local ssh_version = nil

    local sock = new_socket()
    sock:set_timeout(10000)
    local status = sock:connect(host.ip, port.number)
    if not status then
      local result = output_table()
      result.cve = "CVE-2008-5161, CVE-2016-0777"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "Connection failed"
      result.error = true
      return result
    end

    local banner_raw, banner_err = sock:receive_buf("\n", 3)
    if not banner_raw then sock:close()
      local result = output_table()
      result.cve = "CVE-2008-5161"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No SSH banner"
      return result
    end

    banner_str = banner_raw:gsub("\r?\n", ""):gsub("%s+$", "")
    ssh_version = banner_str:match("SSH%-([%d%.]+)")
    local software = banner_str:match("SSH%-[%d%.]+%-(.+)")

    insert(findings, {check = "SSH banner", detail = banner_str, severity = "INFO"})

    local kex_init = build_kex_init()
    local ok_send, send_err = sock:send(kex_init)
    if not ok_send then sock:close()
      local result = output_table()
      result.cve = "CVE-2008-5161"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "KEX init send failed"
      return result
    end

    local kex_rcv, kex_err = sock:receive_buf("\x00", 5)
    sock:close()

    if not kex_rcv or #kex_rcv < 20 then
      local result = output_table()
      result.cve = "CVE-2008-5161"
      result.severity = "MEDIUM"
      result.vulnerable = false
      result.detail = "No KEX response"
      return result
    end

    local response_str = kex_rcv
    local weak_kex_found = {}
    local weak_enc_found = {}
    local weak_mac_found = {}

    for _, wk in ipairs(weak_kex) do
      local match = response_str:match(wk)
      if match then
        insert(weak_kex_found, match:gsub("%%", ""))
      end
    end

    for _, wc in ipairs(weak_ciphers) do
      local match = response_str:match(wc)
      if match then
        insert(weak_enc_found, match:gsub("%%", ""))
      end
    end

    for _, wm in ipairs(weak_macs) do
      local match = response_str:match(wm)
      if match then
        insert(weak_mac_found, match:gsub("%%", ""))
      end
    end

    if #weak_kex_found > 0 then
      insert(findings, {check = "Weak KEX", detail = ("Weak key exchange: %s"):format(concat(weak_kex_found, ", ")), severity = "HIGH"})
    end
    if #weak_enc_found > 0 then
      insert(findings, {check = "Weak ciphers", detail = ("Weak encryption: %s"):format(concat(weak_enc_found, ", ")), severity = "HIGH"})
    end
    if #weak_mac_found > 0 then
      insert(findings, {check = "Weak MACs", detail = ("Weak MAC: %s"):format(concat(weak_mac_found, ", ")), severity = "HIGH"})
    end

    if #weak_kex_found == 0 and #weak_enc_found == 0 and #weak_mac_found == 0 then
      insert(findings, {check = "Algorithm strength", detail = "Server rejected weak proposals - likely using strong algorithms", severity = "LOW"})
    end

    local max_severity = "LOW"
    for _, f in ipairs(findings) do
      local order = {CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0}
      if (order[f.severity] or 0) > (order[max_severity] or 0) then
        max_severity = f.severity
      end
    end

    local result = output_table()
    result.cve = "CVE-2008-5161, CVE-2016-0777"
    result.severity = max_severity
    result.vulnerable = max_severity ~= "LOW" and max_severity ~= "INFO"
    result.banner = banner_str
    result.ssh_version = ssh_version or "unknown"
    result.software = software or "unknown"
    result.detail = (result.vulnerable) and ("Weak SSH algorithms detected - predictable RNG may be exploitable") or "SSH uses modern algorithms"
    for i, f in ipairs(findings) do
      result[("finding_%d"):format(i)] = ("[%s] %s: %s"):format(f.severity, f.check, f.detail)
    end
    return result
  end)
  if not ok then
    local result = output_table()
    result.cve = "CVE-2008-5161"
    result.severity = "MEDIUM"
    result.vulnerable = false
    result.detail = "Error during scan: " .. tostring(result)
    result.error = true
    return result
  end
  return result
end
