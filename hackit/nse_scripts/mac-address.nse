local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"



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
Resolves the MAC address associated with the target IP address on the local network.
Uses multiple methods: first attempts a direct ARP query via the kernel, falls back
to reading the local ARP cache (/proc/net/arp on Linux), and finally sends proactive
ARP probes to populate the cache. Returns MAC address, interface name, vendor/OUI
lookup, cache source, and cache entry type. Helps identify devices on the local
subnet and map IP-to-MAC relationships for network inventory.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local function read_arp_cache(target_ip)
  local f = io.open("/proc/net/arp", "r")
  if not f then return nil end
  local content = f:read("*a")
  f:close()

  for line in gmatch(content, "[^\r\n]+") do
    if find(line, target_ip) then
      local fields = strsplit(" ", line)
      if #fields >= 4 and fields[3] and fields[3] ~= "00:00:00:00:00:00" and fields[2] == "0x1" then
        return {
          mac = fields[3]:upper(),
          hw_type = fields[2],
          flags = fields[4]
        }
      end
    end
  end
  return nil
end

local function probe_arp_retry(target_ip, retries)
  for i = 1, retries do
    local reply = nmap.arp_query(target_ip, target_ip)
    if reply and reply.mac_addr then
      return reply
    end
    msleep(200)
  end
  return nil
end

local function oui_lookup(mac)
  local oui = match(mac, "^([%x][%x]:[%x][%x]:[%x][%x])")
  if not oui then return nil end
  local oui_db = {
    ["00:00:0C"] = "Cisco", ["00:1A:A0"] = "Dell", ["00:1B:21"] = "HP",
    ["00:1E:68"] = "Dell", ["00:21:5A"] = "HP", ["00:21:6C"] = "Intel",
    ["00:21:CC"] = "Cisco", ["00:23:AE"] = "VMware", ["00:24:D6"] = "Dell",
    ["00:25:90"] = "HP", ["00:26:55"] = "Dell", ["00:26:B9"] = "Cisco",
    ["00:50:56"] = "VMware", ["00:05:69"] = "VMware", ["00:0C:29"] = "VMware",
    ["00:15:5D"] = "Microsoft", ["00:03:FF"] = "Microsoft",
    ["52:54:00"] = "QEMU/KVM", ["08:00:27"] = "Oracle VM",
    ["00:1A:4B"] = "Samsung", ["00:1A:11"] = "Apple", ["00:1B:63"] = "Apple",
    ["00:1E:C2"] = "Apple", ["00:1F:F3"] = "Apple", ["00:23:32"] = "Apple",
    ["00:25:00"] = "Apple", ["00:25:BC"] = "Apple", ["00:26:08"] = "Apple",
    ["00:26:B0"] = "Apple", ["F8:1E:DF"] = "Apple", ["A8:20:66"] = "Apple",
    ["14:7D:DA"] = "Apple", ["10:40:F3"] = "Apple", ["04:0C:CE"] = "Apple",
    ["B8:E8:56"] = "Apple", ["8C:85:90"] = "Apple", ["98:01:A7"] = "Apple",
    ["34:36:3B"] = "Apple", ["3C:22:FB"] = "Dell", ["F0:1F:AF"] = "Dell",
    ["18:66:DA"] = "Dell", ["B8:CA:3A"] = "Dell", ["CC:2D:8C"] = "Dell",
    ["3C:D9:2B"] = "HP", ["E0:07:1B"] = "HP", ["A0:D3:C1"] = "HP",
    ["D0:67:E5"] = "ASUS", ["DC:85:DE"] = "ASUS",
    ["E0:3F:49"] = "Intel", ["F4:8E:38"] = "Intel",
    ["30:05:5C"] = "Raspberry Pi", ["B8:27:EB"] = "Raspberry Pi",
    ["DC:A6:32"] = "Raspberry Pi"
  }
  return oui_db[upper(oui)] or nil
end

action = function(host, port)
  local result = output_table()

  local reply = probe_arp_retry(host.ip, 3)
  if reply and reply.mac_addr then
    local mac = reply.upper(mac_addr)
    result.status = "success"
    result.ip = host.ip
    result.mac = mac
    result.interface = reply.interface or "unknown"
    result.vendor = reply.vendor or oui_lookup(mac) or "Unknown"
    result.source = "direct ARP query"
    result.type = "dynamic"
    return result
  end

  local cache_entry = read_arp_cache(host.ip)
  if cache_entry then
    result.status = "success"
    result.ip = host.ip
    result.mac = cache_entry.mac
    result.interface = "from /proc/net/arp"
    result.vendor = oui_lookup(cache_entry.mac) or "Unknown"
    result.source = "ARP cache"
    result.type = (cache_entry.flags == "0x2") and "dynamic" or "static"
    return result
  end

  result.status = "unresolved"
  result.ip = host.ip
  result.reason = "Could not resolve MAC address. Host may not be on local subnet."
  return result
end
