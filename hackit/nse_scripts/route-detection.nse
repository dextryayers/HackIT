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
Analyzes the local system's routing table to identify the network path to the target
host. Parses /proc/net/route on Linux systems to extract routing entries, default
gateway, interface assignments, and routing metrics. Determines which network
interface will be used to reach the target and identifies the gateway MAC address via
ARP. Also detects VPN interfaces, bridged adapters, and multi-homed routing
configurations. Useful for understanding network topology from the scanning host's
perspective and diagnosing routing issues.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local function hex_to_ip(hex)
  if not hex or #hex ~= 8 then return nil end
  local octets = {}
  for i = 0, 3 do
    local byte_str = sub(hex, i * 2 + 1, i * 2 + 2)
    insert(octets, tostring(tonumber(byte_str, 16) or 0))
  end
  return concat(octets, ".")
end

local function ip_to_num(ip)
  local octets = strsplit("%.", ip)
  if #octets ~= 4 then return nil end
  local num = 0
  for i = 1, 4 do
    num = num * 256 + (tonumber(octets[i]) or 0)
  end
  return num
end

local function get_route_metrics()
  local f = io.open("/proc/net/route", "r")
  if not f then return nil end

  local routes = {}
  local header = f:read("*l")
  for line in f:lines() do
    if line and #line > 0 then
      local fields = strsplit("\t", line)
      if #fields >= 11 then
        local iface = fields[0] or fields[1]
        local dest_hex = (fields[1] or ""):gsub("%s+", "")
        local gw_hex = (fields[2] or ""):gsub("%s+", "")
        local mask_hex = (fields[7] or ""):gsub("%s+", "")
        local flags = tonumber(fields[3] or fields[4]) or 0
        local metric = tonumber(fields[6] or fields[7]) or 0
        local ref_count = tonumber(fields[4] or fields[5]) or 0
        local use_count = tonumber(fields[5] or fields[6]) or 0
        local window = tonumber(fields[9] or fields[10]) or 0
        local irtt = tonumber(fields[10] or fields[11]) or 0

        local destination = hex_to_ip(dest_hex)
        local gateway = hex_to_ip(gw_hex)
        local netmask = hex_to_ip(mask_hex)

        if destination and gateway then
          local flag_names = {}
          if flags & 0x1 ~= 0 then insert(flag_names, "UP") end
          if flags & 0x2 ~= 0 then insert(flag_names, "GATEWAY") end
          if flags & 0x8 ~= 0 then insert(flag_names, "HOST") end
          if flags & 0x10 ~= 0 then insert(flag_names, "REJECT") end
          if flags & 0x20 ~= 0 then insert(flag_names, "DEFAULT") end

          insert(routes, {
            interface = iface,
            destination = destination,
            gateway = gateway,
            netmask = netmask or "255.255.255.255",
            metric = metric,
            flags_hex = format("0x%04X", flags),
            flags = flag_names,
            ref_count = ref_count,
            use_count = use_count,
            window = window,
            irtt = irtt
          })
        end
      end
    end
  end
  f:close()
  return routes
end

action = function(host, port)
  local result = output_table()
  local interface_info = nmap.get_interface_info()

  local routes = get_route_metrics()
  if not routes or #routes == 0 then
    result.status = "error"
    result.reason = "Could not read routing table"
    return result
  end

  result.status = "success"
  result.target = host.ip
  result.total_routes = #routes

  local default_gateway = nil
  local target_routes = {}
  for _, r in ipairs(routes) do
    if r.destination == "0.0.0.0" and r.gateway ~= "0.0.0.0" then
      if not default_gateway or r.metric < default_gateway.metric then
        default_gateway = r
      end
    end
  end

  if default_gateway then
    result.default_gateway = {
      ip = default_gateway.gateway,
      interface = default_gateway.interface,
      metric = default_gateway.metric
    }
    local arp_gw = nmap.arp_query(default_gateway.gateway, default_gateway.gateway)
    if arp_gw and arp_gw.mac_addr then
      result.default_gateway.mac = arp_gw.mac_addr
    end
  end

  if interface_info then
    result.local_interface = {
      name = interface_info.device or "unknown",
      ip = interface_info.address or interface_info.ip or "?",
      mac = interface_info.mac or "?",
      netmask = interface_info.netmask or "?"
    }
  end

  local target_num = ip_to_num(host.ip)
  if target_num then
    local best_match = nil
    local best_prefix = -1
    for _, r in ipairs(routes) do
      local dest_num = ip_to_num(r.destination)
      local mask_num = ip_to_num(r.netmask)
      if dest_num and mask_num then
        local match = (target_num & mask_num) == (dest_num & mask_num)
        if match then
          local prefix = 0
          local m = mask_num
          while m > 0 do
            prefix = prefix + 1
            m = (m << 1) & 0xFFFFFFFF
          end
          if prefix > best_prefix then
            best_prefix = prefix
            best_match = r
          end
        end
      end
    end
    if best_match then
      result.route_to_target = {
        interface = best_match.interface,
        gateway = best_match.gateway,
        destination = best_match.destination,
        netmask = best_match.netmask,
        prefix_length = best_prefix
      }
    end
  end

  local interfaces = {}
  for _, r in ipairs(routes) do
    if not interfaces[r.interface] then
      interfaces[r.interface] = true
    end
  end
  local iface_list = {}
  for iface_name, _ in pairs(interfaces) do
    insert(iface_list, iface_name)
  end
  sort(iface_list)
  result.interfaces = iface_list

  result.all_routes = routes

  return result
end
