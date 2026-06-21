

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

local category_map = {
  audit = "audit",
  bgp = "network",
  broadcast = "network",
  brute = "brute",
  cassandra = "info",
  clock = "ntp",
  cloud = "cloud",
  coap = "info",
  cockroachdb = "sql",
  couchdb = "info",
  db2 = "sql",
  dns = "dns",
  domain = "dns",
  elasticsearch = "info",
  fragmentation = "network",
  ftp = "ftp",
  graphql = "http",
  h323 = "network",
  host = "network",
  http = "http",
  influxdb = "info",
  info = "info",
  ip = "network",
  ipidseq = "network",
  ldap = "ldap",
  mac = "network",
  malware = "network",
  mariadb = "sql",
  memcached = "info",
  mongodb = "mongodb",
  mqtt = "info",
  ms = "sql",
  mtu = "network",
  mysql = "sql",
  neo4j = "info",
  network = "network",
  ntp = "ntp",
  null = "smb",
  oracle = "sql",
  postgresql = "sql",
  rdp = "network",
  redis = "redis",
  rest = "http",
  reverse = "dns",
  riak = "info",
  route = "network",
  rsync = "network",
  sip = "network",
  smb = "smb",
  smtp = "smtp",
  ssh = "ssh",
  ssl = "ssl",
  swagger = "http",
  tcp = "network",
  tftp = "network",
  traceroute = "network",
  ttl = "network",
  uptime = "info",
  vpn = "vpn",
  websocket = "http",
  winrm = "info",
  wmi = "info",
}

local category_map_mt = {
  __index = function(_, prefix)
    return "network"
  end,
  __newindex = function()
    error("category_map is read-only")
  end,
}

setmetatable(category_map, category_map_mt)

function category_map.get(script_name)
  local base = script_name:match("^(.+)%-")
  if not base then
    base = script_name
  end
  local cat = rawget(category_map, base)
  if cat then
    return cat
  end
  for prefix, mapped in pairs(category_map) do
    if type(prefix) == "string" and script_name:find("^" .. prefix .. "%-") then
      return mapped
    end
  end
  return "network"
end

function category_map.reverse()
  local by_cat = {}
  for prefix, cat in pairs(category_map) do
    if type(prefix) == "string" then
      by_cat[cat] = by_cat[cat] or {}
      insert(by_cat[cat], prefix)
    end
  end
  return by_cat
end

function category_map.categories()
  return {
    "audit", "brute", "cloud", "dns", "ftp", "http", "info",
    "ldap", "mongodb", "network", "ntp", "redis", "smb", "smtp",
    "sql", "ssh", "ssl", "vpn",
  }
end

return category_map
