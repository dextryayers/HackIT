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
Enumerates DNS SRV (Service) records from the target DNS server for a comprehensive
set of common network services. SRV records define the location (hostname and port)
of specific services within a domain. The script queries for over 60 service types
covering communication (SIP, XMPP), directory (LDAP, Kerberos), mail (IMAP, POP3,
SMTP), web (HTTP, HTTPS), file transfer (FTP, SFTP), database (MySQL, PostgreSQL,
MongoDB, Redis), messaging (MQTT), and infrastructure (NTP, SNMP, syslog) protocols.
Results include resolved IP addresses and are sorted by service name. Essential for
mapping service infrastructure in enterprise environments.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local srv_services = {
  "_sip._tcp", "_sip._udp", "_sipfederationtls._tcp",
  "_xmpp-client._tcp", "_xmpp-server._tcp",
  "_ldap._tcp", "_ldap._udp",
  "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp",
  "_ntp._udp", "_ntp._tcp",
  "_http._tcp", "_https._tcp",
  "_imap._tcp", "_imaps._tcp",
  "_pop3._tcp", "_pop3s._tcp",
  "_smtp._tcp", "_submission._tcp",
  "_caldav._tcp", "_carddav._tcp",
  "_ftp._tcp", "_ssh._tcp", "_telnet._tcp",
  "_vnc._tcp", "_rdp._tcp",
  "_mysql._tcp", "_postgresql._tcp",
  "_mongodb._tcp", "_redis._tcp",
  "_elasticsearch._tcp", "_memcache._tcp",
  "_mqtt._tcp", "_stun._tcp", "_turn._tcp",
  "_tftp._udp", "_rsync._tcp",
  "_syslog._udp", "_snmp._udp",
  "_git._tcp", "_svn._tcp",
  "_puppet._tcp", "_chef._tcp",
  "_docker._tcp", "_etcd._tcp",
  "_consul._tcp", "_vault._tcp",
  "_prometheus._tcp", "_grafana._tcp",
  "_jenkins._tcp", "_sonarqube._tcp"
}

action = function(host, port)
  local result = output_table()
  local domain = host.targetname or ""
  local found_services = {}

  for _, service in ipairs(srv_services) do
    local query_name = (domain and #domain > 0) and (service .. "." .. domain) or service
    local opts = {
      host = host.ip,
      port = port.number,
      dtype = "SRV",
      timeout = 4000,
      retries = 1
    }

    local ok, answer = pcall(dns.query, query_name, opts)
    if ok and answer and #answer > 0 then
      for _, record in ipairs(answer) do
        local entry = {
          service = service,
          query = query_name,
          target = (record.target or tostring(record)):gsub("%.$", ""),
          port = record.port or 0,
          priority = record.priority or 0,
          weight = record.weight or 0
        }

        local a_ok, a_records = pcall(dns.query, entry.target, {
          host = host.ip, dtype = "A", timeout = 3000
        })
        if a_ok and a_records and #a_records > 0 then
          entry.ip_addresses = {}
          for _, v in ipairs(a_records) do
            entry.ip_addresses[#entry.ip_addresses + 1] = tostring(v)
          end
        end

        insert(found_services, entry)
      end
    end
  end

  sort(found_services, function(a, b) return a.service < b.service end)

  result.status = "success"
  result.server = host.ip .. ":" .. port.number
  result.domain = (domain ~= "") and domain or "(root zone)"

  if #found_services > 0 then
    result.services_found = #found_services
    result.services = found_services

    local categories = {}
    for _, s in ipairs(found_services) do
      local cat = "other"
      if s.match(service, "_sip") or s.match(service, "_xmpp") or s.match(service, "_stun") then
        cat = "communication"
      elseif s.match(service, "_ldap") or s.match(service, "_kerberos") then
        cat = "authentication"
      elseif s.match(service, "_imap") or s.match(service, "_pop3") or s.match(service, "_smtp") or s.match(service, "_submission") then
        cat = "mail"
      elseif s.match(service, "_mysql") or s.match(service, "_postgresql") or s.match(service, "_mongodb") or s.match(service, "_redis") or s.match(service, "_elastic") or s.match(service, "_memcache") then
        cat = "database"
      elseif s.match(service, "_http") or s.match(service, "_https") then
        cat = "web"
      elseif s.match(service, "_docker") or s.match(service, "_etcd") or s.match(service, "_consul") or s.match(service, "_vault") or s.match(service, "_prometheus") or s.match(service, "_grafana") or s.match(service, "_jenkins") then
        cat = "infrastructure"
      end
      if not categories[cat] then categories[cat] = {} end
      categories[cat][#categories[cat] + 1] = s.service
    end
    result.categories = categories
  else
    result.services_found = 0
    result.reason = "No SRV service records found"
  end

  return result
end
