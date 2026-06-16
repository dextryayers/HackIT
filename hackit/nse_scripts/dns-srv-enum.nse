local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

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
  local result = stdnse.output_table()
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

        found_services[#found_services + 1] = entry
      end
    end
  end

  table.sort(found_services, function(a, b) return a.service < b.service end)

  result.status = "success"
  result.server = host.ip .. ":" .. port.number
  result.domain = (domain ~= "") and domain or "(root zone)"

  if #found_services > 0 then
    result.services_found = #found_services
    result.services = found_services

    local categories = {}
    for _, s in ipairs(found_services) do
      local cat = "other"
      if s.service:match("_sip") or s.service:match("_xmpp") or s.service:match("_stun") then
        cat = "communication"
      elseif s.service:match("_ldap") or s.service:match("_kerberos") then
        cat = "authentication"
      elseif s.service:match("_imap") or s.service:match("_pop3") or s.service:match("_smtp") or s.service:match("_submission") then
        cat = "mail"
      elseif s.service:match("_mysql") or s.service:match("_postgresql") or s.service:match("_mongodb") or s.service:match("_redis") or s.service:match("_elastic") or s.service:match("_memcache") then
        cat = "database"
      elseif s.service:match("_http") or s.service:match("_https") then
        cat = "web"
      elseif s.service:match("_docker") or s.service:match("_etcd") or s.service:match("_consul") or s.service:match("_vault") or s.service:match("_prometheus") or s.service:match("_grafana") or s.service:match("_jenkins") then
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
