local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Enumerates domain controllers and Active Directory services on the target network by
querying DNS SRV records for common Active Directory and enterprise service types.
Queries include: _ldap._tcp (LDAP), _kerberos._tcp (KDC), _gc._tcp (Global Catalog),
_kpasswd._tcp (password change), and many others. Performs additional resolution
of discovered targets to IP addresses. Helps map domain infrastructure, identify
authentication services, and locate critical directory services in Windows Active
Directory environments. Supports custom domain suffixes and DNS server targeting.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local srv_services = {
  { name = "_ldap._tcp", desc = "LDAP (Active Directory)" },
  { name = "_kerberos._tcp", desc = "Kerberos (KDC)" },
  { name = "_gc._tcp", desc = "Global Catalog" },
  { name = "_kpasswd._tcp", desc = "Kerberos Password Change" },
  { name = "_ldap._udp", desc = "LDAP over UDP" },
  { name = "_kerberos._udp", desc = "Kerberos over UDP" },
  { name = "_ntp._udp", desc = "NTP Time Service" },
  { name = "_dns._tcp", desc = "DNS Service" },
  { name = "_msdcs", desc = "Microsoft Domain Controller" },
  { name = "_sites._tcp", desc = "Active Directory Sites" },
  { name = "_tcp._tcp", desc = "AD TCP services" },
  { name = "_udp._tcp", desc = "AD UDP services" },
  { name = "_autodiscover._tcp", desc = "Exchange Autodiscover" },
  { name = "_caldav._tcp", desc = "CalDAV Calendar" },
  { name = "_carddav._tcp", desc = "CardDAV Contacts" },
  { name = "_imap._tcp", desc = "IMAP Mail" },
  { name = "_pop3._tcp", desc = "POP3 Mail" },
  { name = "_smtp._tcp", desc = "SMTP Mail" },
  { name = "_certificates._tcp", desc = "Certificate Services" },
  { name = "_policies._tcp", desc = "Group Policies" }
}

local function safe_srv_query(query_name, opts)
  local ok, result = pcall(dns.query, query_name, opts)
  if not ok or not result then return nil end
  local entries = {}
  if type(result) == "table" then
    for _, record in ipairs(result) do
      if type(record) == "table" then
        entries[#entries + 1] = record
      else
        entries[#entries + 1] = { target = tostring(record) }
      end
    end
  end
  return #entries > 0 and entries or nil
end

action = function(host, port)
  local result = stdnse.output_table()
  local domain = host.targetname or ""
  local services = {}

  for _, svc in ipairs(srv_services) do
    local query_name = (domain and #domain > 0) and (svc.name .. "." .. domain) or svc.name
    local opts = {
      host = host.ip,
      port = port.number,
      dtype = "SRV",
      timeout = 5000,
      retries = 1
    }

    local records = safe_srv_query(query_name, opts)
    if records then
      for _, record in ipairs(records) do
        local entry = {
          service = svc.desc,
          query = query_name,
          target = record.target or tostring(record),
          port = record.port or 0,
          priority = record.priority or 0,
          weight = record.weight or 0
        }

        local a_opts = { host = host.ip, dtype = "A", timeout = 3000 }
        local a_ok, a_records = pcall(dns.query, entry.target, a_opts)
        if a_ok and a_records and #a_records > 0 then
          entry.ip_addresses = {}
          for _, v in ipairs(a_records) do
            entry.ip_addresses[#entry.ip_addresses + 1] = tostring(v)
          end
        end

        services[#services + 1] = entry
      end
    end
  end

  result.status = "success"
  result.server = host.ip
  result.domain = (domain ~= "") and domain or "(root zone)"
  result.port = port.number

  if #services > 0 then
    result.services_found = #services
    result.services = services

    local dc_count = 0
    for _, s in ipairs(services) do
      if s.service == "LDAP (Active Directory)" or s.service == "Global Catalog" or s.service == "Kerberos (KDC)" then
        dc_count = dc_count + 1
      end
    end
    result.domain_controllers_identified = dc_count
  else
    result.services_found = 0
    result.reason = "No domain controllers or AD services discovered"
  end

  return result
end
