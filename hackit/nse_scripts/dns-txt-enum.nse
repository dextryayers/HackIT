local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Enumerates DNS TXT records from the target domain to extract configuration and
verification data. TXT records can hold arbitrary text and are commonly used for:
SPF (Sender Policy Framework) specifying authorized mail servers, DKIM (DomainKeys
Identified Mail) cryptographic keys for email signing, DMARC (Domain-based Message
Authentication, Reporting, and Conformance) policies, domain ownership verification
tokens, and various application-specific configurations. The script queries the root
domain and common DKIM selector names. Results are categorized by purpose (SPF,
DKIM, DMARC, ownership, general) for easy analysis.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

action = function(host, port)
  local result = stdnse.output_table()
  local domain = host.targetname

  if not domain or #domain == 0 then
    result.status = "error"
    result.reason = "No target domain name specified"
    return result
  end

  local txt_queries = {
    { name = domain, desc = "Root domain", category = "general" },
    { name = "_dmarc." .. domain, desc = "DMARC", category = "email_auth" },
    { name = "default._domainkey." .. domain, desc = "DKIM (default)", category = "dkim" },
    { name = "*._domainkey." .. domain, desc = "DKIM (wildcard)", category = "dkim" },
    { name = "selector1._domainkey." .. domain, desc = "DKIM selector1", category = "dkim" },
    { name = "selector2._domainkey." .. domain, desc = "DKIM selector2", category = "dkim" },
    { name = "_domainkey." .. domain, desc = "DKIM domain key", category = "dkim" },
    { name = "_spf." .. domain, desc = "SPF", category = "email_auth" },
    { name = "aspmx1." .. domain, desc = "SPF include", category = "email_auth" },
    { name = "_smtp._tls." .. domain, desc = "SMTP TLS (MTA-STS)", category = "email_security" }
  }

  local common_selectors = {
    "google", "mail", "smtp", "amazonses", "mandrill",
    "sendgrid", "sparkpost", "mailgun", "zoho", "outlook",
    "office365", "microsoft", "exchange", "protonmail",
    "fastmail", "gmail", "ymail", "aol", "yahoo",
    "dkim1", "dkim2", "selector", "s1", "s2",
    "k1", "k2", "key1", "key2", "rsa", "ed25519"
  }

  local all_records = {}

  for _, query in ipairs(txt_queries) do
    local opts = { host = host.ip, port = port.number, dtype = "TXT", timeout = 5000 }
    local ok, answer = pcall(dns.query, query.name, opts)
    if ok and answer and #answer > 0 then
      for _, record in ipairs(answer) do
        local txt_string = tostring(record):gsub('"', "")
        all_records[#all_records + 1] = {
          query = query.name,
          description = query.desc,
          category = query.category,
          value = txt_string
        }
      end
    end
  end

  for _, sel in ipairs(common_selectors) do
    local query_name = sel .. "._domainkey." .. domain
    local opts = { host = host.ip, port = port.number, dtype = "TXT", timeout = 3000 }
    local ok, answer = pcall(dns.query, query_name, opts)
    if ok and answer and #answer > 0 then
      for _, record in ipairs(answer) do
        local txt_string = tostring(record):gsub('"', "")
        all_records[#all_records + 1] = {
          query = query_name,
          description = "DKIM (" .. sel .. ")",
          category = "dkim",
          value = txt_string
        }
      end
    end
  end

  result.status = "success"
  result.domain = domain
  result.server = host.ip .. ":" .. port.number

  if #all_records > 0 then
    result.total_records = #all_records
    result.records = all_records

    local categorized = {}
    for _, r in ipairs(all_records) do
      if not categorized[r.category] then categorized[r.category] = {} end
      categorized[r.category][#categorized[r.category] + 1] = r
    end
    result.records_by_category = categorized

    local spf_records = {}
    local dkim_records = {}
    local dmarc_records = {}
    for _, r in ipairs(all_records) do
      local val_lower = r.value:lower()
      if val_lower:find("v=spf1") then
        spf_records[#spf_records + 1] = r
      end
      if val_lower:find("v=dkim1") or val_lower:find("p=") and r.category == "dkim" then
        dkim_records[#dkim_records + 1] = r
      end
      if val_lower:find("v=dmarc1") then
        dmarc_records[#dmarc_records + 1] = r
      end
    end

    result.email_authentication = {}
    result.email_authentication.spf = (#spf_records > 0)
    result.email_authentication.dkim = (#dkim_records > 0)
    result.email_authentication.dmarc = (#dmarc_records > 0)
    result.email_authentication.has_all_three = (#spf_records > 0 and #dkim_records > 0 and #dmarc_records > 0)
  else
    result.total_records = 0
    result.reason = "No TXT records found"
  end

  return result
end
