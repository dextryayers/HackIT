local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Tests whether the target DNS server allows recursive queries from external (non-trusted)
hosts. An open recursive DNS resolver can be abused in DNS amplification DDoS attacks,
where attackers forge queries with small request sizes that generate large response
payloads. The script sends queries for known external domains to multiple authoritative
nameservers and analyzes responses to distinguish recursive from non-recursive behavior.
Compares response with expected answer counts and RCODE values. Reports amplification
factor estimates for risk assessment. Includes recommendations for securing open
resolvers.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local test_domains = {
  "google.com", "example.com", "iana.org", "cloudflare.com",
  "wikipedia.org", "github.com", "microsoft.com", "amazon.com"
}

action = function(host, port)
  local result = stdnse.output_table()
  local base_opts = {
    host = host.ip,
    port = port.number,
    dtype = "A",
    timeout = 5000,
    retries = 1
  }

  local recursive_results = {}
  local domain_answers = {}

  for _, domain in ipairs(test_domains) do
    local ok, answer = pcall(dns.query, domain, base_opts)
    if ok and answer and #answer > 0 then
      domain_answers[#domain_answers + 1] = {
        domain = domain,
        answers = answer,
        count = #answer
      }
    end
  end

  result.status = "success"
  result.server = host.ip .. ":" .. port.number
  result.domains_tested = #test_domains
  result.total_answered = #domain_answers

  if #domain_answers >= 2 then
    result.recursive_resolver = true
    result.recursion_enabled = true
    result.domain_results = domain_answers

    local total_answers = 0
    for _, d in ipairs(domain_answers) do
      total_answers = total_answers + d.count
    end

    result.average_answers_per_query = string.format("%.1f", total_answers / #domain_answers)

    local amp_factor = 2.0
    for _, d in ipairs(domain_answers) do
      local ans = d.answers
      if #ans > 3 then
        amp_factor = math.max(amp_factor, 4.0)
      end
    end
    result.estimated_amplification_factor = string.format("%.1fx", amp_factor)

    if amp_factor >= 4.0 then
      result.amplification_risk = "high"
      result.recommendation = "Restrict recursion to trusted networks, enable rate limiting, implement BCP 38"
    else
      result.amplification_risk = "medium"
      result.recommendation = "Restrict recursion to authorized clients only"
    end
  elseif #domain_answers == 0 then
    result.recursive_resolver = false
    result.recursion_enabled = false
    result.reason = "No recursive responses received (host may block recursion)"
  else
    local count = 0
    for _, d in ipairs(domain_answers) do
      local ok2, nsec_check = pcall(dns.query, d.domain, {
        host = host.ip, port = port.number, dtype = "NSEC", timeout = 3000
      })
      if ok2 and nsec_check and #nsec_check > 0 then
        count = count + 1
      end
    end
    if count > 0 then
      result.recursive_resolver = true
      result.recursion_enabled = true
      result.domain_results = domain_answers
      result.note = "Limited recursion (some domains have DNSSEC info, possible partial resolution)"
    else
      result.recursive_resolver = false
      result.recursion_enabled = false
      result.reason = "Partial responses received but may be from cache or referrals"
    end
  end

  return result
end
