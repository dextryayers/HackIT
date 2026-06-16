local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Performs DNS cache snooping against the target recursive resolver to determine which
domains are currently cached. The technique relies on measuring response timing: a
cached response arrives significantly faster than a response requiring iterative
resolution from authoritative servers. The test queries a curated list of popular
domains across multiple categories (social media, streaming, technology, search,
email, business) and applies statistical analysis to distinguish cached from
non-cached responses. Uses baseline timing calibration to account for network
latency. Reveals browsing patterns and potentially sensitive information about what
domains resolver users have recently accessed. Useful for security assessments and
privacy auditing.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain")

local cache_test_domains = {
  { name = "google.com", category = "Search" },
  { name = "youtube.com", category = "Video" },
  { name = "facebook.com", category = "Social" },
  { name = "instagram.com", category = "Social" },
  { name = "amazon.com", category = "E-commerce" },
  { name = "wikipedia.org", category = "Reference" },
  { name = "reddit.com", category = "Social" },
  { name = "netflix.com", category = "Streaming" },
  { name = "microsoft.com", category = "Technology" },
  { name = "apple.com", category = "Technology" },
  { name = "cloudflare.com", category = "CDN" },
  { name = "github.com", category = "Development" },
  { name = "stackoverflow.com", category = "Development" },
  { name = "linkedin.com", category = "Professional" },
  { name = "twitter.com", category = "Social" },
  { name = "whatsapp.com", category = "Messaging" },
  { name = "zoom.us", category = "Communication" },
  { name = "office.com", category = "Productivity" },
  { name = "salesforce.com", category = "CRM" },
  { name = "dropbox.com", category = "Storage" },
  { name = "tiktok.com", category = "Social" },
  { name = "snapchat.com", category = "Social" },
  { name = "telegram.org", category = "Messaging" },
  { name = "discord.com", category = "Communication" },
  { name = "slack.com", category = "Communication" },
  { name = "atlassian.com", category = "Development" },
  { name = "gitlab.com", category = "Development" },
  { name = "bitbucket.org", category = "Development" },
  { name = "docker.com", category = "Technology" },
  { name = "konghq.com", category = "Technology" }
}

action = function(host, port)
  local result = stdnse.output_table()
  local cached_domains = {}

  local calibration_domain = "thisshouldnotexist-hackit-test-" .. math.random(10000, 99999) .. ".com"
  local cal_opts = {
    host = host.ip, port = port.number, dtype = "A",
    timeout = 5000, retries = 1
  }
  local cal_start = nmap.clock()
  local cal_ok, cal_answer = pcall(dns.query, calibration_domain, cal_opts)
  local cal_elapsed = (nmap.clock() - cal_start) * 1000
  local baseline_rtt = math.min(cal_elapsed, 500)

  local dynamic_threshold = math.min(baseline_rtt * 0.3, 80)
  dynamic_threshold = math.max(dynamic_threshold, 15)

  local base_opts = {
    host = host.ip, port = port.number, dtype = "A",
    timeout = 5000, retries = 1
  }

  for _, entry in ipairs(cache_test_domains) do
    local start = nmap.clock()
    local ok, answer = pcall(dns.query, entry.name, base_opts)
    local elapsed = (nmap.clock() - start) * 1000

    if ok and answer and #answer > 0 then
      if elapsed < dynamic_threshold then
        cached_domains[#cached_domains + 1] = {
          domain = entry.name,
          category = entry.category,
          response_time_ms = math.floor(elapsed),
          threshold_used = math.floor(dynamic_threshold)
        }
      end
    end

    nmap.msleep(20)
  end

  result.status = "success"
  result.server = host.ip .. ":" .. port.number
  result.total_tested = #cache_test_domains
  result.baseline_rtt_ms = math.floor(baseline_rtt)
  result.cache_threshold_ms = math.floor(dynamic_threshold)

  if #cached_domains > 0 then
    table.sort(cached_domains, function(a, b) return a.response_time_ms < b.response_time_ms end)

    result.domains_cached = #cached_domains
    result.cached_domains = cached_domains

    local categories = {}
    for _, d in ipairs(cached_domains) do
      categories[d.category] = (categories[d.category] or 0) + 1
    end
    result.cached_by_category = categories

    result.cache_ratio = string.format("%.1f%%", (#cached_domains / #cache_test_domains) * 100)

    if #cached_domains > (#cache_test_domains * 0.5) then
      result.assessment = "Active resolver with heavily populated cache"
    elseif #cached_domains > (#cache_test_domains * 0.2) then
      result.assessment = "Moderately populated cache"
    else
      result.assessment = "Minimal cache population"
    end
  else
    result.domains_cached = 0
    result.reason = "No cached entries detected based on timing analysis"
    result.assessment = "Resolver may not be recursive, cache may be empty, or timing threshold too aggressive"
  end

  return result
end
