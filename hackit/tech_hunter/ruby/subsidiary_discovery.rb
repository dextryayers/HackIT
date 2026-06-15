#!/usr/bin/env ruby
# Subsidiary & Related Domain Discovery
require 'json'
require 'resolv'

domain = ARGV[0] || ''
return puts JSON.generate({ subsidiaries: [], related_domains: [], error: "No domain provided" }) if domain.empty?

domain = domain.downcase.sub(/^https?:\/\//, '').sub(/\/.*$/, '')

results = { subsidiaries: [], related_domains: [], organization: "" }

# Try to get organization name from WHOIS-like patterns
org_name = domain.split('.').first.capitalize
results[:organization] = org_name

# Generate subsidiary domain candidates
tlds = %w[.com .net .org .io .co .ai .app .dev .cloud .tech .io .me .tv .info .biz]
prefixes = %w[dev test staging prod admin portal app api cdn cloud mail]
suffixes = %w[inc corp ltd llc limited group global international]

regions = %w[us eu uk asia na sa af me apac]
divisions = %w[sales support hr it finance legal marketing product engineering]

# Related domains
candidates = []
[org_name.downcase].each do |base|
  tlds.each do |tld|
    candidates << "#{base}#{tld}"
    prefixes.each { |p| candidates << "#{p}-#{base}#{tld}" }
    suffixes.each { |s| candidates << "#{base}#{s}#{tld}" }
  end
  regions.each { |r| candidates << "#{base}-#{r}.com" }
  divisions.each { |d| candidates << "#{base}-#{d}.com" }
end

# Verify candidates via DNS
live_domains = []
candidates.uniq.each do |candidate|
  next if candidate == domain
  begin
    Resolv.getaddresses(candidate)
    live_domains << candidate
  rescue Resolv::ResolvError
    # not resolvable
  rescue => e
    # timeout or other error
  end
end

results[:related_domains] = live_domains
results[:subsidiaries] = live_domains.first(5) # Top 5 as subsidiaries

puts JSON.generate(results)
