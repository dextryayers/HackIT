#!/usr/bin/env ruby
# Origin IP Discovery via DNS History
require 'json'
require 'resolv'

domain = ARGV[0] || ''
history_json = ARGV[1] || '[]'
historical_ips = JSON.parse(history_json) rescue []

results = { origin_ips: [], candidates: [], method: '' }

# Collect current IPs
current_ips = []
begin
  current_ips = Resolv.getaddresses(domain).select { |ip| ip =~ Resolv::IPv4::Regex }
rescue; end

results[:candidates] = current_ips

# Check historical IPs from input
historical_ips.each do |ip|
  next if current_ips.include?(ip)
  results[:origin_ips] << ip
end

# Try direct IP connection via Common CDN bypass techniques
if results[:origin_ips].empty?
  results[:method] = "No historical data - try CloudFail or similar tools"
else
  results[:method] = "Historical DNS data"
end

results[:origin_ips].uniq!
results[:candidates].uniq!

puts JSON.generate(results)
