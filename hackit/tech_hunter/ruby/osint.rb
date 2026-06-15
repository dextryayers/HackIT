#!/usr/bin/env ruby
# OSINT Data Collector
require 'json'
require 'open-uri'
require 'resolv'

input = STDIN.read
data = JSON.parse(input) rescue {}
domain = data['domain'] || ''

results = []
return puts JSON.generate(results) if domain.empty?

begin
  # Try common subdomains via DNS
  subdomains = %w[www mail ftp admin api dev test staging blog shop cdn m app]
  subdomains.each do |sub|
    host = "#{sub}.#{domain}"
    begin
      Resolv.getaddresses(host)
      results << host
    rescue Resolv::ResolvError
      # not found
    end
  end
rescue => e
  # DNS failed silently
end

begin
  # Try Wayback Machine for historical URLs
  wb_url = "http://web.archive.org/cdx/search/cdx?url=#{domain}&output=json&limit=10"
  wb_data = URI.open(wb_url, read_timeout: 5).read rescue ""
  unless wb_data.empty?
    JSON.parse(wb_data).each do |entry|
      results << "wayback:#{entry[2]}" if entry[2]
    end
  end
rescue
  # Silent fail
end

puts JSON.generate(results.uniq)
