#!/usr/bin/env ruby
# Contact Scraper - extracts emails and phones from HTML
require 'json'

body = ARGV[0] || ""
headers_json = ARGV[1] || "{}"

emails = body.scan(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/).uniq
phones = body.scan(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/).uniq

# Filter out common false positives
emails.reject! { |e| e =~ /\.png$|\.jpg$|\.css$|\.js$|example\.com|domain\.com/ }
phones.reject! { |p| p.length < 8 || p.length > 15 }

# Extract from mailto links
body.scan(/mailto:([^"\s'?]+)/) { |m| emails << m[0] unless emails.include?(m[0]) }

# Extract social media handles
social = []
body.scan(%r{(?:facebook|twitter|linkedin|instagram|github)\.com/([a-zA-Z0-9._]+)}) do |m|
  social << m[0]
end

puts JSON.generate({ scraped_emails: emails.uniq, scraped_phones: phones.uniq, social_media: social.uniq })
