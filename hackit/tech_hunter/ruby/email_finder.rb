#!/usr/bin/env ruby
# Email Finder - extracts emails from multiple sources in HTML
require 'json'
require 'set'

body = ARGV[0] || ""
domain = ARGV[1] || ""

emails = Set.new

# Standard email pattern
body.scan(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/) { |e| emails << e }

# HTML entities encoding
body.scan(/&#64;|%@|%40|\[at\]|\(at\)|ät/) { emails << "possible_obfuscated_email" }

# mailto links
body.scan(/mailto:([^"'\s?>]+)/) { |m| emails << m[0] }

# JSON/JS objects with email keys
body.scan(/"email"\s*:\s*"([^"]+)"/) { |m| emails << m[0] }
body.scan(/'email'\s*:\s*'([^']+)'/) { |m| emails << m[0] }

# Text patterns
body.scan(/(?:Email|E-mail|EMAIL)[:\s]+([a-zA-Z0-9._%+\-@]+)/) { |m| emails << m[0] }

# Role-based email patterns
if domain && !domain.empty?
  base = domain.sub(/^https?:\/\//, '').sub(/\/.*$/, '').sub(/^www\./, '')
  %w[admin info contact support sales help privacy abuse webmaster postmaster].each do |role|
    emails << "#{role}@#{base}"
  end
end

# Filter false positives
emails.reject! { |e| e =~ /example\.com|domain\.com|your\.|\.png$|\.jpg$|\.css$|\.js$|\.gif$/i }
emails.reject! { |e| e.length > 100 || e.length < 5 }

puts JSON.generate({ emails: emails.to_a, count: emails.length })
