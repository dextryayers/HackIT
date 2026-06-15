#!/usr/bin/env ruby
# JavaScript Analyzer - extracts endpoints, secrets, and patterns from JS
require 'json'

body = ARGV[0] || ""
base_url = ARGV[1] || ""

result = { endpoints: [], secrets: [], api_keys: [], patterns: [] }

# Extract endpoint URLs from strings
endpoint_patterns = [
  /["'](https?:\/\/[^"'\s]+)["']/,
  /["'](\/[a-zA-Z0-9_\.\/-]+(?:api|v[0-9]+|rest|graphql)[a-zA-Z0-9_\.\/-]*)["']/i,
  /["'](\/[a-zA-Z0-9_\.\/-]+(?:endpoint|route|path|url|uri)[a-zA-Z0-9_\.\/-]*)["']/i,
  /url\s*[:\=]\s*["']([^"']+)["']/,
  /endpoint\s*[:\=]\s*["']([^"']+)["']/,
  /path\s*[:\=]\s*["']([^"']+)["']/,
]

endpoint_patterns.each do |pat|
  body.scan(pat) { |m| result[:endpoints] << m[0] }
end

# Secret/key patterns
secret_patterns = [
  [/api[_-]?key[_-]?(["\s:=]+)([a-zA-Z0-9_\-]{16,64})/i, 'API Key'],
  [/secret[_-]?(["\s:=]+)([a-zA-Z0-9_\-]{8,64})/i, 'Secret'],
  [/token[_-]?(["\s:=]+)([a-zA-Z0-9_\-\.]{8,256})/i, 'Token'],
  [/password[_-]?(["\s:=]+)([a-zA-Z0-9_\-!@#$%^&*]{6,})/i, 'Password'],
  [/bearer\s+([a-zA-Z0-9_\-\.]{8,})/i, 'Bearer Token'],
  [/ghp_[a-zA-Z0-9]{36}/, 'GitHub Token'],
  [/sk_live_[a-zA-Z0-9]{24,}/, 'Stripe Live Key'],
  [/pk_live_[a-zA-Z0-9]{24,}/, 'Stripe Live Publishable'],
  [/AKIA[0-9A-Z]{16}/, 'AWS Access Key'],
  [/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, 'Private Key'],
  [/xox[bpsar]-[a-zA-Z0-9\-]{24,}/, 'Slack Token'],
  [/SFDC_[a-zA-Z0-9]{34,}/, 'Salesforce Token'],
]

secret_patterns.each do |pat, type|
  body.scan(pat) do |match|
    result[:secrets] << { type: type, match: match[0][0..40] }
  end
end

# Source map references
body.scan(/\/\/# sourceMappingURL=([^\s]+)/) { |m| result[:patterns] << "sourcemap:#{m[0]}" }

# AJAX/fetch calls
body.scan(/(fetch|axios|ajax|XMLHttpRequest)\(["']([^"']+)["']/) { |m| result[:endpoints] << m[1] }

result[:endpoints].uniq!
result[:secrets].uniq! { |s| s[:match] }

puts JSON.generate(result)
