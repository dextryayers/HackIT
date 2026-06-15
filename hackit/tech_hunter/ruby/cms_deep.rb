#!/usr/bin/env ruby
# Deep CMS Detection (beyond basic signatures)
require 'json'

domain = ARGV[0] || ""
body = ARGV[1] || ""
headers_json = ARGV[2] || "{}"

headers = JSON.parse(headers_json) rescue {}
body_lower = body.downcase
server = (headers['Server'] || '').downcase
x_powered = (headers['X-Powered-By'] || '').downcase

result = { 
  cms: "Unknown", version: nil, theme: nil, plugins: [],
  users: [], vulnerable: false, notes: []
}

# WordPress deep
if body.include?('wp-content')
  result[:cms] = "WordPress"
  version_match = body.match(/ver=(\d+\.\d+(?:\.\d+)?)/)
  result[:version] = version_match[1] if version_match
  theme_match = body.match(%r{/wp-content/themes/([^/]+)})
  result[:theme] = theme_match[1] if theme_match
  body.scan(%r{/wp-content/plugins/([^/]+)}) { |m| result[:plugins] << m[0] unless result[:plugins].include?(m[0]) }
  if body.include?('wp-admin') && body.include?('setup-config')
    result[:notes] << "Possible unconfigured WordPress setup"
  end
end

# Drupal deep
if body.include?('drupal.js') || body.include?('Drupal.settings')
  result[:cms] = "Drupal"
  version_match = body.match(/Drupal (\d+\.\d+)/)
  result[:version] = version_match[1] if version_match
  if body.include?('/user/register') || body.include?('/user/login')
    result[:notes] << "Public registration enabled"
  end
end

# Joomla deep  
if body.include?('/media/jui/') || body.include?('com_content')
  result[:cms] = "Joomla"
  version_match = body.match(/joomla! (\d+\.\d+)/i) || body.match(/Joomla (\d+\.\d+)/)
  result[:version] = version_match[1] if version_match
end

# Magento deep
if body.include?('Magento_') || body.include?('mage/')
  result[:cms] = "Magento"
  version_match = body.match(/Magento[,\s]+(\d+\.\d+(?:\.\d+)?)/)
  result[:version] = version_match[1] if version_match
end

# Generic version disclosures
if server.match(/([Nn]ginx|Apache|IIS)\/(\d+\.\d+(?:\.\d+)?)/)
  result[:notes] << "Server: #{$1} #{$2}"
end

if result[:version] && result[:version] < "4.0"
  result[:vulnerable] = true
  result[:notes] << "Outdated CMS version (#{result[:version]})"
end

puts result.to_json
