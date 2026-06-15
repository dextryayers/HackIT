#!/usr/bin/env ruby
# CMS & Cloud Platform Detector
require 'json'

domain = ARGV[0] || ""
body = ARGV[1] || ""
headers_json = ARGV[2] || "{}"

headers = JSON.parse(headers_json) rescue {}
body_lower = body.downcase
server = (headers['Server'] || headers['server'] || '').downcase
x_powered = (headers['X-Powered-By'] || headers['x-powered-by'] || '').downcase
set_cookie = (headers['Set-Cookie'] || headers['set-cookie'] || '').downcase
content_type = (headers['Content-Type'] || headers['content-type'] || '').downcase

result = { cms: "Unknown", cloud: "Unknown/On-Premise", framework: "Unknown", platform: "Unknown" }

# CMS Detection
if body.include?('wp-content') || body.include?('wp-includes') || body.include?('wp-json')
  result[:cms] = "WordPress"
elsif body.include?('Drupal.settings') || body.include?('drupal.js') || body.include?('sites/default')
  result[:cms] = "Drupal"
elsif body.include?('joomla') || body.include?('com_content') || body.include?('/media/system/js/')
  result[:cms] = "Joomla"
elsif body.include?('Mage.Cookies') || body.include?('mage/') || body.include?('Magento_')
  result[:cms] = "Magento"
elsif body.include?('shopify') || body.include?('myshopify.com') || set_cookie.include?('shopify')
  result[:cms] = "Shopify"
elsif server.include?('wix')
  result[:cms] = "Wix"
elsif server.include?('squarespace')
  result[:cms] = "Squarespace"
elsif body.include?('umbraco') || body.include?('/umbraco/')
  result[:cms] = "Umbraco"
elsif body.include?('concrete5') || body.include?('concrete/')
  result[:cms] = "Concrete5"
end

# Framework Detection
if x_powered.include?('express') || body.include?('x-powered-by.*express')
  result[:framework] = "Express.js"
elsif x_powered.include?('rails') || body.include?('csrf-param') || body.include?('authenticity_token')
  result[:framework] = "Ruby on Rails"
elsif body.include?('laravel') || body.include?('csrf-token') || body.include?('livewire')
  result[:framework] = "Laravel"
elsif body.include?('django') || body.include?('csrfmiddlewaretoken')
  result[:framework] = "Django"
elsif server.include?('asp.net') || x_powered.include?('asp.net')
  result[:framework] = "ASP.NET"
elsif server.include?('spring') || body.include?('/actuator') || body.include?('spring')
  result[:framework] = "Spring Boot"
end

# Cloud Detection
if server.include?('cloudflare') || body.include?('__cfduid')
  result[:cloud] = "Cloudflare"
elsif server.include?('akamaighost') || server.include?('akamai')
  result[:cloud] = "Akamai"
elsif server.include?('amazon') || server.include?('aws') || server.include?('cloudfront')
  result[:cloud] = "AWS"
elsif server.include?('azure') || body.include?('azure')
  result[:cloud] = "Azure"
elsif server.include?('gcp') || server.include?('google') || body.include?('googleapis')
  result[:cloud] = "GCP"
elsif server.include?('fastly')
  result[:cloud] = "Fastly"
elsif server.include?('stackpath')
  result[:cloud] = "StackPath"
end

# Platform Detection
if content_type.include?('php') || server.include?('php') || x_powered.include?('php')
  result[:platform] = "PHP"
elsif content_type.include?('java') || server.include?('java') || server.include?('oracle')
  result[:platform] = "Java"
elsif x_powered.include?('python') || body.include?('wsgi')
  result[:platform] = "Python"
elsif x_powered.include?('ruby') || server.include?('passenger') || server.include?('unicorn')
  result[:platform] = "Ruby"
elsif server.include?('iis')
  result[:platform] = "Windows IIS"
end

puts result.to_json
