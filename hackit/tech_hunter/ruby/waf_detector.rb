#!/usr/bin/env ruby
require 'json'

begin
  headers_json = ARGV[0] || '{}'
  _domain = ARGV[1] || ''
  headers = JSON.parse(headers_json) rescue {}

  normalized = {}
  headers.each { |k, v| normalized[k.downcase] = v.to_s }

  indicators = []
  waf_name = nil
  confidence = 0

  checks = {
    'cf-ray' => { name: 'Cloudflare', confidence: 95 },
    'x-sucuri-id' => { name: 'Sucuri', confidence: 90 },
    'x-cdn' => { name: 'CDNetworks', confidence: 85 },
    'x-cdn-reqid' => { name: 'CDNetworks', confidence: 85 },
    'akamai-origin-hop' => { name: 'Akamai', confidence: 90 },
    'x-protected-by' => { name: 'Protected by', confidence: 80 },
    'x-waf' => { name: 'Generic WAF', confidence: 70 }
  }

  checks.each do |header, info|
    if normalized.key?(header)
      indicators << "#{header}: #{normalized[header]}"
      if waf_name.nil? || info[:confidence] > confidence
        waf_name = info[:name]
        confidence = info[:confidence]
      end
    end
  end

  if normalized.key?('server')
    server = normalized['server'].downcase
    if server.include?('cloudflare')
      indicators << "Server: #{normalized['server']}"
      if waf_name.nil? || 95 > confidence
        waf_name = 'Cloudflare'
        confidence = 95
      end
    elsif server.include?('akamai')
      indicators << "Server: #{normalized['server']}"
      if waf_name.nil? || 90 > confidence
        waf_name = 'Akamai'
        confidence = 90
      end
    elsif server.include?('sucuri')
      indicators << "Server: #{normalized['server']}"
      if waf_name.nil? || 90 > confidence
        waf_name = 'Sucuri'
        confidence = 90
      end
    end
  end

  if normalized.key?('x-powered-by')
    xpb = normalized['x-powered-by'].downcase
    if xpb.include?('sucuri')
      indicators << "X-Powered-By: #{normalized['x-powered-by']}"
      if waf_name.nil? || 85 > confidence
        waf_name = 'Sucuri'
        confidence = 85
      end
    end
  end

  waf_cookies = {
    '__cfduid' => 'Cloudflare',
    '__cf_bm' => 'Cloudflare',
    'mod_security' => 'ModSecurity',
    'noyb' => 'Generic WAF'
  }

  cookie_headers = [normalized['set-cookie'], normalized['cookie']].compact.join(' ')
  waf_cookies.each do |cookie, provider|
    if cookie_headers.include?(cookie)
      indicators << "Cookie: #{cookie}"
      if waf_name.nil? || 85 > confidence
        waf_name = provider
        confidence = conf = provider == 'Cloudflare' ? 90 : 75
      end
    end
  end

  if normalized.key?('x-cache') && !normalized['x-cache'].empty?
    xcache = normalized['x-cache']
    %w[cloudflare fastly akamai].each do |p|
      if xcache.downcase.include?(p)
        indicators << "X-Cache: #{xcache} (contains #{p})"
        if waf_name.nil? || 85 > confidence
          waf_name = p.capitalize
          confidence = 85
        end
        break
      end
    end
  end

  if normalized.key?('via')
    via = normalized['via']
    %w[cloudflare akamai fastly].each do |p|
      if via.downcase.include?(p)
        indicators << "Via: #{via}"
        break
      end
    end
  end

  waf_detected = !waf_name.nil?
  details = if waf_detected
              "#{waf_name} CDN/WAF detected via #{indicators.first(2).join(' and ')}"
            else
              'No WAF detected'
            end

  result = {
    waf_detected: waf_detected,
    waf_name: waf_name,
    confidence: confidence > 0 ? confidence : 0,
    indicators: indicators,
    details: details
  }

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
