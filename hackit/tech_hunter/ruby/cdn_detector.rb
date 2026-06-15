#!/usr/bin/env ruby
require 'json'
require 'ipaddr'
require 'resolv'

begin
  ip_str = ARGV[0] || ''
  headers_json = ARGV[1] || '{}'
  _domain = ARGV[2] || ''
  headers = JSON.parse(headers_json) rescue {}

  normalized = {}
  headers.each { |k, v| normalized[k.downcase] = v.to_s }

  indicators = []
  provider = nil
  confidence = 0
  edge_location = nil

  if normalized.key?('cf-cache-status')
    indicators << "CF-Cache-Status: #{normalized['cf-cache-status']}"
    provider = 'Cloudflare'
    confidence = 95
  end

  if normalized.key?('cf-ray')
    indicators << "CF-Ray: #{normalized['cf-ray']}"
    provider = 'Cloudflare'
    confidence = 95
  end

  if normalized.key?('server')
    server = normalized['server'].downcase
    if server.include?('cloudflare')
      indicators << "Server: #{normalized['server']}"
      provider = 'Cloudflare'
      confidence = [confidence, 95].max
    elsif server.include?('akamai') || server.include?('akamaighost')
      indicators << "Server: #{normalized['server']}"
      provider = 'Akamai'
      confidence = [confidence, 90].max
    elsif server.include?('fastly')
      indicators << "Server: #{normalized['server']}"
      provider = 'Fastly'
      confidence = [confidence, 90].max
    end
  end

  if normalized.key?('via')
    via = normalized['via'].downcase
    %w[cloudflare akamai fastly varnish].each do |p|
      if via.include?(p)
        indicators << "Via: #{normalized['via']}"
        provider ||= p.capitalize
        confidence = [confidence, 80].max
        break
      end
    end
    if via.include?('google') || via.include?('1.1')
      indicators << "Via: #{normalized['via']}"
      provider ||= 'Google Cloud CDN'
      confidence = [confidence, 75].max
    end
  end

  if normalized.key?('x-cache')
    xcache = normalized['x-cache']
    indicators << "X-Cache: #{xcache}"
    if xcache.downcase.include?('cloudfront')
      provider = 'CloudFront'
      confidence = [confidence, 95].max
    elsif xcache.downcase.include?('fastly')
      provider = 'Fastly'
      confidence = [confidence, 90].max
    elsif xcache.downcase.include?('hit') || xcache.downcase.include?('miss')
      provider ||= 'Generic CDN'
      confidence = [confidence, 60].max
    end
  end

  if normalized.key?('x-cache-hits')
    indicators << "X-Cache-Hits: #{normalized['x-cache-hits']}"
  end

  if normalized.key?('x-amz-cf-id') || normalized.key?('x-amz-cf-pop')
    indicators << "X-Amz-Cf-* headers present"
    provider = 'CloudFront'
    confidence = [confidence, 95].max
    if normalized['x-amz-cf-pop']
      edge_location = normalized['x-amz-cf-pop'].split(' ').first
    end
  end

  if normalized.key?('x-azure-ref') || normalized.key?('x-azure-fdid')
    indicators << "X-Azure-* headers present"
    provider = 'Azure CDN'
    confidence = [confidence, 90].max
  end

  if normalized.key?('x-cdn')
    indicators << "X-CDN: #{normalized['x-cdn']}"
    provider ||= 'CDNetworks'
    confidence = [confidence, 75].max
  end

  if provider == 'Cloudflare' && normalized['cf-ray']
    loc = normalized['cf-ray'].match(/-([A-Z]+)/)
    if loc
      edge_location = loc[1]
    end
  end

  cdn_detected = !provider.nil?

  result = {
    cdn_detected: cdn_detected,
    provider: provider,
    edge_location: edge_location,
    indicators: indicators,
    confidence: confidence > 0 ? confidence : 0
  }

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
