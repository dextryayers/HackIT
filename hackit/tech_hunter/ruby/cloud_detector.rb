#!/usr/bin/env ruby
# Cloud Provider & Service Detector
require 'json'

body = ARGV[0] || ""
headers_json = ARGV[1] || "{}"
domain = ARGV[2] || ""

headers = JSON.parse(headers_json) rescue {}
body_lower = body.downcase
server = (headers['Server'] || headers['server'] || '').downcase

result = {
  providers: [],
  services: [],
  cdn: false,
  waf: false,
  details: {}
}

# AWS Detection
if server.include?('cloudfront') || server.include?('amazon') || body.include?('s3.amazonaws')
  result[:providers] << "AWS"
  result[:cdn] = true if server.include?('cloudfront')
  result[:details][:aws] = 'CloudFront' if server.include?('cloudfront')
  if body.include?('s3.amazonaws') || body.include?('s3-') || body.include?('s3.')
    result[:services] << 'S3 Bucket'
    result[:details][:aws_services] = 'S3'
  end
end

# Azure Detection
if server.include?('azure') || body.include?('azure') || domain =~ /\.azurewebsites\./
  result[:providers] << "Azure"
  result[:details][:azure] = domain if domain =~ /\.azurewebsites\./
  if body.include?('azureedge') || body.include?('azurefd')
    result[:cdn] = true
    result[:details][:azure_cdn] = true
  end
end

# GCP Detection
if server.include?('gcp') || server.include?('google') || body.include?('googleapis') || domain =~ /\.appspot\.com/
  result[:providers] << "GCP"
  result[:details][:gcp] = true
  if body.include?('storage.googleapis') || body.include?('cloudstorage')
    result[:services] << 'Cloud Storage'
  end
end

# WAF Detection
if server.include?('cloudflare')
  result[:providers] << "Cloudflare"
  result[:waf] = true
  result[:cdn] = true
  result[:details][:cloudflare] = true
end
if server.include?('akamai') || server.include?('akamaighost')
  result[:providers] << "Akamai"
  result[:waf] = true
  result[:cdn] = true
end
if server.include?('fastly')
  result[:providers] << "Fastly"
  result[:cdn] = true
end
if server.include?('incapsula') || body.include?('incapsula')
  result[:providers] << "Incapsula"
  result[:waf] = true
end
if server.include?('sucuri')
  result[:providers] << "Sucuri"
  result[:waf] = true
end

# Other services
if body.include?('firebase') || domain =~ /\.firebaseapp\.com/
  result[:providers] << "Firebase"
  result[:services] << 'Firebase Hosting'
end
if domain =~ /\.netlify\.app|\.netlify\.com/
  result[:providers] << "Netlify"
  result[:services] << 'Netlify Hosting'
end
if domain =~ /\.vercel\.app|\.now\.sh/
  result[:providers] << "Vercel"
  result[:services] << 'Vercel Hosting'
end
if domain =~ /\.herokuapp\.com/
  result[:providers] << "Heroku"
  result[:services] << 'Heroku Hosting'
end
if domain =~ /\.pages\.dev/
  result[:providers] << "Cloudflare Pages"
  result[:services] << 'Cloudflare Pages'
end

result[:providers].uniq!
result[:services].uniq!

puts JSON.generate(result)
