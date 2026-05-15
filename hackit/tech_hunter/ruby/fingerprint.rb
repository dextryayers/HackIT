require 'json'

def analyze(body, headers)
  detected = []
  
  # Industrial-Grade Signature Database
  patterns = {
    "WordPress" => { regex: /wp-content|wp-includes/i, cat: "CMS" },
    "Joomla" => { regex: /Joomla!|option=com_/i, cat: "CMS" },
    "Drupal" => { regex: /Drupal|Drupal\.settings/i, cat: "CMS" },
    "Magento" => { regex: /Mage\.Cookies|skin\/frontend/i, cat: "E-commerce" },
    "Shopify" => { regex: /cdn\.shopify\.com|shopify-payment-button/i, cat: "E-commerce" },
    
    "React" => { regex: /data-reactroot|_reactListening/i, cat: "Frontend Framework" },
    "Vue.js" => { regex: /__vue__|data-v-/i, cat: "Frontend Framework" },
    "Angular" => { regex: /ng-version=|ng-app=/i, cat: "Frontend Framework" },
    "Svelte" => { regex: /svelte-/i, cat: "Frontend Framework" },
    
    "Nginx" => { regex: /nginx/i, cat: "Web Server" },
    "Apache" => { regex: /Apache/i, cat: "Web Server" },
    "LiteSpeed" => { regex: /LiteSpeed/i, cat: "Web Server" },
    "Microsoft-IIS" => { regex: /Microsoft-IIS/i, cat: "Web Server" },
    
    "Cloudflare" => { regex: /cf-ray|__cfduid|server: cloudflare/i, cat: "CDN/WAF" },
    "Akamai" => { regex: /x-akamai-transformed|server: akamaighost/i, cat: "CDN/WAF" },
    "AWS CloudFront" => { regex: /via: cloudfront|x-amz-cf-id/i, cat: "CDN/WAF" },
    
    "PHP" => { regex: /X-Powered-By: PHP|PHPSESSID/i, cat: "Language" },
    "Laravel" => { regex: /laravel_session|XSRF-TOKEN/i, cat: "Backend Framework" },
    "Django" => { regex: /csrftoken|django/i, cat: "Backend Framework" },
    "Express" => { regex: /X-Powered-By: Express/i, cat: "Backend Framework" }
  }

  patterns.each do |name, info|
    matched = false
    if body =~ info[:regex]
      matched = true
    else
      headers.each do |k, v|
        if k =~ info[:regex] || v =~ info[:regex]
          matched = true
          break
        end
      end
    end
    
    if matched
      detected << { name: name, confidence: 98, category: info[:cat] }
    end
  end

  detected
end

begin
  input = JSON.parse(STDIN.read)
  results = analyze(input['body'], input['headers'])
  puts results.to_json
rescue => e
  puts({ error: e.message }.to_json)
end
